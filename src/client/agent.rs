use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep, timeout_at},
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{
        AgentCredentials, AgentEnrollmentRequest, ControlMessage, DiscoveryResult, NativePlan,
        RelayMode, TransportInfo, TunnelTicketClaims,
    },
    transport::{
        HandoffOptions, IrohByteStream, IrohEndpointOptions, MappingDiscovery, PreparedPunch,
        PunchError, PunchIdentity, PunchRole, RelayChoice, TransportError, connect_peer,
        create_endpoint, discover_ipv4_mappings, snapshot_iroh_paths, validate_endpoint_addr,
        wait_endpoint_ready,
    },
};

use super::{
    ClientContext,
    api::{Api, WsStream},
    profile::{self, write_json_atomic},
};

const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TICKET_FRAME: usize = 8 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingAgentIdentity {
    endpoint_secret_key: String,
}

struct TunnelOffer {
    session_id: Uuid,
    target_id: Uuid,
    ticket: String,
    client_endpoint_id: String,
    client_endpoint_addr: EndpointAddr,
    ticket_public_key_pem: String,
    relay_mode: RelayMode,
}

struct AgentRuntime {
    stable_device_secret_key: SecretKey,
    transport_info: TransportInfo,
    active_sessions: JoinSet<()>,
    completed_sessions: Arc<StdMutex<Vec<Uuid>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("agent connection authentication failed: {0}")]
struct AgentAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("server selected an authentication failure: {0}")]
struct ServerAuthenticationFailure(String);

pub async fn enroll(context: &ClientContext, target_id: Uuid, enrollment_code: &str) -> Result<()> {
    let credential_path = profile::agent_credentials_path(&context.config.data_dir, target_id);
    let pending_path = credential_path.with_extension("pending.json");
    let identity = if credential_path.exists() {
        let saved = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
        PendingAgentIdentity {
            endpoint_secret_key: saved.endpoint_secret_key,
        }
    } else {
        match fs::read(&pending_path) {
            Ok(bytes) => serde_json::from_slice::<PendingAgentIdentity>(&bytes)
                .context("read pending target Iroh identity")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = PendingAgentIdentity {
                    endpoint_secret_key: encode_secret_key(&SecretKey::generate()),
                };
                profile::ensure_private_dir(&context.config.data_dir)?;
                write_json_atomic(&pending_path, &identity)?;
                identity
            }
            Err(error) => return Err(error).context("read pending target Iroh identity"),
        }
    };
    let endpoint_secret_key = decode_secret_key(&identity.endpoint_secret_key)?;
    let response = context
        .api
        .agent_enroll(&AgentEnrollmentRequest {
            target_id,
            enrollment_token: enrollment_code.to_owned(),
            agent_endpoint_id: endpoint_secret_key.public().to_string(),
        })
        .await?;
    anyhow::ensure!(
        response.target_id == target_id,
        "server enrolled a different target ID"
    );
    profile::save_agent_credentials(
        &context.config.data_dir,
        &AgentCredentials {
            target_id,
            agent_token: response.agent_token,
            ticket_public_key_pem: response.ticket_public_key_pem,
            endpoint_secret_key: identity.endpoint_secret_key,
        },
    )?;
    if pending_path.exists() {
        fs::remove_file(pending_path).context("remove completed pending Iroh identity")?;
    }
    Ok(())
}

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let credentials = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
    let mut runtime = AgentRuntime {
        stable_device_secret_key: decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        active_sessions: JoinSet::new(),
        completed_sessions: Arc::new(StdMutex::new(Vec::new())),
    };
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control_session(context, target_id, &credentials, &mut runtime).await {
            Ok(()) => bail!("agent control connection closed"),
            Err(error) if is_authentication_error(&error) => {
                tracing::error!(target = %target_id, error = %error, "agent credential was rejected; active SSH sessions will finish");
                while let Some(result) = runtime.active_sessions.join_next().await {
                    if let Err(error) = result {
                        tracing::warn!(target = %target_id, error = %error, "active SSH session ended");
                    }
                }
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(target = %target_id, error = %error, retry_seconds = retry_delay.as_secs(), "agent control connection lost; active SSH sessions remain connected");
                sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(CONTROL_RETRY_MAX);
            }
        }
    }
}

fn endpoint_options(
    context: &ClientContext,
    info: &TransportInfo,
    relay_mode: RelayMode,
    handoff: Option<HandoffOptions>,
) -> Result<IrohEndpointOptions> {
    let relay_choice = match relay_mode {
        RelayMode::Private => {
            let relay_url = info
                .private_relay_url
                .as_deref()
                .context("private Iroh relay is not configured")?;
            let relay_url =
                reqwest::Url::parse(relay_url).context("parse private Iroh relay URL")?;
            let control_origin = reqwest::Url::parse(context.api.issuer())
                .context("parse configured kmesh server URL")?;
            anyhow::ensure!(
                relay_url == control_origin,
                "Iroh private relay URL differs from the configured kmesh server"
            );
            RelayChoice::Private {
                url: relay_url,
                qad_port: info.qad_port,
            }
        }
        RelayMode::PublicDefault => RelayChoice::PublicDefault,
    };
    Ok(IrohEndpointOptions {
        relay_choice,
        tls: context.config.tls.clone(),
        handoff,
    })
}

fn encode_secret_key(secret_key: &SecretKey) -> String {
    URL_SAFE_NO_PAD.encode(secret_key.to_bytes())
}

fn decode_secret_key(encoded: &str) -> Result<SecretKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode saved target Iroh secret key")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("saved target Iroh secret key must contain 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

async fn send_control_sink(
    writer: &mut futures_util::stream::SplitSink<WsStream, Message>,
    message: &ControlMessage,
) -> Result<()> {
    let text = serde_json::to_string(message).context("encode agent control message")?;
    writer
        .send(Message::Text(text.into()))
        .await
        .context("send agent control message")
}

async fn run_agent_session(
    context: &ClientContext,
    credentials: &AgentCredentials,
    stable_device_key: SecretKey,
    transport_info: TransportInfo,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: String,
    relay_mode: RelayMode,
    expires_at: i64,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64;
    let remaining_secs = expires_at.saturating_sub(now);
    ensure_auth(remaining_secs > 0, "agent session preparation has expired")?;
    let deadline =
        Instant::now() + Duration::from_secs(remaining_secs as u64).min(SESSION_SETUP_TIMEOUT);
    let client_id = client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "prepared client EndpointId is invalid".to_owned()
            ))
        })?;
    let data_key = SecretKey::generate();
    let data_id = data_key.public();
    let signature = stable_device_key
        .sign(&crate::identity::agent_session_identity_payload(
            session_id, target_id, relay_mode, &data_id, expires_at,
        ))
        .to_bytes()
        .to_vec();
    outbound
        .send(ControlMessage::AgentIdentity {
            session_id,
            relay_mode,
            target_data_endpoint_id: data_id.to_string(),
            signature,
        })
        .await
        .context("register per-session target data identity")?;

    match next_session_message(&mut control_rx, session_id, deadline).await? {
        None => return Ok(()),
        Some(ControlMessage::IdentityAccepted {
            session_id: accepted,
            relay_mode: accepted_mode,
        }) if accepted == session_id && accepted_mode == relay_mode => {}
        _ => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server returned an unexpected response to the signed target identity".to_owned()
            )));
        }
    }

    let relay_choice = endpoint_options(context, &transport_info, relay_mode, None)
        .map_err(|error| TransportError::Configuration(error.to_string()))?
        .relay_choice;
    let discovery_deadline = std::cmp::min(deadline, Instant::now() + Duration::from_secs(2));
    let discovery = tokio::select! {
        biased;
        control = next_session_message(&mut control_rx, session_id, deadline) => {
            match control? {
                None => return Ok(()),
                Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                    "server sent a control message before target candidate discovery completed".to_owned()
                ))),
            }
        }
        result = discover_ipv4_mappings(&relay_choice, &context.config.tls, discovery_deadline) => {
            result.map_err(anyhow::Error::new)?
        }
    };
    let (discovery_message, mut discovered) = match discovery {
        MappingDiscovery::Ready(discovered) => (
            DiscoveryResult::Ready {
                local_socket: discovered.local_socket,
                observations: discovered.observations.clone(),
            },
            Some(discovered),
        ),
        MappingDiscovery::Unavailable { reason } => (DiscoveryResult::Unavailable { reason }, None),
    };
    outbound
        .send(ControlMessage::CandidatesReady {
            session_id,
            relay_mode,
            discovery: discovery_message,
        })
        .await
        .context("report target QAD candidate discovery")?;

    let first_native_message =
        match next_session_message(&mut control_rx, session_id, deadline).await? {
            None => return Ok(()),
            Some(message) => message,
        };
    let (handoff, selection) = match first_native_message {
        ControlMessage::ContinueNative {
            session_id: received,
            relay_mode: mode,
            plan: NativePlan::Standard,
        } if received == session_id && mode == relay_mode => {
            drop(discovered.take());
            (None, None)
        }
        ControlMessage::PunchPair {
            session_id: received,
            relay_mode: mode,
            target_endpoint_id,
            client_endpoint_id: paired_client_id,
            peer_discovery,
        } if received == session_id && mode == relay_mode => {
            ensure_auth(
                target_endpoint_id == data_id.to_string(),
                "server paired a different per-session target EndpointId",
            )?;
            ensure_auth(
                paired_client_id == client_endpoint_id,
                "server paired a different client EndpointId",
            )?;
            let discovered = discovered.take().ok_or_else(|| {
                anyhow!(AgentAuthenticationFailure(
                    "server requested UDP punching without successful QAD discovery".to_owned()
                ))
            })?;
            let Some(native) = run_target_punch(
                session_id,
                relay_mode,
                data_id,
                client_id,
                data_key.clone(),
                discovered,
                peer_discovery,
                &mut control_rx,
                &outbound,
                deadline,
            )
            .await?
            else {
                return Ok(());
            };
            native
        }
        _ => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected response to target QAD candidates".to_owned()
            )));
        }
    };

    let options = endpoint_options(context, &transport_info, relay_mode, handoff)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let relay_choice = options.relay_choice.clone();
    let endpoint = tokio::select! {
        biased;
        control = next_session_message(&mut control_rx, session_id, deadline) => {
            match control? {
                None => return Ok(()),
                Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                    "server sent a control message before target Endpoint creation completed".to_owned()
                ))),
            }
        }
        result = timeout_at(deadline, create_endpoint(data_key, false, options)) => {
            result
                .context("create per-session target Iroh endpoint before expiry")?
                .map_err(anyhow::Error::new)?
        }
    };
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(RELAY_ENDPOINT_TIMEOUT);
    tokio::select! {
        biased;
        control = next_session_message(&mut control_rx, session_id, deadline) => {
            match control? {
                None => return Ok(()),
                Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                    "server sent a control message before target Endpoint readiness".to_owned()
                ))),
            }
        }
        result = timeout_at(deadline, wait_endpoint_ready(&endpoint, remaining)) => {
            result
                .context("wait for per-session target relay and address readiness")?
                .map_err(anyhow::Error::new)?;
        }
    }
    let target_data_endpoint_id = endpoint.id().to_string();
    outbound
        .send(ControlMessage::AgentReady {
            session_id,
            relay_mode,
            endpoint_addr: endpoint.addr(),
        })
        .await
        .context("publish per-session target Iroh endpoint")?;

    let offer = match next_session_message(&mut control_rx, session_id, deadline).await? {
        None => return Ok(()),
        Some(ControlMessage::DialOffer {
            session_id: received,
            target_id: offered_target_id,
            ticket,
            client_endpoint_id,
            client_endpoint_addr,
            ticket_public_key_pem,
            relay_mode: offered_mode,
        }) if received == session_id && offered_mode == relay_mode => TunnelOffer {
            session_id,
            target_id: offered_target_id,
            ticket,
            client_endpoint_id,
            client_endpoint_addr,
            ticket_public_key_pem,
            relay_mode,
        },
        Some(_) => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected control message before target dial offer".to_owned()
            )));
        }
    };
    ensure_auth(
        offer.target_id == target_id,
        "dial offer target ID differs from Prepare",
    )?;
    let claims = decode_tunnel_ticket(
        &offer.ticket,
        &offer.ticket_public_key_pem,
        context.api.issuer(),
    )
    .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    validate_ticket(&claims, &offer, credentials, endpoint.id())?;
    ensure_auth(
        offer.client_endpoint_addr.ip_addrs().count() <= 32
            && offer.client_endpoint_addr.relay_urls().next().is_some(),
        "client EndpointAddr exceeds address limits or lacks relay candidates",
    )?;
    validate_endpoint_addr(&offer.client_endpoint_addr, &relay_choice)
        .map_err(anyhow::Error::new)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;

    tracing::debug!(
        session = %session_id,
        target_data_endpoint_id,
        raw_selected = selection.is_some(),
        native_handoff_selected = handoff.is_some(),
        endpoint_addr = ?endpoint.addr(),
        "per-session target endpoint ready"
    );
    handle_dial_offer(
        context,
        offer,
        endpoint,
        relay_choice,
        deadline,
        control_rx,
        outbound,
    )
    .await
}

async fn run_target_punch(
    session_id: Uuid,
    relay_mode: RelayMode,
    target_data_id: iroh::EndpointId,
    client_id: iroh::EndpointId,
    data_key: SecretKey,
    discovered: crate::transport::DiscoveredUdpSocket,
    peer_discovery: crate::protocol::ReadyDiscovery,
    control_rx: &mut mpsc::Receiver<ControlMessage>,
    outbound: &mpsc::Sender<ControlMessage>,
    deadline: Instant,
) -> Result<
    Option<(
        Option<HandoffOptions>,
        Option<crate::transport::PunchSelection>,
    )>,
> {
    let mut punch = match PreparedPunch::prepare(
        PunchRole::Target,
        PunchIdentity {
            session_id,
            target_id: target_data_id,
            client_id,
        },
        data_key,
        discovered,
        peer_discovery.local_socket,
        peer_discovery.observations,
    ) {
        Ok(punch) => punch,
        Err(PunchError::Unavailable(reason)) => {
            return if report_target_punch_failure(
                outbound, control_rx, session_id, relay_mode, reason, deadline,
            )
            .await?
            {
                Ok(Some((None, None)))
            } else {
                Ok(None)
            };
        }
        Err(PunchError::Fatal(error)) => return Err(anyhow::Error::new(error)),
    };

    let socket_count = u16::try_from(punch.socket_count())
        .map_err(|_| anyhow!("target punch socket count exceeds protocol limit"))?;
    outbound
        .send(ControlMessage::PunchReady {
            session_id,
            relay_mode,
            socket_count,
        })
        .await
        .context("report target punch socket readiness")?;
    let start = match next_session_message(control_rx, session_id, deadline).await? {
        None => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            return Ok(None);
        }
        Some(ControlMessage::StartPunch {
            session_id: received,
            relay_mode: mode,
        }) if received == session_id && mode == relay_mode => true,
        Some(ControlMessage::ContinueNative {
            session_id: received,
            relay_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == relay_mode => false,
        Some(_) => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected target punch-stage control message".to_owned()
            )));
        }
    };
    if !start {
        punch.finish(false).await.map_err(anyhow::Error::new)?;
        return Ok(Some((None, None)));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let punch_window = remaining
        .saturating_sub(RELAY_ENDPOINT_TIMEOUT)
        .min(Duration::from_secs(38));
    if punch_window.is_zero() {
        punch.finish(false).await.map_err(anyhow::Error::new)?;
        return if report_target_punch_failure(
            outbound,
            control_rx,
            session_id,
            relay_mode,
            "remaining session time is reserved for native relay setup".to_owned(),
            deadline,
        )
        .await?
        {
            Ok(Some((None, None)))
        } else {
            Ok(None)
        };
    }
    let punch_deadline = Instant::now() + punch_window;
    let selection = tokio::select! {
        biased;
        control = next_session_message(control_rx, session_id, deadline) => {
            match control? {
                None => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Ok(None);
                }
                Some(ControlMessage::ContinueNative {
                    session_id: received,
                    relay_mode: mode,
                    plan: NativePlan::Standard,
                }) if received == session_id && mode == relay_mode => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Ok(Some((None, None)));
                }
                Some(_) => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Err(anyhow!(AgentAuthenticationFailure(
                        "server sent an unexpected control event while target punch was active".to_owned()
                    )));
                }
            }
        }
        result = punch.start(punch_deadline) => match result {
            Ok(selection) => selection,
            Err(PunchError::Unavailable(reason)) => {
                punch.finish(false).await.map_err(anyhow::Error::new)?;
                return if report_target_punch_failure(
                    outbound,
                    control_rx,
                    session_id,
                    relay_mode,
                    reason,
                    deadline,
                )
                .await?
                {
                    Ok(Some((None, None)))
                } else {
                    Ok(None)
                };
            }
            Err(PunchError::Fatal(error)) => {
                punch.finish(false).await.map_err(anyhow::Error::new)?;
                return Err(anyhow::Error::new(error));
            }
        }
    };

    outbound
        .send(ControlMessage::PunchSelected {
            session_id,
            relay_mode,
            index: selection.index,
            local_socket: selection.local_socket,
            peer_observed_addr: selection.peer_observed_addr,
        })
        .await
        .context("report target raw UDP winner")?;
    match next_session_message(control_rx, session_id, deadline).await? {
        None => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Ok(None)
        }
        Some(ControlMessage::ContinueNative {
            session_id: received,
            relay_mode: mode,
            plan:
                NativePlan::Handoff {
                    self_observed_addr,
                    peer_observed_addr,
                },
        }) if received == session_id && mode == relay_mode => {
            ensure_auth(
                peer_observed_addr == selection.peer_observed_addr,
                "server handoff peer tuple differs from the confirmed target punch winner",
            )?;
            let local = punch
                .finish(true)
                .await
                .map_err(anyhow::Error::new)?
                .context("selected target punch did not return a local handoff tuple")?;
            ensure_auth(
                local.index == selection.index && local.bind_addr == selection.local_socket,
                "target punch handoff tuple differs from the selected raw socket",
            )?;
            Ok(Some((
                Some(HandoffOptions {
                    bind_addr: local.bind_addr,
                    self_observed_addr,
                }),
                Some(selection),
            )))
        }
        Some(ControlMessage::ContinueNative {
            session_id: received,
            relay_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == relay_mode => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Ok(Some((None, Some(selection))))
        }
        Some(_) => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected target native handoff control message".to_owned()
            )))
        }
    }
}

async fn report_target_punch_failure(
    outbound: &mpsc::Sender<ControlMessage>,
    control_rx: &mut mpsc::Receiver<ControlMessage>,
    session_id: Uuid,
    relay_mode: RelayMode,
    reason: String,
    deadline: Instant,
) -> Result<bool> {
    outbound
        .send(ControlMessage::PunchFailed {
            session_id,
            relay_mode,
            reason,
        })
        .await
        .context("report target punch network failure")?;
    match next_session_message(control_rx, session_id, deadline).await? {
        Some(ControlMessage::ContinueNative {
            session_id: received,
            relay_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == relay_mode => Ok(true),
        None => Ok(false),
        Some(_) => Err(anyhow!(AgentAuthenticationFailure(
            "server sent a nonstandard native plan after target punch failure".to_owned()
        ))),
    }
}

async fn next_session_message(
    receiver: &mut mpsc::Receiver<ControlMessage>,
    session_id: Uuid,
    deadline: Instant,
) -> Result<Option<ControlMessage>> {
    let message = timeout_at(deadline, receiver.recv())
        .await
        .map_err(|_| anyhow::Error::new(TransportError::Timeout("agent session setup")))?;
    let Some(message) = message else {
        return Ok(None);
    };
    match &message {
        ControlMessage::Close {
            session_id: received,
            ..
        } if *received == session_id => return Ok(None),
        ControlMessage::Error {
            session_id: Some(received),
            code,
            message,
        } if *received == session_id => {
            return Err(match code.as_str() {
                "authentication" | "authorization" => {
                    anyhow!(AgentAuthenticationFailure(message.clone()))
                }
                "network" => anyhow::Error::new(TransportError::Network(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    message.clone(),
                ))),
                "configuration" => {
                    anyhow::Error::new(TransportError::Configuration(message.clone()))
                }
                _ => anyhow!("server rejected agent session: {message}"),
            });
        }
        _ => {}
    }
    ensure_auth(
        message_session_id(&message) == Some(session_id),
        "server sent a control message for a different agent session",
    )?;
    Ok(Some(message))
}

fn agent_session_error_code(error: &anyhow::Error) -> &'static str {
    if is_authentication_error(error)
        || error.chain().any(|source| {
            source
                .downcast_ref::<TransportError>()
                .is_some_and(|error| {
                    error.is_auth_failure()
                        || matches!(
                            error,
                            TransportError::Authentication(_)
                                | TransportError::Tls(_)
                                | TransportError::ProtocolViolation(_)
                        )
                })
        })
    {
        "authentication"
    } else if error.chain().any(|source| {
        source
            .downcast_ref::<TransportError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    TransportError::Configuration(_) | TransportError::Iroh(_)
                )
            })
    }) {
        "configuration"
    } else {
        "network"
    }
}

async fn control_session(
    context: &ClientContext,
    target_id: Uuid,
    credentials: &AgentCredentials,
    runtime: &mut AgentRuntime,
) -> Result<()> {
    let ws = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.agent_control(&credentials.agent_token),
    )
    .await
    .context("agent control connection timed out")??;
    let (mut writer, mut reader) = ws.split();
    let completed = {
        let mut completed = runtime
            .completed_sessions
            .lock()
            .expect("completed session lock poisoned");
        std::mem::take(&mut *completed)
    };
    for session_id in completed {
        send_control_sink(
            &mut writer,
            &ControlMessage::Close {
                session_id,
                reason: "session_finished_while_control_was_offline".to_owned(),
            },
        )
        .await
        .context("report SSH session finished while control was offline")?;
    }
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ControlMessage>(64);
    let (done_tx, mut done_rx) = mpsc::channel::<Uuid>(16);
    let mut sessions: HashMap<Uuid, mpsc::Sender<ControlMessage>> = HashMap::new();
    loop {
        tokio::select! {
            Some(message) = outbound_rx.recv() => {
                send_control_sink(&mut writer, &message).await.context("send agent control message")?;
            }
            Some(session_id) = done_rx.recv() => {
                sessions.remove(&session_id);
            }
            joined = runtime.active_sessions.join_next(), if !runtime.active_sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(error = %error, "active SSH session task failed");
                }
            }
            incoming = reader.next() => {
                let Some(incoming) = incoming else { bail!("agent control WebSocket ended") };
                let incoming = incoming.context("read agent control WebSocket")?;
                if matches!(incoming, Message::Ping(_) | Message::Pong(_)) {
                    continue;
                }
                match Api::control_message(incoming)? {
                    ControlMessage::Prepare {
                        session_id,
                        relay_mode,
                        client_endpoint_id,
                        expires_at,
                    } => {
                        ensure_auth(
                            !sessions.contains_key(&session_id),
                            "server reused active SSH session ID {session_id}"
                        )?;
                        let (session_tx, session_rx) = mpsc::channel(16);
                        sessions.insert(session_id, session_tx);
                        let context = context.clone();
                        let credentials = credentials.clone();
                        let stable_device_key = runtime.stable_device_secret_key.clone();
                        let transport_info = runtime.transport_info.clone();
                        let outbound = outbound_tx.clone();
                        let done = done_tx.clone();
                        let completed = runtime.completed_sessions.clone();
                        runtime.active_sessions.spawn(async move {
                            if let Err(error) = run_agent_session(
                                &context,
                                &credentials,
                                stable_device_key,
                                transport_info,
                                session_id,
                                target_id,
                                client_endpoint_id,
                                relay_mode,
                                expires_at,
                                session_rx,
                                outbound.clone(),
                            )
                            .await
                            {
                                let code = agent_session_error_code(&error);
                                tracing::warn!(session = %session_id, error = %error, "agent SSH setup/session failed");
                                if outbound
                                    .send(ControlMessage::Error {
                                        session_id: Some(session_id),
                                        code: code.to_owned(),
                                        message: error.to_string(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    remember_completed(&completed, session_id);
                                }
                            }
                            let _ = done.send(session_id).await;
                        });
                    }
                    ControlMessage::Error { session_id: None, code, message }
                        if code == "authentication" || code == "authorization" =>
                    {
                        return Err(anyhow!(ServerAuthenticationFailure(format!("server rejected agent control: {message}"))));
                    }
                    message => {
                        if let Some(session_id) = message_session_id(&message)
                            && let Some(sender) = sessions.get(&session_id)
                        {
                            sender.send(message).await.context("route agent session message")?;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_dial_offer(
    context: &ClientContext,
    offer: TunnelOffer,
    endpoint: Endpoint,
    relay_choice: RelayChoice,
    setup_deadline: Instant,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let connection = timeout_at(setup_deadline, async {
        tokio::select! {
            biased;
            control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
                control.map(|()| None)
            },
            connection = connect_peer(&endpoint, offer.client_endpoint_addr.clone(), &relay_choice) => {
                connection.map(Some).map_err(transport_error)
            },
        }
    })
        .await
        .context("target connection exceeded the per-session expiry")?
        ?;
    let Some(connection) = connection else {
        return Ok(());
    };
    let remote_endpoint_id = connection.remote_id().to_string();
    ensure_auth(
        remote_endpoint_id == offer.client_endpoint_id,
        "Iroh peer EndpointId differs from the ticket client EndpointId",
    )?;

    let mut path_events = connection.path_events();
    let direct_deadline = std::cmp::min(Instant::now() + Duration::from_secs(2), setup_deadline);
    let direct_selected = tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = timeout_at(direct_deadline, async {
            loop {
                if connection
                    .paths()
                    .iter()
                    .any(|path| path.is_ip() && path.is_selected())
                {
                    break true;
                }
                if path_events.next().await.is_none() {
                    break false;
                }
            }
        }) => result.unwrap_or(false),
    };
    tracing::debug!(
        session = %offer.session_id,
        direct_selected,
        paths = ?snapshot_iroh_paths(&connection),
        "target Iroh path state before ticket stream"
    );

    let mut stream = tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = IrohByteStream::open_bi(connection) => result.map_err(transport_error)?,
    };
    tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = write_ticket(&mut stream, &offer.ticket) => result.context("send signed tunnel ticket to client")?,
    }
    outbound
        .send(ControlMessage::IrohReady {
            session_id: offer.session_id,
            client_endpoint_id: remote_endpoint_id,
            target_data_endpoint_id: endpoint.id().to_string(),
            relay_mode: offer.relay_mode,
        })
        .await
        .context("report authenticated Iroh peer to server")?;
    if timeout_at(
        setup_deadline,
        wait_activated(offer.session_id, &mut control_rx),
    )
    .await
    .context("target activation exceeded the per-session expiry")??
    {
        return Ok(());
    }

    let mut ssh = tokio::time::timeout(
        Duration::from_secs(context.config.ssh.connect_timeout_secs),
        TcpStream::connect(context.config.ssh.address),
    )
    .await
    .context("connecting to local sshd timed out")?
    .with_context(|| format!("connect to local sshd at {}", context.config.ssh.address))?;
    ssh.set_nodelay(true)
        .context("set local sshd TCP_NODELAY")?;
    let paths_before_ssh = snapshot_iroh_paths(stream.connection());
    tracing::debug!(
        session = %offer.session_id,
        paths = ?paths_before_ssh,
        "target Iroh paths before SSH byte forwarding"
    );
    let result = tokio::io::copy_bidirectional(&mut ssh, &mut stream).await;
    let paths_after_ssh = snapshot_iroh_paths(stream.connection());
    match result {
        Ok((to_ssh, from_ssh)) => {
            tracing::debug!(
                session = %offer.session_id,
                ssh_bytes_to_target = to_ssh,
                ssh_bytes_from_target = from_ssh,
                paths_before = ?paths_before_ssh,
                paths_after = ?paths_after_ssh,
                "target SSH forwarding path and byte counters"
            );
            stream
                .finish_send_and_wait()
                .await
                .context("wait for client to acknowledge final SSH bytes")?;
            stream
                .connection()
                .close(iroh::endpoint::VarInt::from_u32(0), b"ssh session complete");
            tracing::debug!(session = %offer.session_id, to_ssh, from_ssh, "target SSH stream completed");
            outbound
                .send(ControlMessage::Close {
                    session_id: offer.session_id,
                    reason: "ssh_stream_complete".to_owned(),
                })
                .await
                .context("report completed SSH stream")?;
            Ok(())
        }
        Err(error) => {
            tracing::debug!(
                session = %offer.session_id,
                error = %error,
                paths_before = ?paths_before_ssh,
                paths_after = ?paths_after_ssh,
                "target SSH forwarding ended with an Iroh path snapshot"
            );
            let _ = stream.reset();
            Err(error).context("copy SSH data between Iroh and local sshd")
        }
    }
}

async fn write_ticket(stream: &mut IrohByteStream, ticket: &str) -> Result<()> {
    let bytes = ticket.as_bytes();
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_TICKET_FRAME,
        "signed ticket exceeds the handshake frame limit"
    );
    stream
        .write_u32(bytes.len() as u32)
        .await
        .context("write ticket frame length")?;
    stream
        .write_all(bytes)
        .await
        .context("write ticket frame")?;
    stream.flush().await.context("flush ticket frame")
}

async fn wait_for_setup_cancellation(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    loop {
        match inbound.recv().await {
            None => return Ok(()),
            Some(ControlMessage::Close {
                session_id: received,
                ..
            }) if received == session_id => return Ok(()),
            Some(ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            }) if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(AgentAuthenticationFailure(message));
                }
                bail!("server rejected SSH session during setup: {message}");
            }
            Some(_) => {}
        }
    }
}

fn validate_ticket(
    claims: &TunnelTicketClaims,
    offer: &TunnelOffer,
    credentials: &AgentCredentials,
    target_endpoint_id: iroh::EndpointId,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    ensure_auth(
        offer.ticket_public_key_pem == credentials.ticket_public_key_pem,
        "ticket public key differs from enrollment",
    )?;
    ensure_auth(
        claims.session_id == offer.session_id,
        "ticket session ID mismatch",
    )?;
    ensure_auth(
        claims.target_id == offer.target_id,
        "ticket target ID mismatch",
    )?;
    ensure_auth(
        claims.client_endpoint_id == offer.client_endpoint_id,
        "ticket client EndpointId mismatch",
    )?;
    ensure_auth(
        claims.target_endpoint_id == target_endpoint_id.to_string(),
        "ticket target EndpointId mismatch",
    )?;
    ensure_auth(
        offer.client_endpoint_addr.id.to_string() == offer.client_endpoint_id,
        "client EndpointAddr differs from the ticket client EndpointId",
    )?;
    ensure_auth(
        claims.relay_mode == offer.relay_mode,
        "ticket relay mode mismatch",
    )?;
    ensure_auth(
        offer.target_id == credentials.target_id,
        "offer target ID differs from enrolled target",
    )?;
    ensure_auth(
        claims.aud == TUNNEL_TICKET_AUDIENCE,
        "ticket audience mismatch",
    )?;
    ensure_auth(claims.exp > now, "ticket has expired")?;
    offer
        .client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "client EndpointId is invalid".to_owned()
            ))
        })?;
    claims
        .target_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "target EndpointId is invalid".to_owned()
            ))
        })?;
    Ok(())
}

async fn wait_activated(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<bool> {
    loop {
        match inbound.recv().await {
            None => return Ok(false),
            Some(ControlMessage::Activated {
                session_id: received,
            }) if received == session_id => return Ok(true),
            Some(ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            }) if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(AgentAuthenticationFailure(message));
                }
                bail!("server rejected SSH session before activation: {message}");
            }
            Some(ControlMessage::Close {
                session_id: received,
                ..
            }) if received == session_id => return Ok(false),
            Some(_) => {}
        }
    }
}

fn message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Activated { session_id }
        | ControlMessage::IrohReady { session_id, .. }
        | ControlMessage::DialOffer { session_id, .. }
        | ControlMessage::Prepare { session_id, .. }
        | ControlMessage::AgentIdentity { session_id, .. }
        | ControlMessage::IdentityAccepted { session_id, .. }
        | ControlMessage::CandidatesReady { session_id, .. }
        | ControlMessage::PunchPair { session_id, .. }
        | ControlMessage::PunchReady { session_id, .. }
        | ControlMessage::StartPunch { session_id, .. }
        | ControlMessage::PunchSelected { session_id, .. }
        | ControlMessage::PunchFailed { session_id, .. }
        | ControlMessage::ContinueNative { session_id, .. }
        | ControlMessage::AgentReady { session_id, .. }
        | ControlMessage::ClientReady { session_id, .. }
        | ControlMessage::ClientOffer { session_id, .. }
        | ControlMessage::Open { session_id, .. }
        | ControlMessage::Close { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
    }
}

fn remember_completed(completed: &Arc<StdMutex<Vec<Uuid>>>, session_id: Uuid) {
    let mut completed = completed.lock().expect("completed session lock poisoned");
    if !completed.contains(&session_id) {
        completed.push(session_id);
    }
}

pub(super) fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(AgentAuthenticationFailure(message.to_owned())))
    }
}

fn is_authentication_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AgentAuthenticationFailure>().is_some()
        || error
            .downcast_ref::<ServerAuthenticationFailure>()
            .is_some()
}

fn transport_error(error: TransportError) -> anyhow::Error {
    match error {
        TransportError::Authentication(message) => anyhow!(AgentAuthenticationFailure(message)),
        error => anyhow!(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client::proxy::read_ticket, transport::accept_peer};
    use iroh::{Endpoint, endpoint::presets};
    use std::io;
    use tokio::io::AsyncReadExt;

    #[test]
    fn per_session_error_classification_keeps_auth_and_protocol_failures_terminal() {
        assert_eq!(
            agent_session_error_code(&anyhow::Error::new(TransportError::Tls(
                "QAD certificate rejected".to_owned()
            ))),
            "authentication"
        );
        assert_eq!(
            agent_session_error_code(&anyhow::Error::new(TransportError::ProtocolViolation(
                "wrong punch SID".to_owned()
            ))),
            "authentication"
        );
        assert_eq!(
            agent_session_error_code(&anyhow::Error::new(TransportError::Configuration(
                "invalid private relay".to_owned()
            ))),
            "configuration"
        );
        assert_eq!(
            agent_session_error_code(&anyhow::Error::new(TransportError::Network(
                io::Error::from(io::ErrorKind::NetworkUnreachable)
            ))),
            "network"
        );
    }

    async fn context(server_url: &str) -> ClientContext {
        let config = crate::config::Config {
            server_url: server_url.to_owned(),
            ..crate::config::Config::default()
        };
        let api = Api::new(&config).await.expect("build test API client");
        let profiles =
            profile::ProfileStore::new(&config.data_dir, &config.server_url, &config.profile);
        ClientContext {
            config,
            config_path: None,
            api,
            profiles,
        }
    }

    async fn local_endpoints() -> (Endpoint, Endpoint) {
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local accepting client endpoint");
        let target = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local dialing target endpoint");
        (client, target)
    }

    fn offer(client: &Endpoint) -> TunnelOffer {
        TunnelOffer {
            session_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            ticket: "signed-test-ticket".to_owned(),
            client_endpoint_id: client.id().to_string(),
            client_endpoint_addr: client.addr(),
            ticket_public_key_pem: String::new(),
            relay_mode: RelayMode::PublicDefault,
        }
    }

    async fn await_offer(task: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("agent dial did not finish promptly")
            .expect("agent dial task panicked")
    }

    #[tokio::test]
    async fn relay_mode_uses_public_default_only_when_requested() {
        let context = context("https://kmesh.test:9443").await;
        let info = TransportInfo {
            private_relay_url: None,
            qad_port: 3478,
        };

        let public = endpoint_options(&context, &info, RelayMode::PublicDefault, None)
            .expect("public relay mode does not require a private relay");
        assert_eq!(public.relay_choice, RelayChoice::PublicDefault);
        assert!(endpoint_options(&context, &info, RelayMode::Private, None).is_err());
    }

    #[tokio::test]
    async fn private_relay_must_match_the_authenticated_service_origin() {
        let context = context("https://kmesh.test:9443").await;
        let info = TransportInfo {
            private_relay_url: Some("https://kmesh.test:9443".to_owned()),
            qad_port: 3478,
        };
        let options = endpoint_options(&context, &info, RelayMode::Private, None)
            .expect("server private relay matches the control service");
        assert_eq!(
            options.relay_choice,
            RelayChoice::Private {
                url: reqwest::Url::parse("https://kmesh.test:9443").unwrap(),
                qad_port: 3478,
            }
        );

        let malicious = TransportInfo {
            private_relay_url: Some("https://untrusted.example".to_owned()),
            qad_port: 3478,
        };
        assert!(endpoint_options(&context, &malicious, RelayMode::Private, None).is_err());
    }

    #[tokio::test]
    async fn target_dials_the_client_and_reports_only_after_ticket_write() {
        let context = context("https://kmesh.test:9443").await;
        let (client, target) = local_endpoints().await;
        let offer = offer(&client);
        let session_id = offer.session_id;
        let client_endpoint_id = client.id().to_string();
        let target_data_endpoint_id = target.id().to_string();
        let client_task = tokio::spawn(async move {
            let connection = accept_peer(&client)
                .await
                .expect("accept target connection");
            let mut stream = IrohByteStream::accept_bi(connection)
                .await
                .expect("accept target ticket stream");
            read_ticket(&mut stream).await.expect("read target ticket")
        });
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, mut outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_dial_offer(
                &context,
                offer,
                target,
                RelayChoice::PublicDefault,
                Instant::now() + Duration::from_secs(5),
                control_rx,
                outbound,
            )
            .await
        });

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
                .await
                .expect("target did not report Iroh readiness")
            .expect("target control channel closed"),
            ControlMessage::IrohReady { session_id: received, client_endpoint_id: reported_id, target_data_endpoint_id: target_data, relay_mode: RelayMode::PublicDefault }
                if received == session_id && reported_id == client_endpoint_id && target_data == target_data_endpoint_id
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client_task)
                .await
                .expect("client did not receive the ticket")
                .expect("client accept task panicked"),
            "signed-test-ticket"
        );
        control_tx
            .send(ControlMessage::Close {
                session_id,
                reason: "test complete".to_owned(),
            })
            .await
            .expect("cancel pending SSH activation");
        assert!(await_offer(task).await.is_ok());
    }

    #[tokio::test]
    async fn close_cancels_target_dial_before_client_accepts() {
        let context = context("https://kmesh.test:9443").await;
        let (client, target) = local_endpoints().await;
        let offer = offer(&client);
        let session_id = offer.session_id;
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_dial_offer(
                &context,
                offer,
                target,
                RelayChoice::PublicDefault,
                Instant::now() + Duration::from_secs(5),
                control_rx,
                outbound,
            )
            .await
        });

        tokio::task::yield_now().await;
        control_tx
            .send(ControlMessage::Close {
                session_id,
                reason: "cancelled".to_owned(),
            })
            .await
            .expect("send session close");
        assert!(await_offer(task).await.is_ok());
    }

    #[tokio::test]
    async fn control_disconnect_cancels_target_dial() {
        let context = context("https://kmesh.test:9443").await;
        let (client, target) = local_endpoints().await;
        let offer = offer(&client);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_dial_offer(
                &context,
                offer,
                target,
                RelayChoice::PublicDefault,
                Instant::now() + Duration::from_secs(5),
                control_rx,
                outbound,
            )
            .await
        });
        drop(control_tx);
        assert!(await_offer(task).await.is_ok());
    }

    #[tokio::test]
    async fn closing_a_second_session_endpoint_keeps_the_first_ssh_stream_alive() {
        let (client_one, target_one) = local_endpoints().await;
        let (_client_two, target_two) = local_endpoints().await;
        let session_one_endpoint_id = target_one.id();
        let session_two_endpoint_id = target_two.id();
        assert_ne!(session_one_endpoint_id, session_two_endpoint_id);
        assert_ne!(target_one.bound_sockets(), target_two.bound_sockets());

        let client_one_addr = client_one.addr();
        let accept_endpoint = client_one.clone();
        let accept_task = tokio::spawn(async move { accept_peer(&accept_endpoint).await });
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            connect_peer(&target_one, client_one_addr, &RelayChoice::PublicDefault),
        )
        .await
        .expect("first session connection timed out")
        .expect("first session target connects");
        let incoming = tokio::time::timeout(Duration::from_secs(5), accept_task)
            .await
            .expect("first session client did not accept")
            .expect("first session accept task panicked")
            .expect("first session client accepts");
        let mut target_stream = IrohByteStream::open_bi(connection)
            .await
            .expect("open first session stream");
        let mut client_stream = IrohByteStream::accept_bi(incoming)
            .await
            .expect("accept first session stream");

        target_two.close().await;
        target_stream
            .write_all(b"active session survives")
            .await
            .expect("write on first session after closing the second endpoint");
        let mut received = [0u8; 23];
        tokio::time::timeout(
            Duration::from_secs(5),
            client_stream.read_exact(&mut received),
        )
        .await
        .expect("first session read timed out")
        .expect("read first session payload");
        assert_eq!(&received, b"active session survives");
    }
}
