use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use uuid::Uuid;

use crate::protocol::{ControlMessage, RouteMode};

mod attempt;
mod punch;
mod stdio;
mod ticket;
#[cfg(test)]
pub(in crate::client) use ticket::read_ticket;

use super::{
    ClientContext,
    api::{Api, WsStream},
    auth,
    route::{SSH_SETUP_TIMEOUT, attempt_timeout},
};

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const ENDPOINT_CLOSE_BUDGET: Duration = Duration::from_secs(4);

#[derive(Debug, thiserror::Error)]
#[error("SSH access authentication failed: {0}")]
pub(super) struct SshAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("SSH network path failed: {0}")]
pub(super) struct RouteNetworkFailure(#[source] anyhow::Error);

#[derive(Debug, thiserror::Error)]
#[error("SSH session failed after activation: {0}")]
pub(super) struct ActivatedSessionFailure(#[source] anyhow::Error);

pub(super) fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(SshAuthenticationFailure(message.to_owned())))
    }
}

pub(super) fn is_retryable_route_failure(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ActivatedSessionFailure>().is_none()
        && error.downcast_ref::<RouteNetworkFailure>().is_some()
}

pub(super) fn server_setup_error(code: String, message: String) -> anyhow::Error {
    match code.as_str() {
        "authentication" | "authorization" => anyhow!(SshAuthenticationFailure(message)),
        "incompatible_version" => {
            anyhow!("kmesh client and server versions are incompatible: {message}")
        }
        "network" => anyhow::Error::new(RouteNetworkFailure(anyhow!(message))),
        _ => anyhow!("server could not prepare SSH access: {message}"),
    }
}

async fn open_session(
    context: &ClientContext,
    target_id: String,
) -> Result<(Uuid, attempt::OpenSshSession, WsStream, RouteMode)> {
    let target_id = target_id.trim().to_ascii_lowercase();
    let setup_deadline = tokio::time::Instant::now() + SSH_SETUP_TIMEOUT;
    let access_token = tokio::time::timeout_at(setup_deadline, auth::valid_access_token(context))
        .await
        .context("SSH setup timed out during kmesh authentication")??;
    let transport_info = tokio::time::timeout_at(setup_deadline, context.api.transport_info())
        .await
        .context("SSH setup timed out while reading the route configuration")??;
    let route_modes = if transport_info.private_relay_url.is_some() {
        vec![
            RouteMode::PrivateDirect,
            RouteMode::PublicDirect,
            RouteMode::PrivateRelay,
        ]
    } else {
        vec![RouteMode::PublicDirect]
    };
    let private_routes_unavailable = transport_info.private_relay_url.is_none();
    let mut failures = Vec::new();
    let mut connected = None;
    for (index, route_mode) in route_modes.into_iter().enumerate() {
        let attempt_started = tokio::time::Instant::now();
        let attempt_deadline = std::cmp::min(
            setup_deadline - ENDPOINT_CLOSE_BUDGET,
            attempt_started + attempt_timeout(route_mode),
        );
        let access_token = if index == 0 {
            access_token.clone()
        } else {
            tokio::time::timeout_at(attempt_deadline, auth::valid_access_token(context))
                .await
                .context("SSH setup timed out while refreshing kmesh authentication")??
        };
        let mut control = connect_control(context, &access_token, attempt_deadline)
            .await
            .with_context(|| format!("connect kmesh control for route {route_mode:?}"))?;
        let (session_id, secret_key) = attempt::new_attempt_identity();
        match attempt::open_ssh_session(
            &mut control,
            attempt::SshAttempt {
                client: context,
                transport_info: &transport_info,
                target_id: target_id.clone(),
                session_id,
                secret_key,
                route_mode,
                attempt_deadline,
                setup_deadline,
            },
        )
        .await
        {
            Ok(session) => {
                connected = Some((session_id, session, control, route_mode));
                break;
            }
            Err(error) => {
                let _ = tokio::time::timeout_at(
                    setup_deadline,
                    close_session_best_effort(&mut control, session_id, "route_attempt_failed"),
                )
                .await;
                let elapsed_ms = attempt_started.elapsed().as_millis();
                tracing::warn!(
                    session = %session_id,
                    route_mode = ?route_mode,
                    elapsed_ms,
                    error = %error,
                    "SSH route attempt failed"
                );
                eprintln!(
                    "SSH route {:?} failed after {} ms: {}",
                    route_mode,
                    elapsed_ms,
                    super::format_error(&error),
                );
                failures.push(format!(
                    "{route_mode:?} session={session_id} elapsed_ms={elapsed_ms}: {error:#}"
                ));
                if !is_retryable_route_failure(&error) {
                    let mut route_history = failures.clone();
                    if private_routes_unavailable {
                        route_history.insert(
                            0,
                            "PrivateDirect unavailable: server has no configured private relay"
                                .to_owned(),
                        );
                        route_history.push(
                            "PrivateRelay unavailable: server has no configured private relay"
                                .to_owned(),
                        );
                    }
                    return Err(error).context(format!(
                        "SSH route plan stopped: {}",
                        route_history.join("; ")
                    ));
                }
                if tokio::time::Instant::now() >= setup_deadline {
                    break;
                }
            }
        }
    }
    let connected = match connected {
        Some(connected) => connected,
        None => {
            if private_routes_unavailable {
                failures.insert(
                    0,
                    "PrivateDirect unavailable: server has no configured private relay".to_owned(),
                );
                failures.push(
                    "PrivateRelay unavailable: server has no configured private relay".to_owned(),
                );
            }
            return Err(anyhow!(
                "all SSH routes failed before activation: {}",
                failures.join("; ")
            ));
        }
    };
    Ok(connected)
}

pub async fn run(context: &ClientContext, target_id: String) -> Result<()> {
    let (session_id, ssh_session, mut control, _) = open_session(context, target_id).await?;
    let attempt::OpenSshSession {
        endpoint,
        mut stream,
    } = ssh_session;
    let transfer = stdio::copy_stdio(&mut stream).await;
    if transfer.is_err() {
        let _ = stream.reset();
    }
    let reason = if transfer.is_err() {
        "client_ssh_stream_failed"
    } else {
        "ssh_stream_complete"
    };
    if let Err(error) = Api::send_control(
        &mut control,
        &ControlMessage::Close {
            session_id,
            reason: reason.to_owned(),
        },
    )
    .await
    {
        tracing::debug!(session = %session_id, error = %error, "SSH finished after control channel disconnected");
    }
    attempt::close_endpoint(&endpoint).await;
    let (ssh_upload_bytes, ssh_download_bytes) =
        transfer.context("copy local SSH stdio over Iroh")?;
    eprintln!(
        "SSH traffic: local to target={} bytes; target to local={} bytes",
        ssh_upload_bytes, ssh_download_bytes,
    );
    Ok(())
}

async fn connect_control(
    context: &ClientContext,
    access_token: &str,
    setup_deadline: tokio::time::Instant,
) -> Result<WsStream> {
    let deadline = std::cmp::min(
        setup_deadline,
        tokio::time::Instant::now() + CONTROL_CONNECT_TIMEOUT,
    );
    tokio::time::timeout_at(deadline, context.api.connect_control(access_token))
        .await
        .context("kmesh control connection timed out")?
}

async fn close_session(control: &mut WsStream, session_id: Uuid, reason: &str) -> Result<()> {
    Api::send_control(
        control,
        &ControlMessage::Close {
            session_id,
            reason: reason.to_owned(),
        },
    )
    .await
}

async fn close_session_best_effort(control: &mut WsStream, session_id: Uuid, reason: &str) {
    if let Err(error) = close_session(control, session_id, reason).await {
        tracing::debug!(session = %session_id, error = %error, "failed to close pending SSH session");
    }
}

/// Open the same authorized route as ProxyCommand, but do not start an SSH login.
pub(super) async fn probe(
    context: &ClientContext,
    target_id: String,
) -> Result<(RouteMode, Result<()>)> {
    let (session_id, session, mut control, mode) = open_session(context, target_id).await?;
    let attempt::OpenSshSession {
        endpoint,
        mut stream,
    } = session;
    let result = tokio::time::timeout(
        Duration::from_secs(12),
        read_ssh_identification(&mut stream),
    )
    .await
    .context("The SSH service did not respond within 12 seconds.")
    .and_then(|result| result);
    let _ = stream.reset();
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        close_session_best_effort(&mut control, session_id, "doctor_complete"),
    )
    .await;
    attempt::close_endpoint(&endpoint).await;
    Ok((mode, result))
}

async fn read_ssh_identification(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<()> {
    use tokio::io::AsyncReadExt;
    // RFC 4253 permits lines before the identification. Bound both memory and work.
    let mut line = Vec::new();
    for _ in 0..8192 {
        let byte = stream
            .read_u8()
            .await
            .context("The SSH service closed before its identification.")?;
        line.push(byte);
        if line.len() > 255 {
            anyhow::bail!("The SSH service returned an invalid identification.");
        }
        if byte == b'\n' {
            if line.starts_with(b"SSH-") {
                let software = line
                    .strip_prefix(b"SSH-2.0-")
                    .or_else(|| line.strip_prefix(b"SSH-1.99-"));
                let valid = software.is_some_and(|value| {
                    value.first().is_some_and(|byte| (33..=126).contains(byte))
                }) && line.ends_with(b"\r\n")
                    && line[..line.len() - 2]
                        .iter()
                        .all(|byte| (32..=126).contains(byte));
                anyhow::ensure!(valid, "The SSH service returned an invalid identification.");
                return Ok(());
            }
            line.clear();
        }
    }
    anyhow::bail!("The SSH service did not return an identification.")
}

#[cfg(test)]
mod diagnostic_tests {
    use super::read_ssh_identification;

    #[tokio::test]
    async fn identification_requires_ssh_and_bounds_untrusted_input() {
        for banner in [
            b"SSH-2.0-OpenSSH_9.0\r\n".as_slice(),
            b"Notice\r\nSSH-2.0-test\r\n",
        ] {
            assert!(read_ssh_identification(&mut &banner[..]).await.is_ok());
        }
        for banner in [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"SSH-1.5-test\r\n",
            b"SSH-2.0-\r\n",
            b"SSH-1.99-\r\n",
            b"SSH-2.0- \r\n",
            b"SSH-2.0-test\x1b\r\n",
        ] {
            assert!(read_ssh_identification(&mut &banner[..]).await.is_err());
        }
        assert!(
            read_ssh_identification(&mut &vec![b'x'; 8193][..])
                .await
                .is_err()
        );
    }
}
