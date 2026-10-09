use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout_at},
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use super::{
    AgentContext, AgentRuntime, AgentVersionIncompatibility, CONTROL_CONNECT_TIMEOUT,
    ServerAuthenticationFailure, ensure_auth, is_authentication_error, server_session_error,
    session,
};
use crate::{
    client::api::{Api, WsStream},
    protocol::{AgentCredentials, ControlMessage},
    transport::TransportError,
};

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

pub(super) async fn next_session_message(
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
            return Err(server_session_error(code, message.clone()));
        }
        _ => {}
    }
    ensure_auth(
        message_session_id(&message) == Some(session_id),
        "server sent a control message for a different agent session",
    )?;
    Ok(Some(message))
}

pub(super) fn agent_session_error_code(error: &anyhow::Error) -> &'static str {
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

pub(super) async fn control_session(
    context: &AgentContext,
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
                        route_mode,
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
                            if let Err(error) = session::run_agent_session(
                                &context,
                                &credentials,
                                stable_device_key,
                                transport_info,
                                session::AgentSessionPrepare {
                                    session_id,
                                    client_endpoint_id,
                                    route_mode,
                                    expires_at,
                                    control_rx: session_rx,
                                    outbound: outbound.clone(),
                                },
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
                    ControlMessage::Error { session_id: None, code, message }
                        if code == "incompatible_version" =>
                    {
                        return Err(anyhow!(AgentVersionIncompatibility(message)));
                    }
                    message => {
                        route_session_message(&mut sessions, message).await;
                    }
                }
            }
        }
    }
}

pub(super) async fn route_session_message(
    sessions: &mut HashMap<Uuid, mpsc::Sender<ControlMessage>>,
    message: ControlMessage,
) {
    let Some(session_id) = message_session_id(&message) else {
        return;
    };
    let Some(sender) = sessions.get(&session_id) else {
        return;
    };
    if sender.send(message).await.is_err() {
        tracing::debug!(
            session = %session_id,
            error = "session mailbox closed",
            "removing completed agent SSH session from control routing"
        );
        sessions.remove(&session_id);
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
        | ControlMessage::PathReady { session_id, .. }
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
