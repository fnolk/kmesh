use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use iroh::{EndpointAddr, SecretKey};
use tokio::{task::JoinSet, time::sleep};
use uuid::Uuid;

use super::api::Api;
use crate::{
    protocol::{AgentEnrollmentRequest, RouteMode, TransportInfo},
    transport::TransportError,
};

mod control;
mod identity;
mod punch;
mod route;
mod session;
mod state;
#[cfg(test)]
mod tests;

const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TICKET_FRAME: usize = 8 * 1024;

pub(super) use state::{data_dir, prepare_data_dir};

#[derive(Clone)]
pub(super) struct AgentContext {
    pub(super) api: Api,
    pub(super) ssh_address: SocketAddr,
    pub(super) ssh_connect_timeout_secs: u64,
}

pub(super) struct AgentRuntime {
    pub(super) stable_device_secret_key: SecretKey,
    pub(super) transport_info: TransportInfo,
    pub(super) active_sessions: JoinSet<()>,
    pub(super) completed_sessions: Arc<StdMutex<Vec<Uuid>>>,
}

pub(super) struct TunnelOffer {
    pub(super) session_id: Uuid,
    pub(super) target_id: String,
    pub(super) ticket: String,
    pub(super) client_endpoint_id: String,
    pub(super) client_endpoint_addr: EndpointAddr,
    pub(super) ticket_public_key_pem: String,
    pub(super) route_mode: RouteMode,
}

#[derive(Debug, thiserror::Error)]
#[error("agent connection authentication failed: {0}")]
pub(super) struct AgentAuthenticationFailure(pub(super) String);

#[derive(Debug, thiserror::Error)]
#[error("server rejected authentication: {0}")]
pub(super) struct ServerAuthenticationFailure(pub(super) String);

#[derive(Debug, thiserror::Error)]
#[error("kmesh agent and server versions are incompatible: {0}")]
pub(super) struct AgentVersionIncompatibility(pub(super) String);

pub async fn enroll(
    server_addr: &str,
    server_port: u16,
    data_dir: &Path,
    target_id: String,
    enrollment_code: &str,
    ssh_address: SocketAddr,
    ssh_connect_timeout_secs: u64,
) -> Result<String> {
    let target_id = state::normalize_target_id(&target_id)?;
    let api = Api::new_for_server(server_addr, server_port).await?;
    let origin = api.issuer();
    state::ensure_target_dir(data_dir, &target_id)?;

    let existing = state::load_optional(data_dir, &target_id)?;
    if let Some(saved) = &existing {
        anyhow::ensure!(
            saved.server_origin()? == origin,
            "This target ID already has state for another server. Use a different data directory."
        );
    }

    let identity = if let Some(saved) = existing {
        state::PendingAgentIdentity {
            server_addr: saved.server_addr,
            server_port: saved.server_port,
            endpoint_secret_key: saved.endpoint_secret_key,
        }
    } else if let Some(pending) = state::load_pending(data_dir, &target_id)? {
        anyhow::ensure!(
            crate::config::server_origin(&pending.server_addr, pending.server_port)? == origin,
            "An enrollment attempt for this target ID uses another server. Use a different data directory."
        );
        pending
    } else {
        let identity = state::PendingAgentIdentity {
            server_addr: server_addr.to_owned(),
            server_port,
            endpoint_secret_key: identity::encode_secret_key(&SecretKey::generate()),
        };
        state::save_pending(data_dir, &target_id, &identity)?;
        identity
    };
    let endpoint_secret_key = identity::decode_secret_key(&identity.endpoint_secret_key)?;
    let response = api
        .agent_enroll(&AgentEnrollmentRequest {
            target_id: target_id.clone(),
            enrollment_token: enrollment_code.to_owned(),
            agent_endpoint_id: endpoint_secret_key.public().to_string(),
        })
        .await?;
    anyhow::ensure!(
        response.target_id == target_id,
        "The server returned a different target ID."
    );
    let state = state::AgentState {
        target_id,
        server_addr: server_addr.to_owned(),
        server_port,
        agent_token: response.agent_token,
        ticket_public_key_pem: response.ticket_public_key_pem,
        endpoint_secret_key: identity.endpoint_secret_key,
        ssh_address,
        ssh_connect_timeout_secs,
    };
    state::save(data_dir, &state)?;
    state::clear_pending(data_dir, &state.target_id)?;
    Ok(state.target_id)
}

pub async fn run(data_dir: &Path, target_id: String) -> Result<()> {
    let target_id = state::normalize_target_id(&target_id)?;
    let saved = state::load(data_dir, &target_id)?;
    anyhow::ensure!(
        saved.target_id == target_id,
        "The state file has a different target ID."
    );
    let api = Api::new_for_server(&saved.server_addr, saved.server_port).await?;
    let context = AgentContext {
        api,
        ssh_address: saved.ssh_address,
        ssh_connect_timeout_secs: saved.ssh_connect_timeout_secs,
    };
    let credentials = saved.credentials();
    let mut runtime = AgentRuntime {
        stable_device_secret_key: identity::decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        active_sessions: JoinSet::new(),
        completed_sessions: Arc::new(StdMutex::new(Vec::new())),
    };
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control::control_session(&context, &credentials, &mut runtime).await {
            Ok(()) => bail!("agent control connection closed"),
            Err(error) if is_terminal_connection_error(&error) => {
                let reason = if is_authentication_error(&error) {
                    "agent credential was rejected"
                } else {
                    "agent and server kmesh versions are incompatible"
                };
                tracing::error!(target = %target_id, error = %error, "{reason}; active SSH sessions will finish");
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

pub(super) fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(AgentAuthenticationFailure(message.to_owned())))
    }
}

pub(super) fn is_authentication_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AgentAuthenticationFailure>().is_some()
        || error
            .downcast_ref::<ServerAuthenticationFailure>()
            .is_some()
}

pub(super) fn is_terminal_connection_error(error: &anyhow::Error) -> bool {
    is_authentication_error(error)
        || error
            .downcast_ref::<AgentVersionIncompatibility>()
            .is_some()
}

pub(super) fn transport_error(error: TransportError) -> anyhow::Error {
    match error {
        TransportError::Authentication(message) => anyhow!(AgentAuthenticationFailure(message)),
        error => anyhow!(error),
    }
}

pub(super) fn server_session_error(code: &str, message: String) -> anyhow::Error {
    match code {
        "authentication" | "authorization" => anyhow!(AgentAuthenticationFailure(message)),
        "network" => anyhow::Error::new(TransportError::Network(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            message,
        ))),
        "configuration" => anyhow::Error::new(TransportError::Configuration(message)),
        _ => anyhow::Error::new(TransportError::ProtocolViolation(format!(
            "server rejected SSH session ({code}): {message}"
        ))),
    }
}
