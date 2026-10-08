use std::{
    fs,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{EndpointAddr, SecretKey};
use tokio::{task::JoinSet, time::sleep};
use uuid::Uuid;

use super::{ClientContext, profile, profile::write_json_atomic};
use crate::{
    protocol::{AgentCredentials, AgentEnrollmentRequest, RouteMode, TransportInfo},
    transport::TransportError,
};

mod control;
mod identity;
mod punch;
mod route;
mod session;
#[cfg(test)]
mod tests;

const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TICKET_FRAME: usize = 8 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct PendingAgentIdentity {
    endpoint_secret_key: String,
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
    context: &ClientContext,
    target_id: String,
    enrollment_code: &str,
) -> Result<()> {
    let target_id = target_id.trim().to_ascii_lowercase();
    let server_origin = context.api.issuer();
    profile::ensure_agent_credentials_dir(&context.config.data_dir, server_origin)?;
    let credential_path =
        profile::agent_credentials_path(&context.config.data_dir, server_origin, &target_id);
    let pending_path = credential_path.with_extension("pending.json");
    let identity = if credential_path.exists() {
        let saved =
            profile::load_agent_credentials(&context.config.data_dir, server_origin, &target_id)?;
        PendingAgentIdentity {
            endpoint_secret_key: saved.endpoint_secret_key,
        }
    } else {
        match fs::read(&pending_path) {
            Ok(bytes) => serde_json::from_slice::<PendingAgentIdentity>(&bytes)
                .context("read pending target Iroh identity")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = PendingAgentIdentity {
                    endpoint_secret_key: identity::encode_secret_key(&SecretKey::generate()),
                };
                write_json_atomic(&pending_path, &identity)?;
                identity
            }
            Err(error) => return Err(error).context("read pending target Iroh identity"),
        }
    };
    let endpoint_secret_key = identity::decode_secret_key(&identity.endpoint_secret_key)?;
    let response = context
        .api
        .agent_enroll(&AgentEnrollmentRequest {
            target_id: target_id.clone(),
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
        server_origin,
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

pub async fn run(context: &ClientContext, target_id: String) -> Result<()> {
    let target_id = target_id.trim().to_ascii_lowercase();
    let credentials = profile::load_agent_credentials(
        &context.config.data_dir,
        context.api.issuer(),
        &target_id,
    )?;
    let mut runtime = AgentRuntime {
        stable_device_secret_key: identity::decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        active_sessions: JoinSet::new(),
        completed_sessions: Arc::new(StdMutex::new(Vec::new())),
    };
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control::control_session(context, &credentials, &mut runtime).await {
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
