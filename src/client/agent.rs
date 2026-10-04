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

pub(super) use control::agent_session_error_code;
pub(super) use route::endpoint_options;
pub(super) use session::handle_dial_offer;

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
    pub(super) target_id: Uuid,
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
#[error("server selected an authentication failure: {0}")]
pub(super) struct ServerAuthenticationFailure(pub(super) String);

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
                    endpoint_secret_key: identity::encode_secret_key(&SecretKey::generate()),
                };
                profile::ensure_private_dir(&context.config.data_dir)?;
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
        stable_device_secret_key: identity::decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        active_sessions: JoinSet::new(),
        completed_sessions: Arc::new(StdMutex::new(Vec::new())),
    };
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control::control_session(context, target_id, &credentials, &mut runtime).await {
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
