use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::{Method, Response, Url, header::AUTHORIZATION};
use serde::{Serialize, de::DeserializeOwned};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

use crate::{
    config::{Config, TlsConfig},
    protocol::{
        AdminRequest, AdminResponse, AgentEnrollmentRequest, AgentEnrollmentResponse,
        ControlMessage, LoginTokens, PasswordLoginRequest, PublicKeyChallenge,
        PublicKeyChallengeRequest, PublicKeyLoginRequest, RefreshRequest, TargetView,
        TransportInfo,
    },
    transport::{connect_wss, http_client},
};

pub use crate::transport::WsStream;

#[derive(Debug, thiserror::Error)]
pub enum ApiFailure {
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("network request failed: {0}")]
    Network(String),
    #[error("server returned HTTP {status}: {message}")]
    Server { status: u16, message: String },
    #[error("invalid server response: {0}")]
    Protocol(String),
}

#[derive(Clone)]
pub struct Api {
    base_url: String,
    tls: TlsConfig,
    http: reqwest::Client,
}

impl Api {
    pub async fn new(config: &Config) -> Result<Self> {
        let http =
            http_client(&config.tls).map_err(|error| anyhow!("build HTTP client: {error}"))?;
        let base_url = config.server_origin()?;
        Ok(Self {
            base_url,
            tls: config.tls.clone(),
            http,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.base_url
    }

    pub async fn password_login(&self, request: &PasswordLoginRequest) -> Result<LoginTokens> {
        self.post("auth/password", request, None).await
    }

    pub async fn public_key_challenge(
        &self,
        request: &PublicKeyChallengeRequest,
    ) -> Result<PublicKeyChallenge> {
        self.post("auth/challenge", request, None).await
    }

    pub async fn public_key_login(&self, request: &PublicKeyLoginRequest) -> Result<LoginTokens> {
        self.post("auth/public-key", request, None).await
    }

    pub async fn refresh(&self, request: &RefreshRequest) -> Result<LoginTokens> {
        self.post("auth/refresh", request, None).await
    }

    pub async fn logout(&self, access_token: &str) -> Result<()> {
        self.request_empty(Method::POST, "auth/logout", None, Some(access_token))
            .await
    }

    pub async fn me(&self, access_token: &str) -> Result<crate::protocol::MeView> {
        self.get("me", Some(access_token)).await
    }

    pub async fn targets(&self, access_token: &str) -> Result<Vec<TargetView>> {
        self.get("targets", Some(access_token)).await
    }

    pub async fn transport_info(&self) -> Result<TransportInfo> {
        self.get("transport", None).await
    }

    pub async fn admin(&self, access_token: &str, request: &AdminRequest) -> Result<AdminResponse> {
        self.post("admin", request, Some(access_token)).await
    }

    pub async fn agent_enroll(
        &self,
        request: &AgentEnrollmentRequest,
    ) -> Result<AgentEnrollmentResponse> {
        self.post("agent/enroll", request, None).await
    }

    pub async fn connect_control(&self, access_token: &str) -> Result<WsStream> {
        self.websocket("connect", Some(access_token)).await
    }

    pub async fn agent_control(&self, agent_token: &str) -> Result<WsStream> {
        self.websocket("agent/control", Some(agent_token)).await
    }

    pub async fn send_control<S>(
        ws: &mut tokio_tungstenite::WebSocketStream<S>,
        message: &ControlMessage,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let payload = serde_json::to_string(message).context("encode control message")?;
        ws.send(Message::Text(payload.into()))
            .await
            .context("send control message")
    }

    pub fn control_message(
        message: tokio_tungstenite::tungstenite::Message,
    ) -> Result<ControlMessage> {
        use tokio_tungstenite::tungstenite::Message;
        match message {
            Message::Text(text) => serde_json::from_str(&text).context("decode control message"),
            Message::Binary(bytes) => {
                serde_json::from_slice(&bytes).context("decode control message")
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Err(anyhow!(
                "control WebSocket received a non-application frame"
            )),
            Message::Close(_) => Err(anyhow!("control WebSocket closed")),
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, bearer: Option<&str>) -> Result<T> {
        let response = self
            .request(Method::GET, path, Option::<&()>::None, bearer)
            .await?;
        decode_response(response).await
    }

    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        bearer: Option<&str>,
    ) -> Result<R> {
        let response = self.request(Method::POST, path, Some(body), bearer).await?;
        decode_response(response).await
    }

    async fn request_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        bearer: Option<&str>,
    ) -> Result<()> {
        let response = self.request(method, path, body.as_ref(), bearer).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_failure(response).await.into())
        }
    }

    async fn request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        bearer: Option<&str>,
    ) -> Result<Response> {
        let url = self.api_url(path)?;
        let mut request = self.http.request(method, url);
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        request.send().await.map_err(|error| {
            if error.is_connect() || error.is_timeout() {
                anyhow!(ApiFailure::Network(error.to_string()))
            } else {
                anyhow!(ApiFailure::Protocol(error.to_string()))
            }
        })
    }

    async fn websocket(&self, path: &str, bearer: Option<&str>) -> Result<WsStream> {
        let url = self.websocket_url(path)?;
        let mut request = url.as_str().into_client_request()?;
        if let Some(token) = bearer {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        tokio::time::timeout(Duration::from_secs(15), connect_wss(request, &self.tls))
            .await
            .map_err(|_| {
                anyhow!(ApiFailure::Network(
                    "WebSocket connect timed out".to_owned()
                ))
            })?
            .map_err(|error| match error {
                crate::transport::TransportError::Authentication(message) => {
                    anyhow!(ApiFailure::Authentication(message))
                }
                crate::transport::TransportError::Network(error) => {
                    anyhow!(ApiFailure::Network(error.to_string()))
                }
                crate::transport::TransportError::Timeout(message) => {
                    anyhow!(ApiFailure::Network(format!("{message} timed out")))
                }
                error => anyhow!(ApiFailure::Protocol(error.to_string())),
            })
    }

    fn api_url(&self, path: &str) -> Result<Url> {
        Url::parse(&format!("{}/v1/{path}", self.base_url)).context("build API URL")
    }

    fn websocket_url(&self, path: &str) -> Result<Url> {
        let mut url = Url::parse(&format!("{}/v1/{path}", self.base_url))?;
        anyhow::ensure!(url.scheme() == "https", "server URL must use HTTPS");
        url.set_scheme("wss")
            .map_err(|_| anyhow!("invalid WebSocket URL scheme"))?;
        Ok(url)
    }
}

async fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T> {
    if response.status().is_success() {
        response
            .json()
            .await
            .map_err(|error| anyhow!(ApiFailure::Protocol(error.to_string())))
    } else {
        Err(response_failure(response).await.into())
    }
}

async fn response_failure(response: Response) -> ApiFailure {
    let status = response.status();
    let message = response
        .text()
        .await
        .unwrap_or_else(|error| format!("read error body: {error}"));
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        ApiFailure::Authentication(message)
    } else {
        ApiFailure::Server {
            status: status.as_u16(),
            message,
        }
    }
}
