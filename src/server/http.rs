use axum::Router;
use axum::routing::{get, post};

use super::ServerState;

pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/auth/token", post(super::auth::token_login))
        .route(
            "/v1/auth/challenge",
            post(super::auth::public_key_challenge),
        )
        .route("/v1/auth/public-key", post(super::auth::public_key_login))
        .route("/v1/auth/refresh", post(super::auth::refresh))
        .route("/v1/auth/logout", post(super::auth::logout))
        .route("/v1/me", get(super::admin::me))
        .route("/v1/targets", get(super::admin::targets))
        .route("/v1/admin", post(super::admin::operation))
        .route("/v1/agent/enroll", post(super::control::enroll))
        .route("/v1/agent/control", get(super::control::agent_control))
        .route("/v1/connect", get(super::control::client_control))
        .route("/v1/transport", get(super::control::transport_info))
        .layer(axum::extract::DefaultBodyLimit::max(96 * 1024))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
