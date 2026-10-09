use axum::routing::{get, post};
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};

use super::ServerState;

pub fn router(state: ServerState) -> Router {
    let versioned_api = Router::new()
        .route(
            "/v1/auth/challenge",
            post(super::auth::public_key_challenge),
        )
        .route("/v1/auth/public-key", post(super::auth::public_key_login))
        .route("/v1/auth/refresh", post(super::auth::refresh))
        .route("/v1/me", get(super::admin::me))
        .route("/v1/targets", get(super::admin::targets))
        .route("/v1/admin", post(super::admin::operation))
        .route("/v1/agent/enroll", post(super::control::enroll))
        .route("/v1/transport", get(super::control::transport_info))
        .route_layer(middleware::from_fn(require_compatible_version));

    Router::new()
        .route("/health", get(health))
        .route("/v1/agent/control", get(super::control::agent_control))
        .route("/v1/connect", get(super::control::client_control))
        .merge(versioned_api)
        .layer(axum::extract::DefaultBodyLimit::max(96 * 1024))
        .with_state(state)
}

async fn require_compatible_version(request: Request, next: Next) -> Response {
    let client_version = request
        .headers()
        .get(crate::version::VERSION_HEADER)
        .and_then(|value| value.to_str().ok());
    if let Some(message) = crate::version::mismatch(client_version) {
        return super::error::ApiError::incompatible_version(message).into_response();
    }
    next.run(request).await
}

async fn health() -> &'static str {
    "ok"
}
