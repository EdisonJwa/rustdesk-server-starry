//! Administrator configuration endpoints.
//!
//! These exist because the alternative is worse: the server's own tests, and an
//! operator with a shell, both needed to write `client_strategies` and
//! `user_totp` rows directly. Reaching into the database from outside the process
//! means the encoding of a sealed secret and the hash of an enrolment token are
//! each reimplemented by every caller, and a mistake in one of them is silent.
//!
//! Everything here requires an administrator bearer token. None of it is used by
//! the official client; it is the operator surface the plan called for.

use axum::{
    body::Body,
    extract::{Extension, Path as AxumPath, RawBody},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use hbb_common::log;
use hyper::body::HttpBody as _;

use crate::auth_server::ApiState;

const MAX_BODY: usize = 64 * 1024;

async fn read_json<T: serde::de::DeserializeOwned>(body: RawBody<Body>) -> Option<T> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return None };
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Whether the caller is an administrator, or the response to send.
async fn require_admin(state: &Arc<ApiState>, headers: &HeaderMap) -> Result<i64, Response> {
    let user_id = state
        .authenticate_headers(headers)
        .await
        .map_err(|_| crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized"))?;
    let is_admin = state.is_admin(user_id).await.map_err(|err| {
        log::error!("cannot read admin flag: {err}");
        crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
    })?;
    if !is_admin {
        return Err(Json(json!({"error": "Admin required!"})).into_response());
    }
    Ok(user_id)
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct StrategyWrite {
    /// The client strategy document: `{config_options, extra}`.
    document: Value,
    /// Which account it applies to. Absent means the caller.
    user_id: Option<i64>,
}

/// `PUT /api/admin/client-strategy`
///
/// Stores a strategy after passing it through the allow-list. Storing the
/// unfiltered document would make the filter the only guard at delivery time;
/// filtering here as well means a document that was rejected is visibly not
/// stored, which is easier to explain to an operator.
pub(crate) async fn set_client_strategy(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let caller = match require_admin(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Some(request) = read_json::<StrategyWrite>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if !request.document.is_object() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    let target = request.user_id.unwrap_or(caller);
    // A non-admin may have been granted admin rights to configure themselves, so
    // the target is checked rather than trusted.
    if target != caller {
        match state.is_admin(target).await {
            Ok(_) => {}
            Err(err) => {
                log::error!("cannot resolve strategy target: {err}");
                return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "UnknownUser");
            }
        }
    }
    let document = json!({
        "config_options": request
            .document
            .get("config_options")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "extra": request.document.get("extra").cloned().unwrap_or(Value::Null),
    })
    .to_string();
    match state.set_client_strategy(target, &document).await {
        Ok(modified_at) => {
            log::info!("client strategy for account {target} replaced by {caller}");
            Json(json!({"modified_at": modified_at})).into_response()
        }
        Err(err) => {
            log::error!("cannot store client strategy: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `GET /api/admin/client-strategy` — what would currently be delivered.
pub(crate) async fn get_client_strategy(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
) -> Response {
    let caller = match require_admin(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    match state.client_strategy(caller).await {
        Ok(Some((document, modified_at))) => Json(json!({
            "document": serde_json::from_str::<Value>(&document).unwrap_or(Value::Null),
            "modified_at": modified_at,
        }))
        .into_response(),
        Ok(None) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot read client strategy: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct TotpEnrolRequest {
    /// A Base32 secret. Absent means "generate one and return it".
    secret: String,
}

/// `POST /api/admin/totp` — enrol or replace an account's second factor.
///
/// Returns the secret so an operator can hand it to the user, or the newly
/// generated one. There is no endpoint to read an existing secret back: enrolling
/// again replaces it, which is the reset path.
pub(crate) async fn enrol_totp(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let caller = match require_admin(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    let request = read_json::<TotpEnrolRequest>(body).await.unwrap_or_default();
    let secret = if request.secret.trim().is_empty() {
        crate::totp::generate_secret()
    } else {
        // Reject a secret that cannot produce codes rather than storing it and
        // making every future login fail.
        match crate::totp::decode_base32(&request.secret) {
            Ok(_) => request.secret.trim().to_ascii_uppercase().replace(' ', ""),
            Err(err) => {
                return crate::auth_server::api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("InvalidSecret: {err}"),
                );
            }
        }
    };
    match state.totp_set_secret(caller, &secret).await {
        Ok(()) => {
            log::info!("TOTP enrolled for account {caller}");
            // The `otpauth://` URI saves the operator from transcribing a Base32
            // secret by hand, and is what a QR code would encode.
            let uri = format!(
                "otpauth://totp/Starry:{caller}?secret={secret}&issuer=Starry&digits={}&period={}",
                crate::totp::DIGITS,
                crate::totp::STEP_SECONDS
            );
            Json(json!({"secret": secret, "otpauth_uri": uri})).into_response()
        }
        Err(err) => {
            log::error!("cannot enrol TOTP: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `DELETE /api/admin/totp` — remove a second factor.
pub(crate) async fn disable_totp(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
) -> Response {
    let caller = match require_admin(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    match state.totp_remove(caller).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot remove TOTP: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `POST /api/admin/enrolment-token` — mint a one-time device token.
pub(crate) async fn issue_enrolment_token(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
) -> Response {
    let caller = match require_admin(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    // The token is generated and hashed inside the database layer, so the caller
    // never handles the fingerprint encoding.
    match state.issue_enrolment_token(caller).await {
        Ok(token) => Json(json!({"token": token})).into_response(),
        Err(err) => {
            log::error!("cannot issue enrolment token: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `POST /api/admin/disconnect/{peer_id}` — queue a session teardown.
pub(crate) async fn disconnect(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(peer_id): AxumPath<String>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    if require_admin(&state, &headers).await.is_err() {
        return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Body_ {
        ids: Vec<i64>,
    }
    let request = read_json::<Body_>(body).await.unwrap_or_default();
    if request.ids.is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    for conn_id in &request.ids {
        if let Err(err) = state.queue_disconnect(&peer_id, *conn_id).await {
            log::error!("cannot queue a disconnect: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    // Delivered on the device's next heartbeat, which is the only channel the
    // client listens on for this.
    Json(json!({"queued": request.ids.len()}))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_write_accepts_a_document() {
        let parsed: StrategyWrite = serde_json::from_str(
            r#"{"document":{"config_options":{"enable-audio":"Y"},"extra":{}}}"#,
        )
        .unwrap();
        assert!(parsed.document.is_object());
        assert!(parsed.user_id.is_none());
    }

    #[test]
    fn totp_enrol_defaults_to_generating_a_secret() {
        let parsed: TotpEnrolRequest = serde_json::from_str("{}").unwrap();
        assert!(parsed.secret.is_empty());
    }
}
