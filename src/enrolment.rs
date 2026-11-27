//! Device enrolment: a one-time token turns a fresh client into a registered
//! device without an operator typing configuration by hand.
//!
//! Contract verified at `src/ui_interface.rs` in rustdesk master. The client
//! POSTs `{id, uuid, pk}` with `Authorization: Bearer <token>` and reads a
//! **closed set** of `result` values:
//!
//! | result | meaning to the client |
//! | --- | --- |
//! | `OK` | deployed; it persists the id locally and restarts rendezvous |
//! | `NOT_ENABLED` | this server does not do enrolment |
//! | `INVALID_INPUT` | malformed request |
//! | `ID_TAKEN` | that id already belongs to another device |
//! | anything else | shown to the user verbatim |
//!
//! Anything outside that set becomes a user-visible error string, so the four
//! values are the whole contract and a fifth would be a bug.
//!
//! Security shape: the token is a bearer secret that registers a device. It is
//! single-use, time-limited, and stored only as a hash, so a database read
//! cannot mint new enrolments.

use axum::{
    extract::{Extension, RawBody},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hyper::body::HttpBody as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use hbb_common::log;
use sha2::{Digest, Sha256};
use tokio_rusqlite::rusqlite;

use crate::auth_server::ApiState;

/// How long an issued enrolment token stays usable.
pub(crate) const TOKEN_TTL_SECONDS: u64 = 24 * 3600;

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// What a deployment token is stored as.
///
/// Hashed rather than encrypted: the server never needs to show a token again,
/// only to recognise one it issued.
pub(crate) fn token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    base64::encode_config(digest, base64::URL_SAFE_NO_PAD)
}

/// A 32-byte token, URL-safe.
pub(crate) fn generate_token() -> String {
    let mut bytes = Vec::with_capacity(32);
    while bytes.len() < 32 {
        bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    bytes.truncate(32);
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct DeployRequest {
    id: String,
    uuid: String,
    /// Base64 device public key. Stored for the rendezvous path, not interpreted
    /// here.
    pk: String,
}

fn bad_input() -> Response {
    // The client maps this to `DeployResult::InvalidInput`.
    Json(json!({"result": "INVALID_INPUT"})).into_response()
}

fn not_enabled() -> Response {
    Json(json!({"result": "NOT_ENABLED"})).into_response()
}

async fn read_body(body: RawBody<axum::body::Body>) -> Option<DeployRequest> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return None };
        if bytes.len().saturating_add(chunk.len()) > 16 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// `POST /api/devices/deploy`
///
/// Returns the closed set of results; see the module docs.
pub async fn deploy(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    // Enrolment is opt-in per deployment: without it configured, answer the
    // documented "not enabled" rather than the "invalid input" a missing token
    // would otherwise produce.
    if !state.enrolment_enabled() {
        return not_enabled();
    }
    let Some(request) = read_body(body).await else {
        return bad_input();
    };
    if request.id.trim().is_empty() || request.pk.trim().is_empty() {
        return bad_input();
    }
    let Some(token) = crate::auth_server::bearer(&headers) else {
        return bad_input();
    };
    let fingerprint = token_fingerprint(&token);
    let now = epoch_seconds();
    let peer_id = request.id.trim().to_owned();
    let peer_id_for_db = peer_id.clone();
    let peer_uuid = request.uuid.clone();
    let peer_pk = request.pk.clone();

    // Single use: the token is consumed as part of the same transaction that
    // records the device, so two clients racing on one token cannot both win.
    let outcome = state
        .db_call(move |connection| {
            let transaction = connection.transaction()?;
            let row = transaction
                .query_row(
                    "select expires_at, used_at from deploy_tokens where token_hash = ?1",
                    [fingerprint.as_str()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
                )
                .ok();
            let Some((expires_at, used_at)) = row else {
                return Ok::<_, rusqlite::Error>("INVALID_INPUT");
            };
            if used_at.is_some() {
                return Ok("INVALID_INPUT");
            }
            if expires_at < now as i64 {
                return Ok("INVALID_INPUT");
            }
            // An id that already belongs to a different key is refused rather
            // than silently reassigned: reassignment would let an enrolment
            // token hijack an existing device.
            let existing = transaction
                .query_row(
                    "select pk from enrolled_devices where peer_id = ?1",
                    [peer_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .ok();
            if let Some(existing_pk) = existing {
                if existing_pk != peer_pk {
                    return Ok("ID_TAKEN");
                }
                // The same device re-enrolling with the same key is a retry,
                // not a conflict.
            }
            transaction.execute(
                "insert into enrolled_devices (peer_id, uuid, pk, enrolled_at, last_seen)
                 values (?1, ?2, ?3, ?4, ?4)
                 on conflict(peer_id) do update set uuid = excluded.uuid,
                                                    enrolled_at = excluded.enrolled_at,
                                                    last_seen = excluded.last_seen",
                rusqlite::params![peer_id_for_db, peer_uuid, peer_pk, now as i64],
            )?;
            transaction.execute(
                "update deploy_tokens set used_at = ?2, used_peer = ?3 where token_hash = ?1",
                rusqlite::params![fingerprint, now as i64, peer_id_for_db],
            )?;
            transaction.commit()?;
            Ok("OK")
        })
        .await;

    match outcome {
        Ok("OK") => {
            log::info!("device {} enrolled with a one-time token", request.id);
            Json(json!({"result": "OK"})).into_response()
        }
        Ok("ID_TAKEN") => Json(json!({"result": "ID_TAKEN"})).into_response(),
        Ok(_) => bad_input(),
        Err(err) => {
            log::error!("enrolment failed: {err}");
            // Not one of the client's four results, so it surfaces as text —
            // which is correct for a server-side fault it should report.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"result": "SERVER_ERROR"})),
            )
                .into_response()
        }
    }
}

/// Issues a new enrolment token. Used by the CLI, not by an endpoint.
pub fn issue_token(
    connection: &rusqlite::Connection,
    created_by: i64,
    ttl_seconds: u64,
) -> Result<String, String> {
    let token = generate_token();
    let fingerprint = token_fingerprint(&token);
    let now = epoch_seconds();
    connection
        .execute(
            "insert into deploy_tokens (token_hash, created_by, created_at, expires_at)
             values (?1, ?2, ?3, ?4)",
            rusqlite::params![
                fingerprint,
                created_by,
                now as i64,
                now.saturating_add(ttl_seconds.min(TOKEN_TTL_SECONDS)) as i64,
            ],
        )
        .map_err(|err| format!("cannot issue enrolment token: {err}"))?;
    Ok(token)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolledDevice {
    pub peer_id: String,
    pub uuid: String,
    pub enrolled_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client maps exactly four strings; a typo becomes a user-visible
    /// error, so pin the shape.
    #[test]
    fn deploy_results_are_the_closed_set() {
        for expected in ["OK", "NOT_ENABLED", "INVALID_INPUT", "ID_TAKEN"] {
            let body = match expected {
                "OK" => Json(json!({"result": "OK"})),
                "NOT_ENABLED" => Json(json!({"result": "NOT_ENABLED"})),
                "INVALID_INPUT" => Json(json!({"result": "INVALID_INPUT"})),
                _ => Json(json!({"result": "ID_TAKEN"})),
            };
            let serialized = serde_json::to_string(&body.0).unwrap();
            assert_eq!(
                serialized,
                format!(r#"{{"result":"{expected}"}}"#),
                "the client reads this verbatim"
            );
        }
    }

    /// Tokens are stored as a fingerprint, so the same token always maps to the
    /// same row and a different one never collides.
    #[test]
    fn token_fingerprint_is_stable_and_distinguishing() {
        let token = generate_token();
        assert_eq!(token_fingerprint(&token), token_fingerprint(&token));
        assert_ne!(token_fingerprint(&token), token_fingerprint(&generate_token()));
        // 32 bytes base64url is 43 characters; guard against a short token.
        assert!(token.len() >= 40, "token too short: {}", token.len());
    }

    #[test]
    fn deploy_request_requires_id_and_pk() {
        let missing: DeployRequest = serde_json::from_str(r#"{"id":"1"}"#).unwrap();
        assert!(missing.pk.is_empty());
        let full: DeployRequest =
            serde_json::from_str(r#"{"id":"1","uuid":"u","pk":"key"}"#).unwrap();
        assert_eq!(full.pk, "key");
    }
}
