//! Client heartbeat, presence, and server-delivered client strategy.
//!
//! Contract verified against rustdesk master (`src/hbbs_http/sync.rs`). The
//! client polls every three seconds; the response may carry:
//!
//! ```json
//! {"sysinfo": true, "disconnect": [1, 2], "strategy": {"config_options": {...}},
//!  "modified_at": 1700000000}
//! ```
//!
//! `strategy.config_options` is fed to the client's `Config::set_options`. This
//! is server-initiated client configuration, and
//! `docs/reference/CLIENT-STRATEGY-SECURITY.md` is the binding constraint on it.
//! The four rules from that document, in order:
//!
//! 1. only an authenticated heartbeat receives a strategy;
//! 2. `config_options` is allow-listed, and the allow-list is exhaustive;
//! 3. the strategy is bound to the account that authenticated;
//! 4. `disconnect` is separate and carries no configuration.
//!
//! A fifth property is not security but correctness: `modified_at` narrowing. The
//! client stores the value it saw and sends it back, so re-delivering an
//! unchanged document makes it re-apply options on every poll.

use axum::{
    extract::{Extension, RawBody},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hyper::body::HttpBody as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

use hbb_common::log;
use tokio_rusqlite::rusqlite;

use crate::auth_server::ApiState;

// ---------------------------------------------------------------------------
// The allow-list
// ---------------------------------------------------------------------------

/// Every `config_options` key this server may deliver.
///
/// Exhaustive by construction. Each entry is a client setting that cannot widen
/// access: either it selects a transport, points at this server, or is a feature
/// toggle the user could set themselves. See the security document for the
/// per-key reasoning.
pub(crate) const ALLOWED_KEYS: &[&str] = &[
    "relay-server",
    "rendezvous-server",
    "api-server",
    "allow-auto-record-incoming",
    "enable-audio",
    "enable-clipboard",
    "enable-file-transfer",
    "enable-remote-printer",
    "use-webrtc",
    // Delivering `N` here disables this channel, which is strictly narrowing.
    "allow-remote-config-modification",
    "verification-method",
];

/// Keys that must never be delivered, regardless of configuration.
///
/// Listed separately from "everything not in the allow-list" so the intent is
/// reviewable and so a future widening of `ALLOWED_KEYS` cannot silently
/// re-admit one of these. A test asserts the two sets are disjoint.
pub(crate) const FORBIDDEN_KEYS: &[&str] = &[
    "password",
    "key",
    "secret",
    "token",
    "private-key",
    "whitelist",
    "custom-rendezvous-server",
    "stop-service",
    "deny-list",
    "blocklist",
];

/// Whether a key may be delivered.
pub(crate) fn key_is_allowed(key: &str) -> bool {
    if FORBIDDEN_KEYS.iter().any(|forbidden| key == *forbidden) {
        return false;
    }
    ALLOWED_KEYS.iter().any(|allowed| key == *allowed)
}

/// Drops every key the allow-list does not name.
///
/// Pure, so the rule is testable without a database or an HTTP request. Dropped
/// keys are logged by name at `warn`, because a delivery that silently does
/// nothing is harder to diagnose than a noisy one.
pub(crate) fn filter_config_options(options: Map<String, Value>) -> Map<String, Value> {
    let mut kept = Map::new();
    for (key, value) in options {
        if key_is_allowed(&key) {
            kept.insert(key, value);
        } else {
            log::warn!("client strategy dropped a key outside the allow-list: {key}");
        }
    }
    kept
}

/// The document stored for an account, filtered through the allow-list.
///
/// `extra` is delivered verbatim: it is opaque metadata the client does not feed
/// to `set_options`.
pub(crate) fn sanitise_strategy(document: &str) -> Option<(String, i64)> {
    let parsed: Value = serde_json::from_str(document).ok()?;
    let modified_at = parsed
        .get("modified_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let options = parsed
        .get("config_options")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let extra = parsed.get("extra").cloned().unwrap_or(Value::Null);
    let filtered = filter_config_options(options);
    Some((
        json!({"config_options": filtered, "extra": extra}).to_string(),
        modified_at,
    ))
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The heartbeat the client sends. Every field is optional: a client that has
/// not logged in sends only its identity.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct HeartbeatRequest {
    pub id: String,
    pub uuid: String,
    pub ver: String,
    /// Connection ids currently open for this device.
    pub conns: Vec<i64>,
    /// The `modified_at` the client last saw, so an unchanged strategy is not
    /// re-delivered.
    pub modified_at: Option<i64>,
    /// The client also uploads these preset fields when configured.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The heartbeat answer. Absent members are omitted, not null, so the client's
/// `rsp.remove(...)` checks stay false.
#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
pub(crate) struct HeartbeatResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysinfo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect: Option<Vec<i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Value>,
    pub modified_at: i64,
}

async fn read_body(body: RawBody<axum::body::Body>) -> Option<HeartbeatRequest> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return None };
        if bytes.len().saturating_add(chunk.len()) > 32 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /api/heartbeat`
pub(crate) async fn heartbeat(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    let request = read_body(body).await.unwrap_or_default();
    if request.id.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }

    // Rule 1: an unauthenticated heartbeat is answered, so the client does not
    // retry forever, but it carries no strategy and no sysinfo instruction.
    let authenticated = state.authenticate_headers(&headers).await.ok();
    let peer_id = request.id.trim().to_owned();
    let peer_id_for_db = peer_id.clone();
    let uuid = request.uuid.clone();
    let version = request.ver.clone();
    let connections = serde_json::to_string(&request.conns).unwrap_or_else(|_| "[]".to_owned());
    let bound_user = authenticated;

    if let Err(err) = state
        .db_call(move |connection| {
            let now = epoch_seconds() as i64;
            connection.execute(
                "insert into device_presence (peer_id, uuid, version, connections, user_id,
                                              first_seen, last_seen)
                 values (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 on conflict(peer_id) do update set uuid = excluded.uuid,
                    version = excluded.version, connections = excluded.connections,
                    user_id = coalesce(excluded.user_id, user_id),
                    last_seen = excluded.last_seen",
                rusqlite::params![peer_id_for_db, uuid, version, connections, bound_user, now],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
    {
        // Presence is telemetry: failing to record it must not fail the poll, or
        // a database hiccup would make every client retry in a tight loop.
        log::warn!("cannot record device presence: {err}");
    }

    let Some(user_id) = authenticated else {
        return Json(HeartbeatResponse {
            modified_at: request.modified_at.unwrap_or(0),
            ..Default::default()
        })
        .into_response();
    };

    // Rule 3: the strategy belongs to the account that authenticated.
    let stored = state.client_strategy(user_id).await;
    // The answer must carry the *stored* stamp, not the client's echo: the client
    // saves whatever it receives and compares it next poll, so echoing the echo
    // makes an unchanged strategy look new forever.
    let mut modified_at = 0;
    let strategy = match stored {
        Ok(Some((document, stamp))) => {
            modified_at = stamp;
            if request.modified_at == Some(stamp) {
                None
            } else {
                build_strategy_document(&document)
            }
        }
        Ok(None) => None,
        Err(err) => {
            log::error!("cannot read client strategy: {err}");
            None
        }
    };

    // Rule 4: disconnects are separate, and drained on delivery so a client that
    // polls again does not keep receiving the same instruction.
    let disconnects = state.take_disconnects(&peer_id).await.unwrap_or_default();

    let response = HeartbeatResponse {
        sysinfo: None,
        disconnect: if disconnects.is_empty() {
            None
        } else {
            Some(disconnects)
        },
        strategy,
        modified_at,
    };
    Json(response).into_response()
}

/// The `strategy` member for a stored document, allow-list already applied.
///
/// Split out so the parsing happens once and the HTTP handler stays about the
/// request lifecycle.
pub(crate) fn build_strategy_document(document: &str) -> Option<Value> {
    let (sanitised, _) = match sanitise_strategy(document) {
        Some(pair) => pair,
        None => return None,
    };
    let parsed: Value = serde_json::from_str(&sanitised).ok()?;
    Some(json!({
        "config_options": parsed
            .get("config_options")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "extra": parsed.get("extra").cloned().unwrap_or(Value::Null),
    }))
}

/// `POST /api/sysinfo` — the client uploads device details.
///
/// The client treats `SYSINFO_UPDATED` and `ID_NOT_FOUND` specially: the former
/// means "stop re-uploading", the latter triggers a retry.
pub(crate) async fn sysinfo(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    if state.authenticate_headers(&headers).await.is_err() {
        // Refusing here is what stops an unauthenticated caller from stuffing
        // the presence table with arbitrary device records.
        return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    let Some(request) = read_body(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if request.id.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    let peer_id = request.id.trim().to_owned();
    let known = state
        .db_call(move |connection| {
            let exists = connection
                .query_row(
                    "select 1 from device_presence where peer_id = ?1",
                    [peer_id.as_str()],
                    |_| Ok(()),
                )
                .is_ok();
            Ok::<_, rusqlite::Error>(exists)
        })
        .await
        .unwrap_or(false);
    if known {
        // Plain text, not JSON: the client compares the whole body.
        (StatusCode::OK, "SYSINFO_UPDATED").into_response()
    } else {
        (StatusCode::OK, "ID_NOT_FOUND").into_response()
    }
}

/// `POST /api/sysinfo_ver` — lets the client skip an unchanged upload.
pub(crate) async fn sysinfo_version(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    let _ = body;
    if state.authenticate_headers(&headers).await.is_err() {
        return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    // One version string for the whole server: the client only compares it for
    // equality, to decide whether to re-upload.
    (StatusCode::OK, crate::version::VERSION).into_response()
}

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two lists must be disjoint, or the answer would depend on which check
    /// runs first.
    #[test]
    fn allow_and_forbid_lists_are_disjoint() {
        for allowed in ALLOWED_KEYS {
            assert!(
                !FORBIDDEN_KEYS.contains(allowed),
                "{allowed} is both permitted and forbidden"
            );
        }
    }

    /// Every key in the security document's table must actually be deliverable,
    /// and nothing else.
    #[test]
    fn the_allow_list_matches_the_document() {
        let documented = [
            "relay-server",
            "rendezvous-server",
            "api-server",
            "allow-auto-record-incoming",
            "enable-audio",
            "enable-clipboard",
            "enable-file-transfer",
            "enable-remote-printer",
            "use-webrtc",
            "allow-remote-config-modification",
            "verification-method",
        ];
        assert_eq!(ALLOWED_KEYS.len(), documented.len());
        for key in documented {
            assert!(ALLOWED_KEYS.contains(&key), "{key} missing from the allow-list");
        }
    }

    #[test]
    fn filtering_keeps_only_listed_keys() {
        let options = json!({
            "relay-server": "relay.example:21117",
            "enable-audio": "Y",
            "password": "hunter2",
            "whitelist": "anything",
            "totally-made-up": "x",
            "custom-rendezvous-server": "attacker.example"
        });
        let filtered = filter_config_options(options.as_object().unwrap().clone());
        assert_eq!(filtered.len(), 2, "only the two listed keys survive: {filtered:?}");
        assert!(filtered.contains_key("relay-server"));
        assert!(filtered.contains_key("enable-audio"));
        assert!(!filtered.contains_key("password"));
        assert!(!filtered.contains_key("whitelist"));
        assert!(!filtered.contains_key("totally-made-up"));
        assert!(!filtered.contains_key("custom-rendezvous-server"));
    }

    /// A forbidden key must be refused even though it is not in the allow-list,
    /// so that widening the allow-list later cannot re-admit it silently.
    #[test]
    fn forbidden_keys_are_refused_explicitly() {
        for key in FORBIDDEN_KEYS {
            assert!(!key_is_allowed(key), "{key} must never be deliverable");
        }
    }

    #[test]
    fn sanitise_drops_unlisted_keys_and_preserves_modified_at() {
        let document = json!({
            "config_options": {"enable-audio": "Y", "password": "x"},
            "extra": {"note": "kept verbatim"},
            "modified_at": 1_700_000_000
        })
        .to_string();
        let (sanitised, modified_at) = sanitise_strategy(&document).unwrap();
        assert_eq!(modified_at, 1_700_000_000);
        let parsed: Value = serde_json::from_str(&sanitised).unwrap();
        assert_eq!(parsed["config_options"]["enable-audio"], "Y");
        assert!(parsed["config_options"].get("password").is_none());
        assert_eq!(parsed["extra"]["note"], "kept verbatim");
    }

    /// The delivered document drops forbidden keys and keeps the rest.
    #[test]
    fn build_strategy_document_applies_the_allow_list() {
        let document = json!({
            "config_options": {"enable-audio": "Y", "token": "leak"},
            "extra": {"x": 1}
        })
        .to_string();
        let built = build_strategy_document(&document).expect("valid document");
        assert_eq!(built["config_options"]["enable-audio"], "Y");
        assert!(
            built["config_options"].get("token").is_none(),
            "a forbidden key must not survive: {built}"
        );
        assert_eq!(built["extra"]["x"], 1);
    }

    #[test]
    fn sanitise_rejects_a_non_json_document() {
        assert!(sanitise_strategy("{not json").is_none());
    }

    /// Absent members must be omitted rather than null: the client decides what
    /// to do with `rsp.remove("strategy")`, and null would still be a key.
    #[test]
    fn response_omits_absent_members() {
        let response = HeartbeatResponse {
            modified_at: 5,
            ..Default::default()
        };
        let serialized = serde_json::to_string(&response).unwrap();
        assert_eq!(serialized, r#"{"modified_at":5}"#);
    }

    #[test]
    fn response_carries_only_what_is_present() {
        let response = HeartbeatResponse {
            disconnect: Some(vec![1, 2]),
            modified_at: 7,
            ..Default::default()
        };
        let parsed: Value =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        assert_eq!(parsed["disconnect"], json!([1, 2]));
        assert!(parsed.get("strategy").is_none());
        assert!(parsed.get("sysinfo").is_none());
    }

    #[test]
    fn heartbeat_request_tolerates_the_clients_extras() {
        // The client also sends preset address-book fields when configured.
        let raw = json!({
            "id": "1", "uuid": "u", "ver": "1.5.0",
            "conns": [1, 2], "modified_at": 3,
            "preset-address-book-name": "office"
        });
        let request: HeartbeatRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(request.id, "1");
        assert_eq!(request.conns, vec![1, 2]);
        assert_eq!(request.modified_at, Some(3));
        assert_eq!(
            request.extra.get("preset-address-book-name"),
            Some(&Value::String("office".to_owned()))
        );
    }
}
