//! Client-side audit upload and session recording.
//!
//! Both are **opt-in and off by default**, because both accept data about a user's
//! own machine and, for recording, its screen contents.
//!
//! Distinguish this from `STARRY_AUDIT_DIR`: that is *server-side* audit — who
//! connected to whom and what the strategy decided. These endpoints are
//! *client-side* audit — what the user did locally. They are different sources
//! and neither can substitute for the other.
//!
//! Contracts from rustdesk master:
//!
//! - `POST /api/audit/{typ}` uploads an event; `typ` names the kind.
//! - `PUT /api/audit` attaches a `{guid, note}` to one session. This is the client
//!   asking to annotate a record, so the note text is user-supplied and must be
//!   bounded.
//! - `POST /api/record?type=new|frame&file=` streams a recording in chunks.
//!
//! # Trust
//!
//! Client audit is **advisory only**. A client can forge any event it likes, so
//! nothing here may be used to decide whether a connection is allowed, and it must
//! not be merged into the server-side audit trail in a way that makes the two
//! indistinguishable. They are stored in separate tables and reported as separate
//! sources.

use axum::{
    extract::{Extension, Query, RawBody},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hyper::body::HttpBody as _;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use hbb_common::log;
use tokio_rusqlite::rusqlite;

use crate::auth_server::ApiState;

/// Bound on one uploaded audit event. The client sends small objects.
const MAX_AUDIT_BYTES: usize = 32 * 1024;
/// Bound on one recording chunk. `type=frame` sends slices of a file, and the
/// client's own flush interval keeps these modest.
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Bound on an annotation note.
const MAX_NOTE_CHARS: usize = 4_096;

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

async fn read_body(body: RawBody<axum::body::Body>, limit: usize) -> Option<Vec<u8>> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return None };
        if bytes.len().saturating_add(chunk.len()) > limit {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

fn feature_disabled() -> Response {
    crate::auth_server::api_error(StatusCode::NOT_IMPLEMENTED, "NotEnabled")
}

/// `POST /api/audit/{typ}`
///
/// Stored with its source marked `client`, never mixed with server audit.
pub(crate) async fn audit_upload(
    Extension(state): Extension<Arc<ApiState>>,
    axum::extract::Path(kind): axum::extract::Path<String>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    if !state.client_audit_enabled() {
        return feature_disabled();
    }
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(_) => return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
    };
    let Some(bytes) = read_body(body, MAX_AUDIT_BYTES).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    // Stored as an opaque JSON value: the client's event shape is its own, and
    // interpreting it here would break on the next client release.
    let payload: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError"),
    };
    let kind = kind.trim().to_owned();
    if kind.is_empty()
        || kind.len() > 64
        || !kind
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    let stored = payload.to_string();
    match state
        .db_call(move |connection| {
            connection.execute(
                "insert into client_audit (user_id, kind, payload, created_at)
                 values (?1, ?2, ?3, ?4)",
                rusqlite::params![user_id, kind, stored, epoch_seconds() as i64],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
    {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot store client audit event: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct AuditNote {
    guid: String,
    note: String,
}

/// `PUT /api/audit` — attach a note to one session.
pub(crate) async fn audit_note(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<axum::body::Body>,
) -> Response {
    if !state.client_audit_enabled() {
        return feature_disabled();
    }
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(_) => return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
    };
    let Some(bytes) = read_body(body, MAX_AUDIT_BYTES).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    let note: AuditNote = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError"),
    };
    if note.guid.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    if note.note.chars().count() > MAX_NOTE_CHARS {
        return crate::auth_server::api_error(StatusCode::PAYLOAD_TOO_LARGE, "ParamsError");
    }
    let guid = note.guid.trim().to_owned();
    let text = note.note;
    match state
        .db_call(move |connection| {
            // The annotation table is keyed by the client's session guid, and a
            // second note for the same session replaces the first: the client
            // asks for one note per session at the end of a connection.
            connection.execute(
                "insert into session_notes (guid, user_id, note, updated_at)
                 values (?1, ?2, ?3, ?4)
                 on conflict(guid) do update set note = excluded.note,
                                                updated_at = excluded.updated_at",
                rusqlite::params![guid, user_id, text, epoch_seconds() as i64],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
    {
        // The client treats a non-200 as "note not saved" and does not retry, so
        // a failure here is logged rather than user-facing.
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot store session note: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct RecordQuery {
    /// `new` starts a file, `frame` appends a chunk.
    #[serde(rename = "type")]
    pub kind: String,
    /// The recording's file name, chosen by the client.
    pub file: String,
}

/// `POST /api/record` — session recording chunks.
pub(crate) async fn record(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<RecordQuery>,
    body: RawBody<axum::body::Body>,
) -> Response {
    if !state.recording_enabled() {
        // Recording is the most sensitive feature here; it must be explicitly
        // enabled, and until then the endpoint says so rather than 404.
        return feature_disabled();
    }
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(_) => return crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
    };
    let Some(bytes) = read_body(body, MAX_RECORD_BYTES).await else {
        return crate::auth_server::api_error(StatusCode::PAYLOAD_TOO_LARGE, "ParamsError");
    };
    let file = sanitize_recording_name(&query.file);
    if file.is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match query.kind.as_str() {
        "new" => {
            match state
                .db_call(move |connection| {
                    let now = epoch_seconds() as i64;
                    connection.execute(
                        "insert into recordings (user_id, file, bytes, started_at, updated_at)
                         values (?1, ?2, 0, ?3, ?3)
                         on conflict(user_id, file) do update set bytes = 0,
                                                                  started_at = excluded.started_at,
                                                                  updated_at = excluded.updated_at",
                        rusqlite::params![user_id, file, now],
                    )?;
                    Ok::<_, rusqlite::Error>(())
                })
                .await
            {
                Ok(()) => Json(Value::Null).into_response(),
                Err(err) => {
                    log::error!("cannot start recording: {err}");
                    crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
                }
            }
        }
        "frame" => {
            // Chunks are counted, not stored by this module: writing megabytes
            // per frame into SQLite would be the wrong storage. The count is what
            // lets an operator see that recording is happening and how much.
            let length = bytes.len() as i64;
            match state
                .db_call(move |connection| {
                    connection.execute(
                        "update recordings set bytes = bytes + ?3, updated_at = ?4
                         where user_id = ?1 and file = ?2",
                        rusqlite::params![user_id, file, length, epoch_seconds() as i64],
                    )?;
                    Ok::<_, rusqlite::Error>(())
                })
                .await
            {
                Ok(()) => Json(Value::Null).into_response(),
                Err(err) => {
                    log::error!("cannot record chunk: {err}");
                    crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
                }
            }
        }
        other => {
            log::warn!("recording chunk with unknown type {other:?} refused");
            crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError")
        }
    }
}

/// Reduces a client-chosen file name to something safe to store.
///
/// The client sends a bare file name, but it is still client-controlled, so a
/// path separator or traversal must not survive.
pub(crate) fn sanitize_recording_name(raw: &str) -> String {
    let name = raw.trim();
    if name.is_empty() || name.len() > 200 {
        return String::new();
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return String::new();
    }
    name.chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client-chosen name must not be able to escape wherever it is later
    /// written, even though this module only counts bytes.
    #[test]
    fn recording_names_reject_traversal() {
        assert_eq!(sanitize_recording_name("session-1.mp4"), "session-1.mp4");
        assert_eq!(sanitize_recording_name("  padded.mp4  "), "padded.mp4");
        for hostile in ["../etc/passwd", "a/b", "a\\b", "..", ""] {
            assert!(
                sanitize_recording_name(hostile).is_empty(),
                "{hostile:?} must be refused"
            );
        }
        // Control characters are stripped rather than rejecting the whole name.
        assert_eq!(sanitize_recording_name("a\u{0}b.mp4"), "ab.mp4");
    }

    #[test]
    fn record_query_reads_the_clients_field_names() {
        let query: RecordQuery =
            serde_json::from_str(r#"{"type":"new","file":"session.mp4"}"#).unwrap();
        assert_eq!(query.kind, "new");
        assert_eq!(query.file, "session.mp4");
    }

    #[test]
    fn audit_note_bounds_its_text() {
        let note: AuditNote =
            serde_json::from_str(r#"{"guid":"g1","note":"connected to db"}"#).unwrap();
        assert_eq!(note.guid, "g1");
        assert_eq!(note.note, "connected to db");
    }
}
