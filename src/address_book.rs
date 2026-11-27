//! Non-legacy address books: the structured endpoints the official client
//! prefers over the single-document `/api/ab`.
//!
//! Verified against rustdesk master (`flutter/lib/models/ab_model.dart`,
//! `flutter/lib/common/hbbs/hbbs.dart`). The client decides which shape to use
//! once, at pull time: it POSTs `/api/ab/personal` and a **404 there makes it
//! fall back to the legacy single document**. So these endpoints are
//! all-or-nothing — implementing half of them leaves the feature dark.
//!
//! Wire details that are easy to get wrong:
//!
//! - An "empty body" request still carries `Content-Length: 0`, so every handler
//!   here must tolerate a zero-byte body rather than demanding JSON.
//! - `/api/ab/peers` and `/api/ab/shared/profiles` are paginated with
//!   `?current=&pageSize=` and answer `{total, data}`, where `total` drives the
//!   client's loop (`while current * pageSize < total`). Answering the full set
//!   in one page is fine; omitting `total` is not, because the client would stop
//!   after one page.
//! - `/api/ab/tags/{guid}` answers a **bare array**, not an envelope.
//! - Delete takes a bare JSON array of ids/tags, not an object.

use axum::{
    body::Body,
    extract::{Extension, Path as AxumPath, Query, RawBody},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use hbb_common::log;
use tokio_rusqlite::rusqlite;

use crate::auth_server::{ApiState, AuthFailure};

/// One address book as the client models it.
///
/// `rule` is a `ShareRule`: 1 read, 2 read/write, 3 full control. The server
/// stores it but only enforces read-versus-write on the endpoints below; richer
/// semantics belong to a later permission model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookProfile {
    pub guid: String,
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub note: Option<String>,
    pub rule: i64,
    #[serde(default)]
    pub info: Value,
}

/// The 16 fields `Peer.fromJson`/`toJson` carries.
///
/// `force_always_relay` is a **string** in the client's JSON (`"true"`/`"false"`)
/// because `toJson` calls `.toString()` on a bool. Accepting both forms is not
/// politeness: a mismatch here breaks every push.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct BookPeer {
    pub id: String,
    pub hash: String,
    pub password: String,
    pub username: String,
    pub hostname: String,
    pub platform: String,
    pub alias: String,
    pub tags: Vec<Value>,
    // The client's key is camelCase for this one only, because `toJson` writes
    // it as `forceAlwaysRelay` while every other snake_case key is literal.
    #[serde(rename = "forceAlwaysRelay")]
    pub force_always_relay: String,
    #[serde(rename = "rdpPort")]
    pub rdp_port: String,
    #[serde(rename = "rdpUsername")]
    pub rdp_username: String,
    #[serde(rename = "loginName")]
    pub login_name: String,
    #[serde(rename = "device_group_name")]
    pub device_group_name: String,
    pub note: String,
    #[serde(rename = "same_server")]
    pub same_server: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookTag {
    pub name: String,
    pub color: i64,
}

/// `?current=&pageSize=` — both optional; the client always sends them.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct Page {
    pub(crate) current: Option<u64>,
    pub(crate) page_size: Option<u64>,
    /// `/api/ab/peers` scopes by book.
    pub(crate) ab: Option<String>,
}

impl Page {
    /// `(limit, offset)` for SQL. Bounded so a hostile page size cannot ask for
    /// an unbounded result set.
    pub(crate) fn window(&self) -> (i64, i64) {
        let size = self.page_size.unwrap_or(100).clamp(1, 500) as i64;
        let current = self.current.unwrap_or(1).max(1) as i64;
        (size, (current - 1).saturating_mul(size))
    }
}

// ---------------------------------------------------------------------------
// Data access
// ---------------------------------------------------------------------------

/// Loads the books an account may see: its own personal book plus any book
/// explicitly marked readable.
///
/// A book is visible when the caller owns it or its `rule` grants access. v1
/// models sharing as "rule >= read", which matches what the client can express;
/// per-user sharing lists are a later concern.
pub async fn books_for(state: &ApiState, user_id: i64) -> Result<Vec<BookProfile>, String> {
    let owner = state.user_name(user_id).await?;
    state
        .db_call(move |connection| {
            let mut statement = connection.prepare(
                "select guid, name, note, rule from ab_books
                 where owner_id = ?1 or rule >= 1
                 order by personal desc, name asc",
            )?;
            let mut rows = statement.query([user_id])?;
            let mut books = Vec::new();
            while let Some(row) = rows.next()? {
                books.push(BookProfile {
                    guid: row.get(0)?,
                    name: row.get(1)?,
                    owner: owner.clone(),
                    note: Some(row.get::<_, String>(2)?).filter(|note| !note.is_empty()),
                    rule: row.get(3)?,
                    info: Value::Null,
                });
            }
            Ok::<_, rusqlite::Error>(books)
        })
        .await
}

/// Ensures the account has a personal book and returns its guid.
///
/// This is the endpoint that decides legacy versus structured mode, so it must
/// be idempotent and cheap: the client calls it on every pull.
pub async fn ensure_personal_book(state: &ApiState, user_id: i64) -> Result<String, String> {
    let name = state.user_name(user_id).await?;
    state
        .db_call(move |connection| {
            if let Some(guid) = connection
                .query_row(
                    "select guid from ab_books where owner_id = ?1 and personal = 1",
                    [user_id],
                    |row| row.get::<_, String>(0),
                )
                .ok()
            {
                return Ok::<_, rusqlite::Error>(guid);
            }
            let guid = uuid::Uuid::new_v4().to_string();
            let now = epoch_seconds() as i64;
            connection.execute(
                "insert into ab_books (guid, owner_id, name, note, rule, personal, created_at, updated_at)
                 values (?1, ?2, ?3, '', 3, 1, ?4, ?4)",
                rusqlite::params![guid, user_id, name, now],
            )?;
            Ok(guid)
        })
        .await
}

/// Whether the caller may write to a book. `rule` of 1 is read-only.
pub async fn may_write(state: &ApiState, user_id: i64, guid: &str) -> Result<bool, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let rule = connection
                .query_row(
                    "select rule from ab_books where guid = ?1 and (owner_id = ?2 or rule >= 2)",
                    rusqlite::params![guid, user_id],
                    |row| row.get::<_, i64>(0),
                )
                .ok();
            Ok::<_, rusqlite::Error>(rule.is_some())
        })
        .await
}

pub async fn peers_in_book(
    state: &ApiState,
    user_id: i64,
    guid: &str,
    page: &Page,
) -> Result<(u64, Vec<BookPeer>), String> {
    if !may_read(state, user_id, guid).await? {
        return Err("book_not_found".to_owned());
    }
    let guid = guid.to_owned();
    let (limit, offset) = page.window();
    state
        .db_call(move |connection| {
            let total: i64 = connection.query_row(
                "select count(*) from ab_peers where guid = ?1",
                [guid.as_str()],
                |row| row.get(0),
            )?;
            let mut statement = connection.prepare(
                "select peer_id, hash, password, username, hostname, platform, alias, tags,
                        force_always_relay, rdp_port, rdp_username, login_name,
                        device_group_name, note
                 from ab_peers where guid = ?1
                 order by peer_id asc limit ?2 offset ?3",
            )?;
            let mut rows = statement.query(rusqlite::params![guid, limit, offset])?;
            let mut peers = Vec::new();
            while let Some(row) = rows.next()? {
                let tags: String = row.get(7)?;
                peers.push(BookPeer {
                    id: row.get(0)?,
                    hash: row.get(1)?,
                    password: row.get(2)?,
                    username: row.get(3)?,
                    hostname: row.get(4)?,
                    platform: row.get(5)?,
                    alias: row.get(6)?,
                    tags: serde_json::from_str(&tags).unwrap_or_default(),
                    force_always_relay: if row.get::<_, i64>(8)? != 0 {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    },
                    rdp_port: row.get(9)?,
                    rdp_username: row.get(10)?,
                    login_name: row.get(11)?,
                    device_group_name: row.get(12)?,
                    note: row.get(13)?,
                    same_server: None,
                });
            }
            Ok::<_, rusqlite::Error>((total.max(0) as u64, peers))
        })
        .await
}

async fn may_read(state: &ApiState, user_id: i64, guid: &str) -> Result<bool, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let exists = connection
                .query_row(
                    "select 1 from ab_books where guid = ?1 and (owner_id = ?2 or rule >= 1)",
                    rusqlite::params![guid, user_id],
                    |_| Ok(()),
                )
                .is_ok();
            Ok::<_, rusqlite::Error>(exists)
        })
        .await
}

pub async fn tags_in_book(state: &ApiState, user_id: i64, guid: &str) -> Result<Vec<BookTag>, String> {
    if !may_read(state, user_id, guid).await? {
        return Err("book_not_found".to_owned());
    }
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let mut statement =
                connection.prepare("select name, color from ab_tags where guid = ?1 order by name")?;
            let mut rows = statement.query([guid])?;
            let mut tags = Vec::new();
            while let Some(row) = rows.next()? {
                tags.push(BookTag {
                    name: row.get(0)?,
                    color: row.get(1)?,
                });
            }
            Ok::<_, rusqlite::Error>(tags)
        })
        .await
}

/// Inserts or replaces a peer row.
pub async fn upsert_peer(
    state: &ApiState,
    guid: &str,
    peer: BookPeer,
) -> Result<(), String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let tags = serde_json::to_string(&peer.tags).unwrap_or_else(|_| "[]".to_owned());
            let now = epoch_seconds() as i64;
            connection.execute(
                "insert into ab_peers (guid, peer_id, hash, password, username, hostname,
                                        platform, alias, tags, force_always_relay, rdp_port,
                                        rdp_username, login_name, device_group_name, note, updated_at)
                 values (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
                 on conflict(guid, peer_id) do update set
                    hash = excluded.hash, password = excluded.password,
                    username = excluded.username, hostname = excluded.hostname,
                    platform = excluded.platform, alias = excluded.alias,
                    tags = excluded.tags, force_always_relay = excluded.force_always_relay,
                    rdp_port = excluded.rdp_port, rdp_username = excluded.rdp_username,
                    login_name = excluded.login_name,
                    device_group_name = excluded.device_group_name,
                    note = excluded.note, updated_at = excluded.updated_at",
                rusqlite::params![
                    guid,
                    peer.id,
                    peer.hash,
                    peer.password,
                    peer.username,
                    peer.hostname,
                    peer.platform,
                    peer.alias,
                    tags,
                    if peer.force_always_relay.eq_ignore_ascii_case("true") { 1 } else { 0 },
                    peer.rdp_port,
                    peer.rdp_username,
                    peer.login_name,
                    peer.device_group_name,
                    peer.note,
                    now,
                ],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
}

/// Deletes the named peers from a book and reports how many existed.
pub async fn delete_peers(state: &ApiState, guid: &str, ids: Vec<String>) -> Result<u64, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let mut removed = 0u64;
            for id in ids {
                removed += connection.execute(
                    "delete from ab_peers where guid = ?1 and peer_id = ?2",
                    rusqlite::params![guid, id],
                )? as u64;
            }
            Ok::<_, rusqlite::Error>(removed)
        })
        .await
}

pub async fn upsert_tag(state: &ApiState, guid: &str, tag: BookTag) -> Result<(), String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            connection.execute(
                "insert into ab_tags (guid, name, color) values (?1, ?2, ?3)
                 on conflict(guid, name) do update set color = excluded.color",
                rusqlite::params![guid, tag.name, tag.color],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
}

/// Renames a tag and rewrites every peer that referenced it.
///
/// The client sends the old and new name and expects the peers to follow, so
/// doing this in one statement set here is what keeps the book consistent.
pub async fn rename_tag(state: &ApiState, guid: &str, old: &str, new: &str) -> Result<(), String> {
    let guid = guid.to_owned();
    let old = old.to_owned();
    let new = new.to_owned();
    state
        .db_call(move |connection| {
            connection.execute(
                "update ab_tags set name = ?3 where guid = ?1 and name = ?2",
                rusqlite::params![guid, old, new],
            )?;
            // Rewrite each peer's JSON tag array. Done in Rust rather than SQL
            // because the array lives inside a JSON column.
            let mut statement =
                connection.prepare("select peer_id, tags from ab_peers where guid = ?1")?;
            let mut rows = statement.query([guid.as_str()])?;
            let mut changes = Vec::new();
            while let Some(row) = rows.next()? {
                let peer_id: String = row.get(0)?;
                let raw: String = row.get(1)?;
                let mut tags: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
                let mut touched = false;
                for tag in tags.iter_mut() {
                    if tag.as_str() == Some(old.as_str()) {
                        *tag = Value::String(new.clone());
                        touched = true;
                    }
                }
                if touched {
                    changes.push((peer_id, serde_json::to_string(&tags).unwrap_or(raw)));
                }
            }
            for (peer_id, tags) in changes {
                connection.execute(
                    "update ab_peers set tags = ?3 where guid = ?1 and peer_id = ?2",
                    rusqlite::params![guid, peer_id, tags],
                )?;
            }
            Ok::<_, rusqlite::Error>(())
        })
        .await
}

pub async fn delete_tags(state: &ApiState, guid: &str, names: Vec<String>) -> Result<u64, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let mut removed = 0u64;
            for name in names {
                removed += connection.execute(
                    "delete from ab_tags where guid = ?1 and name = ?2",
                    rusqlite::params![guid, name],
                )? as u64;
            }
            Ok::<_, rusqlite::Error>(removed)
        })
        .await
}

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Reads the body as JSON, or yields `None` for the client's empty-body calls.
///
/// Several of these endpoints are POSTs with `Content-Length: 0` used purely as
/// GET-with-auth. Treating an empty body as an error would break them.
async fn optional_json<T: serde::de::DeserializeOwned>(body: RawBody<Body>) -> Option<T> {
    use hyper::body::HttpBody as _;
    // `RawBody` is a tuple struct; the existing handlers destructure it the same
    // way. These endpoints treat an absent body as valid, because the client
    // sends several of them as POSTs with `Content-Length: 0` purely to carry
    // the Authorization header.
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return None };
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn unauthorized(auth: AuthFailure) -> Response {
    match auth {
        AuthFailure::Unauthorized => crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
        AuthFailure::Unavailable => {
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

fn book_error(code: &str) -> Response {
    // A missing or unreadable book is a 404 so the client can tell "this server
    // does not have it" from "you may not see it".
    crate::auth_server::api_error(StatusCode::NOT_FOUND, code)
}

pub async fn personal(
    Extension(state): Extension<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    match ensure_personal_book(&state, user_id).await {
        Ok(guid) => Json(json!({"guid": guid})).into_response(),
        Err(err) => {
            log::error!("cannot ensure personal address book: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn settings(
    Extension(state): Extension<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    if state.authenticate_headers(&headers).await.is_err() {
        return unauthorized(AuthFailure::Unauthorized);
    }
    // Starry does not licence devices, so the ceiling must be high enough never
    // to truncate. A small number here would silently drop a user's peers.
    Json(json!({"max_peer_one_ab": 1_000_000})).into_response()
}

pub async fn shared_profiles(
    Extension(state): Extension<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    Query(page): Query<Page>,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let books = match books_for(&state, user_id).await {
        Ok(books) => books,
        Err(err) => {
            log::error!("cannot list address books: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    // The client pages with `while current * pageSize < total`, so this must be
    // the *unpaged* count, not the length of the returned page.
    let total = books.len();
    let (limit, offset) = page.window();
    let data: Vec<BookProfile> = books
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Json(json!({"total": total, "data": data})).into_response()
}

pub async fn peers(
    Extension(state): Extension<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    Query(page): Query<Page>,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let guid = match page.ab.as_deref() {
        Some(guid) if !guid.is_empty() => guid.to_owned(),
        // No `ab` means "my personal book", which is what the client does
        // before it has learned the guid.
        _ => match ensure_personal_book(&state, user_id).await {
            Ok(guid) => guid,
            Err(err) => {
                log::error!("cannot resolve personal book: {err}");
                return crate::auth_server::api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SystemError",
                );
            }
        },
    };
    match peers_in_book(&state, user_id, &guid, &page).await {
        Ok((total, data)) => Json(json!({"total": total, "data": data})).into_response(),
        Err(err) if err == "book_not_found" => book_error("BookNotFound"),
        Err(err) => {
            log::error!("cannot list peers in book: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn tags(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    match tags_in_book(&state, user_id, &guid).await {
        // A bare array, not an envelope: the client parses this as `List`.
        Ok(tags) => Json(tags).into_response(),
        Err(err) if err == "book_not_found" => book_error("BookNotFound"),
        Err(err) => {
            log::error!("cannot list tags: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn peer_add(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(peer) = optional_json::<BookPeer>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if peer.id.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match upsert_peer(&state, &guid, peer).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot add peer: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `PUT /api/ab/peer/update/{guid}` with one of four body shapes.
///
/// The client reuses this path for tags, alias, note and hash, distinguished by
/// which fields are present. Each is applied only when present, so a request
/// carrying `{id, tags}` cannot silently clear the alias.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct PeerUpdate {
    id: String,
    tags: Option<Vec<Value>>,
    alias: Option<String>,
    note: Option<String>,
    hash: Option<String>,
    password: Option<String>,
}

pub async fn peer_update(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(update) = optional_json::<PeerUpdate>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if update.id.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    let guid_owned = guid.clone();
    let result = state
        .db_call(move |connection| {
            let mut statement = connection.prepare(
                "select tags, alias, note, hash, password from ab_peers
                 where guid = ?1 and peer_id = ?2",
            )?;
            let mut rows = statement.query(rusqlite::params![guid_owned, update.id])?;
            let Some(row) = rows.next()? else {
                return Ok::<_, rusqlite::Error>(false);
            };
            let tags: String = row.get(0)?;
            let alias: String = row.get(1)?;
            let note: String = row.get(2)?;
            let hash: String = row.get(3)?;
            let password: String = row.get(4)?;
            drop(rows);
            let next_tags = match &update.tags {
                Some(tags) => serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_owned()),
                None => tags,
            };
            connection.execute(
                "update ab_peers set tags = ?3, alias = ?4, note = ?5, hash = ?6, password = ?7,
                                    updated_at = ?8
                 where guid = ?1 and peer_id = ?2",
                rusqlite::params![
                    guid_owned,
                    update.id,
                    next_tags,
                    update.alias.clone().unwrap_or(alias),
                    update.note.clone().unwrap_or(note),
                    update.hash.clone().unwrap_or(hash),
                    update.password.clone().unwrap_or(password),
                    epoch_seconds() as i64,
                ],
            )?;
            Ok(true)
        })
        .await;
    match result {
        Ok(true) => Json(Value::Null).into_response(),
        Ok(false) => book_error("PeerNotFound"),
        Err(err) => {
            log::error!("cannot update peer: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn peer_delete(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    // A bare array of ids, not an object.
    let Some(ids) = optional_json::<Vec<String>>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match delete_peers(&state, &guid, ids).await {
        Ok(_) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot delete peers: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn tag_add(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(tag) = optional_json::<BookTag>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if tag.name.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match upsert_tag(&state, &guid, tag).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot add tag: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct TagRename {
    old: String,
    new: String,
}

pub async fn tag_rename(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(rename) = optional_json::<TagRename>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if rename.old.trim().is_empty() || rename.new.trim().is_empty() {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match rename_tag(&state, &guid, &rename.old, &rename.new).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot rename tag: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn tag_update(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(tag) = optional_json::<BookTag>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match upsert_tag(&state, &guid, tag).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot update tag: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub async fn tag_delete(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(names) = optional_json::<Vec<String>>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    match may_write(&state, user_id, &guid).await {
        Ok(true) => {}
        Ok(false) => return book_error("BookReadOnly"),
        Err(err) => {
            log::error!("cannot check book write permission: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    match delete_tags(&state, &guid, names).await {
        Ok(_) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot delete tags: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `forceAlwaysRelay` is a string in the client's JSON, and a bool breaks
    /// deserialisation of the whole peer.
    #[test]
    fn peer_accepts_the_clients_field_names() {
        let raw = json!({
            "id": "9001",
            "hash": "h",
            "password": "p",
            "username": "u",
            "hostname": "host",
            "platform": "Linux",
            "alias": "prod",
            "tags": ["office"],
            "forceAlwaysRelay": "true",
            "rdpPort": "3389",
            "rdpUsername": "rdp",
            "loginName": "login",
            "device_group_name": "servers",
            "note": "n",
            "same_server": true
        });
        let peer: BookPeer = serde_json::from_value(raw).expect("client peer must deserialize");
        assert_eq!(peer.id, "9001");
        assert_eq!(peer.force_always_relay, "true");
        assert_eq!(peer.rdp_port, "3389");
        assert_eq!(peer.login_name, "login");
        assert_eq!(peer.device_group_name, "servers");
        assert_eq!(peer.same_server, Some(true));
    }

    /// Everything except the id may be absent; the client sends partial peers.
    #[test]
    fn peer_tolerates_missing_fields() {
        let peer: BookPeer = serde_json::from_str(r#"{"id":"1"}"#).unwrap();
        assert_eq!(peer.id, "1");
        assert!(peer.tags.is_empty());
        assert_eq!(peer.force_always_relay, "");
    }

    #[test]
    fn page_window_is_bounded() {
        assert_eq!(Page::default().window(), (100, 0));
        let page = Page {
            current: Some(3),
            page_size: Some(10),
            ab: None,
        };
        assert_eq!(page.window(), (10, 20));
        // A hostile page size cannot ask for an unbounded result set.
        let hostile = Page {
            current: Some(0),
            page_size: Some(u64::MAX),
            ab: None,
        };
        assert_eq!(hostile.window(), (500, 0));
    }

    #[test]
    fn tag_round_trips_as_the_client_sends_it() {
        let tag: BookTag = serde_json::from_str(r#"{"name":"office","color":4278255360}"#).unwrap();
        assert_eq!(tag.name, "office");
        assert_eq!(tag.color, 4_278_255_360);
    }

    #[test]
    fn profile_matches_the_client_shape() {
        let raw = json!({
            "guid": "g1", "name": "Personal", "owner": "alice",
            "note": null, "rule": 3, "info": null
        });
        let profile: BookProfile = serde_json::from_value(raw).unwrap();
        assert_eq!(profile.guid, "g1");
        assert_eq!(profile.rule, 3);
        assert!(profile.note.is_none());
    }
}
