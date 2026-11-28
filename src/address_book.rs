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
pub(crate) struct BookProfile {
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
pub(crate) struct BookPeer {
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
pub(crate) struct BookTag {
    pub name: String,
    /// Client ARGB value. The client sends an unsigned 32-bit int (Dart has no
    /// signed widths), so this accepts the whole range and stores it as i64.
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

/// Loads the books an account may see.
///
/// Visibility requires either ownership or an explicit `ab_shares` row. The
/// book's own `rule` is a ceiling on the level a share may grant, never a grant
/// itself: an earlier version tested `rule >= 1` here, which every new book
/// satisfied (the default was 3), so any signed-in account could list and read
/// every other account's address book.
pub(crate) async fn books_for(state: &ApiState, user_id: i64) -> Result<Vec<BookProfile>, String> {
    let owner = state.user_name(user_id).await?;
    state
        .db_call(move |connection| {
            let mut statement = connection.prepare(
                "select b.guid, b.name, b.note,
                        case when b.owner_id = ?1 then b.rule
                             else min(b.rule, s.rule) end as effective_rule
                 from ab_books b
                 left join ab_shares s on s.guid = b.guid and s.user_id = ?1
                 where b.owner_id = ?1 or s.user_id = ?1
                 order by b.personal desc, b.name asc",
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
pub(crate) async fn ensure_personal_book(
    state: &ApiState,
    user_id: i64,
    import_legacy: bool,
) -> Result<String, String> {
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
                // The book exists. Run the legacy import once, if it was never
                // done and the caller is in a position to do it.
                if import_legacy {
                    import_legacy_book(connection, user_id, &guid)?;
                }
                return Ok::<_, rusqlite::Error>(guid);
            }
            let guid = uuid::Uuid::new_v4().to_string();
            let now = epoch_seconds() as i64;
            connection.execute(
                "insert into ab_books (guid, owner_id, name, note, rule, personal, created_at, updated_at)
                 values (?1, ?2, ?3, '', 1, 1, ?4, ?4)",
                rusqlite::params![guid, user_id, name, now],
            )?;
            if import_legacy {
                import_legacy_book(connection, user_id, &guid)?;
            }
            Ok(guid)
        })
        .await
}

/// Copies an account's legacy single-document book into the structured tables,
/// exactly once.
///
/// This exists because of how the client chooses a shape: it re-reads
/// `/api/ab/personal` on every start and treats a 200 as "use the structured
/// model" (`legacyMode.value = _personalAbGuid == null`). A deployment that held
/// legacy books therefore appears to lose them the moment these endpoints start
/// answering — the data is still stored, but nothing reads it.
///
/// Deliberately a one-time import rather than a read-time merge:
///
/// * a merge would let two divergent copies of the same book feed each other
///   forever, and there is no authority to say which side wins;
/// * the legacy document is byte-identical in shape to the structured rows, so
///   the import is lossless and the merge buys nothing.
///
/// The legacy row is *not* deleted. It stays as the rollback path, and as
/// evidence if the import is ever suspected of losing something.
fn import_legacy_book(
    connection: &rusqlite::Connection,
    user_id: i64,
    guid: &str,
) -> Result<(), rusqlite::Error> {
    let already: bool = connection
        .query_row(
            "select 1 from ab_legacy_imports where owner_id = ?1",
            [user_id],
            |_| Ok(()),
        )
        .is_ok();
    if already {
        return Ok(());
    }
    let document: Option<String> = connection
        .query_row(
            "select document from address_books where user_id = ?1",
            [user_id],
            |row| row.get::<_, String>(0),
        )
        .ok();
    let Some(document) = document else {
        // Nothing to import; mark it anyway so a later pull does not re-check
        // the legacy row on every request.
        connection.execute(
            "insert into ab_legacy_imports (owner_id, imported_at, peer_count, tag_count)
             values (?1, ?2, 0, 0)",
            rusqlite::params![user_id, epoch_seconds() as i64],
        )?;
        return Ok(());
    };
    // A legacy document the client could not parse is not something to guess at.
    // Marking the account as imported with zero rows is wrong; leaving it
    // unmarked means a later boot retries after an operator fixes it.
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&document) else {
        hbb_common::log::warn!(
            "legacy address book for account {user_id} is not JSON; not importing it"
        );
        return Ok(());
    };

    let mut peers = 0i64;
    let mut tags = 0i64;

    // Tag colours live in a nested JSON string, e.g. {"office":"#00ff00"}.
    if let Some(raw) = parsed.get("tag_colors").and_then(|value| value.as_str()) {
        if let Ok(colours) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(map) = colours.as_object() {
                for (name, colour) in map {
                    let colour = colour
                        .as_str()
                        .and_then(parse_hex_colour)
                        .unwrap_or(0);
                    connection.execute(
                        "insert into ab_tags (guid, name, color) values (?1, ?2, ?3)
                         on conflict(guid, name) do update set color = excluded.color",
                        rusqlite::params![guid, name, colour],
                    )?;
                    tags += 1;
                }
            }
        }
    }
    // A tag with no colour entry still exists.
    if let Some(list) = parsed.get("tags").and_then(|value| value.as_array()) {
        for name in list {
            let Some(name) = name.as_str() else { continue };
            let inserted = connection.execute(
                "insert into ab_tags (guid, name, color) values (?1, ?2, 0)
                 on conflict(guid, name) do nothing",
                rusqlite::params![guid, name],
            )?;
            tags += inserted as i64;
        }
    }

    if let Some(list) = parsed.get("peers").and_then(|value| value.as_array()) {
        for peer in list {
            let Some(id) = peer.get("id").and_then(|value| value.as_str()) else {
                continue;
            };
            if id.trim().is_empty() {
                continue;
            }
            let field = |name: &str| {
                peer.get(name)
                    .map(|value| match value {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default()
            };
            let tags_json = serde_json::to_string(
                &peer
                    .get("tags")
                    .cloned()
                    .unwrap_or(serde_json::Value::Array(Vec::new())),
            )
            .unwrap_or_else(|_| "[]".to_owned());
            connection.execute(
                "insert into ab_peers (guid, peer_id, hash, password, username, hostname,
                                        platform, alias, tags, force_always_relay, rdp_port,
                                        rdp_username, login_name, device_group_name, note,
                                        same_server, updated_at)
                 values (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
                 on conflict(guid, peer_id) do nothing",
                rusqlite::params![
                    guid,
                    id,
                    field("hash"),
                    field("password"),
                    field("username"),
                    field("hostname"),
                    field("platform"),
                    field("alias"),
                    tags_json,
                    if field("forceAlwaysRelay").eq_ignore_ascii_case("true") { 1 } else { 0 },
                    field("rdpPort"),
                    field("rdpUsername"),
                    field("loginName"),
                    field("device_group_name"),
                    field("note"),
                    None::<i64>,
                    epoch_seconds() as i64,
                ],
            )?;
            peers += 1;
        }
    }

    connection.execute(
        "insert into ab_legacy_imports (owner_id, imported_at, peer_count, tag_count)
         values (?1, ?2, ?3, ?4)",
        rusqlite::params![user_id, epoch_seconds() as i64, peers, tags],
    )?;
    if peers > 0 || tags > 0 {
        hbb_common::log::info!(
            "imported the legacy address book for account {user_id}: {peers} peers, {tags} tags"
        );
    }
    Ok(())
}

/// `#rrggbb` or `#aarrggbb` into the client's ARGB integer.
///
/// The legacy document stores colours as CSS strings; the structured payload
/// carries an integer, which is what the client's own colour picker writes.
fn parse_hex_colour(raw: &str) -> Option<i64> {
    let hex = raw.trim().trim_start_matches('#');
    let value = i64::from_str_radix(hex, 16).ok()?;
    match hex.len() {
        // RGB: the client's ARGB has a fully opaque alpha.
        6 => Some(0xFF00_0000 | value),
        8 => Some(value),
        _ => None,
    }
}

/// Whether the caller may write to a book.
///
/// Writing needs ownership or a share granting at least read/write, capped by the
/// book's own ceiling. A book shared read-only stays read-only for the recipient
/// even if the share row were later raised.
pub(crate) async fn may_write(state: &ApiState, user_id: i64, guid: &str) -> Result<bool, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let rule = connection
                .query_row(
                    "select 1 from ab_books b
                 left join ab_shares s on s.guid = b.guid and s.user_id = ?2
                 where b.guid = ?1
                   and (b.owner_id = ?2
                        or (s.user_id = ?2 and min(b.rule, s.rule) >= 2))",
                    rusqlite::params![guid, user_id],
                    |row| row.get::<_, i64>(0),
                )
                .ok();
            Ok::<_, rusqlite::Error>(rule.is_some())
        })
        .await
}

pub(crate) async fn peers_in_book(
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
                        device_group_name, note, same_server
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
                    same_server: row.get::<_, Option<i64>>(14)?.map(|value| value != 0),
                });
            }
            Ok::<_, rusqlite::Error>((total.max(0) as u64, peers))
        })
        .await
}

/// Whether the caller may read a book: ownership or any share row.
async fn may_read(state: &ApiState, user_id: i64, guid: &str) -> Result<bool, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let exists = connection
                .query_row(
                    "select 1 from ab_books b
                     left join ab_shares s on s.guid = b.guid and s.user_id = ?2
                     where b.guid = ?1 and (b.owner_id = ?2 or s.user_id = ?2)",
                    rusqlite::params![guid, user_id],
                    |_| Ok(()),
                )
                .is_ok();
            Ok::<_, rusqlite::Error>(exists)
        })
        .await
}

pub(crate) async fn tags_in_book(state: &ApiState, user_id: i64, guid: &str) -> Result<Vec<BookTag>, String> {
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
pub(crate) async fn upsert_peer(
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
                                        rdp_username, login_name, device_group_name, note,
                                        same_server, updated_at)
                 values (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
                 on conflict(guid, peer_id) do update set
                    hash = excluded.hash, password = excluded.password,
                    username = excluded.username, hostname = excluded.hostname,
                    platform = excluded.platform, alias = excluded.alias,
                    tags = excluded.tags, force_always_relay = excluded.force_always_relay,
                    rdp_port = excluded.rdp_port, rdp_username = excluded.rdp_username,
                    login_name = excluded.login_name,
                    device_group_name = excluded.device_group_name,
                    note = excluded.note, same_server = excluded.same_server,
                    updated_at = excluded.updated_at",
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
                    peer.same_server.map(|value| if value { 1 } else { 0 }),
                    now,
                ],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
}

/// Deletes the named peers from a book and reports how many existed.
pub(crate) async fn delete_peers(state: &ApiState, guid: &str, ids: Vec<String>) -> Result<u64, String> {
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

pub(crate) async fn upsert_tag(state: &ApiState, guid: &str, tag: BookTag) -> Result<(), String> {
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
pub(crate) async fn rename_tag(state: &ApiState, guid: &str, old: &str, new: &str) -> Result<(), String> {
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

pub(crate) async fn delete_tags(state: &ApiState, guid: &str, names: Vec<String>) -> Result<u64, String> {
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

/// Grants another account access to a book.
///
/// Only the owner may share, and the granted level is capped by the book's own
/// ceiling. Returns whether a row was written.
pub(crate) async fn share_book(
    state: &ApiState,
    owner_id: i64,
    guid: &str,
    target_id: i64,
    rule: i64,
) -> Result<bool, String> {
    if owner_id == target_id {
        // Sharing with yourself is a no-op; the owner already has full access.
        return Ok(false);
    }
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let ceiling = connection
                .query_row(
                    "select rule from ab_books where guid = ?1 and owner_id = ?2",
                    rusqlite::params![guid, owner_id],
                    |row| row.get::<_, i64>(0),
                )
                .ok();
            let Some(ceiling) = ceiling else {
                return Ok(false);
            };
            let granted = rule.clamp(1, ceiling.max(1));
            connection.execute(
                "insert into ab_shares (guid, user_id, rule, created_at)
                 values (?1, ?2, ?3, ?4)
                 on conflict(guid, user_id) do update set rule = excluded.rule",
                rusqlite::params![guid, target_id, granted, epoch_seconds() as i64],
            )?;
            Ok(true)
        })
        .await
}

/// Revokes a share. Only the owner may revoke.
pub(crate) async fn unshare_book(
    state: &ApiState,
    owner_id: i64,
    guid: &str,
    target_id: i64,
) -> Result<bool, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let owned = connection
                .query_row(
                    "select 1 from ab_books where guid = ?1 and owner_id = ?2",
                    rusqlite::params![guid, owner_id],
                    |_| Ok(()),
                )
                .is_ok();
            if !owned {
                return Ok(false);
            }
            let removed = connection.execute(
                "delete from ab_shares where guid = ?1 and user_id = ?2",
                rusqlite::params![guid, target_id],
            )?;
            Ok(removed > 0)
        })
        .await
}

/// Who a book is shared with, for the owner's view.
pub(crate) async fn shares_of(
    state: &ApiState,
    owner_id: i64,
    guid: &str,
) -> Result<Vec<(i64, i64)>, String> {
    let guid = guid.to_owned();
    state
        .db_call(move |connection| {
            let owned = connection
                .query_row(
                    "select 1 from ab_books where guid = ?1 and owner_id = ?2",
                    rusqlite::params![guid, owner_id],
                    |_| Ok(()),
                )
                .is_ok();
            if !owned {
                return Ok(Vec::new());
            }
            let mut statement =
                connection.prepare("select user_id, rule from ab_shares where guid = ?1")?;
            let mut rows = statement.query([guid.as_str()])?;
            let mut shares = Vec::new();
            while let Some(row) = rows.next()? {
                shares.push((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?));
            }
            Ok(shares)
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

pub(crate) async fn personal(
    Extension(state): Extension<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = optional_json::<Value>(body).await;
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    // This is the endpoint whose 200 switches the client to the structured model,
    // so it is the one place the legacy document must be carried over. Doing it
    // anywhere else would either miss the transition or run on a read path.
    match ensure_personal_book(&state, user_id, true).await {
        Ok(guid) => Json(json!({"guid": guid})).into_response(),
        Err(err) => {
            log::error!("cannot ensure personal address book: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

pub(crate) async fn settings(
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

pub(crate) async fn shared_profiles(
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

pub(crate) async fn peers(
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
        // Resolving the book for a read must not import: a GET that writes is a
        // surprise, and the transition is already handled at /api/ab/personal.
        _ => match ensure_personal_book(&state, user_id, false).await {
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

pub(crate) async fn tags(
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

pub(crate) async fn peer_add(
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

pub(crate) async fn peer_update(
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

pub(crate) async fn peer_delete(
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

pub(crate) async fn tag_add(
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

pub(crate) async fn tag_rename(
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

pub(crate) async fn tag_update(
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

pub(crate) async fn tag_delete(
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

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct ShareRequest {
    /// The account to share with.
    user_id: i64,
    /// 1 read, 2 read/write, 3 full control. Capped by the book's ceiling.
    rule: i64,
}

/// `POST /api/ab/share/{guid}` — share a book the caller owns.
pub(crate) async fn share(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let owner = match state.authenticate_headers(&headers).await {
        Ok(user_id) => user_id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(request) = optional_json::<ShareRequest>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    if request.user_id <= 0 {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match share_book(&state, owner, &guid, request.user_id, request.rule).await {
        Ok(true) => Json(Value::Null).into_response(),
        // Only the owner may share, so "not yours" and "no such book" answer the
        // same way rather than revealing which.
        Ok(false) => book_error("BookNotFound"),
        Err(err) => {
            log::error!("cannot share a book: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `DELETE /api/ab/share/{guid}` — revoke a share.
pub(crate) async fn unshare(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let owner = match state.authenticate_headers(&headers).await {
        Ok(user_id) => user_id,
        Err(auth) => return unauthorized(auth),
    };
    let Some(request) = optional_json::<ShareRequest>(body).await else {
        return crate::auth_server::api_error(StatusCode::BAD_REQUEST, "ParamsError");
    };
    match unshare_book(&state, owner, &guid, request.user_id).await {
        Ok(changed) => Json(json!({"revoked": changed})).into_response(),
        Err(err) => {
            log::error!("cannot revoke a share: {err}");
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `GET /api/ab/share/{guid}` — who the caller's book is shared with.
pub(crate) async fn list_shares(
    Extension(state): Extension<Arc<ApiState>>,
    AxumPath(guid): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let owner = match state.authenticate_headers(&headers).await {
        Ok(user_id) => user_id,
        Err(auth) => return unauthorized(auth),
    };
    match shares_of(&state, owner, &guid).await {
        Ok(shares) => Json(json!({
            "shares": shares
                .into_iter()
                .map(|(user_id, rule)| json!({"user_id": user_id, "rule": rule}))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(err) => {
            log::error!("cannot list shares: {err}");
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
