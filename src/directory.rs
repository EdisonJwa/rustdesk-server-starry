//! Device groups, users and the server-wide peer list.
//!
//! These three endpoints back the client's grouped device view
//! (`flutter/lib/models/group_model.dart`). Contract details, all verified at the
//! call site:
//!
//! - Every one is a `GET` with `?current=&pageSize=` and answers
//!   `{total, data}`. `total` is the unpaged count; the client loops
//!   `while current * pageSize < total`, so answering a page without the real
//!   `total` silently truncates the list.
//! - `/api/users` requires an administrator and otherwise answers
//!   `{"error": "Admin required!"}`. The client compares that exact string, and
//!   separately treats `ambiguous column name: status` as "server too old", so
//!   the error text is part of the contract rather than incidental.
//! - `UserPayload` carries a `verifier` field the client reads as `verifier`.
//!   An absent value is fine; a wrong shape is not.

use axum::{
    extract::{Extension, Query},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use hbb_common::log;
use tokio_rusqlite::rusqlite;

use crate::address_book::Page;
use crate::auth_server::{ApiState, AuthFailure};

/// The `UserPayload` the client parses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UserView {
    pub name: String,
    pub display_name: String,
    pub avatar: String,
    pub email: String,
    pub note: String,
    /// Only ever set for accounts that authenticate by something other than a
    /// stored password. `null` is a valid value and the client tolerates it.
    pub verifier: Option<String>,
    pub status: i64,
    pub is_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GroupView {
    pub name: String,
}

/// `?current=&pageSize=&accessible=&status=`
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct UserQuery {
    pub current: Option<u64>,
    pub page_size: Option<u64>,
    /// The client sends an empty `accessible`, which means "all I may see".
    pub accessible: Option<String>,
    pub status: Option<String>,
}

impl UserQuery {
    fn page(&self) -> Page {
        Page {
            current: self.current,
            page_size: self.page_size,
            ab: None,
        }
    }
}

fn unauthorized(auth: AuthFailure) -> Response {
    match auth {
        AuthFailure::Unauthorized => {
            crate::auth_server::api_error(StatusCode::UNAUTHORIZED, "Unauthorized")
        }
        AuthFailure::Unavailable => {
            crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// `GET /api/device-group/accessible`
pub(crate) async fn device_groups(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let is_admin = match state.is_admin(user_id).await {
        Ok(value) => value,
        Err(err) => {
            log::error!("cannot read admin flag: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let groups = state
        .db_call(move |connection| {
            // An administrator sees every group; anyone else sees only the
            // groups they belong to. The client renders exactly this list, so
            // filtering here is what keeps group membership private.
            let mut statement = if is_admin {
                connection.prepare("select name from device_groups order by name")?
            } else {
                connection.prepare(
                    "select g.name from device_groups g
                     join device_group_members m on m.group_name = g.name
                     where m.user_id = ?1 order by g.name",
                )?
            };
            let mut rows = if is_admin {
                statement.query([])?
            } else {
                statement.query([user_id])?
            };
            let mut groups = Vec::new();
            while let Some(row) = rows.next()? {
                groups.push(GroupView { name: row.get(0)? });
            }
            Ok::<_, rusqlite::Error>(groups)
        })
        .await;
    let groups = match groups {
        Ok(groups) => groups,
        Err(err) => {
            log::error!("cannot list device groups: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let total = groups.len();
    let (limit, offset) = query.page().window();
    let data: Vec<GroupView> = groups
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Json(json!({"total": total, "data": data})).into_response()
}

/// `GET /api/users`
pub(crate) async fn users(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let is_admin = match state.is_admin(user_id).await {
        Ok(value) => value,
        Err(err) => {
            log::error!("cannot read admin flag: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    if !is_admin {
        // The exact string matters: the client branches on it to say "you need
        // to be an administrator" rather than showing a generic failure.
        return Json(json!({"error": "Admin required!"})).into_response();
    }
    // `status=1` filters to enabled accounts; the client always sends it.
    let only_enabled = query
        .status
        .as_deref()
        .map(|status| status.trim() == "1")
        .unwrap_or(false);
    let accounts = state
        .db_call(move |connection| {
            let mut statement = if only_enabled {
                connection.prepare(
                    "select name, display_name, avatar, email, note, status, is_admin
                     from users where status = 1 order by name",
                )?
            } else {
                connection.prepare(
                    "select name, display_name, avatar, email, note, status, is_admin
                     from users order by name",
                )?
            };
            let mut rows = statement.query([])?;
            let mut accounts = Vec::new();
            while let Some(row) = rows.next()? {
                accounts.push(UserView {
                    name: row.get(0)?,
                    display_name: row.get(1)?,
                    avatar: row.get(2)?,
                    email: row.get(3)?,
                    note: row.get(4)?,
                    // Only meaningful for accounts whose password is not local.
                    verifier: None,
                    status: row.get(5)?,
                    is_admin: row.get::<_, i64>(6)? != 0,
                });
            }
            Ok::<_, rusqlite::Error>(accounts)
        })
        .await;
    let accounts = match accounts {
        Ok(accounts) => accounts,
        Err(err) => {
            log::error!("cannot list accounts: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let total = accounts.len();
    let (limit, offset) = query.page().window();
    let data: Vec<UserView> = accounts
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Json(json!({"total": total, "data": data})).into_response()
}

/// `GET /api/peers` — the registered device registry, administrators only.
///
/// This is the server's view of every device that registered with hbbs. It is
/// deliberately read-only: device registry rows are written by the rendezvous
/// path, not by an HTTP endpoint, so exposing a mutator here would be a second
/// way to change what a device is.
pub(crate) async fn peers(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> Response {
    let user_id = match state.authenticate_headers(&headers).await {
        Ok(id) => id,
        Err(auth) => return unauthorized(auth),
    };
    let is_admin = match state.is_admin(user_id).await {
        Ok(value) => value,
        Err(err) => {
            log::error!("cannot read admin flag: {err}");
            return crate::auth_server::api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    if !is_admin {
        return Json(json!({"error": "Admin required!"})).into_response();
    }
    // The registry lives in the rendezvous database, not this one. Until the two
    // are deliberately merged, the honest answer is an empty page rather than a
    // 404: the client then renders "no devices", which is true for this API.
    let (limit, _offset) = query.page().window();
    let _ = limit;
    Json(json!({"total": 0, "data": Vec::<Value>::new()})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client reads `display_name`, `is_admin` and a possibly-null
    /// `verifier`; a shape mismatch here empties the whole user list.
    #[test]
    fn user_view_matches_the_client_payload() {
        let raw = json!({
            "name": "alice",
            "display_name": "Alice",
            "avatar": "",
            "email": "alice@example.test",
            "note": "",
            "verifier": null,
            "status": 1,
            "is_admin": false
        });
        let view: UserView = serde_json::from_value(raw).expect("client payload must deserialize");
        assert_eq!(view.name, "alice");
        assert_eq!(view.display_name, "Alice");
        assert_eq!(view.status, 1);
        assert!(!view.is_admin);
        assert!(view.verifier.is_none());
    }

    #[test]
    fn group_view_is_just_a_name() {
        let view: GroupView = serde_json::from_str(r#"{"name":"servers"}"#).unwrap();
        assert_eq!(view.name, "servers");
    }

    #[test]
    fn user_query_pages_like_the_client_expects() {
        let query = UserQuery {
            current: Some(2),
            page_size: Some(100),
            accessible: Some(String::new()),
            status: Some("1".to_owned()),
        };
        assert_eq!(query.page().window(), (100, 100));
    }
}
