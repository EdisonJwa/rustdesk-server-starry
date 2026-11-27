//! Starry API v1: local accounts, RustDesk-compatible login, and
//! connection-token issuance.
//!
//! The wire contract is not invented here; it mirrors what the official
//! clients actually do (verified against rustdesk 1.5.x):
//!
//! - `GET /api/login-options` returns a JSON **array of strings** of third
//!   party providers. An empty array means "password login only".
//! - `POST /api/login` answers `{access_token, type: "access_token", user}`
//!   where `user` is the flat `UserPayload` object (not `user_info`).
//! - The returned `access_token` is stored by the client and later sent
//!   verbatim as `PunchHoleRequest.token` / `RequestRelay.token`. It therefore
//!   **is** the connection credential and must be the EdDSA JWT that hbbs
//!   verifies against `connection_auth.jwks.file`.
//! - `POST /api/currentUser` (capital U) echoes the flat `UserPayload` for the
//!   bearer token, and 401 makes the client drop its stored session.
//! - `POST /api/logout` revokes the session.
//!
//! The JWKS file this module publishes carries a digest-bound freshness stamp
//! (`<name>.metadata.json`) and is re-stamped on a heartbeat: hbbs treats a
//! keyset that has not been re-attested as stale and fails closed, so the
//! issuer must keep asserting that the keyset is current.

use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, RawBody},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use hbb_common::log;
use hyper::body::HttpBody as _;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_rusqlite::{rusqlite, Connection};

/// Request bodies carry credentials and device fingerprints, nothing large.
const MAX_API_BODY: usize = 16 * 1024;
/// An address book is pushed as one JSON string, so it needs its own bound: 16 KiB
/// is far too small for a few hundred peers. Bounded so a single push cannot
/// exhaust memory or the database.
const MAX_ADDRESS_BOOK_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOGIN_FAILURES: u32 = 10;
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(300);
const MAX_TRACKED_ADDRESSES: usize = 4_096;
const SESSION_PRUNE_GRACE_SECONDS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub db_path: PathBuf,
    pub key_path: PathBuf,
    pub jwks_path: PathBuf,
    pub issuer: String,
    pub audience: String,
    pub base_scope: String,
    pub token_ttl_seconds: u64,
    pub connection_token_ttl_seconds: u64,
    pub jwks_heartbeat_seconds: u64,
    pub bcrypt_cost: u32,
    pub admin_password: Option<String>,
    /// Read `X-Forwarded-For` when the API runs behind a TLS terminator.
    pub trust_proxy: bool,
}

impl ApiConfig {
    pub fn from_env() -> Result<Self, String> {
        let listen = env_or("STARRY_API_LISTEN", "0.0.0.0:21114")
            .parse::<SocketAddr>()
            .map_err(|err| format!("STARRY_API_LISTEN is not a socket address: {err}"))?;
        let db_path = absolute_path(env_or("STARRY_API_DB", "users.db"))?;
        let key_path = absolute_path(env_or("STARRY_API_KEY_FILE", "api-signing-key"))?;
        let jwks_path = absolute_path(env_or("STARRY_API_JWKS_FILE", "auth/jwks.json"))?;
        let issuer = env_or("STARRY_API_ISSUER", "https://api.starry.local");
        validate_issuer(&issuer)?;
        let config = Self {
            listen,
            db_path,
            key_path,
            jwks_path,
            issuer,
            audience: env_or("STARRY_API_AUDIENCE", "rustdesk-connect"),
            base_scope: env_or("STARRY_API_SCOPE", "connect:initiate"),
            token_ttl_seconds: env_u64("STARRY_API_TOKEN_TTL_SECONDS", 604_800)?,
            connection_token_ttl_seconds: env_u64("STARRY_API_CONNECTION_TOKEN_TTL_SECONDS", 3_600)?,
            jwks_heartbeat_seconds: env_u64("STARRY_API_JWKS_HEARTBEAT_SECONDS", 300)?,
            bcrypt_cost: env_u64("STARRY_API_BCRYPT_COST", 12)? as u32,
            admin_password: std::env::var("ADMIN_PASSWORD").ok().filter(|p| !p.is_empty()),
            trust_proxy: env_or("STARRY_API_TRUST_PROXY", "0") == "1",
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.audience.trim().is_empty() {
            return Err("STARRY_API_AUDIENCE must not be empty".to_owned());
        }
        if self.base_scope.trim().is_empty() {
            return Err("STARRY_API_SCOPE must not be empty".to_owned());
        }
        if !(60..=31_536_000).contains(&self.token_ttl_seconds) {
            return Err("STARRY_API_TOKEN_TTL_SECONDS must be between 60 and 31536000".to_owned());
        }
        if !(60..=86_400).contains(&self.connection_token_ttl_seconds) {
            return Err(
                "STARRY_API_CONNECTION_TOKEN_TTL_SECONDS must be between 60 and 86400".to_owned(),
            );
        }
        // hbbs fails closed once its cache stamp is older than
        // `max_stale_seconds` (default 3600), so the heartbeat must stay well
        // inside that window or a healthy server would start denying clients.
        if !(30..=1_800).contains(&self.jwks_heartbeat_seconds) {
            return Err("STARRY_API_JWKS_HEARTBEAT_SECONDS must be between 30 and 1800".to_owned());
        }
        if !(4..=15).contains(&self.bcrypt_cost) {
            return Err("STARRY_API_BCRYPT_COST must be between 4 and 15".to_owned());
        }
        if let Some(password) = self.admin_password.as_deref() {
            if password.len() < 8 {
                return Err("ADMIN_PASSWORD must be at least 8 characters".to_owned());
            }
        }
        Ok(())
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn env_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u64>()
            .map_err(|err| format!("{name} is not an integer: {err}")),
        _ => Ok(default),
    }
}

fn absolute_path(value: String) -> Result<PathBuf, String> {
    std::path::absolute(&value).map_err(|err| format!("path {value} cannot be resolved: {err}"))
}

/// hbbs refuses any issuer that is not a plain HTTPS URL, and the token `iss`
/// must match its configured value exactly, so catch the mistake here.
fn validate_issuer(issuer: &str) -> Result<(), String> {
    let parsed = url::Url::parse(issuer).map_err(|err| format!("STARRY_API_ISSUER is invalid: {err}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "STARRY_API_ISSUER must be an HTTPS URL without credentials or fragment".to_owned(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signing key and JWKS publication
// ---------------------------------------------------------------------------

struct SigningKey {
    kid: String,
    secret: sign::SecretKey,
    public: Vec<u8>,
}

impl SigningKey {
    fn load_or_create(path: &Path) -> Result<Self, String> {
        let secret = match std::fs::read_to_string(path) {
            Ok(contents) => {
                let raw = decode_config(contents.trim(), base64::STANDARD)
                    .map_err(|_| format!("signing key {} is not valid base64", path.display()))?;
                sign::SecretKey::from_slice(&raw)
                    .ok_or_else(|| format!("signing key {} is not a 64-byte Ed25519 key", path.display()))?
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let (public, secret) = sign::gen_keypair();
                let encoded = base64::encode(&secret.0);
                create_private_key(path, encoded.as_bytes())?;
                log::info!(
                    "Generated API signing key at {} (kid {})",
                    path.display(),
                    kid_for(&public.0)
                );
                secret
            }
            Err(err) => {
                return Err(format!("cannot read signing key {}: {err}", path.display()));
            }
        };
        let public = secret.public_key();
        Ok(Self {
            kid: kid_for(&public.0),
            secret,
            public: public.0.to_vec(),
        })
    }

    fn jwks_document(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": self.kid,
                "key_ops": ["verify"],
                "x": encode_config(&self.public, URL_SAFE_NO_PAD),
            }]
        }))
        .unwrap_or_default()
    }

    fn decoding_key(&self) -> DecodingKey {
        // hbbs builds its verifier the same way from the JWK `x` value.
        DecodingKey::from_ed_der(&self.public)
    }
}

/// A kid derived from the public key keeps one identity across restarts while
/// still changing if the operator rotates the key file.
fn kid_for(public: &[u8]) -> String {
    let digest = Sha256::digest(public);
    let hex: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    format!("starry-api-{hex}")
}

fn create_private_key(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("cannot create signing key {}: {err}", path.display()))?;
    use std::io::Write as _;
    file.write_all(contents)
        .map_err(|err| format!("cannot write signing key {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("cannot sync signing key {}: {err}", path.display()))?;
    Ok(())
}

/// Publishes the keyset together with the digest-bound freshness stamp hbbs
/// reads. The two files are written atomically so a crash can never pair a new
/// keyset with an old stamp (hbbs rejects a digest mismatch, and must).
fn publish_jwks(path: &Path, document: &[u8], attested_at: u64) -> Result<(), String> {
    let metadata = serde_json::to_vec(&json!({
        "version": 1,
        "fetched_at_epoch_seconds": attested_at,
        "jwks_sha256": hex_sha256(document),
    }))
    .map_err(|err| format!("cannot serialize JWKS metadata: {err}"))?;
    write_atomic(path, document)?;
    write_atomic(&metadata_path(path)?, &metadata)
}

fn metadata_path(path: &Path) -> Result<PathBuf, String> {
    let mut name = path
        .file_name()
        .ok_or_else(|| "JWKS path has no file name".to_owned())?
        .to_os_string();
    name.push(".metadata.json");
    Ok(path.with_file_name(name))
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "path has no valid file name".to_owned())?;
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let result = (|| {
        use std::io::Write as _;
        let mut file = options
            .open(&temporary)
            .map_err(|err| format!("cannot create {}: {err}", temporary.display()))?;
        file.write_all(contents)
            .map_err(|err| format!("cannot write {}: {err}", temporary.display()))?;
        file.sync_all()
            .map_err(|err| format!("cannot sync {}: {err}", temporary.display()))?;
        drop(file);
        std::fs::rename(&temporary, path)
            .map_err(|err| format!("cannot publish {}: {err}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn hex_sha256(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
create table if not exists users (
    id integer primary key autoincrement,
    name text not null unique,
    password_hash text not null,
    display_name text not null default '',
    avatar text not null default '',
    email text not null default '',
    note text not null default '',
    status integer not null default 1,
    is_admin integer not null default 0,
    auth_version integer not null default 1,
    extra_scopes text not null default '',
    created_at integer not null,
    updated_at integer not null
);
create table if not exists sessions (
    jti text primary key,
    user_id integer not null,
    auth_version integer not null,
    issued_at integer not null,
    expires_at integer not null,
    revoked_at integer,
    client_ip text not null default '',
    device_id text not null default '',
    device_uuid text not null default ''
);
create index if not exists sessions_user on sessions (user_id);
create index if not exists sessions_expiry on sessions (expires_at);
-- Address book, one opaque document per user.
--
-- The client owns the shape: it sends {tags, peers, tag_colors} as a JSON string
-- and parses it back verbatim, so this table stores the payload without
-- interpreting it. Keeping the server out of that schema is deliberate — a
-- client update must not require a server migration.
create table if not exists address_books (
    user_id integer primary key,
    document text not null,
    updated_at integer not null
);
-- External identity bindings for OIDC login.
--
-- One row per (provider, subject). The subject is the identity provider's
-- stable identifier for the human; `email` is advisory and may change, so it is
-- stored for display rather than used as the key.
--
-- Deliberately separate from `users`: an account can start with a password and
-- later gain an SSO binding, and a deployment can run OIDC with no local
-- password at all. Keeping the binding in its own table means neither shape is
-- privileged.
create table if not exists oidc_links (
    provider text not null,
    subject text not null,
    user_id integer not null,
    email text not null default '',
    created_at integer not null,
    last_login_at integer not null,
    primary key (provider, subject)
);
create index if not exists oidc_links_user on oidc_links (user_id);
-- ---------------------------------------------------------------------------
-- Non-legacy address books.
--
-- The legacy shape is one opaque document per account (`address_books`). The
-- structured shape the client also understands is several named books per
-- account plus per-peer rows, which is what makes sharing and pagination
-- possible. Both are kept: the client picks based on whether
-- `POST /api/ab/personal` answers 200 or 404, and a deployment may legitimately
-- serve legacy only.
create table if not exists ab_books (
    guid text primary key,
    owner_id integer not null,
    name text not null,
    note text not null default '',
    -- ShareRule: 1 read, 2 read/write, 3 full control.
    rule integer not null default 3,
    personal integer not null default 1,
    created_at integer not null,
    updated_at integer not null
);
create index if not exists ab_books_owner on ab_books (owner_id);
create table if not exists ab_peers (
    guid text not null,
    peer_id text not null,
    hash text not null default '',
    password text not null default '',
    username text not null default '',
    hostname text not null default '',
    platform text not null default '',
    alias text not null default '',
    -- JSON array of tag names. A peer's tags are a set owned by the peer row,
    -- so no join table is needed for the client's shape.
    tags text not null default '[]',
    force_always_relay integer not null default 0,
    rdp_port text not null default '',
    rdp_username text not null default '',
    login_name text not null default '',
    device_group_name text not null default '',
    note text not null default '',
    updated_at integer not null,
    primary key (guid, peer_id)
);
create index if not exists ab_peers_guid on ab_peers (guid);
create table if not exists ab_tags (
    guid text not null,
    name text not null,
    -- Client-side ARGB integer, stored as given. The server never interprets it.
    color integer not null default 0,
    primary key (guid, name)
);
-- ---------------------------------------------------------------------------
-- Device groups.
create table if not exists device_groups (
    name text primary key,
    created_at integer not null
);
create table if not exists device_group_members (
    group_name text not null,
    user_id integer not null,
    primary key (group_name, user_id)
);
-- ---------------------------------------------------------------------------
-- TOTP second factor.
create table if not exists user_totp (
    user_id integer primary key,
    -- Base32 secret, sealed with the API signing key's filesystem protection.
    -- The claim is only usable while the row exists.
    secret text not null,
    confirmed_at integer,
    last_used_step integer not null default 0,
    created_at integer not null
);
-- ---------------------------------------------------------------------------
-- Device enrolment tokens (`/api/devices/deploy`).
create table if not exists deploy_tokens (
    token_hash text primary key,
    created_by integer not null,
    created_at integer not null,
    expires_at integer not null,
    used_at integer,
    used_peer text not null default ''
);
-- ---------------------------------------------------------------------------
-- Heartbeats: device presence, and the strategy the server hands back.
create table if not exists device_presence (
    peer_id text primary key,
    uuid text not null default '',
    version text not null default '',
    connections text not null default '[]',
    user_id integer,
    first_seen integer not null,
    last_seen integer not null
);
create table if not exists client_strategies (
    -- One row per user is enough: the client sends `modified_at` so an
    -- unchanged document is not re-delivered.
    user_id integer primary key,
    document text not null,
    modified_at integer not null
);
-- Pending `disconnect` instructions, drained by the next heartbeat.
create table if not exists disconnect_requests (
    peer_id text primary key,
    created_at integer not null
);
";

#[derive(Clone, Debug)]
struct User {
    id: i64,
    name: String,
    password_hash: String,
    display_name: String,
    avatar: String,
    email: String,
    note: String,
    status: i64,
    is_admin: bool,
    auth_version: i64,
    extra_scopes: String,
}

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        name: row.get(1)?,
        password_hash: row.get(2)?,
        display_name: row.get(3)?,
        avatar: row.get(4)?,
        email: row.get(5)?,
        note: row.get(6)?,
        status: row.get(7)?,
        is_admin: row.get::<_, i64>(8)? != 0,
        auth_version: row.get(9)?,
        extra_scopes: row.get(10)?,
    })
}

const USER_COLUMNS: &str =
    "id, name, password_hash, display_name, avatar, email, note, status, is_admin, auth_version, extra_scopes";

/// Opens the database and applies the schema. Synchronous on purpose: the CLI
/// subcommands use it directly, and `run` hands the same file to the async
/// connection afterwards.
pub fn open_database(path: &Path) -> Result<rusqlite::Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    let connection = rusqlite::Connection::open(path)
        .map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    connection
        .execute_batch(SCHEMA)
        .map_err(|err| format!("cannot initialize {}: {err}", path.display()))?;
    Ok(connection)
}

fn lookup_user_sync(connection: &rusqlite::Connection, name: &str) -> Result<Option<User>, String> {
    let mut statement = connection
        .prepare(&format!("select {USER_COLUMNS} from users where name = ?1"))
        .map_err(|err| err.to_string())?;
    let mut rows = statement.query([name]).map_err(|err| err.to_string())?;
    match rows.next().map_err(|err| err.to_string())? {
        Some(row) => Ok(Some(user_from_row(row).map_err(|err| err.to_string())?)),
        None => Ok(None),
    }
}

pub fn hash_password(password: &str, cost: u32) -> Result<String, String> {
    bcrypt::hash(password, cost).map_err(|err| format!("cannot hash password: {err}"))
}

/// Creates a user. `password` is plaintext at this boundary only; the database
/// stores the bcrypt hash.
pub fn create_user(
    connection: &rusqlite::Connection,
    name: &str,
    password: &str,
    display_name: Option<&str>,
    is_admin: bool,
    extra_scopes: Option<&str>,
    cost: u32,
) -> Result<i64, String> {
    validate_user_fields(name, password)?;
    let now = epoch_seconds() as i64;
    let hash = hash_password(password, cost)?;
    connection
        .execute(
            "insert into users (name, password_hash, display_name, status, is_admin, auth_version, extra_scopes, created_at, updated_at)
             values (?1, ?2, ?3, 1, ?4, 1, ?5, ?6, ?6)",
            rusqlite::params![
                name.trim(),
                hash,
                display_name.unwrap_or(""),
                if is_admin { 1 } else { 0 },
                extra_scopes.unwrap_or(""),
                now
            ],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE") {
                format!("user {} already exists", name.trim())
            } else {
                format!("cannot create user: {err}")
            }
        })?;
    Ok(connection.last_insert_rowid())
}

/// Sets a new password and bumps `auth_version`, which invalidates every token
/// and session issued for the old credential.
pub fn set_password(
    connection: &rusqlite::Connection,
    name: &str,
    password: &str,
    cost: u32,
) -> Result<(), String> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters".to_owned());
    }
    let hash = hash_password(password, cost)?;
    let changed = connection
        .execute(
            "update users set password_hash = ?2, auth_version = auth_version + 1, updated_at = ?3 where name = ?1",
            rusqlite::params![name.trim(), hash, epoch_seconds() as i64],
        )
        .map_err(|err| format!("cannot update password: {err}"))?;
    if changed == 0 {
        return Err(format!("no such user: {}", name.trim()));
    }
    Ok(())
}

pub fn set_user_status(
    connection: &rusqlite::Connection,
    name: &str,
    enabled: bool,
) -> Result<(), String> {
    let status = if enabled { 1 } else { 0 };
    let changed = connection
        .execute(
            "update users set status = ?2, auth_version = auth_version + 1, updated_at = ?3 where name = ?1",
            rusqlite::params![name.trim(), status, epoch_seconds() as i64],
        )
        .map_err(|err| format!("cannot update user: {err}"))?;
    if changed == 0 {
        return Err(format!("no such user: {}", name.trim()));
    }
    Ok(())
}

pub fn list_users(connection: &rusqlite::Connection) -> Result<Vec<(String, bool, bool, i64)>, String> {
    let mut statement = connection
        .prepare("select name, status, is_admin, auth_version from users order by id")
        .map_err(|err| err.to_string())?;
    let mut rows = statement.query([]).map_err(|err| err.to_string())?;
    let mut users = Vec::new();
    while let Some(row) = rows.next().map_err(|err| err.to_string())? {
        users.push((
            row.get::<_, String>(0).map_err(|err| err.to_string())?,
            row.get::<_, i64>(1).map_err(|err| err.to_string())? != 0,
            row.get::<_, i64>(2).map_err(|err| err.to_string())? != 0,
            row.get::<_, i64>(3).map_err(|err| err.to_string())?,
        ));
    }
    Ok(users)
}

/// Coerces an external login name into something `validate_user_fields`
/// accepts.
///
/// IdP-supplied names are arbitrary strings: an e-mail address contains `@`, a
/// display name may contain spaces, and neither is a legal account name here.
/// Rather than reject the login, the name is reduced to a safe form and the
/// original is kept as `display_name` by the caller.
fn sanitize_account_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_whitespace() || ch.is_control() || ch == '/' || ch == '\\' {
            out.push('-');
        } else {
            out.push(ch);
        }
    }
    // Collapse runs of the replacement so "a  b" does not become "a--b".
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        return "oidc-user".to_owned();
    }
    // The column takes 64 characters, and suffixing needs headroom.
    if trimmed.chars().count() > 48 {
        return trimmed.chars().take(48).collect();
    }
    trimmed
}

fn validate_user_fields(name: &str, password: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err("user name must be 1-64 characters".to_owned());
    }
    if name
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '\\')
    {
        return Err("user name must not contain whitespace, path separators, or controls".to_owned());
    }
    if password.len() < 8 {
        return Err("password must be at least 8 characters".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    token_use: String,
    scope: Scope,
    sub: String,
    user_id: u64,
    auth_version: u64,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scope {
    Text(String),
    Values(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

impl Scope {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Text(value) => value.split_ascii_whitespace().any(|value| value == expected),
            Self::Values(values) => values.iter().any(|value| value == expected),
        }
    }
}

struct TokenRequest<'a> {
    key: &'a SigningKey,
    issuer: &'a str,
    audience: &'a str,
    user_id: i64,
    auth_version: i64,
    scope: &'a str,
    ttl_seconds: u64,
}

/// Signs a token carrying every claim hbbs validates. The signature is
/// produced with sodiumoxide and the segments are base64url-no-pad, matching
/// the construction hbbs's canonical-form check accepts.
fn mint_token(request: TokenRequest<'_>) -> Result<(String, String), String> {
    let now = epoch_seconds();
    let jti = uuid::Uuid::new_v4().to_string();
    let header = encode_config(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "kid": request.key.kid,
            "typ": "at+jwt",
        }))
        .map_err(|err| err.to_string())?,
        URL_SAFE_NO_PAD,
    );
    let payload = encode_config(
        serde_json::to_vec(&json!({
            "iss": request.issuer,
            "aud": request.audience,
            "token_use": "access",
            "scope": request.scope,
            "sub": request.user_id.to_string(),
            "user_id": request.user_id,
            "auth_version": request.auth_version,
            "jti": jti,
            "iat": now,
            "nbf": now,
            "exp": now.saturating_add(request.ttl_seconds),
        }))
        .map_err(|err| err.to_string())?,
        URL_SAFE_NO_PAD,
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign::sign_detached(signing_input.as_bytes(), &request.key.secret);
    Ok((
        format!(
            "{signing_input}.{}",
            encode_config(signature.as_ref(), URL_SAFE_NO_PAD)
        ),
        jti,
    ))
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub(crate) struct ApiState {
    db: Connection,
    key: Arc<SigningKey>,
    config: ApiConfig,
    dummy_hash: String,
    limiter: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// OIDC login state. Always present; `enabled()` is false unless the
    /// operator configured at least one provider, which keeps the endpoints
    /// answering "not configured" instead of 404 so a client's probe is
    /// unambiguous.
    ///
    /// An `Arc` because the discovery fetch and the callback both run on the
    /// blocking pool, which needs an owned handle rather than a borrow.
    oidc: Arc<crate::oidc::OidcRuntime>,
}

impl ApiState {
    async fn user_by_name(&self, name: &str) -> Result<Option<User>, String> {
        let name = name.to_owned();
        self.db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(&format!("select {USER_COLUMNS} from users where name = ?1"))?;
                let mut rows = statement.query([name.as_str()])?;
                match rows.next()? {
                    Some(row) => Ok::<_, rusqlite::Error>(Some(user_from_row(row)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|err| err.to_string())
    }

    async fn user_by_id(&self, id: i64) -> Result<Option<User>, String> {
        self.db
            .call(move |connection| {
                let mut statement = connection
                    .prepare(&format!("select {USER_COLUMNS} from users where id = ?1"))?;
                let mut rows = statement.query([id])?;
                match rows.next()? {
                    Some(row) => Ok::<_, rusqlite::Error>(Some(user_from_row(row)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|err| err.to_string())
    }

    async fn insert_session(
        &self,
        jti: String,
        user_id: i64,
        auth_version: i64,
        expires_at: u64,
        client_ip: String,
        device_id: String,
        device_uuid: String,
    ) -> Result<(), String> {
        let now = epoch_seconds() as i64;
        self.db
            .call(move |connection| {
                connection.execute(
                    "insert into sessions (jti, user_id, auth_version, issued_at, expires_at, client_ip, device_id, device_uuid)
                     values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![jti, user_id, auth_version, now, expires_at as i64, client_ip, device_id, device_uuid],
                )?;
                connection.execute(
                    "delete from sessions where user_id = ?1 and expires_at < ?2",
                    rusqlite::params![user_id, now - SESSION_PRUNE_GRACE_SECONDS as i64],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|err| err.to_string())
    }

    /// Resolves the local account bound to an external identity, creating it
    /// on first sight.
    ///
    /// Linking is keyed on `(provider, subject)` and never on the e-mail
    /// address: an IdP is free to change or recycle e-mail addresses, and
    /// treating them as identities would let a later holder of a recycled
    /// address inherit the earlier person's account.
    ///
    /// The account name comes from the claims, but a collision with an existing
    /// unrelated account is resolved by suffixing rather than by attaching the
    /// binding to that account — otherwise anyone who could set `email` at the
    /// IdP could take over a same-named local user.
    async fn link_or_create_oidc_user(
        &self,
        provider: String,
        subject: String,
        preferred_name: String,
        email: String,
        display_name: String,
        avatar: String,
        bcrypt_cost: u32,
    ) -> Result<User, String> {
        let db = &self.db;
        let provider_for_lookup = provider.clone();
        let subject_for_lookup = subject.clone();
        if let Some(user_id) = db
            .call(move |connection| {
                let mut statement = connection.prepare(
                    "select u.id from oidc_links l join users u on u.id = l.user_id
                     where l.provider = ?1 and l.subject = ?2",
                )?;
                let mut rows = statement.query([provider_for_lookup.as_str(), subject_for_lookup.as_str()])?;
                let Some(row) = rows.next()? else {
                    return Ok::<_, rusqlite::Error>(None);
                };
                let id: i64 = row.get(0)?;
                Ok(Some(id))
            })
            .await
            .map_err(|err| err.to_string())?
        {
            self.upsert_oidc_link(user_id, provider, subject, email).await?;
            return self
                .user_by_id(user_id)
                .await?
                .ok_or_else(|| "linked account disappeared".to_owned());
        }

        // First login for this identity: mint a local account with a random
        // password. OIDC users never learn it, and it cannot be used to log in
        // through /api/login because nothing sets it to a known value.
        let created = self
            .create_oidc_account(
                preferred_name,
                email.clone(),
                display_name,
                avatar,
                bcrypt_cost,
            )
            .await?;
        self.upsert_oidc_link(created, provider, subject, email).await?;
        self.user_by_id(created)
            .await?
            .ok_or_else(|| "newly created account disappeared".to_owned())
    }

    /// Creates an account for an external identity, picking a free name.
    async fn create_oidc_account(
        &self,
        preferred_name: String,
        email: String,
        display_name: String,
        avatar: String,
        bcrypt_cost: u32,
    ) -> Result<i64, String> {
        // A password nobody knows: generated here, hashed, and never returned.
        let unusable = uuid::Uuid::new_v4().to_string();
        let hash = hash_password_async(unusable, bcrypt_cost).await?;
        let preferred_name = sanitize_account_name(&preferred_name);
        let display = if display_name.trim().is_empty() {
            preferred_name.clone()
        } else {
            display_name
        };
        self.db
            .call(move |connection| {
                let now = epoch_seconds() as i64;
                // Try the preferred name, then suffixed variants. Bounded so a
                // hostile IdP cannot spin here.
                for attempt in 0..64 {
                    let name = if attempt == 0 {
                        preferred_name.clone()
                    } else {
                        format!("{preferred_name}-{attempt}")
                    };
                    let result = connection.execute(
                        "insert into users (name, password_hash, display_name, avatar, email, status, is_admin, auth_version, extra_scopes, created_at, updated_at)
                         values (?1, ?2, ?3, ?4, ?5, 1, 0, 1, '', ?6, ?6)",
                        rusqlite::params![name, hash, display, avatar, email, now],
                    );
                    match result {
                        Ok(_) => return Ok::<_, rusqlite::Error>(connection.last_insert_rowid()),
                        Err(err) if err.to_string().contains("UNIQUE") => continue,
                        Err(err) => return Err(err),
                    }
                }
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some("cannot find a free account name".to_owned()),
                ))
            })
            .await
            .map_err(|err| err.to_string())
    }

    /// Records or refreshes the binding between an external identity and an
    /// account.
    ///
    /// An upsert because the same identity logs in repeatedly: the e-mail may
    /// change and the timestamps always do, while the `(provider, subject)` key
    /// and its `user_id` must not. The caller passes the account, so a rename at
    /// the IdP cannot repoint an existing binding at a different user.
    async fn upsert_oidc_link(
        &self,
        user_id: i64,
        provider: String,
        subject: String,
        email: String,
    ) -> Result<(), String> {
        self.db
            .call(move |connection| {
                let now = epoch_seconds() as i64;
                connection.execute(
                    "insert into oidc_links (provider, subject, user_id, email, created_at, last_login_at)
                     values (?1, ?2, ?3, ?4, ?5, ?5)
                     on conflict(provider, subject) do update set
                         email = excluded.email,
                         last_login_at = excluded.last_login_at",
                    rusqlite::params![provider, subject, user_id, email, now],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|err| err.to_string())
    }

    async fn revoke_session(&self, jti: &str) -> Result<(), String> {
        let jti = jti.to_owned();
        self.db
            .call(move |connection| {
                connection.execute(
                    "update sessions set revoked_at = ?2 where jti = ?1 and revoked_at is null",
                    rusqlite::params![jti, epoch_seconds() as i64],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|err| err.to_string())
    }

    /// Reads one account's address book, or `None` when it was never pushed.
    async fn address_book_get(&self, user_id: i64) -> Result<Option<String>, String> {
        self.db
            .call(move |connection| {
                let mut statement =
                    connection.prepare("select document from address_books where user_id = ?1")?;
                let mut rows = statement.query([user_id])?;
                match rows.next()? {
                    Some(row) => Ok::<_, rusqlite::Error>(Some(row.get::<_, String>(0)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|err| err.to_string())
    }

    /// Replaces one account's address book. The client always pushes the whole
    /// document, so this is an upsert rather than a merge.
    async fn address_book_put(&self, user_id: i64, document: &str) -> Result<(), String> {
        let document = document.to_owned();
        self.db
            .call(move |connection| {
                connection.execute(
                    "insert into address_books (user_id, document, updated_at) values (?1, ?2, ?3)
                     on conflict(user_id) do update set document = excluded.document,
                                                        updated_at = excluded.updated_at",
                    rusqlite::params![user_id, document, epoch_seconds() as i64],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|err| err.to_string())
    }

    /// The single source of truth for "may this token still act": the session
    /// row must be live and the user must still be enabled at the same
    /// auth version that was minted into the token.
    async fn session_verdict(&self, jti: &str, user_id: i64, auth_version: i64) -> Result<Verdict, String> {
        let jti = jti.to_owned();
        let row = self
            .db
            .call(move |connection| {
                let mut statement = connection.prepare(
                    "select s.revoked_at, s.expires_at, s.auth_version, u.status, u.auth_version
                     from sessions s join users u on u.id = s.user_id where s.jti = ?1 and s.user_id = ?2",
                )?;
                let mut rows = statement.query(rusqlite::params![jti, user_id])?;
                match rows.next()? {
                    Some(row) => Ok::<_, rusqlite::Error>(Some((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|err| err.to_string())?;
        let Some((revoked_at, expires_at, session_auth_version, user_status, user_auth_version)) = row
        else {
            return Ok(Verdict::Inactive("revoked"));
        };
        if revoked_at.is_some() || session_auth_version != auth_version {
            return Ok(Verdict::Inactive("revoked"));
        }
        if expires_at <= epoch_seconds() as i64 {
            return Ok(Verdict::Inactive("expired"));
        }
        if user_status != 1 || user_auth_version != auth_version {
            return Ok(Verdict::Inactive("user_disabled"));
        }
        Ok(Verdict::Active)
    }

    /// Rate-limit decision is taken before the password is even looked up so a
    /// blocked address costs no bcrypt work.
    fn login_allowed(&self, ip: IpAddr) -> bool {
        let Ok(mut limiter) = self.limiter.lock() else {
            return false;
        };
        let Some((failures, started)) = limiter.get(&ip) else {
            return true;
        };
        if started.elapsed() > LOGIN_FAILURE_WINDOW {
            limiter.remove(&ip);
            return true;
        }
        *failures < MAX_LOGIN_FAILURES
    }

    fn record_login_failure(&self, ip: IpAddr) {
        let Ok(mut limiter) = self.limiter.lock() else {
            return;
        };
        if limiter.len() >= MAX_TRACKED_ADDRESSES {
            limiter.retain(|_, (_, started)| started.elapsed() <= LOGIN_FAILURE_WINDOW);
            if limiter.len() >= MAX_TRACKED_ADDRESSES {
                return;
            }
        }
        let entry = limiter.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() > LOGIN_FAILURE_WINDOW {
            *entry = (1, Instant::now());
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
    }

    fn record_login_success(&self, ip: IpAddr) {
        if let Ok(mut limiter) = self.limiter.lock() {
            limiter.remove(&ip);
        }
    }

    /// Verifies a bearer token fully: signature, claims, then the session row.
    async fn authenticate(&self, token: &str) -> Result<(Claims, User), AuthFailure> {
        let claims = self.verify_local(token)?;
        let verdict = self
            .session_verdict(&claims.jti, claims.user_id as i64, claims.auth_version as i64)
            .await
            .map_err(|_| AuthFailure::Unavailable)?;
        if let Verdict::Inactive(_) = verdict {
            return Err(AuthFailure::Unauthorized);
        }
        let user = self
            .user_by_id(claims.user_id as i64)
            .await
            .map_err(|_| AuthFailure::Unavailable)?
            .ok_or(AuthFailure::Unauthorized)?;
        Ok((claims, user))
    }

    /// Authenticates a request from its `Authorization: Bearer` header.
    ///
    /// Every endpoint that needs the caller repeats this, so it lives here
    /// rather than being open-coded per handler; a handler that forgets the
    /// bearer prefix would otherwise fail in a way that looks like a bad token.
    /// The authenticated account id, which is all the sibling modules need.
    ///
    /// Returning the id rather than `User` keeps the account struct private to
    /// this module: the address book and enforcement handlers should not be able
    /// to read a password hash just because they resolved an identity.
    pub(crate) async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<i64, AuthFailure> {
        let token = bearer(headers).ok_or(AuthFailure::Unauthorized)?;
        let (_, user) = self.authenticate(&token).await?;
        Ok(user.id)
    }

    /// The stored Base32 TOTP secret, if the account has a second factor.
    pub(crate) async fn totp_secret(&self, user_id: i64) -> Result<Option<String>, String> {
        self.db_call(move |connection| {
            let secret = connection
                .query_row(
                    "select secret from user_totp where user_id = ?1",
                    [user_id],
                    |row| row.get::<_, String>(0),
                )
                .ok();
            Ok::<_, rusqlite::Error>(secret)
        })
        .await
    }

    /// The last TOTP time step this account spent, or 0 if none.
    pub(crate) async fn totp_last_step(&self, user_id: i64) -> Result<u64, String> {
        self.db_call(move |connection| {
            let step = connection
                .query_row(
                    "select last_used_step from user_totp where user_id = ?1",
                    [user_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0);
            Ok::<_, rusqlite::Error>(step.max(0) as u64)
        })
        .await
    }

    /// Marks a time step as spent. Only moves forward.
    pub(crate) async fn totp_consume_step(&self, user_id: i64, step: u64) -> Result<(), String> {
        self.db_call(move |connection| {
            connection.execute(
                "update user_totp set last_used_step = max(last_used_step, ?2)
                 where user_id = ?1",
                rusqlite::params![user_id, step as i64],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
    }

    /// Enrols or replaces an account's TOTP secret. Not confirmed until the
    /// caller proves it can generate a code.
    pub(crate) async fn totp_set_secret(&self, user_id: i64, secret: &str) -> Result<(), String> {
        let secret = secret.to_owned();
        self.db_call(move |connection| {
            let now = epoch_seconds() as i64;
            connection.execute(
                "insert into user_totp (user_id, secret, last_used_step, created_at)
                 values (?1, ?2, 0, ?3)
                 on conflict(user_id) do update set secret = excluded.secret,
                                                 confirmed_at = null,
                                                 last_used_step = 0",
                rusqlite::params![user_id, secret, now],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
    }

    /// Whether an account is an administrator.
    pub(crate) async fn is_admin(&self, user_id: i64) -> Result<bool, String> {
        self.user_by_id(user_id)
            .await?
            .map(|user| user.is_admin)
            .ok_or_else(|| format!("account {user_id} disappeared"))
    }

    /// The account name for an id, used to fill `owner` in address book rows.
    pub(crate) async fn user_name(&self, user_id: i64) -> Result<String, String> {
        self.user_by_id(user_id)
            .await?
            .map(|user| user.name)
            .ok_or_else(|| format!("account {user_id} disappeared"))
    }

    /// Runs a closure on the blocking SQLite connection.
    ///
    /// `tokio_rusqlite::Connection::call` is already async; this wrapper exists
    /// only so the new modules do not each have to import the type and reason
    /// about the error mapping.
    pub(crate) async fn db_call<F, R>(&self, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
        R: Send + 'static,
    {
        self.db.call(f).await.map_err(|err| err.to_string())
    }

    fn verify_local(&self, token: &str) -> Result<Claims, AuthFailure> {
        if token.is_empty() || token.len() > 8_192 {
            return Err(AuthFailure::Unauthorized);
        }
        let header = decode_header(token).map_err(|_| AuthFailure::Unauthorized)?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some("at+jwt") {
            return Err(AuthFailure::Unauthorized);
        }
        if header.kid.as_deref() != Some(self.key.kid.as_str()) {
            return Err(AuthFailure::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.leeway = 30;
        validation.set_required_spec_claims(&["iss", "aud", "sub"]);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        let claims = decode::<Claims>(token, &self.key.decoding_key(), &validation)
            .map_err(|_| AuthFailure::Unauthorized)?
            .claims;
        let now = epoch_seconds();
        if claims.iss != self.config.issuer
            || !claims.aud.contains(&self.config.audience)
            || !claims.scope.contains(&self.config.base_scope)
            || claims.token_use != "access"
            || claims.user_id == 0
            || claims.sub != claims.user_id.to_string()
            || claims.auth_version == 0
            || uuid::Uuid::parse_str(&claims.jti).is_err()
            || claims.nbf > now.saturating_add(30)
            || claims.iat > now.saturating_add(30)
            || claims.exp <= claims.iat
            || claims.exp.saturating_add(30) < now
        {
            return Err(AuthFailure::Unauthorized);
        }
        Ok(claims)
    }
}

enum Verdict {
    Active,
    Inactive(&'static str),
}

pub(crate) enum AuthFailure {
    Unauthorized,
    Unavailable,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/api/login-options", get(login_options))
        .route("/api/login", post(login))
        .route("/api/currentUser", get(current_user).post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/connection-token", post(connection_token))
        .route("/api/introspect", post(introspect))
        // The client GETs to pull and POSTs to push the same opaque document.
        // A literal `null` means "no address book" and is a normal answer.
        .route("/api/ab", get(address_book).post(address_book_push))
        // Structured address books. The client POSTs /api/ab/personal first and
        // falls back to the legacy single document only if that answers 404, so
        // these must all exist together or the feature stays dark.
        .route("/api/ab/personal", post(crate::address_book::personal))
        .route("/api/ab/settings", post(crate::address_book::settings))
        .route(
            "/api/ab/shared/profiles",
            post(crate::address_book::shared_profiles),
        )
        .route("/api/ab/peers", post(crate::address_book::peers))
        .route("/api/ab/tags/:guid", post(crate::address_book::tags))
        .route("/api/ab/peer/add/:guid", post(crate::address_book::peer_add))
        .route(
            "/api/ab/peer/update/:guid",
            axum::routing::put(crate::address_book::peer_update),
        )
        .route(
            "/api/ab/peer/:guid",
            axum::routing::delete(crate::address_book::peer_delete),
        )
        .route("/api/ab/tag/add/:guid", post(crate::address_book::tag_add))
        .route(
            "/api/ab/tag/rename/:guid",
            axum::routing::put(crate::address_book::tag_rename),
        )
        .route(
            "/api/ab/tag/update/:guid",
            axum::routing::put(crate::address_book::tag_update),
        )
        .route(
            "/api/ab/tag/:guid",
            axum::routing::delete(crate::address_book::tag_delete),
        )
        .route(
            "/api/device-group/accessible",
            get(crate::directory::device_groups),
        )
        .route("/api/users", get(crate::directory::users))
        .route("/api/peers", get(crate::directory::peers))
        // OIDC: the client starts a login, then polls for its result. The
        // browser half lands on /oidc/callback, which the IdP redirects to.
        .route("/api/oidc/auth", post(oidc_auth_start))
        .route("/api/oidc/auth-query", get(oidc_auth_query))
        .route("/oidc/callback", get(oidc_callback))
        .fallback(axum::routing::any(unknown_endpoint))
        .layer(Extension(state))
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "live"}))
}

/// Third-party login options: the client parses this as `List<String>` and
/// derives provider buttons from the entries. An empty array is the correct
/// answer when no OIDC provider is configured, while an object would make the
/// client fail to parse the body.
///
/// The `common-oidc/<json>` form is used rather than `oidc/<name>` because the
/// client checks for that prefix first and it is the only form that can label
/// and brand several providers at once.
async fn login_options(Extension(state): Extension<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.oidc.config.login_option_entries())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LoginRequest {
    username: String,
    password: String,
    id: String,
    uuid: String,
    #[serde(rename = "type")]
    login_type: String,
    /// Second step only: the handle issued by the first step.
    #[serde(default)]
    secret: String,
    /// Second step only. The client sends this field and `tfa_code` with the
    /// same value, and has sent both a string and a number for it.
    #[serde(default, deserialize_with = "crate::totp::flexible_code")]
    verification_code: String,
    #[serde(default, deserialize_with = "crate::totp::flexible_code")]
    tfa_code: String,
    /// Device binding, kept for parity with the login payload.
    #[serde(default)]
    device_info: serde_json::Value,
    #[serde(default)]
    auto_login: bool,
}

async fn login(
    Extension(state): Extension<Arc<ApiState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let client_ip = effective_ip(&state.config, &headers, peer.ip());
    if !state.login_allowed(client_ip) {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "TooManyAttempts");
    }
    let request = match read_json::<LoginRequest>(body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    // Two request types reach this endpoint:
    //
    // * `account` (and empty) is the first step: a password check;
    // * `email_code` is the second step of a two-factor login, which the client
    //   sends with the `secret` from step one and the code the user typed. It
    //   carries the same username and password.
    //
    // Anything else is refused rather than silently treated as a password login.
    let is_second_step = request.login_type == "email_code";
    if !request.login_type.is_empty()
        && request.login_type != "account"
        && !is_second_step
    {
        return api_error(StatusCode::BAD_REQUEST, "UnsupportedLoginType");
    }
    let username = request.username.trim().to_owned();
    if username.is_empty() || request.password.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }

    let user = match state.user_by_name(&username).await {
        Ok(user) => user,
        Err(err) => {
            log::error!("login lookup failed: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    // Unknown users still run a bcrypt comparison against a dummy hash so the
    // response time does not reveal whether the account exists.
    let (Some(user), true) = (
        user.clone(),
        verify_password(&request.password, user.as_ref().map_or(&state.dummy_hash, |u| &u.password_hash)).await,
    ) else {
        state.record_login_failure(client_ip);
        return api_error(StatusCode::UNAUTHORIZED, "UsernameOrPasswordError");
    };
    if user.status != 1 {
        return api_error(StatusCode::FORBIDDEN, "UserDisabled");
    }

    if is_second_step {
        return finish_totp_login(state, user, request, client_ip).await;
    }
    if let Some(response) = begin_totp_challenge(&state, &user, client_ip).await {
        return response;
    }

    state.record_login_success(client_ip);
    log::info!("API login accepted for {} from {}", user.name, client_ip);
    issue_access_token(state, user, request, client_ip).await
}

async fn current_user(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    // The client sends {id, uuid} here; the payload is not needed, but leaving
    // it unread can wedge a keep-alive connection.
    let _ = read_json::<Value>(body).await;
    match state.authenticate(&bearer(&headers).unwrap_or_default()).await {
        Ok((_, user)) => Json(user_payload(&user)).into_response(),
        Err(AuthFailure::Unauthorized) => api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
        Err(AuthFailure::Unavailable) => {
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

async fn logout(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = read_json::<Value>(body).await;
    let Some(token) = bearer(&headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };
    // A token that no longer verifies is already logged out; answering 401
    // would only make well-behaved clients retry.
    if let Ok(claims) = state.verify_local(&token) {
        if let Err(err) = state.revoke_session(&claims.jti).await {
            log::error!("cannot revoke session: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    }
    Json(json!(null)).into_response()
}

async fn connection_token(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let _ = read_json::<Value>(body).await;
    let token = match state.authenticate(&bearer(&headers).unwrap_or_default()).await {
        Ok((_, user)) => user,
        Err(AuthFailure::Unauthorized) => {
            return api_error(StatusCode::UNAUTHORIZED, "Unauthorized")
        }
        Err(AuthFailure::Unavailable) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    };
    let scope = token_scope(&state.config.base_scope, &token.extra_scopes);
    let ttl = state.config.connection_token_ttl_seconds;
    let minted = mint_token(TokenRequest {
        key: &state.key,
        issuer: &state.config.issuer,
        audience: &state.config.audience,
        user_id: token.id,
        auth_version: token.auth_version,
        scope: &scope,
        ttl_seconds: ttl,
    });
    let (jwt, jti) = match minted {
        Ok(minted) => minted,
        Err(err) => {
            log::error!("cannot mint connection token: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    if let Err(err) = state
        .insert_session(jti, token.id, token.auth_version, epoch_seconds().saturating_add(ttl), String::new(), String::new(), String::new())
        .await
    {
        log::error!("cannot record connection session: {err}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
    }
    Json(json!({"token": jwt, "expires_in": ttl})).into_response()
}

/// Answers step one when the account has a second factor configured.
///
/// `Some(response)` means "stop, this login needs a code"; `None` means the
/// account has no TOTP row and the password login may complete.
///
/// The response deliberately carries `type: "email_code"` and
/// `tfa_type: "tfa_check"`: that pair is what makes the client show its
/// verification dialog and post again. It carries no access token.
async fn begin_totp_challenge(
    state: &Arc<ApiState>,
    user: &User,
    client_ip: IpAddr,
) -> Option<Response> {
    let has_totp = match state.totp_secret(user.id).await {
        Ok(secret) => secret.is_some(),
        Err(err) => {
            // Fail closed: if we cannot tell whether a second factor is
            // required, do not hand out a credential.
            log::error!("cannot read TOTP state: {err}");
            return Some(api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError"));
        }
    };
    if !has_totp {
        return None;
    }
    let secret = crate::totp::issue_challenge(user.id, crate::totp::now_seconds());
    log::info!(
        "API login awaiting TOTP code for {} from {}",
        user.name,
        client_ip
    );
    Some(
        Json(json!({
            "access_token": "",
            "type": "email_code",
            "tfa_type": "tfa_check",
            "secret": secret,
            "user": user_payload(user),
        }))
        .into_response(),
    )
}

/// Completes a two-factor login.
async fn finish_totp_login(
    state: Arc<ApiState>,
    user: User,
    request: LoginRequest,
    client_ip: IpAddr,
) -> Response {
    let now = crate::totp::now_seconds();
    // Expiry, forgery and account binding are all checked by this call: the
    // handle cannot be replayed against another account even with a valid code.
    if !crate::totp::read_challenge_for(&request.secret, user.id, now) {
        crate::totp::log_rejection("expired_forged_or_foreign_challenge");
        state.record_login_failure(client_ip);
        return api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    let stored = match state.totp_secret(user.id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            // The row disappeared between the two steps: refuse rather than
            // treat it as "second factor removed".
            crate::totp::log_rejection("no_secret");
            return api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
        }
        Err(err) => {
            log::error!("cannot read TOTP secret: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let secret_bytes = match crate::totp::decode_base32(&stored) {
        Ok(bytes) => bytes,
        Err(err) => {
            log::error!("stored TOTP secret is not Base32: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let last_used = match state.totp_last_step(user.id).await {
        Ok(step) => step,
        Err(err) => {
            log::error!("cannot read TOTP replay state: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    let submitted = if request.verification_code.is_empty() {
        request.tfa_code.as_str()
    } else {
        request.verification_code.as_str()
    };
    let verdict = crate::totp::check_code(
        &secret_bytes,
        submitted,
        crate::totp::step_at(now),
        last_used,
    );
    if let crate::totp::TotpVerdict::Accepted { step } = verdict {
        // Record the consumed step before issuing anything, so a crash cannot
        // let the same code be used twice.
        if let Err(err) = state.totp_consume_step(user.id, step).await {
            log::error!("cannot record TOTP step: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
        state.record_login_success(client_ip);
        log::info!("API login completed with TOTP for {}", user.name);
        return issue_access_token(state, user, request, client_ip).await;
    }
    crate::totp::log_rejection(crate::totp::describe(&verdict));
    state.record_login_failure(client_ip);
    api_error(StatusCode::UNAUTHORIZED, "UsernameOrPasswordError")
}

/// Mints and records the session for a completed login.
///
/// Shared by the password path and the two-factor path so the two cannot drift
/// apart in the claims they carry.
async fn issue_access_token(
    state: Arc<ApiState>,
    user: User,
    request: LoginRequest,
    client_ip: IpAddr,
) -> Response {
    let scope = token_scope(&state.config.base_scope, &user.extra_scopes);
    let ttl = state.config.token_ttl_seconds;
    let (token, jti) = match mint_token(TokenRequest {
        key: &state.key,
        issuer: &state.config.issuer,
        audience: &state.config.audience,
        user_id: user.id,
        auth_version: user.auth_version,
        scope: &scope,
        ttl_seconds: ttl,
    }) {
        Ok(minted) => minted,
        Err(err) => {
            log::error!("cannot mint login token: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };
    if let Err(err) = state
        .insert_session(
            jti,
            user.id,
            user.auth_version,
            epoch_seconds().saturating_add(ttl),
            client_ip.to_string(),
            request.id,
            request.uuid,
        )
        .await
    {
        log::error!("cannot record session: {err}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
    }
    Json(json!({
        "access_token": token,
        "type": "access_token",
        "tfa_type": "",
        "secret": "",
        "user": user_payload(&user),
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IntrospectRequest {
    token: String,
}

/// RFC 7662-shaped introspection for hbbs's optional verifier. hbbs only
/// reaches this endpoint behind mTLS, so it is opt-in infrastructure rather
/// than part of the default path; without it, revocation takes effect through
/// token expiry or key rotation.
async fn introspect(
    Extension(state): Extension<Arc<ApiState>>,
    body: RawBody<Body>,
) -> Response {
    let request = match read_json::<IntrospectRequest>(body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let claims = match state.verify_local(&request.token) {
        Ok(claims) => claims,
        Err(_) => return Json(json!({"active": false, "reason": "revoked"})).into_response(),
    };
    let verdict = state
        .session_verdict(&claims.jti, claims.user_id as i64, claims.auth_version as i64)
        .await;
    match verdict {
        Ok(Verdict::Active) => Json(json!({"active": true, "sub": claims.sub})).into_response(),
        Ok(Verdict::Inactive(reason)) => {
            Json(json!({"active": false, "sub": claims.sub, "reason": reason})).into_response()
        }
        Err(_) => api_error(StatusCode::SERVICE_UNAVAILABLE, "SystemError"),
    }
}

/// `GET /api/ab` — pull this account's address book.
///
/// The reply shape is what the client parses: `{"data": "<json string>",
/// "licensed_devices": N}`. The document is echoed back verbatim; the server does
/// not interpret `{tags, peers, tag_colors}`, so a client update cannot require a
/// server change. `null` is the client's own "no address book yet" answer, and it
/// treats a 401 as "sign out", so an unknown account must not get one.
async fn address_book(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
) -> Response {
    let user = match state.authenticate(&bearer(&headers).unwrap_or_default()).await {
        Ok((_, user)) => user,
        Err(AuthFailure::Unauthorized) => {
            return api_error(StatusCode::UNAUTHORIZED, "Unauthorized")
        }
        Err(AuthFailure::Unavailable) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    };
    match state.address_book_get(user.id).await {
        Ok(Some(document)) => Json(json!({
            "data": document,
            "licensed_devices": reader_licensed_devices(),
        }))
        .into_response(),
        Ok(None) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot read the address book: {err}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AddressBookPush {
    /// JSON-encoded `{tags, peers, tag_colors}`, exactly as the client sent it.
    data: String,
}

/// `POST /api/ab` — replace this account's address book.
///
/// The client sends `{"data": "<json string>"}` and accepts `null` as success.
/// The payload is validated as JSON so a corrupt push cannot poison the pull, but
/// its structure is not otherwise inspected.
async fn address_book_push(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    let user = match state.authenticate(&bearer(&headers).unwrap_or_default()).await {
        Ok((_, user)) => user,
        Err(AuthFailure::Unauthorized) => {
            return api_error(StatusCode::UNAUTHORIZED, "Unauthorized")
        }
        Err(AuthFailure::Unavailable) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    };
    let push = match read_json_limited::<AddressBookPush>(body, MAX_ADDRESS_BOOK_BYTES).await {
        Ok(push) => push,
        Err(response) => return response,
    };
    if push.data.len() > MAX_ADDRESS_BOOK_BYTES {
        return api_error(StatusCode::PAYLOAD_TOO_LARGE, "AddressBookTooLarge");
    }
    if serde_json::from_str::<Value>(&push.data).is_err() {
        return api_error(StatusCode::BAD_REQUEST, "ParamsError");
    }
    match state.address_book_put(user.id, &push.data).await {
        Ok(()) => Json(Value::Null).into_response(),
        Err(err) => {
            log::error!("cannot store the address book: {err}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

/// Device count the client uses to trim an oversized book. Starry does not
/// licence devices, so this reports an effectively unbounded number rather than
/// silently truncating someone's peers.
fn reader_licensed_devices() -> u64 {
    1_000_000
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct OidcAuthRequest {
    /// The provider name the client got from `/api/login-options`.
    op: String,
    /// Device id, so the issued session is bound to the machine that asked.
    id: String,
    uuid: String,
    device_info: Value,
    api_domain: String,
}

/// Answers `{code, url}`: the client opens `url` in a browser and polls
/// `/api/oidc/auth-query` with `code` until the login completes.
async fn oidc_auth_start(
    Extension(state): Extension<Arc<ApiState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: RawBody<Body>,
) -> Response {
    if !state.oidc.enabled() {
        return api_error(StatusCode::NOT_IMPLEMENTED, "OidcNotConfigured");
    }
    let request = match read_json::<OidcAuthRequest>(body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(provider) = state.oidc.provider(&request.op).cloned() else {
        return api_error(StatusCode::BAD_REQUEST, "UnknownOidcProvider");
    };
    let _ = request.api_domain;
    log::info!(
        "OIDC login started for provider {} from {} (device {}, info {})",
        provider.name,
        effective_ip(&state.config, &headers, peer.ip()),
        request.id,
        request.device_info
    );

    // Discovery is a network call, so it runs off the async reactor.
    let runtime = state.oidc.clone_handle();
    let provider_for_task = provider.clone();
    let document =
        match hbb_common::tokio::task::spawn_blocking(move || runtime.discovery(&provider_for_task))
            .await
        {
            Ok(Ok(document)) => document,
            Ok(Err(err)) => {
                log::error!("cannot load OIDC discovery: {err}");
                return api_error(StatusCode::BAD_GATEWAY, "OidcDiscoveryFailed");
            }
            Err(err) => {
                log::error!("OIDC discovery task failed: {err}");
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
            }
        };

    let nonce = crate::oidc::random_token();
    let state_parameter = crate::oidc::random_token();
    let code_verifier = crate::oidc::random_token();
    let challenge = crate::oidc::code_challenge(&code_verifier);
    let url = match crate::oidc::authorization_url(
        &document,
        &provider,
        &state_parameter,
        &nonce,
        &challenge,
    ) {
        Ok(url) => url,
        Err(err) => {
            log::error!("cannot build OIDC authorization URL: {err}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError");
        }
    };

    let pending = crate::oidc::PendingLogin {
        provider: provider.name.clone(),
        nonce,
        state_parameter,
        code_verifier,
        device_id: request.id,
        device_uuid: request.uuid,
        created: Instant::now(),
        state: crate::oidc::PendingState::Waiting,
    };
    let code = match state
        .oidc
        .pending
        .insert(pending, state.oidc.config.request_ttl)
    {
        Ok(code) => code,
        Err(err) => {
            log::warn!("cannot record OIDC login: {}", err.as_str());
            return api_error(StatusCode::TOO_MANY_REQUESTS, "TooManyAttempts");
        }
    };
    Json(json!({"code": code, "url": url})).into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OidcQueryRequest {
    code: String,
    id: String,
    uuid: String,
}

/// Polled once a second by the client until the browser half completes.
///
/// The answer is wrapped in `{"body": "<json string>"}` because the client
/// parses the outer object first and then parses the inner string as an
/// `HbbHttpResponse`, which decides success versus error by the presence of a
/// top-level `error` key rather than by HTTP status.
async fn oidc_auth_query(
    Extension(state): Extension<Arc<ApiState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<OidcQueryRequest>,
) -> Response {
    if !state.oidc.enabled() {
        return oidc_query_error("OidcNotConfigured");
    }
    if query.code.is_empty() {
        return oidc_query_error("ParamsError");
    }
    let ttl = state.oidc.config.request_ttl;
    let pending = match state.oidc.pending.peek(&query.code, ttl) {
        Ok(pending) => pending,
        // "No authed oidc is found" is the exact substring the client ignores
        // while it keeps polling, so every not-yet-finished case must use it.
        // Anything else makes the client stop and surface an error.
        Err(_) => return oidc_query_error("No authed oidc is found"),
    };
    // A pending login that is not yet completed must read as "keep waiting".
    if !matches!(pending.state, crate::oidc::PendingState::Completed(_)) {
        return oidc_query_error("No authed oidc is found");
    }

    // Credentials are handed out exactly once, so the entry is consumed here.
    // Reading it through `take_completed` rather than the peeked copy is what
    // makes the second poll empty.
    let login = match state.oidc.pending.take_completed(&query.code, ttl) {
        Ok(login) => login,
        Err(_) => return oidc_query_error("No authed oidc is found"),
    };
    let user = match state
        .link_or_create_oidc_user(
            pending.provider.clone(),
            login.subject,
            login.username,
            login.email.unwrap_or_default(),
            login.display_name,
            login.avatar,
            state.config.bcrypt_cost,
        )
        .await
    {
        Ok(user) => user,
        Err(err) => {
            log::error!("cannot link OIDC identity: {err}");
            return oidc_query_error("SystemError");
        }
    };
    if user.status != 1 {
        return oidc_query_error("UserDisabled");
    }

    let scope = token_scope(&state.config.base_scope, &user.extra_scopes);
    let token_ttl = state.config.token_ttl_seconds;
    let (token, jti) = match mint_token(TokenRequest {
        key: &state.key,
        issuer: &state.config.issuer,
        audience: &state.config.audience,
        user_id: user.id,
        auth_version: user.auth_version,
        scope: &scope,
        ttl_seconds: token_ttl,
    }) {
        Ok(minted) => minted,
        Err(err) => {
            log::error!("cannot mint OIDC login token: {err}");
            return oidc_query_error("SystemError");
        }
    };
    if let Err(err) = state
        .insert_session(
            jti,
            user.id,
            user.auth_version,
            epoch_seconds().saturating_add(token_ttl),
            effective_ip(&state.config, &headers, peer.ip()).to_string(),
            query.id,
            query.uuid,
        )
        .await
    {
        log::error!("cannot record OIDC session: {err}");
        return oidc_query_error("SystemError");
    }
    log::info!(
        "OIDC login accepted for {} via {}",
        user.name,
        pending.provider
    );
    oidc_query_success(json!({
        "access_token": token,
        "type": "access_token",
        "tfa_type": "",
        "secret": "",
        "user": user_payload(&user),
    }))
}

/// Wraps an error so the client's `HbbHttpResponse` parser sees `error`.
fn oidc_query_error(code: &str) -> Response {
    let inner = json!({"error": code}).to_string();
    Json(json!({"body": inner})).into_response()
}

/// Wraps a successful payload the same way.
fn oidc_query_success(payload: Value) -> Response {
    let inner = payload.to_string();
    Json(json!({"body": inner})).into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OidcCallbackRequest {
    code: String,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
}

/// The browser half: the IdP redirects here with `code` and `state`.
///
/// Redeems the authorization code at the token endpoint, verifies the id_token
/// and records the completed login. The answer is HTML because a browser is
/// what lands here.
async fn oidc_callback(
    Extension(state): Extension<Arc<ApiState>>,
    axum::extract::Query(query): axum::extract::Query<OidcCallbackRequest>,
) -> Response {
    if let Some(error) = query.error.as_deref() {
        log::warn!(
            "OIDC provider returned an error: {error} ({})",
            query.error_description.unwrap_or_default()
        );
        return oidc_callback_page(StatusCode::BAD_REQUEST, "Sign-in was not completed.");
    }
    if query.state.is_empty() || query.code.is_empty() {
        return oidc_callback_page(
            StatusCode::BAD_REQUEST,
            "The sign-in response was incomplete.",
        );
    }
    let ttl = state.oidc.config.request_ttl;
    let pending_code = match state.oidc.pending.code_for_state(&query.state, ttl) {
        Ok(code) => code,
        // An unknown state is either a stale tab or a forged callback; both are
        // refused without saying which.
        Err(_) => {
            return oidc_callback_page(StatusCode::BAD_REQUEST, "This sign-in link has expired.")
        }
    };
    let pending = match state.oidc.pending.peek(&pending_code, ttl) {
        Ok(pending) => pending,
        Err(_) => {
            return oidc_callback_page(StatusCode::BAD_REQUEST, "This sign-in link has expired.")
        }
    };
    let Some(provider) = state.oidc.provider(&pending.provider).cloned() else {
        return oidc_callback_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The provider is no longer configured.",
        );
    };

    // The exchange and verification are synchronous HTTP plus crypto, so they
    // run on the blocking pool rather than stalling the API's reactor.
    let runtime = state.oidc.clone_handle();
    let provider_for_task = provider.clone();
    let code = query.code.clone();
    let verifier = pending.code_verifier.clone();
    let nonce = pending.nonce.clone();
    let result = hbb_common::tokio::task::spawn_blocking(move || {
        exchange_and_verify(&runtime, &provider_for_task, &code, &verifier, &nonce)
    })
    .await;

    let claims = match result {
        Ok(Ok(claims)) => claims,
        Ok(Err(rejection)) => {
            log::warn!("OIDC callback rejected: {}", rejection.as_str());
            return oidc_callback_page(StatusCode::UNAUTHORIZED, "Sign-in could not be verified.");
        }
        Err(err) => {
            log::error!("OIDC callback task failed: {err}");
            return oidc_callback_page(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in failed.");
        }
    };

    let login = crate::oidc::CompletedLogin {
        username: claims.username(&provider),
        subject: claims.sub.clone(),
        email: claims.email.clone(),
        display_name: claims.name.clone().unwrap_or_default(),
        avatar: claims.picture.clone().unwrap_or_default(),
    };
    match state
        .oidc
        .pending
        .complete(&pending_code, &query.state, login, ttl)
    {
        Ok(()) => oidc_callback_page(
            StatusCode::OK,
            "Sign-in complete. You can close this window.",
        ),
        Err(err) => {
            log::warn!(
                "OIDC callback could not complete the login: {}",
                err.as_str()
            );
            oidc_callback_page(
                StatusCode::BAD_REQUEST,
                "This sign-in was already completed.",
            )
        }
    }
}

/// Redeems the authorization code and validates the resulting id_token.
fn exchange_and_verify(
    runtime: &crate::oidc::OidcRuntime,
    provider: &crate::oidc::Provider,
    code: &str,
    code_verifier: &str,
    nonce: &str,
) -> Result<crate::oidc::IdTokenClaims, crate::oidc::TokenRejection> {
    use crate::oidc::TokenRejection;
    let document = runtime.discovery(provider).map_err(|err| {
        log::error!("OIDC discovery failed during callback: {err}");
        TokenRejection::SignatureOrFormat
    })?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| TokenRejection::SignatureOrFormat)?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", provider.redirect_uri.clone()),
        ("client_id", provider.client_id.clone()),
        ("code_verifier", code_verifier.to_owned()),
    ];
    if let Some(secret) = provider.client_secret.as_deref() {
        form.push(("client_secret", secret.to_owned()));
    }
    let response = client
        .post(&document.token_endpoint)
        .form(&form)
        .send()
        .map_err(|err| {
            log::error!("OIDC token exchange failed: {err}");
            TokenRejection::SignatureOrFormat
        })?;
    if !response.status().is_success() {
        log::warn!("OIDC token endpoint answered {}", response.status());
        return Err(TokenRejection::SignatureOrFormat);
    }
    let token: crate::oidc::TokenResponse = response
        .json()
        .map_err(|_| TokenRejection::SignatureOrFormat)?;
    let id_token = token.id_token.ok_or(TokenRejection::SignatureOrFormat)?;
    let jwks = runtime.jwks(&document).map_err(|err| {
        log::error!("cannot fetch OIDC JWKS: {err}");
        TokenRejection::SignatureOrFormat
    })?;
    let claims = crate::oidc::verify_signature(&id_token, provider, &jwks)?;
    crate::oidc::validate_claims(
        &claims,
        provider,
        nonce,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0),
    )?;
    Ok(claims)
}

fn oidc_callback_page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Starry sign-in</title></head>\
         <body style=\"font-family:system-ui;margin:4rem auto;max-width:32rem;text-align:center\">\
         <p>{message}</p></body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn unknown_endpoint() -> Response {
    api_error(StatusCode::NOT_FOUND, "NotFound")
}

fn user_payload(user: &User) -> Value {
    json!({
        "name": user.name,
        "display_name": user.display_name,
        "avatar": user.avatar,
        "email": user.email,
        "note": user.note,
        "status": user.status,
        "is_admin": user.is_admin,
        // The Rust client's UserPayload carries `info` unconditionally.
        "info": {},
    })
}

fn token_scope(base: &str, extra: &str) -> String {
    let mut scope = base.split_ascii_whitespace().map(str::to_owned).collect::<Vec<_>>();
    for value in extra.split_ascii_whitespace() {
        if !scope.iter().any(|existing| existing == value) {
            scope.push(value.to_owned());
        }
    }
    scope.join(" ")
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    (!token.trim().is_empty()).then(|| token.trim().to_owned())
}

fn effective_ip(config: &ApiConfig, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if !config.trust_proxy {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

pub(crate) fn api_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

async fn read_json<T: DeserializeOwned>(body: RawBody<Body>) -> Result<T, Response> {
    read_json_limited(body, MAX_API_BODY).await
}

/// Reads a JSON body up to `limit` bytes.
///
/// Most endpoints carry credentials and device fingerprints, so they share a tight
/// bound. The address book is the one payload that is legitimately large, and it
/// passes its own limit rather than raising everyone's.
async fn read_json_limited<T: DeserializeOwned>(
    body: RawBody<Body>,
    limit: usize,
) -> Result<T, Response> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return Err(api_error(StatusCode::BAD_REQUEST, "ParamsError"));
        };
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(api_error(StatusCode::PAYLOAD_TOO_LARGE, "ParamsError"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| api_error(StatusCode::BAD_REQUEST, "ParamsError"))
}

async fn verify_password(password: &str, hash: &str) -> bool {
    let password = password.to_owned();
    let hash = hash.to_owned();
    hbb_common::tokio::task::spawn_blocking(move || {
        bcrypt::verify(password, &hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

async fn hash_password_async(password: String, cost: u32) -> Result<String, String> {
    hbb_common::tokio::task::spawn_blocking(move || hash_password(&password, cost))
        .await
        .map_err(|err| err.to_string())?
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Runs the API server until a shutdown signal arrives.
pub async fn run(config: ApiConfig) -> Result<(), String> {
    let _ = sodiumoxide::init();

    let key = Arc::new(SigningKey::load_or_create(&config.key_path)?);
    publish_jwks(&config.jwks_path, &key.jwks_document(), epoch_seconds())?;
    log::info!(
        "API JWKS published to {} (kid {}); point hbbs connection_auth.jwks.file here",
        config.jwks_path.display(),
        key.kid
    );

    let oidc_config = crate::oidc::OidcConfig::from_env()?;

    let database = open_database(&config.db_path)?;
    if let Some(password) = config.admin_password.clone() {
        bootstrap_admin(&database, &password, config.bcrypt_cost)?;
    }
    drop(database);
    let db = Connection::open(&config.db_path)
        .await
        .map_err(|err| format!("cannot open {}: {err}", config.db_path.display()))?;

    let dummy_hash = hash_password_async(uuid::Uuid::new_v4().to_string(), config.bcrypt_cost).await?;
    let oidc = Arc::new(crate::oidc::OidcRuntime::new(oidc_config));
    if oidc.enabled() {
        log::info!(
            "OIDC enabled with {} provider(s): {}",
            oidc.config.providers.len(),
            oidc.config
                .providers
                .iter()
                .map(|provider| provider.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let state = Arc::new(ApiState {
        db,
        key: key.clone(),
        config: config.clone(),
        dummy_hash,
        limiter: Mutex::new(HashMap::new()),
        oidc,
    });

    // Keep re-attesting the keyset: hbbs fails closed once the stamp is older
    // than its max_stale_seconds, so a running issuer must renew it.
    {
        let key = key.clone();
        let path = config.jwks_path.clone();
        let heartbeat = Duration::from_secs(config.jwks_heartbeat_seconds);
        hbb_common::tokio::spawn(async move {
            loop {
                hbb_common::tokio::time::sleep(heartbeat).await;
                if let Err(err) = publish_jwks(&path, &key.jwks_document(), epoch_seconds()) {
                    log::error!("cannot re-attest JWKS {}: {err}", path.display());
                }
            }
        });
    }

    let app = router(state);
    let bound = axum::Server::try_bind(&config.listen)
        .map_err(|err| format!("cannot bind API server {}: {err}", config.listen))?;
    let local_addr = bound.local_addr();
    let server = bound
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = crate::common::listen_signal().await;
        });
    log::info!(
        "Starry API listening on http://{} (issuer {}, audience {})",
        local_addr,
        config.issuer,
        config.audience
    );
    server.await.map_err(|err| format!("API server failed: {err}"))
}

fn bootstrap_admin(
    connection: &rusqlite::Connection,
    password: &str,
    cost: u32,
) -> Result<(), String> {
    match lookup_user_sync(connection, "admin")? {
        Some(existing) => {
            if bcrypt::verify(password, &existing.password_hash).unwrap_or(false) {
                return Ok(());
            }
            // ADMIN_PASSWORD is the declared source of truth when set: applying
            // it also bumps auth_version, which revokes the old sessions.
            set_password(connection, "admin", password, cost)?;
            log::info!("ADMIN_PASSWORD applied to the existing admin account");
        }
        None => {
            create_user(connection, "admin", password, Some("admin"), true, None, cost)?;
            log::info!("Created the bootstrap admin account");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        let _ = sodiumoxide::init();
        let (public, secret) = sign::gen_keypair();
        SigningKey {
            kid: kid_for(&public.0),
            secret,
            public: public.0.to_vec(),
        }
    }

    fn test_config(directory: &Path, admin: Option<&str>) -> ApiConfig {
        ApiConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            db_path: directory.join("users.db"),
            key_path: directory.join("api-signing-key"),
            jwks_path: directory.join("auth/jwks.json"),
            issuer: "https://api.example.test".to_owned(),
            audience: "rustdesk-connect".to_owned(),
            base_scope: "connect:initiate".to_owned(),
            token_ttl_seconds: 3_600,
            connection_token_ttl_seconds: 3_600,
            jwks_heartbeat_seconds: 300,
            bcrypt_cost: 4,
            admin_password: admin.map(str::to_owned),
            trust_proxy: false,
        }
    }

    #[test]
    fn minted_tokens_satisfy_the_hbbs_jwt_contract() {
        let key = test_key();
        let (token, jti) = mint_token(TokenRequest {
            key: &key,
            issuer: "https://api.example.test",
            audience: "rustdesk-connect",
            user_id: 7,
            auth_version: 3,
            scope: "connect:initiate connect:group:lab",
            ttl_seconds: 3_600,
        })
        .unwrap();
        let verifier = crate::connection_auth::test_verifier(
            "https://api.example.test",
            "rustdesk-connect",
            &key.jwks_document(),
        );
        let (user_id, scope) = verifier
            .verify_token(&token)
            .expect("hbbs must accept an API-minted token");
        assert_eq!(user_id, 7);
        assert!(scope.split_ascii_whitespace().any(|value| value == "connect:initiate"));
        assert!(scope.split_ascii_whitespace().any(|value| value == "connect:group:lab"));
        assert_eq!(uuid::Uuid::parse_str(&jti).unwrap().to_string(), jti);
    }

    #[test]
    fn jwks_document_matches_the_key_and_carries_a_kid() {
        let key = test_key();
        let document: Value = serde_json::from_slice(&key.jwks_document()).unwrap();
        let jwk = &document["keys"][0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], key.kid);
        assert_eq!(
            decode_config(jwk["x"].as_str().unwrap(), URL_SAFE_NO_PAD).unwrap(),
            key.public
        );
    }

    #[test]
    fn published_keyset_is_digest_bound_and_heartbeat_renewable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth/jwks.json");
        let key = test_key();
        let document = key.jwks_document();
        publish_jwks(&path, &document, 1_700_000_000).unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(metadata_path(&path).unwrap()).unwrap()).unwrap();
        assert_eq!(metadata["version"], 1);
        assert_eq!(metadata["fetched_at_epoch_seconds"], 1_700_000_000u64);
        assert_eq!(metadata["jwks_sha256"], hex_sha256(&document));

        publish_jwks(&path, &document, 1_700_000_300).unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(metadata_path(&path).unwrap()).unwrap()).unwrap();
        assert_eq!(metadata["fetched_at_epoch_seconds"], 1_700_000_300u64);
    }

    #[test]
    fn scopes_merge_without_duplicates() {
        assert_eq!(token_scope("connect:initiate", ""), "connect:initiate");
        assert_eq!(
            token_scope("connect:initiate", "connect:group:lab  connect:initiate"),
            "connect:initiate connect:group:lab"
        );
    }

    #[test]
    fn password_login_requires_a_long_enough_credential() {
        let directory = tempfile::tempdir().unwrap();
        let connection = open_database(&directory.path().join("users.db")).unwrap();
        assert!(create_user(&connection, "alice", "short", None, false, None, 4).is_err());
        assert!(create_user(&connection, "alice", "long-enough", None, false, None, 4).is_ok());
        assert!(create_user(&connection, "alice", "long-enough", None, false, None, 4).is_err());
    }

    #[test]
    fn password_change_bumps_auth_version() {
        let directory = tempfile::tempdir().unwrap();
        let connection = open_database(&directory.path().join("users.db")).unwrap();
        create_user(&connection, "alice", "long-enough", None, false, None, 4).unwrap();
        let before = lookup_user_sync(&connection, "alice").unwrap().unwrap();
        set_password(&connection, "alice", "another-one", 4).unwrap();
        let after = lookup_user_sync(&connection, "alice").unwrap().unwrap();
        assert_eq!(after.auth_version, before.auth_version + 1);
        assert!(bcrypt::verify("another-one", &after.password_hash).unwrap());
    }

    /// The address book is stored and returned byte-for-byte: the client owns the
    /// document shape, so any server-side rewriting would corrupt a client update.
    #[test]
    fn an_address_book_round_trips_verbatim() {
        let directory = tempfile::tempdir().unwrap();
        let connection = open_database(&directory.path().join("users.db")).unwrap();
        // The inner tag_colors value is itself a JSON string, so the document
        // contains escaped quotes; use a delimiter that cannot collide.
        let document = r##"{"tags":["office"],"peers":[{"id":"123","alias":"prod-1","hash":"abc"}],"tag_colors":"{\"office\":\"#ff0000\"}"}"##;
        connection
            .execute(
                "insert into address_books (user_id, document, updated_at) values (1, ?1, 0)",
                [document],
            )
            .unwrap();
        let stored: String = connection
            .query_row("select document from address_books where user_id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(stored, document);

        // A second push for the same user replaces rather than appends.
        let replacement = r#"{"tags":[],"peers":[],"tag_colors":"{}"}"#;
        connection
            .execute(
                "insert into address_books (user_id, document, updated_at) values (1, ?1, 1)
                 on conflict(user_id) do update set document = excluded.document,
                                                    updated_at = excluded.updated_at",
                [replacement],
            )
            .unwrap();
        let stored: String = connection
            .query_row("select document from address_books where user_id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(stored, replacement);
        let count: i64 = connection
            .query_row("select count(*) from address_books", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "a push must not accumulate rows");
    }

    #[test]
    fn bootstrap_admin_is_idempotent_and_env_driven() {
        let directory = tempfile::tempdir().unwrap();
        let connection = open_database(&directory.path().join("users.db")).unwrap();
        bootstrap_admin(&connection, "first-password", 4).unwrap();
        let first = lookup_user_sync(&connection, "admin").unwrap().unwrap();
        bootstrap_admin(&connection, "first-password", 4).unwrap();
        let second = lookup_user_sync(&connection, "admin").unwrap().unwrap();
        assert_eq!(first.auth_version, second.auth_version, "a no-op boot must not revoke sessions");

        bootstrap_admin(&connection, "second-password", 4).unwrap();
        let third = lookup_user_sync(&connection, "admin").unwrap().unwrap();
        assert_eq!(third.auth_version, first.auth_version + 1);
        assert!(bcrypt::verify("second-password", &third.password_hash).unwrap());
    }

    #[test]
    fn issuer_must_be_https() {
        assert!(validate_issuer("https://api.example.test").is_ok());
        assert!(validate_issuer("http://api.example.test").is_err());
        assert!(validate_issuer("https://user:pw@api.example.test").is_err());
        assert!(validate_issuer("https://api.example.test/#frag").is_err());
    }

    #[test]
    fn unreachable_key_file_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, "not base64!").unwrap();
        assert!(SigningKey::load_or_create(&path).is_err());
    }

    #[test]
    fn config_rejects_heartbeats_outside_the_hbbs_staleness_window() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = test_config(directory.path(), None);
        config.jwks_heartbeat_seconds = 7_200;
        assert!(config.validate().is_err());
        config.jwks_heartbeat_seconds = 300;
        assert!(config.validate().is_ok());
    }
}
