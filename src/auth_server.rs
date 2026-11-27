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

struct ApiState {
    db: Connection,
    key: Arc<SigningKey>,
    config: ApiConfig,
    dummy_hash: String,
    limiter: Mutex<HashMap<IpAddr, (u32, Instant)>>,
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

enum AuthFailure {
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
        .fallback(axum::routing::any(unknown_endpoint))
        .layer(Extension(state))
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "live"}))
}

/// Password login only: the client parses this as `List<String>` and derives
/// third-party buttons from entries. An empty array is the correct answer,
/// while an object would make the client fail to parse the body.
async fn login_options() -> impl IntoResponse {
    Json(Vec::<String>::new())
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
    // Only password login is supported; anything else (SMS/e-mail codes) must
    // say so instead of silently failing the password check.
    if !request.login_type.is_empty() && request.login_type != "account" {
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
        Ok(token) => token,
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
    state.record_login_success(client_ip);
    log::info!("API login accepted for {} from {}", user.name, client_ip);
    Json(json!({
        "access_token": token,
        "type": "access_token",
        "tfa_type": "",
        "secret": "",
        "user": user_payload(&user),
    }))
    .into_response()
}

async fn current_user(
    Extension(state): Extension<Arc<ApiState>>,
    headers: HeaderMap,
) -> Response {
    match state.authenticate(&bearer(&headers).unwrap_or_default()).await {
        Ok((_, user)) => Json(user_payload(&user)).into_response(),
        Err(AuthFailure::Unauthorized) => api_error(StatusCode::UNAUTHORIZED, "Unauthorized"),
        Err(AuthFailure::Unavailable) => {
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "SystemError")
        }
    }
}

async fn logout(Extension(state): Extension<Arc<ApiState>>, headers: HeaderMap) -> Response {
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
) -> Response {
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

fn bearer(headers: &HeaderMap) -> Option<String> {
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

fn api_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

async fn read_json<T: DeserializeOwned>(body: RawBody<Body>) -> Result<T, Response> {
    let RawBody(mut body) = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return Err(api_error(StatusCode::BAD_REQUEST, "ParamsError"));
        };
        if bytes.len().saturating_add(chunk.len()) > MAX_API_BODY {
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

    let database = open_database(&config.db_path)?;
    if let Some(password) = config.admin_password.clone() {
        bootstrap_admin(&database, &password, config.bcrypt_cost)?;
    }
    drop(database);
    let db = Connection::open(&config.db_path)
        .await
        .map_err(|err| format!("cannot open {}: {err}", config.db_path.display()))?;

    let dummy_hash = hash_password_async(uuid::Uuid::new_v4().to_string(), config.bcrypt_cost).await?;
    let state = Arc::new(ApiState {
        db,
        key: key.clone(),
        config: config.clone(),
        dummy_hash,
        limiter: Mutex::new(HashMap::new()),
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
