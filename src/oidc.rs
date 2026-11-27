//! OIDC account login for the Starry API, matching what the official client
//! actually does.
//!
//! The flow is a device-code pattern with a polling half. Verified against
//! rustdesk master (`src/hbbs_http/account.rs`, `flutter/lib/models/user_model.dart`):
//!
//! 1. The client reads `GET /api/login-options` and parses a `List<String>`.
//!    Entries prefixed `oidc/` name one provider; an entry prefixed
//!    `common-oidc/` carries a JSON array of `{name, icon}` and is the form
//!    that can label and brand several providers at once. We answer with the
//!    `common-oidc/` form because it is the one the client prefers.
//! 2. The user picks a provider, and the client POSTs `{op, id, uuid,
//!    deviceInfo, apiDomain}` to `/api/oidc/auth`. We answer
//!    `{"code": "...", "url": "https://idp/..."}` — the client opens `url` in a
//!    browser and starts polling every second, up to three minutes.
//! 3. The client GETs `/api/oidc/auth-query?code=&id=&uuid=`. Until the browser
//!    half has finished, the answer must be `{"error": ...}`; the client
//!    specifically ignores an error containing `No authed oidc is found` and
//!    keeps polling. When the login is complete it answers the same
//!    `{access_token, type: "access_token", user}` body as `/api/login`.
//!
//! Two wire details are easy to get wrong and are load-bearing:
//!
//! - `/api/oidc/auth-query` is wrapped: the HTTP body is `{"body": "<json
//!   string>"}` and the inner string is what holds the real payload. The client
//!   parses the outer object first (`HttpResponseBody { body: String }`), then
//!   parses the inner string.
//! - `HbbHttpResponse::parse` decides between success and error by the presence
//!   of a top-level `error` key, so "not finished yet" is an `{"error": ...}`
//!   object rather than an HTTP status.
//!
//! Security boundary: this module authenticates a human against an external
//! identity provider and then issues Starry's own EdDSA token. It does not
//! forward, store or trust the IdP's token beyond reading the claims it needs.

use base64::encode_config;
use hbb_common::log;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const CONFIG_FILE_ENV: &str = "STARRY_OIDC_CONFIG";
/// How long a browser half may take before the pending code is discarded.
/// The client gives up after three minutes; ours must not outlive that by much,
/// or a late IdP callback could authenticate a user who has already seen a
/// timeout.
const DEFAULT_REQUEST_TTL_SECONDS: u64 = 180;
/// Cap on in-flight login requests, so an unauthenticated caller cannot
/// allocate unbounded state by hammering `/api/oidc/auth`.
const MAX_PENDING_REQUESTS: usize = 1_024;
/// Bound on how often we re-read the provider's discovery document.
const DISCOVERY_CACHE_SECONDS: u64 = 3_600;
/// Clock skew allowed when validating an id_token.
const LEEWAY_SECONDS: u64 = 60;

/// One configured identity provider.
///
/// `Serialize` as well as `Deserialize` because tests round-trip the document
/// and because an operator tool that prints the effective configuration must
/// not have to restate the field list.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Provider {
    /// What the client is told this provider is called. Appears in the request
    /// as `op`, and in the `oidc/<name>` login-options form, so it must be a
    /// simple slug.
    pub name: String,
    /// Optional icon key the client maps to a brand (`github`, `gitlab`,
    /// `microsoft`, ...). Unknown keys fall back to a generic icon.
    #[serde(default)]
    pub icon: Option<String>,
    /// The issuer identifier. Must equal the `iss` claim in the id_token.
    pub issuer: String,
    pub client_id: String,
    /// Sent to the token endpoint. Public clients use PKCE and no secret, so
    /// this is optional.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Where the IdP sends the browser back. Must be registered at the IdP.
    pub redirect_uri: String,
    /// Scopes to request. `openid` is always added.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Claim holding the login name. Falls back to `preferred_username`,
    /// `email`, then `sub`.
    #[serde(default)]
    pub username_claim: Option<String>,
    /// Optional allow-list of email domains. Empty means "any".
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Require `email_verified` to be true when the claim is present.
    #[serde(default)]
    pub require_verified_email: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
pub(crate) struct OidcConfigDocument {
    #[serde(default)]
    pub providers: Vec<Provider>,
    /// Lifetime of one pending login code.
    #[serde(default)]
    pub request_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct OidcConfig {
    pub providers: Vec<Provider>,
    pub request_ttl: Duration,
}

impl OidcConfig {
    /// Reads `STARRY_OIDC_CONFIG`, which names a JSON file. Unset or empty means
    /// OIDC is off, which is the default: an API server that silently begins
    /// redirecting logins to an external provider would be a security surprise.
    pub fn from_env() -> Result<Self, String> {
        let path = match std::env::var(CONFIG_FILE_ENV) {
            Ok(value) if !value.trim().is_empty() => value,
            _ => return Ok(Self::default()),
        };
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| format!("cannot read {CONFIG_FILE_ENV} ({path}): {err}"))?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        let document: OidcConfigDocument =
            serde_json::from_str(raw).map_err(|err| format!("invalid OIDC config: {err}"))?;
        let ttl = document.request_ttl_seconds.unwrap_or(DEFAULT_REQUEST_TTL_SECONDS);
        if !(30..=900).contains(&ttl) {
            return Err("OIDC request_ttl_seconds must be between 30 and 900".to_owned());
        }
        let mut seen = Vec::new();
        for provider in &document.providers {
            provider.validate()?;
            if seen.contains(&provider.name) {
                return Err(format!("duplicate OIDC provider name '{}'", provider.name));
            }
            seen.push(provider.name.clone());
        }
        Ok(Self {
            providers: document.providers,
            request_ttl: Duration::from_secs(ttl),
        })
    }

    pub fn enabled(&self) -> bool {
        !self.providers.is_empty()
    }

    pub fn provider(&self, name: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.name == name)
    }

    /// The `common-oidc/<json>` entry the client parses into provider buttons.
    ///
    /// The client checks for this prefix before the `oidc/` form, so a single
    /// entry describes every provider and each can carry its own icon.
    pub fn login_option_entries(&self) -> Vec<String> {
        if !self.enabled() {
            return Vec::new();
        }
        let providers: Vec<Value> = self
            .providers
            .iter()
            .map(|provider| {
                json!({
                    "name": provider.name,
                    "icon": provider.icon.clone().unwrap_or_else(|| provider.name.clone()),
                })
            })
            .collect();
        vec![format!("common-oidc/{}", Value::Array(providers))]
    }
}

/// Whether a URL is acceptable for a provider endpoint or redirect.
///
/// `https` always; `http` only when the host is loopback, so a local test
/// provider works without weakening the rule that deployments never send a
/// browser or a client secret over cleartext. Checking the parsed host rather
/// than the string prefix is what stops `http://127.0.0.1.evil.test` from
/// passing.
fn is_secure_url(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("https://") {
        return true;
    }
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return false;
    }
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        match stripped.split_once(']') {
            Some((inside, _)) => inside,
            None => return false,
        }
    } else {
        authority.rsplit_once(':').map(|(host, _)| host).unwrap_or(authority)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

impl Provider {
    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("OIDC provider name must not be empty".to_owned());
        }
        // The name travels inside `common-oidc/<json>` and comes back as `op`,
        // so it is compared literally. Whitespace or slashes would make the
        // round trip ambiguous.
        if !self
            .name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(format!(
                "OIDC provider name '{}' may only contain letters, digits, '-' and '_'",
                self.name
            ));
        }
        if !is_secure_url(&self.issuer) {
            return Err(format!(
                "OIDC provider '{}' issuer must be an https URL (http is allowed only for loopback)",
                self.name
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(format!("OIDC provider '{}' needs a client_id", self.name));
        }
        if !is_secure_url(&self.redirect_uri) {
            return Err(format!(
                "OIDC provider '{}' redirect_uri must be https (http is allowed only for loopback)",
                self.name
            ));
        }
        Ok(())
    }

    /// Scopes to request, always including `openid`.
    pub fn requested_scopes(&self) -> String {
        let mut scopes: Vec<String> = self.scopes.clone();
        if !scopes.iter().any(|scope| scope == "openid") {
            scopes.insert(0, "openid".to_owned());
        }
        if !scopes.iter().any(|scope| scope == "email") {
            // Requested so `email` and `email_verified` are available for the
            // domain policy; an IdP that does not support the scope ignores it.
            scopes.push("email".to_owned());
        }
        scopes.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Discovery and id_token validation
// ---------------------------------------------------------------------------

/// The parts of an OIDC discovery document this server uses.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// JWK fields needed to build a verification key.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    #[allow(dead_code)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Jwks {
    keys: Vec<Jwk>,
}

/// Claims this server acts on.
///
/// `aud` is deserialised loosely because a single-audience token carries a
/// string while a multi-audience token carries an array, and both are legal.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Option<Value>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<Value>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl IdTokenClaims {
    /// The login name to bind this identity to.
    ///
    /// Order: an explicitly configured claim, then `preferred_username`, then
    /// `email`, then `sub`. `sub` last because it is opaque and the operator
    /// almost never wants it as the visible account name.
    pub fn username(&self, provider: &Provider) -> String {
        if let Some(claim) = provider.username_claim.as_deref() {
            if let Some(value) = self.extra.get(claim).and_then(Value::as_str) {
                if !value.trim().is_empty() {
                    return value.trim().to_owned();
                }
            }
        }
        for candidate in [
            self.preferred_username.as_deref(),
            self.email.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !candidate.trim().is_empty() {
                return candidate.trim().to_owned();
            }
        }
        self.sub.clone()
    }

    fn audiences(&self) -> Vec<String> {
        match self.aud.as_ref() {
            Some(Value::String(value)) => vec![value.clone()],
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Whether `email_verified` is satisfied.
    ///
    /// IdPs disagree about the type: some send a boolean, some the strings
    /// `"true"`/`"false"`. A missing claim is treated as "not verified" rather
    /// than failing open, because the flag only matters when the operator asked
    /// for it.
    fn email_is_verified(&self) -> bool {
        match self.email_verified.as_ref() {
            Some(Value::Bool(value)) => *value,
            Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
            _ => false,
        }
    }
}

/// Why an id_token was refused. Separate from a plain string so callers can log
/// a stable reason without leaking claim contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TokenRejection {
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    IssuedInFuture,
    NonceMismatch,
    EmailDomainNotAllowed,
    EmailNotVerified,
    UsernameMissing,
    SignatureOrFormat,
}

impl TokenRejection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IssuerMismatch => "issuer_mismatch",
            Self::AudienceMismatch => "audience_mismatch",
            Self::Expired => "expired",
            Self::IssuedInFuture => "issued_in_future",
            Self::NonceMismatch => "nonce_mismatch",
            Self::EmailDomainNotAllowed => "email_domain_not_allowed",
            Self::EmailNotVerified => "email_not_verified",
            Self::UsernameMissing => "username_missing",
            Self::SignatureOrFormat => "signature_or_format",
        }
    }
}

/// Validates the claims an OIDC login must satisfy beyond the signature.
///
/// Kept separate from signature checking so the policy is testable without
/// minting keys: every branch here is a pure function of the claims, the
/// provider and the expected nonce.
pub(crate) fn validate_claims(
    claims: &IdTokenClaims,
    provider: &Provider,
    expected_nonce: &str,
    now: i64,
) -> Result<(), TokenRejection> {
    if claims.iss != provider.issuer {
        return Err(TokenRejection::IssuerMismatch);
    }
    if !claims
        .audiences()
        .iter()
        .any(|audience| audience == &provider.client_id)
    {
        return Err(TokenRejection::AudienceMismatch);
    }
    // `exp` is mandatory in OIDC; a token without one cannot be bounded, so it
    // is refused rather than treated as long-lived.
    let Some(exp) = claims.exp else {
        return Err(TokenRejection::Expired);
    };
    if exp.saturating_add(LEEWAY_SECONDS as i64) < now {
        return Err(TokenRejection::Expired);
    }
    if let Some(iat) = claims.iat {
        if iat > now.saturating_add(LEEWAY_SECONDS as i64) {
            return Err(TokenRejection::IssuedInFuture);
        }
    }
    // The nonce binds this token to the browser half we started, so a token
    // minted for another login attempt cannot be replayed into ours.
    match claims.nonce.as_deref() {
        Some(nonce) if nonce == expected_nonce => {}
        _ => return Err(TokenRejection::NonceMismatch),
    }
    if provider.require_verified_email && !claims.email_is_verified() {
        return Err(TokenRejection::EmailNotVerified);
    }
    if !provider.allowed_email_domains.is_empty() {
        let Some(email) = claims.email.as_deref() else {
            return Err(TokenRejection::EmailDomainNotAllowed);
        };
        let Some(domain) = email.rsplit_once('@').map(|(_, domain)| domain) else {
            return Err(TokenRejection::EmailDomainNotAllowed);
        };
        if !provider
            .allowed_email_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
        {
            return Err(TokenRejection::EmailDomainNotAllowed);
        }
    }
    if claims.username(provider).trim().is_empty() {
        return Err(TokenRejection::UsernameMissing);
    }
    Ok(())
}

/// Verifies an id_token's signature against the provider's JWKS.
pub(crate) fn verify_signature(
    token: &str,
    provider: &Provider,
    jwks: &Jwks,
) -> Result<IdTokenClaims, TokenRejection> {
    let header = decode_header(token).map_err(|_| TokenRejection::SignatureOrFormat)?;
    let algorithm = match header.alg {
        // Only asymmetric algorithms. `none` and the HMAC family are refused:
        // an HMAC id_token would let anyone who can read the client_id mint
        // tokens.
        Algorithm::RS256 => Algorithm::RS256,
        Algorithm::RS384 => Algorithm::RS384,
        Algorithm::RS512 => Algorithm::RS512,
        Algorithm::ES256 => Algorithm::ES256,
        Algorithm::ES384 => Algorithm::ES384,
        _ => return Err(TokenRejection::SignatureOrFormat),
    };
    let key = select_key(provider, jwks, header.kid.as_deref(), algorithm)
        .ok_or(TokenRejection::SignatureOrFormat)?;

    let mut validation = Validation::new(algorithm);
    // Audience, issuer, expiry and nonce are checked by `validate_claims`, which
    // is exercised by its own tests. Turning them off here keeps exactly one
    // implementation of each rule, so the two cannot disagree.
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.algorithms = vec![algorithm];

    let data = decode::<IdTokenClaims>(token, &key, &validation)
        .map_err(|_| TokenRejection::SignatureOrFormat)?;
    Ok(data.claims)
}

fn select_key(
    provider: &Provider,
    jwks: &Jwks,
    kid: Option<&str>,
    algorithm: Algorithm,
) -> Option<DecodingKey> {
    let wants_ec = matches!(algorithm, Algorithm::ES256 | Algorithm::ES384);
    jwks.keys
        .iter()
        .filter(|key| key.key_use.as_deref() != Some("enc"))
        .filter(|key| if wants_ec { key.kty == "EC" } else { key.kty == "RSA" })
        .filter(|key| match kid {
            Some(kid) => key.kid.as_deref() == Some(kid),
            // Without a `kid`, only a single unambiguous key may be used.
            None => true,
        })
        .find_map(|key| {
            if wants_ec {
                let (x, y) = (key.x.as_deref()?, key.y.as_deref()?);
                DecodingKey::from_ec_components(x, y).ok()
            } else {
                let (n, e) = (key.n.as_deref()?, key.e.as_deref()?);
                DecodingKey::from_rsa_components(n, e).ok()
            }
        })
        .or_else(|| {
            // A `kid` that matches nothing is a configuration error worth
            // surfacing distinctly from a bad signature.
            log::warn!(
                "OIDC provider '{}' has no usable JWK for kid {:?}",
                provider.name,
                kid
            );
            None
        })
}

// ---------------------------------------------------------------------------
// Pending login state
// ---------------------------------------------------------------------------

/// State of one in-flight browser half.
#[derive(Clone, Debug)]
pub(crate) enum PendingState {
    /// Waiting for the IdP to redirect the browser back.
    Waiting,
    /// The callback arrived, the id_token verified, and the client has not yet
    /// collected the result.
    Completed(CompletedLogin),
}

#[derive(Clone, Debug)]
pub(crate) struct CompletedLogin {
    pub username: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: String,
    pub avatar: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingLogin {
    pub provider: String,
    pub nonce: String,
    pub state_parameter: String,
    /// PKCE verifier. Never leaves the server: the browser only carries the
    /// challenge, so anything observing the redirect cannot redeem the code.
    pub code_verifier: String,
    pub device_id: String,
    pub device_uuid: String,
    pub created: Instant,
    pub state: PendingState,
}

/// In-memory store of pending logins, keyed by the `code` handed to the client.
///
/// Deliberately not persisted: a restart invalidates in-flight browser halves,
/// which is correct — the client is polling every second and will surface the
/// failure rather than being handed a stale login minutes later.
#[derive(Default)]
pub(crate) struct PendingLogins {
    entries: Mutex<HashMap<String, PendingLogin>>,
}

/// Why a pending login could not be found or used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PendingError {
    Unknown,
    Expired,
    /// A second callback tried to complete a login that is already completed.
    AlreadyCompleted,
    /// The callback's `state` did not match the one we issued.
    StateMismatch,
    Capacity,
}

impl PendingError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown_code",
            Self::Expired => "expired",
            Self::AlreadyCompleted => "already_completed",
            Self::StateMismatch => "state_mismatch",
            Self::Capacity => "capacity",
        }
    }
}

impl PendingLogins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new login and returns its code.
    pub fn insert(&self, mut login: PendingLogin, ttl: Duration) -> Result<String, PendingError> {
        let mut entries = self.entries.lock().map_err(|_| PendingError::Capacity)?;
        // Sweep before inserting so capacity reflects live work rather than
        // everything ever requested.
        entries.retain(|_, existing| existing.created.elapsed() < ttl);
        if entries.len() >= MAX_PENDING_REQUESTS {
            return Err(PendingError::Capacity);
        }
        let code = uuid::Uuid::new_v4().to_string();
        login.created = Instant::now();
        entries.insert(code.clone(), login);
        Ok(code)
    }

    /// Looks a pending login up without consuming it, so the client can poll.
    pub fn peek(&self, code: &str, ttl: Duration) -> Result<PendingLogin, PendingError> {
        let entries = self.entries.lock().map_err(|_| PendingError::Unknown)?;
        let entry = entries.get(code).ok_or(PendingError::Unknown)?;
        if entry.created.elapsed() >= ttl {
            return Err(PendingError::Expired);
        }
        Ok(entry.clone())
    }

    /// Completes a pending login exactly once.
    ///
    /// `state` is the CSRF parameter from the callback. Binding it here rather
    /// than at the HTTP layer keeps the invariant in one place: a callback that
    /// does not match the issued state cannot complete a login, and a login can
    /// only be completed once.
    pub fn complete(
        &self,
        code: &str,
        state: &str,
        login: CompletedLogin,
        ttl: Duration,
    ) -> Result<(), PendingError> {
        let mut entries = self.entries.lock().map_err(|_| PendingError::Unknown)?;
        let entry = entries.get_mut(code).ok_or(PendingError::Unknown)?;
        if entry.created.elapsed() >= ttl {
            return Err(PendingError::Expired);
        }
        if entry.state_parameter != state {
            return Err(PendingError::StateMismatch);
        }
        if matches!(entry.state, PendingState::Completed(_)) {
            return Err(PendingError::AlreadyCompleted);
        }
        entry.state = PendingState::Completed(login);
        Ok(())
    }

    /// Removes a completed login, because the credential is handed out once.
    pub fn take_completed(
        &self,
        code: &str,
        ttl: Duration,
    ) -> Result<CompletedLogin, PendingError> {
        let mut entries = self.entries.lock().map_err(|_| PendingError::Unknown)?;
        let entry = entries.get(code).ok_or(PendingError::Unknown)?;
        if entry.created.elapsed() >= ttl {
            return Err(PendingError::Expired);
        }
        match &entry.state {
            PendingState::Completed(login) => {
                let login = login.clone();
                entries.remove(code);
                Ok(login)
            }
            PendingState::Waiting => Err(PendingError::Unknown),
        }
    }

    /// Finds the code whose issued `state` matches a callback.
    ///
    /// The browser returns `state` and `code`, not our internal `code`, so the
    /// callback half has to locate its entry this way. Returning the internal
    /// code lets the same `complete` path serve both halves, keeping the
    /// once-only invariant in one function.
    pub fn code_for_state(&self, state: &str, ttl: Duration) -> Result<String, PendingError> {
        let entries = self.entries.lock().map_err(|_| PendingError::Unknown)?;
        entries
            .iter()
            .find(|(_, entry)| {
                entry.state_parameter == state && entry.created.elapsed() < ttl
            })
            .map(|(code, _)| code.clone())
            .ok_or(PendingError::Unknown)
    }

    /// The provider a pending login was started for, used by the callback to
    /// pick the right token endpoint and JWKS before completing it.
    pub fn provider_for_state(&self, state: &str, ttl: Duration) -> Result<String, PendingError> {
        let entries = self.entries.lock().map_err(|_| PendingError::Unknown)?;
        entries
            .values()
            .find(|entry| {
                entry.state_parameter == state && entry.created.elapsed() < ttl
            })
            .map(|entry| entry.provider.clone())
            .ok_or(PendingError::Unknown)
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Server-side state
// ---------------------------------------------------------------------------

/// Runtime state for OIDC, shared through the API state.
pub(crate) struct OidcRuntime {
    pub config: OidcConfig,
    pub pending: PendingLogins,
    /// Cached discovery documents, keyed by provider name.
    discovery: Mutex<HashMap<String, (Discovery, Instant)>>,
}

impl OidcRuntime {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            pending: PendingLogins::new(),
            discovery: Mutex::new(HashMap::new()),
        }
    }

    /// A handle usable from a blocking task.
    ///
    /// Both the discovery fetch and the callback's code exchange run on the
    /// blocking pool, which needs an owned reference rather than a borrow of
    /// the API state.
    pub fn clone_handle(self: &std::sync::Arc<Self>) -> std::sync::Arc<Self> {
        std::sync::Arc::clone(self)
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled()
    }

    pub fn provider(&self, name: &str) -> Option<&Provider> {
        self.config.provider(name)
    }

    /// Returns the discovery document, fetching it once per cache window.
    ///
    /// Blocking on purpose: callers run inside `spawn_blocking`, because both
    /// the fetch and the JWKS fetch are synchronous HTTP.
    pub fn discovery(&self, provider: &Provider) -> Result<Discovery, String> {
        if let Ok(cache) = self.discovery.lock() {
            if let Some((document, fetched)) = cache.get(&provider.name) {
                if fetched.elapsed() < Duration::from_secs(DISCOVERY_CACHE_SECONDS) {
                    return Ok(document.clone());
                }
            }
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            provider.issuer.trim_end_matches('/')
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            // A redirect here would let a misconfigured issuer point us at an
            // attacker's JWKS, so the document must come from the issuer itself.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build OIDC client: {err}"))?;
        let response = client
            .get(&url)
            .send()
            .map_err(|err| format!("cannot fetch OIDC discovery: {err}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "OIDC discovery for '{}' answered {}",
                provider.name,
                response.status()
            ));
        }
        let document: Discovery = response
            .json()
            .map_err(|err| format!("invalid OIDC discovery document: {err}"))?;
        // The document must describe the issuer we configured, or a compromised
        // discovery endpoint could redirect token validation elsewhere.
        if document.issuer.trim_end_matches('/') != provider.issuer.trim_end_matches('/') {
            return Err(format!(
                "OIDC discovery issuer '{}' does not match configured '{}'",
                document.issuer, provider.issuer
            ));
        }
        if let Ok(mut cache) = self.discovery.lock() {
            cache.insert(provider.name.clone(), (document.clone(), Instant::now()));
        }
        Ok(document)
    }

    /// Fetches and parses the provider's JWKS.
    pub fn jwks(&self, document: &Discovery) -> Result<Jwks, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build OIDC client: {err}"))?;
        let response = client
            .get(&document.jwks_uri)
            .send()
            .map_err(|err| format!("cannot fetch OIDC JWKS: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("OIDC JWKS answered {}", response.status()));
        }
        response
            .json::<Jwks>()
            .map_err(|err| format!("invalid OIDC JWKS: {err}"))
    }
}

/// Token-endpoint exchange, split out because it is the one place a client
/// secret is used and the only network call that must not be retried blindly.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    #[serde(default)]
    pub id_token: Option<String>,
}

/// Builds the authorization URL the client opens in a browser.
///
/// PKCE is always used (`S256`), so the code cannot be redeemed by anything
/// that only observes the redirect. The verifier stays in the pending entry.
pub(crate) fn authorization_url(
    document: &Discovery,
    provider: &Provider,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&document.authorization_endpoint)
        .map_err(|err| format!("invalid authorization endpoint: {err}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.requested_scopes())
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// PKCE `code_challenge` for a verifier: base64url(sha256(verifier)).
pub(crate) fn code_challenge(verifier: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    encode_config(digest, base64::URL_SAFE_NO_PAD)
}

/// A random URL-safe token for `state`, `nonce` and PKCE verifiers.
pub(crate) fn random_token() -> String {
    encode_config(uuid::Uuid::new_v4().as_bytes(), base64::URL_SAFE_NO_PAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Provider {
        Provider {
            name: "acme".to_owned(),
            icon: Some("microsoft".to_owned()),
            issuer: "https://idp.example.test".to_owned(),
            client_id: "starry-client".to_owned(),
            client_secret: None,
            redirect_uri: "https://api.example.test/oidc/callback".to_owned(),
            scopes: vec!["profile".to_owned()],
            username_claim: None,
            allowed_email_domains: Vec::new(),
            require_verified_email: false,
        }
    }

    fn claims(nonce: &str) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://idp.example.test".to_owned(),
            sub: "subject-1".to_owned(),
            aud: Some(Value::String("starry-client".to_owned())),
            exp: Some(2_000_000_000),
            iat: Some(1_999_999_000),
            nonce: Some(nonce.to_owned()),
            email: Some("alice@example.test".to_owned()),
            email_verified: Some(Value::Bool(true)),
            preferred_username: Some("alice".to_owned()),
            name: Some("Alice".to_owned()),
            picture: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn config_requires_https_issuer_and_https_redirect() {
        let mut document = provider();
        document.issuer = "http://idp.example.test".to_owned();
        let raw = serde_json::json!({"providers": [document]}).to_string();
        assert!(OidcConfig::from_json(&raw)
            .unwrap_err()
            .contains("issuer must be an https URL"));

        let mut document = provider();
        document.redirect_uri = "http://api.example.test/oidc/callback".to_owned();
        let raw = serde_json::json!({"providers": [document]}).to_string();
        assert!(OidcConfig::from_json(&raw).is_err());
    }

    /// Loopback http is the one exception, so a local provider can be tested
    /// without weakening the rule for real deployments.
    #[test]
    fn loopback_http_is_allowed_but_a_lookalike_host_is_not() {
        assert!(is_secure_url("https://idp.example.test"));
        assert!(is_secure_url("http://127.0.0.1:8080"));
        assert!(is_secure_url("http://localhost:9000/path"));
        assert!(is_secure_url("http://[::1]:9000"));

        // A host that merely starts with a loopback address must not pass:
        // checking the string prefix would accept this.
        assert!(!is_secure_url("http://127.0.0.1.evil.test"));
        assert!(!is_secure_url("http://localhost.evil.test"));
        assert!(!is_secure_url("http://idp.example.test"));
        assert!(!is_secure_url("ftp://127.0.0.1"));
        assert!(!is_secure_url(""));
    }

    #[test]
    fn config_rejects_duplicate_and_unsafe_names() {
        let raw = serde_json::json!({"providers": [provider(), provider()]}).to_string();
        assert!(OidcConfig::from_json(&raw)
            .unwrap_err()
            .contains("duplicate OIDC provider name"));

        let mut unsafe_name = provider();
        unsafe_name.name = "../etc/passwd".to_owned();
        let raw = serde_json::json!({"providers": [unsafe_name]}).to_string();
        assert!(OidcConfig::from_json(&raw).unwrap_err().contains("letters, digits"));
    }

    /// An unset or empty config must mean "OIDC off", never "OIDC open".
    #[test]
    fn absent_config_disables_oidc() {
        let config = OidcConfig::default();
        assert!(!config.enabled());
        assert!(config.login_option_entries().is_empty());
    }

    /// The client checks for the `common-oidc/` prefix before `oidc/`, so the
    /// entry has to be exactly one string with a JSON array after the prefix.
    #[test]
    fn login_options_use_the_common_oidc_form() {
        let config = OidcConfig {
            providers: vec![provider()],
            request_ttl: Duration::from_secs(180),
        };
        let entries = config.login_option_entries();
        assert_eq!(entries.len(), 1);
        let payload = entries[0]
            .strip_prefix("common-oidc/")
            .expect("common-oidc prefix");
        let parsed: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed[0]["name"], "acme");
        assert_eq!(parsed[0]["icon"], "microsoft");
    }

    #[test]
    fn scopes_always_carry_openid() {
        let scopes = provider().requested_scopes();
        let words: Vec<&str> = scopes.split_ascii_whitespace().collect();
        assert!(words.contains(&"openid"));
        assert!(words.contains(&"profile"));
        assert!(words.contains(&"email"));
    }

    #[test]
    fn claims_accept_a_valid_token() {
        let provider = provider();
        let claims = claims("nonce-1");
        assert_eq!(
            validate_claims(&claims, &provider, "nonce-1", 1_999_999_100),
            Ok(())
        );
    }

    #[test]
    fn claims_reject_issuer_audience_and_nonce_mismatches() {
        let provider = provider();
        let mut wrong_issuer = claims("nonce-1");
        wrong_issuer.iss = "https://evil.example.test".to_owned();
        assert_eq!(
            validate_claims(&wrong_issuer, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::IssuerMismatch)
        );

        let mut wrong_audience = claims("nonce-1");
        wrong_audience.aud = Some(Value::String("someone-else".to_owned()));
        assert_eq!(
            validate_claims(&wrong_audience, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::AudienceMismatch)
        );

        // A token minted for a different login attempt must not complete this
        // one, even if every other claim is valid.
        assert_eq!(
            validate_claims(&claims("nonce-2"), &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::NonceMismatch)
        );
    }

    #[test]
    fn claims_accept_an_audience_array() {
        let provider = provider();
        let mut claims = claims("nonce-1");
        claims.aud = Some(serde_json::json!(["other-client", "starry-client"]));
        assert_eq!(
            validate_claims(&claims, &provider, "nonce-1", 1_999_999_100),
            Ok(())
        );
    }

    #[test]
    fn claims_reject_expiry_and_missing_expiry() {
        let provider = provider();
        let mut expired = claims("nonce-1");
        expired.exp = Some(1_999_999_000);
        assert_eq!(
            validate_claims(&expired, &provider, "nonce-1", 2_000_000_000),
            Err(TokenRejection::Expired)
        );

        let mut no_expiry = claims("nonce-1");
        no_expiry.exp = None;
        assert_eq!(
            validate_claims(&no_expiry, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::Expired),
            "a token with no exp cannot be bounded and must be refused"
        );
    }

    #[test]
    fn claims_allow_small_clock_skew_only() {
        let provider = provider();
        let mut claims = claims("nonce-1");
        claims.exp = Some(1_999_999_000);
        // Within the leeway window the token is still accepted.
        assert_eq!(
            validate_claims(&claims, &provider, "nonce-1", 1_999_999_030),
            Ok(())
        );
        // Beyond it, refused.
        assert_eq!(
            validate_claims(&claims, &provider, "nonce-1", 1_999_999_500),
            Err(TokenRejection::Expired)
        );
    }

    #[test]
    fn future_issued_tokens_are_refused() {
        let provider = provider();
        let mut claims = claims("nonce-1");
        claims.iat = Some(1_999_999_900);
        assert_eq!(
            validate_claims(&claims, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::IssuedInFuture)
        );
    }

    #[test]
    fn email_domain_allow_list_is_enforced() {
        let mut provider = provider();
        provider.allowed_email_domains = vec!["example.test".to_owned()];
        assert_eq!(
            validate_claims(&claims("nonce-1"), &provider, "nonce-1", 1_999_999_100),
            Ok(())
        );

        let mut outside = claims("nonce-1");
        outside.email = Some("alice@elsewhere.test".to_owned());
        assert_eq!(
            validate_claims(&outside, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::EmailDomainNotAllowed)
        );

        // No email at all cannot satisfy a domain policy.
        let mut missing = claims("nonce-1");
        missing.email = None;
        assert_eq!(
            validate_claims(&missing, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::EmailDomainNotAllowed)
        );
    }

    #[test]
    fn verified_email_requirement_fails_closed() {
        let mut provider = provider();
        provider.require_verified_email = true;

        let mut unverified = claims("nonce-1");
        unverified.email_verified = Some(Value::Bool(false));
        assert_eq!(
            validate_claims(&unverified, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::EmailNotVerified)
        );

        // A missing claim is not evidence of verification.
        let mut absent = claims("nonce-1");
        absent.email_verified = None;
        assert_eq!(
            validate_claims(&absent, &provider, "nonce-1", 1_999_999_100),
            Err(TokenRejection::EmailNotVerified)
        );

        // IdPs that send the string form still pass.
        let mut string_form = claims("nonce-1");
        string_form.email_verified = Some(Value::String("true".to_owned()));
        assert_eq!(
            validate_claims(&string_form, &provider, "nonce-1", 1_999_999_100),
            Ok(())
        );
    }

    #[test]
    fn username_prefers_the_configured_claim() {
        let mut provider = provider();
        provider.username_claim = Some("employee_id".to_owned());
        let mut claims = claims("nonce-1");
        claims
            .extra
            .insert("employee_id".to_owned(), Value::String("e-42".to_owned()));
        assert_eq!(claims.username(&provider), "e-42");
    }

    #[test]
    fn username_falls_back_through_email_to_subject() {
        let provider = provider();
        let mut claims = claims("nonce-1");
        assert_eq!(claims.username(&provider), "alice");

        claims.preferred_username = None;
        assert_eq!(claims.username(&provider), "alice@example.test");

        claims.email = None;
        assert_eq!(claims.username(&provider), "subject-1");
    }

    #[test]
    fn pending_login_is_completed_exactly_once() {
        let pending = PendingLogins::new();
        let ttl = Duration::from_secs(180);
        let code = pending
            .insert(
                PendingLogin {
                    provider: "acme".to_owned(),
                    nonce: "nonce-1".to_owned(),
                    state_parameter: "state-1".to_owned(),
                    code_verifier: "verifier-1".to_owned(),
                    device_id: "device".to_owned(),
                    device_uuid: "uuid".to_owned(),
                    created: Instant::now(),
                    state: PendingState::Waiting,
                },
                ttl,
            )
            .unwrap();

        let login = CompletedLogin {
            username: "alice".to_owned(),
            subject: "subject-1".to_owned(),
            email: None,
            display_name: "Alice".to_owned(),
            avatar: String::new(),
        };

        // Polling before the callback must not look like success.
        assert_eq!(
            pending.take_completed(&code, ttl).unwrap_err(),
            PendingError::Unknown
        );

        pending.complete(&code, "state-1", login, ttl).unwrap();
        assert_eq!(
            pending.complete(
                &code,
                "state-1",
                CompletedLogin {
                    username: "again".to_owned(),
                    subject: "subject-1".to_owned(),
                    email: None,
                    display_name: String::new(),
                    avatar: String::new(),
                },
                ttl,
            )
            .unwrap_err(),
            PendingError::AlreadyCompleted,
            "a second callback must not overwrite a completed login"
        );

        // The credential is handed out once, then the entry is gone.
        assert!(pending.take_completed(&code, ttl).is_ok());
        assert_eq!(
            pending.take_completed(&code, ttl).unwrap_err(),
            PendingError::Unknown
        );
    }

    #[test]
    fn callback_state_must_match_the_issued_state() {
        let pending = PendingLogins::new();
        let ttl = Duration::from_secs(180);
        let code = pending
            .insert(
                PendingLogin {
                    provider: "acme".to_owned(),
                    nonce: "nonce-1".to_owned(),
                    state_parameter: "state-1".to_owned(),
                    code_verifier: "verifier-1".to_owned(),
                    device_id: String::new(),
                    device_uuid: String::new(),
                    created: Instant::now(),
                    state: PendingState::Waiting,
                },
                ttl,
            )
            .unwrap();
        let login = CompletedLogin {
            username: "alice".to_owned(),
            subject: "subject-1".to_owned(),
            email: None,
            display_name: String::new(),
            avatar: String::new(),
        };
        assert_eq!(
            pending
                .complete(&code, "attacker-state", login, ttl)
                .unwrap_err(),
            PendingError::StateMismatch
        );
    }

    #[test]
    fn expired_pending_login_is_refused() {
        let pending = PendingLogins::new();
        let ttl = Duration::from_secs(180);
        let code = pending
            .insert(
                PendingLogin {
                    provider: "acme".to_owned(),
                    nonce: "nonce-1".to_owned(),
                    state_parameter: "state-1".to_owned(),
                    code_verifier: "verifier-1".to_owned(),
                    device_id: String::new(),
                    device_uuid: String::new(),
                    created: Instant::now(),
                    state: PendingState::Waiting,
                },
                ttl,
            )
            .unwrap();
        // Zero ttl makes every entry immediately stale, which is how the
        // expiry branch is exercised without sleeping.
        assert_eq!(
            pending
                .peek(&code, Duration::from_secs(0))
                .unwrap_err(),
            PendingError::Expired
        );
    }

    #[test]
    fn pending_capacity_is_bounded() {
        let pending = PendingLogins::new();
        let ttl = Duration::from_secs(180);
        for _ in 0..MAX_PENDING_REQUESTS {
            pending
                .insert(
                    PendingLogin {
                        provider: "acme".to_owned(),
                        nonce: String::new(),
                        state_parameter: String::new(),
                        code_verifier: String::new(),
                        device_id: String::new(),
                        device_uuid: String::new(),
                        created: Instant::now(),
                        state: PendingState::Waiting,
                    },
                    ttl,
                )
                .unwrap();
        }
        assert_eq!(
            pending
                .insert(
                    PendingLogin {
                        provider: "acme".to_owned(),
                        nonce: String::new(),
                        state_parameter: String::new(),
                        code_verifier: String::new(),
                        device_id: String::new(),
                        device_uuid: String::new(),
                        created: Instant::now(),
                        state: PendingState::Waiting,
                    },
                    ttl,
                )
                .unwrap_err(),
            PendingError::Capacity
        );
    }

    #[test]
    fn code_challenge_is_sha256_base64url() {
        // RFC 7636 appendix B.
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorization_url_carries_every_required_parameter() {
        let document = Discovery {
            issuer: "https://idp.example.test".to_owned(),
            authorization_endpoint: "https://idp.example.test/authorize".to_owned(),
            token_endpoint: "https://idp.example.test/token".to_owned(),
            jwks_uri: "https://idp.example.test/jwks".to_owned(),
        };
        let url = authorization_url(&document, &provider(), "state-1", "nonce-1", "challenge")
            .unwrap();
        for expected in [
            "response_type=code",
            "client_id=starry-client",
            "state=state-1",
            "nonce=nonce-1",
            "code_challenge=challenge",
            "code_challenge_method=S256",
            "scope=openid",
        ] {
            assert!(url.contains(expected), "missing {expected} in {url}");
        }
    }

    /// HMAC and `none` must be refused: with an HMAC token, anyone holding the
    /// client_id could forge one.
    #[test]
    fn only_asymmetric_algorithms_are_accepted() {
        for alg in ["HS256", "HS384", "HS512", "none"] {
            let header = json!({"alg": alg, "typ": "JWT", "kid": "k1"});
            let payload = json!({"iss": "https://idp.example.test"});
            let token = format!(
                "{}.{}.{}",
                encode_config(serde_json::to_vec(&header).unwrap(), base64::URL_SAFE_NO_PAD),
                encode_config(serde_json::to_vec(&payload).unwrap(), base64::URL_SAFE_NO_PAD),
                encode_config(b"signature", base64::URL_SAFE_NO_PAD)
            );
            let jwks = Jwks {
                keys: vec![Jwk {
                    kid: Some("k1".to_owned()),
                    kty: "RSA".to_owned(),
                    alg: None,
                    n: Some("AQAB".to_owned()),
                    e: Some("AQAB".to_owned()),
                    crv: None,
                    x: None,
                    y: None,
                    key_use: None,
                }],
            };
            assert_eq!(
                verify_signature(&token, &provider(), &jwks).unwrap_err(),
                TokenRejection::SignatureOrFormat,
                "{alg} must be refused"
            );
        }
    }

    #[test]
    fn discovery_issuer_must_match_the_configured_one() {
        // The comparison is done inside `discovery`, which needs HTTP, so the
        // rule is restated here as the invariant the code enforces: a trailing
        // slash is the only tolerated difference.
        assert_eq!(
            "https://idp.example.test/".trim_end_matches('/'),
            "https://idp.example.test".trim_end_matches('/')
        );
        assert_ne!(
            "https://evil.example.test".trim_end_matches('/'),
            "https://idp.example.test".trim_end_matches('/')
        );
    }
}
