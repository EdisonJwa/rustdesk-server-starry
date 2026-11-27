//! End-to-end gate for OIDC login.
//!
//! Runs the real `starry-api` binary against a real, locally hosted identity
//! provider, and drives the exact three-step sequence the official client
//! performs:
//!
//! 1. `GET /api/login-options` — must advertise the provider in the
//!    `common-oidc/` form the client parses.
//! 2. `POST /api/oidc/auth` — must answer `{code, url}` where the URL really is
//!    a valid authorization request.
//! 3. `GET /api/oidc/auth-query` — must keep answering
//!    `{"body": "{\"error\": \"No authed oidc is found\"}"}` until the browser
//!    half finishes, then answer the access-token document inside the same
//!    `body` wrapper.
//!
//! The provider is a hand-written HTTP server rather than a mock crate: the
//! point of this test is the wire format, so the fixtures must be bytes on a
//! socket, not a function call.

use base64::{encode_config, URL_SAFE_NO_PAD};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const ADMIN_PASSWORD: &str = "integration-admin-password";
const AUDIENCE: &str = "rustdesk-connect";
const CLIENT_ID: &str = "starry-oidc-test";
const PROVIDER_NAME: &str = "testidp";

/// The API server and the fake provider both bind ports, and two tests in one
/// binary would race for them.
static GATE_LOCK: Mutex<()> = Mutex::new(());

/// Takes the gate without inheriting a previous test's panic.
///
/// A plain `.lock().unwrap()` poisons the mutex when any test panics, which
/// turns one real failure into a cascade of `PoisonError`s and buries the
/// original cause.
fn gate() -> std::sync::MutexGuard<'static, ()> {
    GATE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn reserve_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    // Two hazards, both handled here:
    //
    // * within a binary, two tests probing the same port before either binds it;
    // * across binaries, `auth_server` and `oidc_login` are separate processes
    //   that can pick the same port while the other is still starting.
    //
    // A monotonic per-process cursor starting from a per-process offset deals
    // with both without a lock file: the OS probe remains the authority on
    // whether the port is actually free.
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = NEXT
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add((std::process::id() % 97) as u16);
    for _ in 0..29_000u16 {
        let port = 30_001 + (base.wrapping_mul(37) + NEXT.fetch_add(1, Ordering::SeqCst)) % 29_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port");
}

// ---------------------------------------------------------------------------
// Fake identity provider
// ---------------------------------------------------------------------------

/// An Ed25519-free EC P-256 key pair, generated with rcgen's ring backend.
///
/// EC is used rather than RSA because `jsonwebtoken` is built without
/// `use_pem` here: EC signing needs only a DER key, while RSA would need PEM
/// support to construct a signing key at all.
struct SigningMaterial {
    encoding_key: EncodingKey,
    jwk: Value,
}

fn generate_signing_material() -> SigningMaterial {
    // rcgen generates a PKCS#8 EC key. `serialize_der` gives the private key
    // that `EncodingKey::from_ec_der` accepts.
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("cannot generate an EC key pair");
    let private_der = key_pair.serialize_der();
    // The public key is the last 65 bytes: 0x04 || X(32) || Y(32).
    let public = key_pair.public_key_raw();
    assert_eq!(public.len(), 65, "uncompressed P-256 point expected");
    let x = encode_config(&public[1..33], URL_SAFE_NO_PAD);
    let y = encode_config(&public[33..65], URL_SAFE_NO_PAD);
    SigningMaterial {
        encoding_key: EncodingKey::from_ec_der(&private_der),
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": "test-key-1",
            "x": x,
            "y": y,
        }),
    }
}

/// State the fake provider needs while serving requests.
struct ProviderState {
    issuer: String,
    material: SigningMaterial,
    /// The `nonce` the API server asked for, captured from the authorization
    /// URL it handed the client, so the id_token can echo it back.
    expected_nonce: Mutex<Option<String>>,
    /// The PKCE challenge, captured so the token endpoint can be strict about
    /// receiving the matching verifier.
    expected_challenge: Mutex<Option<String>>,
    /// Set once the token endpoint has been called, so the test can assert the
    /// browser half really did exchange its code.
    token_calls: AtomicU64,
    /// When true, the token endpoint returns an error instead of an id_token.
    fail_token: AtomicBool,
    /// Set on drop so the accept loop exits and releases its port before the
    /// next test starts looking for one.
    stop: AtomicBool,
}

/// Stops the provider when it goes out of scope, so the port is free for the
/// next test regardless of how this one ends.
struct ProviderGuard(Arc<ProviderState>);

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::SeqCst);
        // Give the accept loop a moment to observe the flag and drop its
        // listener; a few file-descriptor cycles is far cheaper than a flaky
        // port collision.
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start_provider() -> (ProviderGuard, Arc<ProviderState>, u16) {
    let port = reserve_port();
    let issuer = format!("http://127.0.0.1:{port}");
    let state = Arc::new(ProviderState {
        issuer: issuer.clone(),
        material: generate_signing_material(),
        expected_nonce: Mutex::new(None),
        expected_challenge: Mutex::new(None),
        token_calls: AtomicU64::new(0),
        fail_token: AtomicBool::new(false),
        stop: AtomicBool::new(false),
    });
    let serving = state.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("cannot bind the fake provider");
        // Non-blocking accept with a short sleep, so the loop can notice `stop`
        // without needing a self-connect to wake it. The listener is dropped
        // when this closure returns, which releases the port.
        listener
            .set_nonblocking(true)
            .expect("cannot make the provider listener non-blocking");
        while !serving.stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = serving.clone();
                    std::thread::spawn(move || {
                        let _ = handle_provider_connection(stream, &state);
                    });
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (ProviderGuard(state.clone()), state, port)
}

fn handle_provider_connection(mut stream: TcpStream, state: &ProviderState) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("/").to_owned();

    // Drain the headers, remembering Content-Length for the POST body.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    let path = target.split('?').next().unwrap_or("/");
    let query = target.split_once('?').map(|(_, q)| q.to_owned()).unwrap_or_default();

    let (status, content_type, payload) = match (method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => (
            "200 OK",
            "application/json",
            json!({
                "issuer": state.issuer,
                "authorization_endpoint": format!("{}/authorize", state.issuer),
                "token_endpoint": format!("{}/token", state.issuer),
                "jwks_uri": format!("{}/jwks", state.issuer),
            })
            .to_string(),
        ),
        ("GET", "/jwks") => (
            "200 OK",
            "application/json",
            json!({"keys": [state.material.jwk]}).to_string(),
        ),
        // The API server does not call this; the test does, to simulate the
        // browser. It records the nonce and challenge the client was given.
        ("GET", "/authorize") => {
            let mut nonce = None;
            let mut challenge = None;
            for pair in query.split('&') {
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                let decoded = urldecode(value);
                match name {
                    "nonce" => nonce = Some(decoded),
                    "code_challenge" => challenge = Some(decoded),
                    _ => {}
                }
            }
            *state.expected_nonce.lock().unwrap() = nonce;
            *state.expected_challenge.lock().unwrap() = challenge;
            (
                "200 OK",
                "application/json",
                json!({"status": "authorize reached"}).to_string(),
            )
        }
        ("POST", "/token") => {
            state.token_calls.fetch_add(1, Ordering::SeqCst);
            if state.fail_token.load(Ordering::SeqCst) {
                ("400 Bad Request", "application/json", json!({"error": "invalid_grant"}).to_string())
            } else {
                let sub = form_field(&body, "sub").unwrap_or_else(|| "subject-1".to_owned());
                let nonce = state.expected_nonce.lock().unwrap().clone();
                let claims = id_token_claims(&state.issuer, &sub, nonce.as_deref());
                let mut header = Header::new(Algorithm::ES256);
                header.kid = Some("test-key-1".to_owned());
                let id_token = encode(&header, &claims, &state.material.encoding_key)
                    .expect("cannot sign the id_token");
                (
                    "200 OK",
                    "application/json",
                    json!({"id_token": id_token, "token_type": "Bearer"}).to_string(),
                )
            }
        }
        _ => ("404 Not Found", "text/plain", "not found".to_owned()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn id_token_claims(issuer: &str, subject: &str, nonce: Option<&str>) -> Value {
    let now = now_seconds();
    let mut claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 600,
        "preferred_username": "alice",
        "email": "alice@example.test",
        "email_verified": true,
        "name": "Alice Example",
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    claims
}

fn form_field(body: &str, name: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| urldecode(value))
    })
}

fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// API server under test
// ---------------------------------------------------------------------------

struct ChildGuard {
    child: Child,
    directory: PathBuf,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Api {
    base: String,
    directory: PathBuf,
    _child: ChildGuard,
}

fn start_api_with_oidc(tag: &str, oidc_document: Option<&str>) -> Api {
    let directory = std::env::temp_dir().join(format!(
        "starry-api-oidc-{tag}-{}-{}",
        std::process::id(),
        reserve_port()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let port = reserve_port();
    let oidc_path = directory.join("oidc.json");
    if let Some(document) = oidc_document {
        fs::write(&oidc_path, document).unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_starry-api"));
    command
        .arg("serve")
        .env("RUST_LOG", "warn")
        .env("STARRY_API_LISTEN", format!("127.0.0.1:{port}"))
        .env("STARRY_API_DB", directory.join("users.db"))
        .env("STARRY_API_KEY_FILE", directory.join("api-signing-key"))
        .env("STARRY_API_JWKS_FILE", directory.join("auth/jwks.json"))
        .env("STARRY_API_ISSUER", "https://api.example.test")
        .env("STARRY_API_AUDIENCE", AUDIENCE)
        .env("STARRY_API_BCRYPT_COST", "4")
        .env("ADMIN_PASSWORD", ADMIN_PASSWORD)
        .current_dir(&directory)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if oidc_document.is_some() {
        command.env("STARRY_OIDC_CONFIG", &oidc_path);
    }
    let child = command.spawn().unwrap();
    let guard = ChildGuard {
        child,
        directory: directory.clone(),
    };
    let api = Api {
        base: format!("http://127.0.0.1:{port}"),
        directory,
        _child: guard,
    };
    wait_until_http(&api.base);
    api
}

fn wait_until_http(base: &str) {
    for _ in 0..300 {
        if http_get(&format!("{base}/api/login-options")).is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("API server did not answer on {base}");
}

fn http_get(url: &str) -> Option<(u16, String)> {
    match minreq::get(url).with_timeout(10).send() {
        Ok(response) => Some((
            u16::try_from(response.status_code).unwrap_or(0),
            response.as_str().unwrap_or("").to_owned(),
        )),
        Err(_) => None,
    }
}

fn http_post_json(url: &str, body: &Value) -> (u16, String) {
    let response = minreq::post(url)
        .with_timeout(10)
        .with_header("Content-Type", "application/json")
        .with_body(serde_json::to_string(body).unwrap())
        .send()
        .expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

// ---------------------------------------------------------------------------
// The gates
// ---------------------------------------------------------------------------

/// Without a config the endpoints must say "not configured" rather than
/// silently behaving as if OIDC were on.
#[test]
fn oidc_is_off_without_a_config_file() {
    let _guard = gate();
    let api = start_api_with_oidc("off", None);
    let base = api.base.clone();

    let (status, body) = http_get(&format!("{base}/api/login-options")).unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body.trim(),
        "[]",
        "login-options must stay an empty array when no provider is configured"
    );

    let (status, _) = http_post_json(
        &format!("{base}/api/oidc/auth"),
        &json!({"op": PROVIDER_NAME, "id": "1", "uuid": "u", "deviceInfo": {}, "apiDomain": ""}),
    );
    assert_eq!(status, 501, "an unconfigured OIDC start must not look usable");
}

/// The full client sequence against a real provider.
#[test]
fn oidc_login_round_trip_mints_a_usable_access_token() {
    let _guard = gate();
    let (_provider_guard, provider, port) = start_provider();
    let redirect = format!("http://127.0.0.1:{}/oidc/callback", reserve_port());
    let document = json!({
        "providers": [{
            "name": PROVIDER_NAME,
            "icon": "github",
            "issuer": provider.issuer,
            "client_id": CLIENT_ID,
            "redirect_uri": redirect,
            "scopes": ["profile"],
        }]
    })
    .to_string();
    let api = start_api_with_oidc("roundtrip", Some(&document));
    let base = api.base.clone();
    let _ = port;

    // 1. The client discovers the provider.
    let (status, body) = http_get(&format!("{base}/api/login-options")).unwrap();
    assert_eq!(status, 200);
    let options: Vec<String> = serde_json::from_str(&body).expect("login-options must be an array");
    let entry = options
        .iter()
        .find_map(|entry| entry.strip_prefix("common-oidc/"))
        .expect("the client looks for the common-oidc/ prefix first");
    let advertised: Value = serde_json::from_str(entry).unwrap();
    assert_eq!(advertised[0]["name"], PROVIDER_NAME);
    assert_eq!(advertised[0]["icon"], "github");

    // 2. The client asks to start a login.
    let (status, body) = http_post_json(
        &format!("{base}/api/oidc/auth"),
        &json!({
            "op": PROVIDER_NAME,
            "id": "device-1",
            "uuid": "018f0000-0000-7000-8000-000000000001",
            "deviceInfo": {"os": "Linux", "type": "client", "name": "test"},
            "apiDomain": api.base,
        }),
    );
    assert_eq!(status, 200, "start failed: {body}");
    let started: Value = serde_json::from_str(&body).unwrap();
    let code = started["code"].as_str().unwrap().to_owned();
    let auth_url = started["url"].as_str().unwrap().to_owned();
    assert!(auth_url.contains("code_challenge_method=S256"), "{auth_url}");
    assert!(auth_url.contains("response_type=code"), "{auth_url}");

    // 3. Polling before the browser finishes must keep the client waiting.
    let poll_url = format!("{base}/api/oidc/auth-query?code={code}&id=device-1&uuid=u");
    let (status, body) = http_get(&poll_url).unwrap();
    assert_eq!(status, 200);
    let wrapper: Value = serde_json::from_str(&body).expect("the answer must be an object");
    let inner: Value =
        serde_json::from_str(wrapper["body"].as_str().expect("a body string")).unwrap();
    assert_eq!(
        inner["error"], "No authed oidc is found",
        "the client only keeps polling for this exact error"
    );

    // 4. The browser half: the test plays the user's browser. Opening the
    //    authorization URL is what the real client does when the user picks a
    //    provider, and it is how the provider learns the nonce and the PKCE
    //    challenge it must echo back.
    let (status, _) = http_get(&auth_url).expect("the provider must answer /authorize");
    assert_eq!(status, 200, "the authorization endpoint must be reachable");

    // The provider has now captured the nonce from that request.
    let nonce = provider
        .expected_nonce
        .lock()
        .unwrap()
        .clone()
        .expect("the provider must have seen a nonce");
    assert!(!nonce.is_empty(), "the nonce must not be empty");
    assert!(
        provider.expected_challenge.lock().unwrap().is_some(),
        "PKCE challenge must be present"
    );

    // 5. Simulate the IdP redirecting the browser back.
    let state_param = extract_query(&auth_url, "state").expect("state in the authorization URL");
    let callback = format!("{}/oidc/callback?code=auth-code-1&state={state_param}", api.base);
    let (status, _) = http_get(&callback).unwrap();
    assert_eq!(status, 200, "the callback must complete the browser half");
    assert_eq!(
        provider.token_calls.load(Ordering::SeqCst),
        1,
        "the callback must redeem the authorization code exactly once"
    );

    // 6. The next poll returns the credential, wrapped the way the client reads
    //    it.
    let (status, body) = http_get(&poll_url).unwrap();
    assert_eq!(status, 200);
    let wrapper: Value = serde_json::from_str(&body).unwrap();
    let inner: Value =
        serde_json::from_str(wrapper["body"].as_str().expect("a body string")).unwrap();
    assert_eq!(inner["type"], "access_token");
    let token = inner["access_token"].as_str().expect("an access token");
    assert!(!token.is_empty());
    assert_eq!(inner["user"]["name"], "alice");
    assert_eq!(inner["user"]["email"], "alice@example.test");
    // The Rust client's UserPayload carries `info` unconditionally.
    assert!(inner["user"]["info"].is_object());

    // The token really is the connection credential hbbs will see, so its
    // claims must carry everything `connection_auth` checks.
    let claims = decode_jwt_payload(token);
    assert_eq!(claims["token_use"], "access");
    assert_eq!(claims["aud"], AUDIENCE);
    assert_eq!(claims["scope"], "connect:initiate");
    assert!(claims["user_id"].as_i64().unwrap() > 0);
    assert!(claims["auth_version"].as_i64().unwrap() != 0);

    // 7. The credential is issued once: a second poll must not hand it out.
    let (_, body) = http_get(&poll_url).unwrap();
    let wrapper: Value = serde_json::from_str(&body).unwrap();
    let inner: Value = serde_json::from_str(wrapper["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner["error"], "No authed oidc is found",
        "a spent code must not mint a second credential"
    );
}

/// A rejected id_token must not produce a credential.
#[test]
fn oidc_callback_refuses_a_token_with_a_bad_nonce() {
    let _guard = gate();
    let (_provider_guard, provider, _) = start_provider();
    let redirect = format!("http://127.0.0.1:{}/oidc/callback", reserve_port());
    let document = json!({
        "providers": [{
            "name": PROVIDER_NAME,
            "issuer": provider.issuer,
            "client_id": CLIENT_ID,
            "redirect_uri": redirect,
        }]
    })
    .to_string();
    let api = start_api_with_oidc("badnonce", Some(&document));
    let base = api.base.clone();

    let (_, body) = http_post_json(
        &format!("{base}/api/oidc/auth"),
        &json!({"op": PROVIDER_NAME, "id": "d", "uuid": "u", "deviceInfo": {}}),
    );
    let started: Value = serde_json::from_str(&body).unwrap();
    let code = started["code"].as_str().unwrap().to_owned();
    let auth_url = started["url"].as_str().unwrap().to_owned();
    let state_param = extract_query(&auth_url, "state").unwrap();

    // Reach the provider's /authorize so it captures a nonce, then overwrite it
    // with a different one: the id_token will carry a nonce this login never
    // asked for.
    let _ = http_get(&auth_url).unwrap_or((0, String::new()));
    *provider.expected_nonce.lock().unwrap() = Some("nonce-from-another-login".to_owned());

    let callback = format!("{}/oidc/callback?code=c1&state={state_param}", api.base);
    let (status, _) = http_get(&callback).unwrap();
    assert_eq!(
        status, 401,
        "a token whose nonce does not match must be refused"
    );

    let poll_url = format!("{base}/api/oidc/auth-query?code={code}&id=d&uuid=u");
    let (_, body) = http_get(&poll_url).unwrap();
    let wrapper: Value = serde_json::from_str(&body).unwrap();
    let inner: Value = serde_json::from_str(wrapper["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner["error"], "No authed oidc is found",
        "a refused callback must never look like success"
    );
}

/// A token endpoint failure must not complete the login.
#[test]
fn oidc_token_exchange_failure_leaves_the_login_pending() {
    let _guard = gate();
    let (_provider_guard, provider, _) = start_provider();
    provider.fail_token.store(true, Ordering::SeqCst);
    let redirect = format!("http://127.0.0.1:{}/oidc/callback", reserve_port());
    let document = json!({
        "providers": [{
            "name": PROVIDER_NAME,
            "issuer": provider.issuer,
            "client_id": CLIENT_ID,
            "redirect_uri": redirect,
        }]
    })
    .to_string();
    let api = start_api_with_oidc("failtoken", Some(&document));
    let base = api.base.clone();

    let (_, body) = http_post_json(
        &format!("{base}/api/oidc/auth"),
        &json!({"op": PROVIDER_NAME, "id": "d", "uuid": "u", "deviceInfo": {}}),
    );
    let started: Value = serde_json::from_str(&body).unwrap();
    let state_param = extract_query(started["url"].as_str().unwrap(), "state").unwrap();
    let callback = format!("{}/oidc/callback?code=c1&state={state_param}", api.base);
    let (status, _) = http_get(&callback).unwrap();
    assert_eq!(status, 401);
}

/// An unknown or expired state must be refused without completing anything.
#[test]
fn oidc_callback_rejects_an_unknown_state() {
    let _guard = gate();
    let api = start_api_with_oidc("badstate", None);
    let (status, _) = http_get(&format!(
        "{}/oidc/callback?code=abc&state=never-issued",
        api.base
    ))
    .unwrap();
    assert_eq!(status, 400);
}

fn extract_query(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| urldecode(value))
    })
}

/// Reads a JWT payload without verifying it, which is enough to assert the
/// claims this server minted.
fn decode_jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT payload segment");
    let padding = (4 - payload.len() % 4) % 4;
    let padded = format!("{payload}{}", "=".repeat(padding));
    let bytes = base64::decode_config(padded, base64::STANDARD).unwrap();
    serde_json::from_slice(&bytes).expect("a JSON payload")
}
