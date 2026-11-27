//! End-to-end gates for the Starry API server.
//!
//! These tests exercise the real binary over HTTP and, in the second test,
//! prove that a token minted by `starry-api` is accepted by a real `hbbs`
//! running `connection_auth.mode: enforce` against the published JWKS. That
//! pairing is the whole point of the feature, so it is asserted end to end
//! rather than only at the unit level.

use base64::{decode_config, URL_SAFE_NO_PAD};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::{
        punch_hole_response, rendezvous_message, PunchHoleRequest, RendezvousMessage,
    },
    timeout,
    tokio::{
        net::TcpStream,
        runtime::Builder,
        time::{sleep, Duration},
    },
    tokio_util::codec::Framed,
};
use serde_json::{json, Value};
use sodiumoxide::crypto::sign;
use std::{
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const ADMIN_PASSWORD: &str = "integration-admin-password";
const ISSUER: &str = "https://api.example.test";
const AUDIENCE: &str = "rustdesk-connect";

/// Two tests each start an API server and one also starts hbbs; ports are
/// reserved by binding and releasing, which races between parallel tests.
static GATE_LOCK: Mutex<()> = Mutex::new(());

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

impl Api {
    fn jwks_path(&self) -> PathBuf {
        self.directory.join("auth/jwks.json")
    }
}

fn reserve_port() -> u16 {
    for port in 30_001..60_000u16 {
        let Ok(listener) = StdTcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        drop(listener);
        return port;
    }
    panic!("no free port");
}

fn reserve_hbbs_ports() -> u16 {
    for port in 30_001..60_000u16 {
        let Ok(nat) = StdTcpListener::bind(("127.0.0.1", port - 1)) else {
            continue;
        };
        let Ok(tcp) = StdTcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        let Ok(websocket) = StdTcpListener::bind(("127.0.0.1", port + 2)) else {
            continue;
        };
        drop(websocket);
        drop(tcp);
        drop(nat);
        return port;
    }
    panic!("no free HBBS port set");
}

fn start_api(tag: &str) -> Api {
    let directory = std::env::temp_dir().join(format!(
        "starry-api-{tag}-{}-{}",
        std::process::id(),
        reserve_port()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let port = reserve_port();
    let child = Command::new(env!("CARGO_BIN_EXE_starry-api"))
        .arg("serve")
        .env("RUST_LOG", "warn")
        .env("STARRY_API_LISTEN", format!("127.0.0.1:{port}"))
        .env("STARRY_API_DB", directory.join("users.db"))
        .env("STARRY_API_KEY_FILE", directory.join("api-signing-key"))
        .env("STARRY_API_JWKS_FILE", directory.join("auth/jwks.json"))
        .env("STARRY_API_ISSUER", ISSUER)
        .env("STARRY_API_AUDIENCE", AUDIENCE)
        .env("STARRY_API_BCRYPT_COST", "4")
        .env("ADMIN_PASSWORD", ADMIN_PASSWORD)
        .current_dir(&directory)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let guard = ChildGuard { child, directory: directory.clone() };
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
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("API server did not answer on {base}");
}

fn http_get(url: &str) -> Option<(u16, String)> {
    match minreq::get(url).with_timeout(5).send() {
        Ok(response) => Some((
            u16::try_from(response.status_code).unwrap_or(0),
            response.as_str().unwrap_or("").to_owned(),
        )),
        Err(_) => None,
    }
}

fn http_get_with_bearer(url: &str, token: &str) -> (u16, String) {
    let response = minreq::get(url)
        .with_timeout(5)
        .with_header("Authorization", format!("Bearer {token}"))
        .send()
        .expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn http_post(url: &str, body: &Value) -> (u16, String) {
    http_post_bearer(url, body, None)
}

fn http_post_bearer(url: &str, body: &Value, bearer: Option<&str>) -> (u16, String) {
    let mut request = minreq::post(url)
        .with_timeout(5)
        .with_header("Content-Type", "application/json")
        .with_body(serde_json::to_string(body).unwrap());
    if let Some(token) = bearer {
        request = request.with_header("Authorization", format!("Bearer {token}"));
    }
    let response = request.send().expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn login(api: &Api, password: &str) -> (u16, Value) {
    let (status, body) = http_post(
        &format!("{}/api/login", api.base),
        &json!({
            "username": "admin",
            "password": password,
            "id": "device-1",
            "uuid": "uuid-1",
            "autoLogin": true,
            "type": "account",
            "deviceInfo": {"os": "Linux", "type": "client", "name": "test"},
        }),
    );
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn login_token(api: &Api) -> String {
    let (status, body) = login(api, ADMIN_PASSWORD);
    assert_eq!(status, 200, "login failed: {body}");
    body["access_token"].as_str().unwrap().to_owned()
}

fn decode_segment(segment: &str) -> Vec<u8> {
    decode_config(segment, URL_SAFE_NO_PAD).expect("token segment is not base64url")
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn login_contract_matches_the_official_client_and_publishes_a_usable_jwks() {
    let _guard = GATE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let api = start_api("contract");

    // login-options: the client decodes a JSON array of provider strings.
    let (status, body) = http_get(&format!("{}/api/login-options", api.base)).unwrap();
    assert_eq!(status, 200);
    let options: Vec<String> = serde_json::from_str(&body).expect("login-options must be an array");
    assert!(options.is_empty());

    // Wrong credentials: non-200 plus an `error` string the client shows.
    let (status, body) = login(&api, "definitely-wrong");
    assert_eq!(status, 401);
    assert_eq!(body["error"], "UsernameOrPasswordError", "body: {body}");

    // Right credentials: the exact LoginResponse shape.
    let (status, body) = login(&api, ADMIN_PASSWORD);
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["type"], "access_token");
    let token = body["access_token"].as_str().unwrap();
    assert_eq!(body["user"]["name"], "admin");
    assert_eq!(body["user"]["status"], 1);
    assert_eq!(body["user"]["is_admin"], true);
    assert!(body["user"]["info"].is_object(), "Rust client requires user.info");
    assert!(body.get("user_info").is_none(), "the client reads `user`, not `user_info`");

    // JWT header must be the EdDSA/at+jwt/kid shape hbbs requires.
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3);
    let header: Value = serde_json::from_slice(&decode_segment(segments[0])).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "at+jwt");
    let kid = header["kid"].as_str().unwrap().to_owned();

    // The published JWKS must verify the signature and name the same kid.
    let jwks: Value = serde_json::from_slice(&fs::read(api.jwks_path()).unwrap()).unwrap();
    let jwk = &jwks["keys"][0];
    assert_eq!(jwk["kid"], kid);
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["alg"], "EdDSA");
    let public = sign::PublicKey::from_slice(
        &decode_config(jwk["x"].as_str().unwrap(), URL_SAFE_NO_PAD).unwrap(),
    )
    .unwrap();
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let signature = sign::Signature::from_bytes(&decode_segment(segments[2])).unwrap();
    assert!(
        sign::verify_detached(&signature, signing_input.as_bytes(), &public),
        "JWKS must verify the login token"
    );

    // Claims carry everything hbbs checks.
    let claims: Value = serde_json::from_slice(&decode_segment(segments[1])).unwrap();
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], AUDIENCE);
    assert_eq!(claims["token_use"], "access");
    assert_eq!(claims["scope"], "connect:initiate");
    assert_eq!(claims["user_id"], 1);
    assert_eq!(claims["sub"], "1");
    assert_eq!(claims["auth_version"], 1);
    assert!(uuid::Uuid::parse_str(claims["jti"].as_str().unwrap()).is_ok());
    let iat = claims["iat"].as_u64().unwrap();
    let exp = claims["exp"].as_u64().unwrap();
    assert!(iat <= now_seconds() + 5);
    assert!(exp > now_seconds());
    assert!(exp > iat);

    // The digest-bound freshness sidecar is what makes hbbs accept the file.
    let metadata: Value = serde_json::from_slice(
        &fs::read(api.directory.join("auth/jwks.json.metadata.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["version"], 1);
    assert!(metadata["fetched_at_epoch_seconds"].as_u64().unwrap() >= iat);
    assert_eq!(
        metadata["jwks_sha256"].as_str().unwrap().len(),
        64,
        "sidecar carries the hex keyset digest"
    );

    // currentUser: flat UserPayload, 401 without a bearer token.
    let (status, body) = http_post_bearer(
        &format!("{}/api/currentUser", api.base),
        &json!({"id": "device-1", "uuid": "uuid-1"}),
        Some(&token),
    );
    assert_eq!(status, 200, "body: {body}");
    let user: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(user["name"], "admin");
    assert_eq!(user["is_admin"], true);

    let (status, _) = http_post_bearer(
        &format!("{}/api/currentUser", api.base),
        &json!({}),
        None,
    );
    assert_eq!(status, 401);

    // A short-lived connection token is minted for tooling and verifies with
    // the same key, but never outlives the configured window.
    let (status, body) = http_post_bearer(
        &format!("{}/api/connection-token", api.base),
        &json!({}),
        Some(&token),
    );
    assert_eq!(status, 200, "body: {body}");
    let connection: Value = serde_json::from_str(&body).unwrap();
    let connection_token = connection["token"].as_str().unwrap();
    let connection_claims: Value =
        serde_json::from_slice(&decode_segment(connection_token.split('.').nth(1).unwrap())).unwrap();
    let connection_exp = connection_claims["exp"].as_u64().unwrap();
    assert!(connection_exp > now_seconds());
    assert!(connection_exp <= now_seconds() + 3_660);

    // Logout revokes the session: the same token stops working immediately.
    let (status, _) = http_post_bearer(
        &format!("{}/api/logout", api.base),
        &json!({"id": "device-1", "uuid": "uuid-1"}),
        Some(&token),
    );
    assert_eq!(status, 200);
    let (status, _) = http_post_bearer(
        &format!("{}/api/currentUser", api.base),
        &json!({}),
        Some(&token),
    );
    assert_eq!(status, 401, "a logged-out token must stop working");

    // Address book: a literal null is the client's "no address book" reply.
    let (status, body) = http_get_with_bearer(&format!("{}/api/ab", api.base), &login_token(&api));
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "null");
    let (status, _) = http_get(&format!("{}/api/ab", api.base)).unwrap();
    assert_eq!(status, 401);

    // Unknown endpoints answer JSON so clients never choke on HTML.
    let (status, body) = http_get(&format!("{}/api/nope", api.base)).unwrap();
    assert_eq!(status, 404);
    assert!(serde_json::from_str::<Value>(&body).is_ok());
}

#[test]
fn hbbs_enforce_accepts_api_minted_tokens_end_to_end() {
    let _guard = GATE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sodiumoxide::init().unwrap();
    let api = start_api("enforce");
    let token = login_token(&api);

    let hbbs_directory = api.directory.join("hbbs");
    fs::create_dir_all(&hbbs_directory).unwrap();
    let config_path = hbbs_directory.join("config.yaml");
    let config_yaml = format!(
        "version: 3
relay_servers:
  - relay.example.test:21117
secure_tcp:
  mode: auto
connection_auth:
  mode: enforce
  issuer: {ISSUER}
  audience: {AUDIENCE}
  token_use: access
  required_scope: connect:initiate
  jwks:
    file: {}
",
        api.jwks_path().display()
    );
    fs::write(&config_path, config_yaml).unwrap();

    let port = reserve_hbbs_ports();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .arg("--port")
        .arg(port.to_string())
        .arg(format!("--starry-config={}", config_path.display()))
        .env("RUST_LOG", "warn")
        .current_dir(&hbbs_directory)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let hbbs = ChildGuard {
        child,
        directory: PathBuf::new(),
    };

    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            wait_until_listening(SocketAddr::from(([127, 0, 0, 1], port))).await;
            // A token minted by the API must reach normal protocol handling.
            assert_normal_protocol_result(punch(port, &token).await);
            // Anonymous connections are what enforce mode exists to stop.
            assert_denied(punch(port, "").await);
            // A token from a different key must be rejected the same way.
            let (_, attacker) = sign::gen_keypair();
            assert_denied(punch(port, &forged_token(&attacker)).await);
        });
    drop(hbbs);
}

async fn wait_until_listening(address: SocketAddr) {
    for _ in 0..300 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("hbbs did not listen on {address}");
}

async fn punch_exchange(port: u16, request: RendezvousMessage) -> RendezvousMessage {
    let exchange = async {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut framed = Framed::new(stream, BytesCodec::new());
        let offer = framed.next().await.unwrap().unwrap();
        let offer = RendezvousMessage::parse_from_bytes(&offer).unwrap();
        assert!(matches!(
            offer.union,
            Some(rendezvous_message::Union::KeyExchange(_))
        ));
        framed
            .send(Bytes::from(request.write_to_bytes().unwrap()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        RendezvousMessage::parse_from_bytes(&response).unwrap()
    };
    timeout(5_000, exchange).await.unwrap()
}

async fn punch(port: u16, token: &str) -> RendezvousMessage {
    punch_exchange(port, punch_message(token)).await
}

fn punch_message(token: &str) -> RendezvousMessage {
    RendezvousMessage {
        union: Some(rendezvous_message::Union::PunchHoleRequest(PunchHoleRequest {
            id: "some-target-id".to_owned(),
            token: token.to_owned(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn assert_normal_protocol_result(message: RendezvousMessage) {
    let Some(rendezvous_message::Union::PunchHoleResponse(response)) = message.union else {
        panic!("authenticated request did not reach normal protocol handling");
    };
    assert_eq!(
        response.failure.enum_value().ok(),
        Some(punch_hole_response::Failure::LICENSE_MISMATCH)
    );
    assert!(response.other_failure.is_empty());
}

fn assert_denied(message: RendezvousMessage) {
    let Some(rendezvous_message::Union::PunchHoleResponse(response)) = message.union else {
        panic!("expected a punch hole denial");
    };
    assert_eq!(
        response.other_failure, "connection authorization failed",
        "message: {:?}",
        response
    );
}

fn forged_token(attacker: &sign::SecretKey) -> String {
    let now = now_seconds();
    let header = base64::encode_config(
        serde_json::to_vec(&json!({"alg": "EdDSA", "kid": "starry-api-forged", "typ": "at+jwt"}))
            .unwrap(),
        URL_SAFE_NO_PAD,
    );
    let payload = base64::encode_config(
        serde_json::to_vec(&json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "token_use": "access",
            "scope": "connect:initiate",
            "sub": "1",
            "user_id": 1,
            "auth_version": 1,
            "jti": "01941f29-7c30-7000-8000-000000001001",
            "iat": now,
            "nbf": now,
            "exp": now + 600
        }))
        .unwrap(),
        URL_SAFE_NO_PAD,
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign::sign_detached(signing_input.as_bytes(), attacker);
    format!(
        "{signing_input}.{}",
        base64::encode_config(signature.as_ref(), URL_SAFE_NO_PAD)
    )
}
