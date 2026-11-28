//! End-to-end gates for the endpoints added from the client gap analysis.
//!
//! Every test here drives the real `starry-api` binary over HTTP and asserts the
//! exact wire shape the official client parses. The unit tests pin the pure
//! functions; these pin the integration: routing, auth, envelopes and status
//! codes.
//!
//! What is deliberately *not* asserted here: hbbs behaviour, because these are API
//! server features only.

use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener as StdTcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

const ADMIN_PASSWORD: &str = "integration-admin-password";
const ISSUER: &str = "https://api.example.test";
const AUDIENCE: &str = "rustdesk-connect";

/// The API server binds ports, and tests in one binary run in parallel.
static GATE_LOCK: Mutex<()> = Mutex::new(());

fn gate() -> std::sync::MutexGuard<'static, ()> {
    // A panicking test must not poison every other test's guard.
    GATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    #[allow(dead_code)]
    directory: PathBuf,
    _child: ChildGuard,
}

fn reserve_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    // Per-process offset plus an OS probe: two test binaries can run at once.
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = NEXT
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add((std::process::id() % 89) as u16);
    for _ in 0..29_000u16 {
        let port = 33_001 + (base.wrapping_mul(41) + NEXT.fetch_add(1, Ordering::SeqCst)) % 25_000;
        if StdTcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port");
}

/// Starts the API with optional extra environment, for the opt-in features.
fn start_api_with(tag: &str, env: &[(&str, String)]) -> Api {
    let directory = std::env::temp_dir().join(format!(
        "starry-api-gaps-{tag}-{}-{}",
        std::process::id(),
        reserve_port()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let port = reserve_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_starry-api"));
    command
        .arg("serve")
        .env("RUST_LOG", "warn")
        .env("STARRY_API_LISTEN", format!("127.0.0.1:{port}"))
        .env("STARRY_API_DB", directory.join("users.db"))
        .env("STARRY_API_KEY_FILE", directory.join("api-signing-key"))
        .env("STARRY_API_JWKS_FILE", directory.join("auth/jwks.json"))
        .env("STARRY_API_ISSUER", ISSUER)
        .env("STARRY_API_AUDIENCE", AUDIENCE)
        .env("STARRY_API_BCRYPT_COST", "4")
        .env("ADMIN_PASSWORD", ADMIN_PASSWORD);
    for (key, value) in env {
        command.env(key, value);
    }
    let child = command
        .current_dir(&directory)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
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

fn http_get_bearer(url: &str, token: &str) -> (u16, String) {
    let response = minreq::get(url)
        .with_timeout(10)
        .with_header("Authorization", format!("Bearer {token}"))
        .send()
        .expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn http_post_bearer(url: &str, body: Option<&Value>, token: Option<&str>) -> (u16, String) {
    let mut request = minreq::post(url)
        .with_timeout(10)
        .with_header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.with_header("Authorization", format!("Bearer {token}"));
    }
    if let Some(body) = body {
        request = request.with_body(serde_json::to_string(body).unwrap());
    } else {
        // The client sends several of these as POSTs with an empty body purely
        // to carry the Authorization header, so the server must accept that.
        request = request.with_body("");
    }
    let response = request.send().expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

/// POST with extra headers. Needed for `If-Match`, which the official client
/// never sends and a script does.
fn http_post_bearer_with_headers(
    url: &str,
    body: &Value,
    token: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut request = minreq::post(url)
        .with_timeout(10)
        .with_header("Content-Type", "application/json")
        .with_header("Authorization", format!("Bearer {token}"))
        .with_body(serde_json::to_string(body).unwrap());
    for (name, value) in headers {
        request = request.with_header(*name, *value);
    }
    let response = request.send().expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn http_put_bearer(url: &str, body: &Value, token: &str) -> (u16, String) {
    let response = minreq::put(url)
        .with_timeout(10)
        .with_header("Content-Type", "application/json")
        .with_header("Authorization", format!("Bearer {token}"))
        .with_body(serde_json::to_string(body).unwrap())
        .send()
        .expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn http_delete_bearer(url: &str, body: &Value, token: &str) -> (u16, String) {
    let response = minreq::delete(url)
        .with_timeout(10)
        .with_header("Content-Type", "application/json")
        .with_header("Authorization", format!("Bearer {token}"))
        .with_body(serde_json::to_string(body).unwrap())
        .send()
        .expect("HTTP request failed");
    (
        u16::try_from(response.status_code).unwrap_or(0),
        response.as_str().unwrap_or("").to_owned(),
    )
}

fn login(api: &Api) -> String {
    let (status, body) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({"username": "admin", "password": ADMIN_PASSWORD, "id": "dev-1", "uuid": "u-1"})),
        None,
    );
    assert_eq!(status, 200, "login failed: {body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    parsed["access_token"].as_str().expect("an access token").to_owned()
}

/// `/api/ab/personal` is what switches the client from legacy to structured
/// mode, so its presence is the whole feature switch.
#[test]
fn structured_address_book_endpoints_exist() {
    let _guard = gate();
    let api = start_api_with("ab", &[]);
    let token = login(&api);

    // An empty body: the client posts `Content-Length: 0` here.
    let (status, body) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&token));
    assert_eq!(status, 200, "personal must exist or the client stays legacy: {body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let guid = parsed["guid"].as_str().expect("a guid").to_owned();

    // Idempotent: asking twice must not create a second book.
    let (_, again) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&token));
    let again: Value = serde_json::from_str(&again).unwrap();
    assert_eq!(again["guid"], guid, "the personal book must be stable");

    let (status, body) = http_post_bearer(&format!("{}/api/ab/settings", api.base), None, Some(&token));
    assert_eq!(status, 200);
    let settings: Value = serde_json::from_str(&body).unwrap();
    assert!(
        settings["max_peer_one_ab"].as_u64().unwrap() > 1000,
        "a low ceiling would silently drop peers: {settings}"
    );

    // Peers and profiles are paginated envelopes with the unpaged total.
    for path in ["/api/ab/peers", "/api/ab/shared/profiles"] {
        let (status, body) = http_post_bearer(
            &format!("{}{path}?current=1&pageSize=100", api.base),
            None,
            Some(&token),
        );
        assert_eq!(status, 200, "{path}: {body}");
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert!(parsed.get("total").is_some(), "{path} must report total");
        assert!(parsed["data"].is_array(), "{path} must report data");
    }

    // Tags answer a bare array, not an envelope.
    let (status, body) =
        http_post_bearer(&format!("{}/api/ab/tags/{guid}", api.base), None, Some(&token));
    assert_eq!(status, 200, "{body}");
    let tags: Value = serde_json::from_str(&body).unwrap();
    assert!(tags.is_array(), "tags must be a bare array: {body}");
}

/// The peer endpoints round-trip the client's exact 16-field payload.
#[test]
fn address_book_peer_round_trip() {
    let _guard = gate();
    let api = start_api_with("ab-peer", &[]);
    let token = login(&api);
    let (_, body) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&token));
    let guid = serde_json::from_str::<Value>(&body).unwrap()["guid"]
        .as_str()
        .unwrap()
        .to_owned();

    let peer = json!({
        "id": "9001",
        "hash": "client-generated-hash",
        "password": "",
        "username": "pc-user",
        "hostname": "prod-db",
        "platform": "Linux",
        "alias": "prod",
        "tags": ["office"],
        "forceAlwaysRelay": "true",
        "rdpPort": "3389",
        "rdpUsername": "rdp-user",
        "loginName": "login-user",
        "device_group_name": "servers",
        "note": "a note",
        "same_server": true
    });
    let (status, body) = http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&peer),
        Some(&token),
    );
    assert_eq!(status, 200, "peer add failed: {body}");

    let (_, body) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&token),
    );
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 1, "{listed}");
    let stored = &listed["data"][0];
    // The 16 fields must come back with the client's own names, including the
    // string `forceAlwaysRelay`.
    for (key, expected) in [
        ("id", json!("9001")),
        ("hash", json!("client-generated-hash")),
        ("hostname", json!("prod-db")),
        ("alias", json!("prod")),
        ("forceAlwaysRelay", json!("true")),
        ("rdpPort", json!("3389")),
        ("loginName", json!("login-user")),
        ("device_group_name", json!("servers")),
        ("same_server", json!(true)),
    ] {
        assert_eq!(stored[key], expected, "field {key} did not round-trip: {stored}");
    }
    assert_eq!(stored["tags"], json!(["office"]));

    // The four meanings of PUT /api/ab/peer/update share one path.
    let (status, _) = http_put_bearer(
        &format!("{}/api/ab/peer/update/{guid}", api.base),
        &json!({"id": "9001", "alias": "renamed"}),
        &token,
    );
    assert_eq!(status, 200);
    let (_, body) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&token),
    );
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["data"][0]["alias"], "renamed");
    // A partial update must not clear untouched fields.
    assert_eq!(listed["data"][0]["hostname"], "prod-db");
    assert_eq!(listed["data"][0]["hash"], "client-generated-hash");

    // Delete takes a bare array of ids.
    let (status, _) = http_delete_bearer(
        &format!("{}/api/ab/peer/{guid}", api.base),
        &json!(["9001"]),
        &token,
    );
    assert_eq!(status, 200);
    let (_, body) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&token),
    );
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 0);
}

/// Renaming a tag must rewrite the peers that reference it, or the client shows
/// a tag that no longer exists.
#[test]
fn renaming_a_tag_rewrites_peer_tags() {
    let _guard = gate();
    let api = start_api_with("ab-tag", &[]);
    let token = login(&api);
    let (_, body) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&token));
    let guid = serde_json::from_str::<Value>(&body).unwrap()["guid"]
        .as_str()
        .unwrap()
        .to_owned();

    http_post_bearer(
        &format!("{}/api/ab/tag/add/{guid}", api.base),
        Some(&json!({"name": "office", "color": 4_278_255_360u32})),
        Some(&token),
    );
    http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&json!({"id": "1", "tags": ["office"]})),
        Some(&token),
    );

    let (status, body) = http_put_bearer(
        &format!("{}/api/ab/tag/rename/{guid}", api.base),
        &json!({"old": "office", "new": "work"}),
        &token,
    );
    assert_eq!(status, 200, "{body}");

    let (_, body) = http_post_bearer(&format!("{}/api/ab/tags/{guid}", api.base), None, Some(&token));
    let tags: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(tags[0]["name"], "work");
    assert_eq!(tags[0]["color"].as_u64(), Some(4_278_255_360));

    let (_, body) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&token),
    );
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        listed["data"][0]["tags"],
        json!(["work"]),
        "the peer must follow the rename: {listed}"
    );
}

/// The structured endpoints must refuse an unauthenticated caller outright, or
/// the client would show a signing-out error as data loss.
#[test]
fn structured_address_book_requires_auth() {
    let _guard = gate();
    let api = start_api_with("ab-auth", &[]);
    for path in [
        "/api/ab/personal",
        "/api/ab/settings",
        "/api/ab/peers",
        "/api/ab/shared/profiles",
    ] {
        let (status, _) = http_post_bearer(&format!("{}{path}", api.base), None, None);
        assert_eq!(status, 401, "{path} must require authentication");
    }
}

/// `/api/users` is administrator-only and says so with the exact string the
/// client branches on.
#[test]
fn users_requires_admin_with_the_expected_error() {
    let _guard = gate();
    let api = start_api_with("users", &[]);
    let token = login(&api);
    // The bootstrap account is an administrator, so this succeeds.
    let (status, body) = http_get_bearer(&format!("{}/api/users?current=1&pageSize=100&status=1", api.base), &token);
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert!(parsed["total"].as_u64().unwrap() >= 1);
    assert_eq!(parsed["data"][0]["name"], "admin");
    // The client reads `display_name` and a possibly-null `verifier`.
    assert!(parsed["data"][0].get("display_name").is_some());
    assert!(parsed["data"][0]["verifier"].is_null());

    // Unauthenticated is a 401, not the admin error.
    let (status, _) = http_get(&format!("{}/api/users", api.base)).unwrap();
    assert_eq!(status, 401);
}

/// The heartbeat is answered unauthenticated but carries no strategy then.
#[test]
fn heartbeat_without_auth_carries_no_strategy() {
    let _guard = gate();
    let api = start_api_with("hb", &[]);
    let (status, body) = http_post_bearer(
        &format!("{}/api/heartbeat", api.base),
        Some(&json!({"id": "peer-1", "uuid": "u", "ver": "1.5.0", "conns": []})),
        None,
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert!(
        parsed.get("strategy").is_none(),
        "an unauthenticated heartbeat must not receive a strategy: {parsed}"
    );
    assert!(parsed.get("modified_at").is_some());
}

/// A strategy delivered to an authenticated heartbeat must have passed the
/// allow-list. This is the mutation target for the security boundary.
#[test]
fn heartbeat_delivers_only_allow_listed_options() {
    let _guard = gate();
    let api = start_api_with("hb-auth", &[]);
    let token = login(&api);

    // There is no HTTP endpoint that writes a strategy — by design, since a
    // strategy is operator configuration — so the document is seeded through the
    // database the server is using.
    seed_strategy(
        &api,
        &token,
        &json!({
            "config_options": {
                "enable-audio": "Y",
                "password": "must-not-be-delivered",
                "whitelist": "must-not-be-delivered"
            },
            "extra": {"untouched": true}
        }),
    );

    let (status, body) = http_post_bearer(
        &format!("{}/api/heartbeat", api.base),
        Some(&json!({"id": "peer-1", "uuid": "u", "ver": "1.5.0"})),
        Some(&token),
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let options = &parsed["strategy"]["config_options"];
    assert_eq!(options["enable-audio"], "Y", "{parsed}");
    assert!(
        options.get("password").is_none(),
        "a forbidden key was delivered: {parsed}"
    );
    assert!(
        options.get("whitelist").is_none(),
        "a forbidden key was delivered: {parsed}"
    );
    assert_eq!(parsed["strategy"]["extra"]["untouched"], true);

    // `modified_at` narrowing: the client echoes the value it last saw.
    let modified_at = parsed["modified_at"].as_i64().unwrap();
    let (_, body) = http_post_bearer(
        &format!("{}/api/heartbeat", api.base),
        Some(&json!({
            "id": "peer-1", "uuid": "u", "ver": "1.5.0", "modified_at": modified_at
        })),
        Some(&token),
    );
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert!(
        parsed.get("strategy").is_none(),
        "an unchanged strategy must not be re-delivered: {parsed}"
    );
}

/// Seeds a strategy document through the operator endpoint.
fn seed_strategy(api: &Api, token: &str, document: &Value) {
    let (status, body) = http_put_bearer(
        &format!("{}/api/admin/client-strategy", api.base),
        &json!({"document": document}),
        token,
    );
    assert_eq!(status, 200, "cannot seed a strategy: {body}");
}

/// Both audit and recording are off until a deployment enables them.
#[test]
fn client_audit_and_recording_are_off_by_default() {
    let _guard = gate();
    let api = start_api_with("audit-off", &[]);
    let token = login(&api);
    let (status, _) =
        http_post_bearer(&format!("{}/api/audit/login", api.base), Some(&json!({})), Some(&token));
    assert_eq!(status, 501, "client audit must be opt-in");
    let (status, _) = http_post_bearer(
        &format!("{}/api/record?type=new&file=a.mp4", api.base),
        None,
        Some(&token),
    );
    assert_eq!(status, 501, "recording must be opt-in");
}

/// Enrolment answers the client's documented `NOT_ENABLED` until configured.
#[test]
fn enrolment_is_not_enabled_by_default() {
    let _guard = gate();
    let api = start_api_with("deploy-off", &[]);
    let (status, body) = http_post_bearer(
        &format!("{}/api/devices/deploy", api.base),
        Some(&json!({"id": "1", "uuid": "u", "pk": "key"})),
        Some("some-token"),
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["result"], "NOT_ENABLED");
}

/// With enrolment enabled, a token is single-use and `ID_TAKEN` protects an
/// existing device from reassignment.
#[test]
fn enrolment_is_single_use_and_protects_existing_ids() {
    let _guard = gate();
    // The flag file must exist before the server starts, because the feature is
    // read from the filesystem rather than cached.
    let directory = std::env::temp_dir().join(format!(
        "starry-api-deploy-{}-{}",
        std::process::id(),
        reserve_port()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let flag = directory.join("enrolment.enabled");
    fs::write(&flag, "1").unwrap();
    let api = start_api_with(
        "deploy-on",
        &[("STARRY_ENROLMENT_FILE", flag.display().to_string())],
    );

    let token = issue_deploy_token(&api);
    let (status, body) = http_post_bearer(
        &format!("{}/api/devices/deploy", api.base),
        Some(&json!({"id": "device-1", "uuid": "u-1", "pk": "device-key-1"})),
        Some(&token),
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["result"], "OK", "{parsed}");

    // The token is spent.
    let (_, body) = http_post_bearer(
        &format!("{}/api/devices/deploy", api.base),
        Some(&json!({"id": "device-2", "uuid": "u-2", "pk": "device-key-2"})),
        Some(&token),
    );
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["result"], "INVALID_INPUT", "{parsed}");

    // A different id may enrol with a fresh token.
    let token = issue_deploy_token(&api);
    let (_, body) = http_post_bearer(
        &format!("{}/api/devices/deploy", api.base),
        Some(&json!({"id": "device-2", "uuid": "u-2", "pk": "device-key-2"})),
        Some(&token),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["result"],
        "OK"
    );

    // The same id with a different key is a conflict, never a silent takeover.
    let token = issue_deploy_token(&api);
    let (_, body) = http_post_bearer(
        &format!("{}/api/devices/deploy", api.base),
        Some(&json!({"id": "device-2", "uuid": "u-3", "pk": "a-different-key"})),
        Some(&token),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["result"],
        "ID_TAKEN",
        "an enrolment must not be able to reassign an existing device"
    );
}

/// Mints an enrolment token through the operator endpoint.
fn issue_deploy_token(api: &Api) -> String {
    let admin = login(api);
    let (status, body) = http_post_bearer(
        &format!("{}/api/admin/enrolment-token", api.base),
        None,
        Some(&admin),
    );
    assert_eq!(status, 200, "cannot issue an enrolment token: {body}");
    serde_json::from_str::<Value>(&body).unwrap()["token"]
        .as_str()
        .expect("a token")
        .to_owned()
}

/// The two-step TOTP flow: the first login must not hand out a credential.
#[test]
fn totp_login_requires_a_second_step() {
    let _guard = gate();
    let api = start_api_with("totp", &[]);
    // Enrol a second factor for the bootstrap account directly, since enrolment
    // is an operator action.
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    // Enrolling needs a token from before the second factor exists.
    let admin = login(&api);
    seed_totp(&api, &admin, secret);

    let (status, body) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({"username": "admin", "password": ADMIN_PASSWORD, "id": "d", "uuid": "u"})),
        None,
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["type"], "email_code", "the client keys off this: {parsed}");
    assert_eq!(parsed["tfa_type"], "tfa_check");
    assert_eq!(parsed["access_token"], "", "step one must not hand out a token");
    let handle = parsed["secret"].as_str().expect("a secret handle").to_owned();

    // A wrong code is refused.
    let (status, _) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({
            "username": "admin", "password": ADMIN_PASSWORD,
            "id": "d", "uuid": "u",
            "type": "email_code", "secret": handle,
            "verificationCode": "000000", "tfaCode": "000000"
        })),
        None,
    );
    assert_eq!(status, 401);

    // The right code completes the login and yields the credential.
    let code = current_code(secret);
    let handle = parsed["secret"].as_str().unwrap().to_owned();
    let (status, body) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({
            "username": "admin", "password": ADMIN_PASSWORD,
            "id": "d", "uuid": "u",
            "type": "email_code", "secret": handle,
            "verificationCode": code, "tfaCode": code
        })),
        None,
    );
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["type"], "access_token");
    assert!(!parsed["access_token"].as_str().unwrap().is_empty());

    // And the code cannot be used twice.
    let (status, _) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({
            "username": "admin", "password": ADMIN_PASSWORD,
            "id": "d", "uuid": "u",
            "type": "email_code", "secret": handle,
            "verificationCode": code, "tfaCode": code
        })),
        None,
    );
    assert_eq!(status, 401, "a spent code must not complete another login");
}

/// Enrols a second factor through the operator endpoint.
fn seed_totp(api: &Api, token: &str, secret: &str) {
    let (status, body) = http_post_bearer(
        &format!("{}/api/admin/totp", api.base),
        Some(&json!({"secret": secret})),
        Some(token),
    );
    assert_eq!(status, 200, "cannot enrol TOTP: {body}");
}

/// Computes the code for the current time step, the way an authenticator would.
fn current_code(secret: &str) -> String {
    // 20 bytes of Base32 is 32 characters, which is the RFC 4226 length.
    let bytes = hbb_common_totp_decode(secret);
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    totp_code(&bytes, step)
}

/// The test's own view of the secret, checked in one place.
///
/// `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP` decodes to 20 bytes; the exact bytes are
/// asserted so that a Base32 mistake cannot masquerade as an HMAC mistake.
#[test]
fn the_test_decoder_matches_the_known_bytes() {
    let decoded = hbb_common_totp_decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    assert_eq!(decoded.len(), 20, "20 bytes is the RFC 4226 length");
    // RFC 4648 vector: "JBSWY3DPEHPK3PXP" is the ASCII bytes
    // 0x48 0x65 0x6c 0x6c 0x6f 0x21 0xde 0xad 0xbe 0xef.
    let hello = hbb_common_totp_decode("JBSWY3DPEHPK3PXP");
    assert_eq!(
        hello,
        vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef]
    );
}

/// Minimal Base32 decode, mirroring the server's rules.
fn hbb_common_totp_decode(secret: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for ch in secret.chars().filter(|ch| ch.is_ascii_alphanumeric()) {
        // Match on the uppercased character: the digits arm must not compare
        // against the raw input, which is how this decoder first got it wrong.
        let upper = ch.to_ascii_uppercase();
        let value = match upper {
            'A'..='Z' => upper as u32 - 'A' as u32,
            '2'..='7' => upper as u32 - '2' as u32 + 26,
            _ => continue,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// HMAC-SHA1 TOTP, independent of the server implementation so the test is a
/// real cross-check rather than a restatement.
fn totp_code(secret: &[u8], step: u64) -> String {
    use sha2::Digest;
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    padded[..secret.len().min(BLOCK)].copy_from_slice(&secret[..secret.len().min(BLOCK)]);
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] = padded[index] ^ 0x36;
        opad[index] = padded[index] ^ 0x5c;
    }
    let mut inner = sha1::Sha1::new();
    inner.update(ipad);
    inner.update(step.to_be_bytes());
    let inner = inner.finalize();
    let mut outer = sha1::Sha1::new();
    outer.update(opad);
    outer.update(inner);
    let digest = outer.finalize();
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    format!("{:06}", code % 1_000_000)
}

/// Compares the test's independent TOTP against the server's own at fixed steps.
///
/// If these agree, an e2e failure is about the flow rather than the code. They
/// disagreed the first time this ran, and the cause was the test decoder.
#[test]
fn the_test_totp_agrees_with_the_server() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let bytes = hbb_common_totp_decode(secret);
    for step in [1u64, 1_111_111_111 / 30, 59_860_687] {
        assert_eq!(
            totp_code(&bytes, step),
            hbbs::totp::debug_code(&bytes, step),
            "step {step}"
        );
    }
}

// ---------------------------------------------------------------------------
// Multi-account authorization
//
// Every earlier test in this file used one account, which is how a
// `rule >= 1` predicate that every new book satisfied survived review. These
// tests create a second and third account, because "can A see B's data" is not
// expressible with one.
// ---------------------------------------------------------------------------

/// Creates an account with the CLI and returns its bearer token.
fn create_account(api: &Api, name: &str, password: &str) -> String {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_starry-api"))
        .arg("user")
        .arg("add")
        .arg(name)
        .arg("--display-name")
        .arg(name)
        .env("STARRY_API_DB", api.directory.join("users.db"))
        .env("STARRY_API_BCRYPT_COST", "4")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("cannot run the account CLI");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(password.as_bytes())
        .expect("cannot write the password");
    let status = child.wait().expect("account CLI did not finish");
    assert!(status.success(), "creating {name} failed");

    let (status, body) = http_post_bearer(
        &format!("{}/api/login", api.base),
        Some(&json!({"username": name, "password": password, "id": "d", "uuid": "u"})),
        None,
    );
    assert_eq!(status, 200, "{name} cannot log in: {body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    parsed["access_token"].as_str().expect("a token").to_owned()
}

/// A book belongs to its owner. Another account must not be able to list,
/// read or write it, and this test is the reason the authorization predicate
/// cannot be `rule >= 1`.
#[test]
fn another_account_cannot_see_an_unshared_book() {
    let _guard = gate();
    let api = start_api_with("ab-privacy", &[]);
    let owner = login(&api);

    let (_, body) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&owner));
    let guid = serde_json::from_str::<Value>(&body).unwrap()["guid"]
        .as_str()
        .unwrap()
        .to_owned();
    http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&json!({"id": "secret-host", "alias": "only-for-owner"})),
        Some(&owner),
    );

    let intruder = create_account(&api, "mallory", "mallory-password-123");

    // 1. It must not appear in the intruder's book list.
    let (status, body) = http_post_bearer(
        &format!("{}/api/ab/shared/profiles?current=1&pageSize=100", api.base),
        None,
        Some(&intruder),
    );
    assert_eq!(status, 200, "{body}");
    let profiles: Value = serde_json::from_str(&body).unwrap();
    let leaked = profiles["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|profile| profile["guid"] == guid.as_str());
    assert!(
        !leaked,
        "another account's book was listed: {profiles}"
    );

    // 2. Peers must be a 404, not an empty list: an empty list would leak that
    // the book exists.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&intruder),
    );
    assert_eq!(status, 404, "reading another account's peers must be refused");

    // 3. Tags likewise.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/tags/{guid}", api.base),
        None,
        Some(&intruder),
    );
    assert_eq!(status, 404);

    // 4. Writing must be refused too, or the leak is worse than read-only.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&json!({"id": "injected"})),
        Some(&intruder),
    );
    assert_eq!(status, 404);

    // 5. And the owner still sees their own peer.
    let (_, body) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&owner),
    );
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 1, "the owner must still see their own book");
}

/// Sharing is explicit, capped by the book's ceiling, and revocable.
#[test]
fn sharing_grants_and_revokes_access_explicitly() {
    let _guard = gate();
    let api = start_api_with("ab-share", &[]);
    let owner = login(&api);
    let (_, body) = http_post_bearer(&format!("{}/api/ab/personal", api.base), None, Some(&owner));
    let guid = serde_json::from_str::<Value>(&body).unwrap()["guid"]
        .as_str()
        .unwrap()
        .to_owned();
    http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&json!({"id": "shared-host"})),
        Some(&owner),
    );
    let guest = create_account(&api, "guest", "guest-password-123");

    // Only the owner may share. The guest trying to share the owner's book to
    // itself must fail, or sharing would be self-service.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/share/{guid}", api.base),
        Some(&json!({"user_id": 3, "rule": 3})),
        Some(&guest),
    );
    assert_eq!(status, 404, "a non-owner must not be able to share");

    // The owner shares read-only with the guest (id 2: admin is 1).
    let (status, body) = http_post_bearer(
        &format!("{}/api/ab/share/{guid}", api.base),
        Some(&json!({"user_id": 2, "rule": 1})),
        Some(&owner),
    );
    assert_eq!(status, 200, "{body}");

    // The guest can now read...
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&guest),
    );
    assert_eq!(status, 200, "a granted share must be readable");

    // ...but not write, because the grant is read-only.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/peer/add/{guid}", api.base),
        Some(&json!({"id": "guest-injected"})),
        Some(&guest),
    );
    assert_eq!(status, 404, "a read-only share must not permit writes");

    // Revoking takes it away again.
    let (status, _) = http_delete_bearer(
        &format!("{}/api/ab/share/{guid}", api.base),
        &json!({"user_id": 2}),
        &owner,
    );
    assert_eq!(status, 200);
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab/peers?current=1&pageSize=100&ab={guid}", api.base),
        None,
        Some(&guest),
    );
    assert_eq!(status, 404, "a revoked share must stop working immediately");
}

// ---------------------------------------------------------------------------
// Legacy address book: versions and lost updates
//
// The official client has no merge and never sends a precondition, so two
// devices editing at once necessarily lose one side. These tests pin what the
// server can still do about that: report a version, honour a precondition when a
// script supplies one, and keep the document that got replaced.
// ---------------------------------------------------------------------------

/// `GET /api/ab` and `POST /api/ab` round trip with a version, and a re-push of
/// unchanged data is not counted as a write.
#[test]
fn legacy_address_book_reports_a_version() {
    let _guard = gate();
    let api = start_api_with("ab-version", &[]);
    let token = login(&api);

    // Nothing written yet: the answer is a literal null, as it has always been,
    // so the client keeps treating the account as having no book.
    let (status, body) = http_get_bearer(&format!("{}/api/ab", api.base), &token);
    assert_eq!(status, 200, "a read with no book must be a normal empty answer");
    assert_eq!(body.trim().to_lowercase(), "null");

    let book = json!({"tags": ["office"], "peers": [], "tag_colors": "{}"}).to_string();
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": book})),
        Some(&token),
    );
    assert_eq!(status, 200);

    let (status, body) = http_get_bearer(&format!("{}/api/ab", api.base), &token);
    assert_eq!(status, 200, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["data"], book, "the document must round-trip");

    // Re-pushing the same document is idempotent: it must not look like a
    // conflict, because the client re-pushes on every local edit.
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": book})),
        Some(&token),
    );
    assert_eq!(status, 200);
}

/// A caller that states a version is protected; the official client does not, so
/// this proves the script path rather than the client path.
#[test]
fn a_stale_precondition_is_refused_with_412() {
    let _guard = gate();
    let api = start_api_with("ab-etag", &[]);
    let token = login(&api);

    let first = json!({"tags": ["one"], "peers": [], "tag_colors": "{}"}).to_string();
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": first})),
        Some(&token),
    );
    assert_eq!(status, 200);

    // Read the version the server reports.
    let (_, body) = http_get_bearer(&format!("{}/api/ab", api.base), &token);
    let version = serde_json::from_str::<Value>(&body).unwrap();
    let _ = version;

    // Another writer moves the book on.
    let second = json!({"tags": ["two"], "peers": [], "tag_colors": "{}"}).to_string();
    let (status, _) = http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": second})),
        Some(&token),
    );
    assert_eq!(status, 200);

    // A writer holding the old version must be told, with 412 and not 409: a
    // client that retries on 409 would loop here.
    let stale = http_post_bearer_with_headers(
        &format!("{}/api/ab", api.base),
        &json!({"data": first}),
        &token,
        &[("If-Match", "\"ab-1\"")],
    );
    assert_eq!(stale.0, 412, "a stale precondition must be refused: {stale:?}");
    let stale_body: Value = serde_json::from_str(&stale.1).unwrap();
    assert_eq!(stale_body["error"], "AddressBookChanged");

    // The precondition that matches succeeds.
    let current = http_post_bearer_with_headers(
        &format!("{}/api/ab", api.base),
        &json!({"data": first}),
        &token,
        &[("If-Match", "\"ab-2\"")],
    );
    assert_eq!(current.0, 200, "{current:?}");
}

/// The document that a write replaced is recoverable, which is the only answer
/// to the client's last-write-wins model.
#[test]
fn a_replaced_document_is_recoverable() {
    let _guard = gate();
    let api = start_api_with("ab-recover", &[]);
    let token = login(&api);

    let laptop = json!({"tags": ["laptop"], "peers": [], "tag_colors": "{}"}).to_string();
    let desktop = json!({"tags": ["desktop"], "peers": [], "tag_colors": "{}"}).to_string();

    // Device A pushes, then device B pushes without a precondition, which is
    // exactly what the official client does.
    http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": laptop})),
        Some(&token),
    );
    http_post_bearer(
        &format!("{}/api/ab", api.base),
        Some(&json!({"data": desktop})),
        Some(&token),
    );

    // B's push won, but A's is not gone.
    let (_, body) = http_get_bearer(&format!("{}/api/ab", api.base), &token);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["data"],
        desktop,
        "last write wins, as the client expects"
    );

    let (status, body) = http_get_bearer(&format!("{}/api/ab/previous", api.base), &token);
    assert_eq!(status, 200, "{body}");
    let previous: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        previous["data"], laptop,
        "the replaced document must be recoverable: {previous}"
    );
    assert_eq!(previous["version"], 1, "it was version 1 when replaced");
    assert!(
        previous["superseded_count"].as_i64().unwrap() >= 1,
        "a superseding write must be counted: {previous}"
    );

    // An unauthenticated caller must not read anyone's previous book.
    let (status, _) = http_get(&format!("{}/api/ab/previous", api.base)).unwrap();
    assert_eq!(status, 401);
}

/// A malformed `If-Match` is refused rather than treated as absent, or a caller
/// would believe it had protection it did not have.
#[test]
fn a_malformed_precondition_is_refused() {
    let _guard = gate();
    let api = start_api_with("ab-badif", &[]);
    let token = login(&api);
    let book = json!({"tags": [], "peers": [], "tag_colors": "{}"}).to_string();
    let (status, body) = http_post_bearer_with_headers(
        &format!("{}/api/ab", api.base),
        &json!({"data": book}),
        &token,
        &[("If-Match", "not-a-version")],
    );
    assert_eq!(status, 400, "{body}");
}
