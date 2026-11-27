use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
        time::{interval, Duration},
    },
    ResultType,
};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{auth, sign};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::prelude::*,
    io::Error,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Usage = (usize, usize, usize, usize);
type WaitingPeer = (Arc<()>, Box<dyn StreamTrait>);

lazy_static::lazy_static! {
    static ref PEERS: Mutex<HashMap<String, WaitingPeer>> = Default::default();
    static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
    static ref PROCESS_STARTED: Instant = Instant::now();
    static ref PROCESS_INSTANCE_ID: String = uuid::Uuid::now_v7().to_string();
    static ref TELEMETRY_AUTH_KEY: Option<auth::Key> = load_telemetry_auth_key();
    static ref TELEMETRY_REPLAY_CACHE: StdMutex<TelemetryReplayCache> = Default::default();
    static ref PROBE_RATE_LIMITER: StdMutex<ProbeRateLimiter> = Default::default();
}

static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static ACTIVE_RELAY_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static PENDING_RELAY_PAIRS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_RELAY_BANDWIDTH_BPS: AtomicUsize = AtomicUsize::new(0);
static MAX_RELAY_SESSIONS: AtomicUsize = AtomicUsize::new(10_000);
static ADMISSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static PROBE_MALFORMED: AtomicU64 = AtomicU64::new(0);
static PROBE_UNSUPPORTED: AtomicU64 = AtomicU64::new(0);
static PROBE_RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
static PROBE_SUCCESSFUL: AtomicU64 = AtomicU64::new(0);
static TELEMETRY_AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static TELEMETRY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROBE_PER_IP_PER_MINUTE: AtomicUsize = AtomicUsize::new(120);
static PROBE_GLOBAL_PER_MINUTE: AtomicUsize = AtomicUsize::new(10_000);
const STARRY_RELAY_TELEMETRY_SCHEMA: u32 = crate::telemetry::SCHEMA_VERSION;
const TELEMETRY_AUTH_CLOCK_SKEW_SECONDS: u64 = 30;
const TELEMETRY_REPLAY_CAPACITY: usize = 4_096;
const PROBE_IP_BUCKET_CAPACITY: usize = 4_096;
const BANDWIDTH_EMA_ALPHA_BASIS_POINTS: u32 = 2_500;
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s
// Only the relay request that opens a pair is a framed message of ours; pairing lifts this
// for a leg that stays framed.
const MAX_RELAY_REQUEST_LEN: usize = 128 << 10;
// Fixed at the handshake, so it is sized for the session a websocket leg carries once paired.
const WS_BUFFER_SIZE: usize = 64 << 10;
// tungstenite's defaults, so lifting the bound restores the transport rather than widening it.
const WS_DEFAULT_MAX_MESSAGE_SIZE: usize = 64 << 20;
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";

#[tokio::main(flavor = "multi_thread")]
pub async fn start_with_bind(
    bind_addr: Option<IpAddr>,
    port: &str,
    key: &str,
) -> ResultType<()> {
    if sodiumoxide::init().is_err() {
        bail!("cannot initialize telemetry authentication");
    }
    let _ = &*TELEMETRY_AUTH_KEY;
    let key = get_server_sk(key)?;
    if let Err(error) = crate::relay_enrollment::preflight(&key) {
        bail!("Relay enrollment preflight failed: {error}");
    }
    crate::ops_surface::spawn();
    crate::fast_media_relay::spawn(&key);
    if let Ok(mut file) = std::fs::File::open(BLACKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blacklist({}): {}",
        BLACKLIST_FILE,
        BLACKLIST.read().await.len()
    );
    if let Ok(mut file) = std::fs::File::open(BLOCKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blocklist({}): {}",
        BLOCKLIST_FILE,
        BLOCKLIST.read().await.len()
    );
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(
                crate::common::listen_tcp(bind_addr, port).await?,
                crate::common::listen_tcp(bind_addr, port2).await?,
                crate::common::listen_console(bind_addr, port).await?,
                &key,
            )
            .await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}

fn check_params() {
    let tmp = crate::common::get_arg("DOWNGRADE_THRESHOLD")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        DOWNGRADE_THRESHOLD_100.store((tmp * 100.) as _, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
    );
    let tmp = crate::common::get_arg("DOWNGRADE_START_CHECK")
        .parse::<usize>()
        .unwrap_or(0);
    if tmp > 0 {
        DOWNGRADE_START_CHECK.store(tmp * 1000, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000
    );
    let tmp = crate::common::get_arg("LIMIT_SPEED")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        LIMIT_SPEED.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::get_arg("TOTAL_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        TOTAL_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    if let Some(capacity) = crate::common::env_var("STARRY_RELAY_CAPACITY_BANDWIDTH_BPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
    {
        TOTAL_BANDWIDTH.store(capacity, Ordering::SeqCst);
    }

    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::env_var("STARRY_RELAY_MAX_SESSIONS")
        .map(|value| value.parse::<usize>().unwrap_or(0).min(u32::MAX as usize))
        .unwrap_or(0);
    if tmp > 0 {
        MAX_RELAY_SESSIONS.store(tmp, Ordering::SeqCst);
    }
    log::info!(
        "STARRY_RELAY_MAX_SESSIONS: {} (enforced admission limit)",
        MAX_RELAY_SESSIONS.load(Ordering::SeqCst)
    );
    set_bounded_rate_from_env(
        "STARRY_RELAY_PROBE_PER_IP_PER_MINUTE",
        &PROBE_PER_IP_PER_MINUTE,
    );
    set_bounded_rate_from_env(
        "STARRY_RELAY_PROBE_GLOBAL_PER_MINUTE",
        &PROBE_GLOBAL_PER_MINUTE,
    );
    log::info!(
        "Relay probe limits: per_ip_per_minute={}, global_per_minute={}",
        PROBE_PER_IP_PER_MINUTE.load(Ordering::SeqCst),
        PROBE_GLOBAL_PER_MINUTE.load(Ordering::SeqCst),
    );
    let tmp = crate::common::get_arg("SINGLE_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        SINGLE_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    )
}

fn starry_version() -> String {
    format!(
        "{}-patch-v{}",
        env!("CARGO_PKG_VERSION"),
        include_str!("../PATCH_VERSION").trim(),
    )
}

#[derive(Default)]
struct TelemetryReplayCache {
    entries: HashSet<String>,
    order: VecDeque<(u64, String)>,
}

impl TelemetryReplayCache {
    fn insert_fresh(&mut self, now: u64, nonce: &str) -> bool {
        while self
            .order
            .front()
            .map(|(seen_at, _)| now.saturating_sub(*seen_at) > TELEMETRY_AUTH_CLOCK_SKEW_SECONDS)
            .unwrap_or(false)
        {
            if let Some((_, expired)) = self.order.pop_front() {
                self.entries.remove(&expired);
            }
        }
        if self.entries.contains(nonce) {
            return false;
        }
        while self.order.len() >= TELEMETRY_REPLAY_CAPACITY {
            if let Some((_, oldest)) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(nonce.to_owned());
        self.order.push_back((now, nonce.to_owned()));
        true
    }
}

#[derive(Default)]
struct ProbeRateLimiter {
    window: u64,
    global: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl ProbeRateLimiter {
    fn allow(&mut self, source: IpAddr, now: u64) -> bool {
        let window = now / 60;
        if self.window != window {
            self.window = window;
            self.global = 0;
            self.per_ip.clear();
        }
        let global_limit = PROBE_GLOBAL_PER_MINUTE.load(Ordering::Relaxed).max(1);
        let per_ip_limit = PROBE_PER_IP_PER_MINUTE.load(Ordering::Relaxed).max(1);
        if self.global >= global_limit {
            return false;
        }
        if !self.per_ip.contains_key(&source) && self.per_ip.len() >= PROBE_IP_BUCKET_CAPACITY {
            return false;
        }
        let count = self.per_ip.entry(source).or_default();
        if *count >= per_ip_limit {
            return false;
        }
        self.global = self.global.saturating_add(1);
        *count = count.saturating_add(1);
        true
    }
}

fn set_bounded_rate_from_env(name: &str, target: &AtomicUsize) {
    let configured = crate::common::env_var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=1_000_000).contains(value));
    if let Some(configured) = configured {
        target.store(configured, Ordering::SeqCst);
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn load_telemetry_auth_key() -> Option<auth::Key> {
    let path = crate::common::env_var("STARRY_RELAY_TELEMETRY_SECRET_FILE")
        .ok()
        .filter(|path| !path.is_empty())?;
    let mut secret = match std::fs::read(&path) {
        Ok(secret) => secret,
        Err(error) => {
            log::error!("Cannot read STARRY_RELAY_TELEMETRY_SECRET_FILE: {error}");
            return None;
        }
    };
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if !(32..=1_024).contains(&secret.len()) {
        log::error!("STARRY_RELAY_TELEMETRY_SECRET_FILE must contain 32..1024 bytes");
        secret.fill(0);
        return None;
    }
    let digest = Sha256::digest(&secret);
    secret.fill(0);
    auth::Key::from_slice(&digest)
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode_tag(value: &str) -> Option<auth::Tag> {
    if value.len() != auth::TAGBYTES * 2 {
        return None;
    }
    let mut decoded = vec![0_u8; auth::TAGBYTES];
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2])?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1])?;
        *output = (high << 4) | low;
    }
    auth::Tag::from_slice(&decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn bounded_request_header<'a>(request: &'a http::Request<()>, name: &str, max: usize) -> Option<&'a str> {
    let value = request.headers().get(name)?.to_str().ok()?;
    (!value.is_empty() && value.len() <= max).then_some(value)
}

fn authenticate_telemetry_request(request: &http::Request<()>) -> Option<String> {
    let key = TELEMETRY_AUTH_KEY.as_ref()?;
    let now = unix_seconds();
    let timestamp = bounded_request_header(request, "x-starry-telemetry-timestamp", 20)?;
    let timestamp_value = timestamp.parse::<u64>().ok()?;
    if now.abs_diff(timestamp_value) > TELEMETRY_AUTH_CLOCK_SKEW_SECONDS {
        return None;
    }
    let nonce = bounded_request_header(request, "x-starry-telemetry-nonce", 32)?;
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let signature = bounded_request_header(request, "x-starry-telemetry-auth", 64)?;
    let tag = hex_decode_tag(signature)?;
    let canonical = format!(
        "starry-telemetry-request-v1\n{timestamp}\n{nonce}\n/ws/telemetry"
    );
    if !auth::verify(&tag, canonical.as_bytes(), key) {
        return None;
    }
    let mut replay = TELEMETRY_REPLAY_CACHE.lock().ok()?;
    replay.insert_fresh(now, nonce).then(|| nonce.to_owned())
}

fn load_basis_points(value: usize, capacity: usize) -> u32 {
    if capacity == 0 {
        return 10_000;
    }
    value
        .saturating_mul(10_000)
        .checked_div(capacity)
        .unwrap_or(10_000)
        .min(10_000) as u32
}

fn is_draining() -> bool {
    let statically_draining = crate::common::env_var("STARRY_RELAY_DRAINING")
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    statically_draining
        || crate::common::env_var("STARRY_RELAY_DRAINING_FILE")
            .ok()
            .filter(|path| !path.is_empty())
            .map(|path| Path::new(&path).is_file())
            .unwrap_or(false)
}

/// One consistent view of the counters the operations surface exposes.
pub(crate) struct OpsSnapshot {
    pub version: String,
    pub uptime_seconds: u64,
    pub active_sessions: u64,
    pub capacity_sessions: u64,
    pub active_bandwidth_bps: u64,
    pub capacity_bandwidth_bps: u64,
    pub load_basis_points: u64,
    pub pending_pairs: u64,
    pub admission_rejections: u64,
    pub probes_successful: u64,
    pub probes_rate_limited: u64,
    pub probes_unsupported: u64,
    pub probes_malformed: u64,
    pub telemetry_auth_failures: u64,
    /// Whether the operator asked this relay to stop taking sessions.
    ///
    /// Distinct from capacity: draining is a decision, a full relay is a
    /// consequence, and an operator reading `/readyz` needs to tell them apart.
    pub draining: bool,
    /// Whether a new relay session would be admitted right now.
    ///
    /// This is the same predicate the data plane applies in
    /// `admission_available`, sampled once so the answer the probe reports is
    /// the answer a peer would get.
    pub admission_open: bool,
}

pub(crate) fn ops_snapshot() -> OpsSnapshot {
    let load = current_relay_load();
    let draining = is_draining();
    // Read the live counters rather than the clamped `load` view: capacity is
    // clamped to at least 1 for display, while admission must see the value the
    // data plane compares against.
    let admission = admission_decision(
        draining,
        ACTIVE_RELAY_SESSIONS.load(Ordering::Relaxed),
        MAX_RELAY_SESSIONS.load(Ordering::Relaxed),
    );
    OpsSnapshot {
        version: starry_version(),
        uptime_seconds: PROCESS_STARTED.elapsed().as_secs(),
        active_sessions: u64::from(load.active_sessions),
        capacity_sessions: u64::from(load.capacity_sessions),
        active_bandwidth_bps: load.bandwidth_bps,
        capacity_bandwidth_bps: load.capacity_bandwidth_bps,
        load_basis_points: u64::from(load.load_basis_points),
        pending_pairs: PENDING_RELAY_PAIRS.load(Ordering::Relaxed) as u64,
        admission_rejections: ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        probes_successful: PROBE_SUCCESSFUL.load(Ordering::Relaxed),
        probes_rate_limited: PROBE_RATE_LIMITED.load(Ordering::Relaxed),
        probes_unsupported: PROBE_UNSUPPORTED.load(Ordering::Relaxed),
        probes_malformed: PROBE_MALFORMED.load(Ordering::Relaxed),
        telemetry_auth_failures: TELEMETRY_AUTH_FAILURES.load(Ordering::Relaxed),
        draining,
        admission_open: admission.is_open(),
    }
}

fn current_relay_load() -> StarryRelayLoad {
    let active_sessions = ACTIVE_RELAY_SESSIONS.load(Ordering::Relaxed);
    let capacity_sessions = MAX_RELAY_SESSIONS.load(Ordering::Relaxed).max(1);
    let bandwidth_bps = ACTIVE_RELAY_BANDWIDTH_BPS.load(Ordering::Relaxed);
    let capacity_bandwidth_bps = TOTAL_BANDWIDTH.load(Ordering::Relaxed).max(1);
    StarryRelayLoad {
        load_basis_points: load_basis_points(active_sessions, capacity_sessions)
            .max(load_basis_points(bandwidth_bps, capacity_bandwidth_bps)),
        active_sessions: active_sessions.min(u32::MAX as usize) as u32,
        capacity_sessions: capacity_sessions.min(u32::MAX as usize) as u32,
        bandwidth_bps: bandwidth_bps as u64,
        capacity_bandwidth_bps: capacity_bandwidth_bps as u64,
        ..Default::default()
    }
}

fn telemetry_payload() -> String {
    let load = current_relay_load();
    let fast_media = crate::fast_media_relay::runtime_snapshot();
    let draining = is_draining();
    let admission_open = !draining && load.active_sessions < load.capacity_sessions;
    let sequence = TELEMETRY_SEQUENCE.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    let fast_media_payload = serde_json::json!({
        "protocol": crate::fast_media_relay::PROTOCOL_VERSION,
        "enabled": fast_media.enabled,
        "healthy": fast_media.healthy,
        "udp_port": fast_media.udp_port.unwrap_or_default(),
        "active_allocations": fast_media.active_allocations,
        "active_streams": fast_media.active_streams,
        "hello_accepted": fast_media.hello_accepted,
        "cookie_rejected": fast_media.cookie_rejected,
        "bind_succeeded": fast_media.bind_succeeded,
        "bind_rejected": fast_media.bind_rejected,
        "grant_rejected": fast_media.grant_rejected,
        "role_mismatch": fast_media.role_mismatch,
        "session_mismatch": fast_media.session_mismatch,
        "allocation_mismatch": fast_media.allocation_mismatch,
        "rebinds": fast_media.rebinds,
        "forwarded_packets": fast_media.forwarded_packets,
        "forwarded_bytes": fast_media.forwarded_bytes,
        "dropped_packets": fast_media.dropped_packets,
        "rate_limited": fast_media.rate_limited,
        "replay_rejected": fast_media.replay_rejected,
        "expired_allocations": fast_media.expired_allocations,
        "listener_failures": fast_media.listener_failures,
    });
    let payload = serde_json::json!({
        "telemetry_schema": STARRY_RELAY_TELEMETRY_SCHEMA,
        "process_instance_id": PROCESS_INSTANCE_ID.as_str(),
        "sequence": sequence,
        "observed_at_unix_ms": unix_millis(),
        "uptime_seconds": PROCESS_STARTED.elapsed().as_secs(),
        "version": starry_version(),
        "relay_probe_protocol": 1,
        "relay_load_protocol": 1,
        "fast_media": fast_media_payload,
        "load_basis_points": load.load_basis_points,
        "active_sessions": load.active_sessions,
        "pending_pairs": PENDING_RELAY_PAIRS.load(Ordering::Relaxed).min(u32::MAX as usize) as u32,
        "capacity_sessions": load.capacity_sessions,
        "bandwidth_bps": load.bandwidth_bps,
        "bandwidth_ema_alpha_basis_points": BANDWIDTH_EMA_ALPHA_BASIS_POINTS,
        "capacity_bandwidth_bps": load.capacity_bandwidth_bps,
        "draining": draining,
        "admission_open": admission_open,
        "admission_rejections": ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        "probe_malformed": PROBE_MALFORMED.load(Ordering::Relaxed),
        "probe_unsupported": PROBE_UNSUPPORTED.load(Ordering::Relaxed),
        "probe_rate_limited": PROBE_RATE_LIMITED.load(Ordering::Relaxed),
        "probe_successful": PROBE_SUCCESSFUL.load(Ordering::Relaxed),
        "telemetry_auth_failures": TELEMETRY_AUTH_FAILURES.load(Ordering::Relaxed),
    });
    base64::encode_config(
        serde_json::to_vec(&payload).unwrap_or_default(),
        base64::URL_SAFE_NO_PAD,
    )
}

fn add_public_capability_headers(response: &mut http::Response<()>) {
    for (name, value) in [
        ("x-starry-version", starry_version()),
        ("x-starry-relay-probe-protocol", "1".to_owned()),
        ("x-starry-relay-load-protocol", "1".to_owned()),
    ] {
        if let Ok(value) = http::HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
}

fn add_authenticated_telemetry_headers(
    response: &mut http::Response<()>,
    request_nonce: &str,
) -> bool {
    let Some(key) = TELEMETRY_AUTH_KEY.as_ref() else {
        return false;
    };
    let payload = telemetry_payload();
    let canonical = format!(
        "starry-telemetry-response-v1\n{request_nonce}\n{payload}"
    );
    let signature = hex_encode(auth::authenticate(canonical.as_bytes(), key).as_ref());
    for (name, value) in [
        ("x-starry-telemetry", payload),
        ("x-starry-telemetry-auth", signature),
    ] {
        let Ok(value) = http::HeaderValue::from_str(&value) else {
            return false;
        };
        response.headers_mut().insert(name, value);
    }
    true
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn atomic_saturating_sub(value: &AtomicUsize, amount: usize) {
    let _ = value.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
        Some(current.saturating_sub(amount))
    });
}

fn admission_available() -> bool {
    admission_decision(
        is_draining(),
        ACTIVE_RELAY_SESSIONS.load(Ordering::SeqCst),
        MAX_RELAY_SESSIONS.load(Ordering::SeqCst),
    )
    .is_open()
}

/// Why a new relay session would be refused, if it would be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionBlock {
    /// The operator set `STARRY_RELAY_DRAINING` or created the draining file.
    Draining,
    /// Every session slot is taken.
    AtCapacity,
}

/// The single admission predicate, shared by the data plane and `/readyz`.
///
/// Both callers must ask the same question: a readiness probe that answered
/// "accepting" while `RelayLoadGuard::try_new` refused a peer would send traffic
/// to a relay that drops it. Keeping the arithmetic here — with the values
/// passed in rather than read from globals — is what lets the tests cover the
/// four combinations without mutating process state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Open,
    Blocked(AdmissionBlock),
}

impl Admission {
    pub(crate) fn is_open(self) -> bool {
        matches!(self, Admission::Open)
    }
}

pub(crate) fn admission_decision(draining: bool, active: usize, capacity: usize) -> Admission {
    if draining {
        // Draining wins over capacity: an operator draining a busy relay wants
        // to see "draining", not "full", because only one of those is a
        // capacity problem they might try to fix by waiting.
        return Admission::Blocked(AdmissionBlock::Draining);
    }
    if active >= capacity.max(1) {
        return Admission::Blocked(AdmissionBlock::AtCapacity);
    }
    Admission::Open
}

struct RelayLoadGuard {
    bandwidth_bps: usize,
}

impl RelayLoadGuard {
    fn try_new() -> Option<Self> {
        if is_draining() {
            return None;
        }
        let capacity = MAX_RELAY_SESSIONS.load(Ordering::SeqCst).max(1);
        ACTIVE_RELAY_SESSIONS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < capacity).then_some(active.saturating_add(1))
            })
            .ok()?;
        Some(Self { bandwidth_bps: 0 })
    }

    fn update(&mut self, sample_bps: usize) {
        let bandwidth_bps = if self.bandwidth_bps == 0 {
            sample_bps
        } else {
            self.bandwidth_bps
                .saturating_mul(3)
                .saturating_add(sample_bps)
                / 4
        };
        if bandwidth_bps >= self.bandwidth_bps {
            ACTIVE_RELAY_BANDWIDTH_BPS.fetch_add(
                bandwidth_bps - self.bandwidth_bps,
                Ordering::SeqCst,
            );
        } else {
            atomic_saturating_sub(
                &ACTIVE_RELAY_BANDWIDTH_BPS,
                self.bandwidth_bps - bandwidth_bps,
            );
        }
        self.bandwidth_bps = bandwidth_bps;
    }
}

impl Drop for RelayLoadGuard {
    fn drop(&mut self) {
        atomic_saturating_sub(&ACTIVE_RELAY_BANDWIDTH_BPS, self.bandwidth_bps);
        atomic_saturating_sub(&ACTIVE_RELAY_SESSIONS, 1);
    }
}

#[cfg(test)]
mod starry_telemetry_tests {
    use super::*;

    #[test]
    fn probe_rate_limiter_enforces_global_per_ip_and_dimension_bounds() {
        PROBE_PER_IP_PER_MINUTE.store(1, Ordering::SeqCst);
        PROBE_GLOBAL_PER_MINUTE.store(2, Ordering::SeqCst);
        let mut limiter = ProbeRateLimiter::default();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(limiter.allow(first, 60));
        assert!(!limiter.allow(first, 60));
        assert!(limiter.allow(second, 60));
        assert!(!limiter.allow("203.0.113.1".parse().unwrap(), 60));
        assert!(limiter.per_ip.len() <= PROBE_IP_BUCKET_CAPACITY);
        PROBE_PER_IP_PER_MINUTE.store(120, Ordering::SeqCst);
        PROBE_GLOBAL_PER_MINUTE.store(10_000, Ordering::SeqCst);
    }

    #[test]
    fn telemetry_replay_cache_is_bounded_and_rejects_reuse() {
        let mut cache = TelemetryReplayCache::default();
        assert!(cache.insert_fresh(100, "nonce-a"));
        assert!(!cache.insert_fresh(100, "nonce-a"));
        for index in 0..TELEMETRY_REPLAY_CAPACITY + 32 {
            assert!(cache.insert_fresh(100, &format!("nonce-{index}")));
        }
        assert!(cache.order.len() <= TELEMETRY_REPLAY_CAPACITY);
        assert!(cache.entries.len() <= TELEMETRY_REPLAY_CAPACITY);
    }
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = "".to_owned();
    let mut fds = cmd.trim().split(' ');
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLACKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLACKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLACKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLOCKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLOCKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLOCKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        DOWNGRADE_THRESHOLD_100.store((v * 100.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<usize>() {
                    if v > 0 {
                        DOWNGRADE_START_CHECK.store(v * 1000, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!("{}s\n", DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000);
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        LIMIT_SPEED.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        TOTAL_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                        limiter.set_speed_limit(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        SINGLE_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .read()
                .await
                .iter()
                .map(|x| (x.0.clone(), *x.1))
                .collect();
            tmp.sort_by(|a, b| ((b.1).1).partial_cmp(&(a.1).1).unwrap());
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}kb/s {}kb/s {}kb/s",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(
    listener: TcpListener,
    listener2: TcpListener,
    listener_console: Option<TcpListener>,
    key: &str,
) {
    check_params();
    let limiter = <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = crate::common::accept_or_pending(listener_console.as_ref()) => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("console listener.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

/// Accepts a relay connection and routes loopback console requests separately.
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    limiter: &Limiter,
    key: &str,
    ws: bool,
) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    if let Err(err) = timeout(1000, stream.write_all(res.as_bytes()))
                        .await
                        .unwrap_or_else(|elapsed| Err(elapsed.into()))
                    {
                        log::warn!("Failed to send the console reply: {err}");
                    }
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    let reported = addr.ip().to_string();
    let listed = |list: &HashSet<String>| list.contains(&ip) || list.contains(&reported);
    if listed(&*BLOCKLIST.read().await) {
        log::info!("{} blocked", ip);
        return;
    }
    let key = key.to_owned();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, &key, limiter, ws).await);
    });
}

/// Prepares a TCP or WebSocket relay stream and begins pairing.
///
/// Starry adds the authenticated `/ws/telemetry` endpoint and public
/// capability headers; the bounded handshake, buffer sizes and forwarded-IP
/// handling follow upstream rustdesk-server 1.1.17 (#722, #725, #747).
async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    let probe_source_ip = addr.ip();
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let telemetry_connection = Arc::new(AtomicBool::new(false));
        let telemetry_flag = telemetry_connection.clone();
        let callback = move |req: &Request, mut response: Response| {
            if req.uri().path() == "/ws/telemetry" {
                if req.uri().query().is_some() {
                    increment(&TELEMETRY_AUTH_FAILURES);
                    return Err(http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Some("Unauthorized".to_owned()))
                        .unwrap());
                }
                let Some(request_nonce) = authenticate_telemetry_request(req) else {
                    increment(&TELEMETRY_AUTH_FAILURES);
                    return Err(http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Some("Unauthorized".to_owned()))
                        .unwrap());
                };
                add_public_capability_headers(&mut response);
                if !add_authenticated_telemetry_headers(&mut response, &request_nonce) {
                    return Err(http::Response::builder()
                        .status(http::StatusCode::SERVICE_UNAVAILABLE)
                        .body(Some("Unavailable".to_owned()))
                        .unwrap());
                }
                telemetry_flag.store(true, Ordering::SeqCst);
                return Ok(response);
            }
            let headers = req.headers();
            // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
            // client IP is preserved when the WebSocket port runs behind a
            // reverse proxy (WSS). They are NOT validated: anyone who can reach
            // this port directly can spoof an arbitrary IP, bypassing IP-based
            // rate limiting / blocking and corrupting logged IPs. Do not expose
            // the WebSocket port directly to untrusted networks; only the
            // reverse proxy, which overwrites these headers, should be able to
            // connect to it.
            // https://github.com/rustdesk/rustdesk-server/issues/634
            let real_ip = headers
                .get("X-Real-IP")
                .or_else(|| headers.get("X-Forwarded-For"))
                .and_then(|header_value| header_value.to_str().ok());
            if let Some(ip) = real_ip {
                if let Ok(ip) = ip.parse() {
                    addr = SocketAddr::new(ip, addr.port());
                }
            }
            add_public_capability_headers(&mut response);
            Ok(response)
        };
        // The message bound is set in make_pair_, once the handshake is done.
        let ws_config = tungstenite::protocol::WebSocketConfig::default()
            .read_buffer_size(WS_BUFFER_SIZE)
            .write_buffer_size(WS_BUFFER_SIZE);
        let mut ws_stream = timeout(
            30_000,
            tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
        )
        .await??;
        if telemetry_connection.load(Ordering::SeqCst) {
            allow_err!(ws_stream.close(None).await);
            return Ok(());
        }
        make_pair_(ws_stream, addr, probe_source_ip, key, limiter).await;
    } else {
        make_pair_(
            FramedStream::from(stream, addr),
            addr,
            probe_source_ip,
            key,
            limiter,
        )
        .await;
    }
    Ok(())
}

/// Answers a public Relay quality probe, or checks the relay key and pairs a
/// request with a waiting connection.
async fn make_pair_(
    stream: impl StreamTrait,
    addr: SocketAddr,
    probe_source_ip: IpAddr,
    key: &str,
    limiter: Limiter,
) {
    let mut stream = stream;
    stream.set_max_packet_length(MAX_RELAY_REQUEST_LEN);
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RelayProbeRequest(probe)) => {
                    let allowed = PROBE_RATE_LIMITER
                        .lock()
                        .map(|mut limiter| limiter.allow(probe_source_ip, unix_seconds()))
                        .unwrap_or(false);
                    if !allowed {
                        increment(&PROBE_RATE_LIMITED);
                        return;
                    }
                    if probe.nonce.len() != 16 {
                        increment(&PROBE_MALFORMED);
                        return;
                    }
                    if probe.protocol_version != 1 {
                        increment(&PROBE_UNSUPPORTED);
                        return;
                    }
                    let mut response = RendezvousMessage::new();
                    response.set_relay_probe_response(RelayProbeResponse {
                        protocol_version: 1,
                        nonce: probe.nonce,
                        starry_version: starry_version(),
                        relay_probe_protocol: 1,
                        relay_load_protocol: 1,
                        ..Default::default()
                    });
                    if let Ok(bytes) = response.write_to_bytes() {
                        if matches!(
                            timeout(30_000, stream.send_raw(bytes.into())).await,
                            Ok(Ok(()))
                        ) {
                            increment(&PROBE_SUCCESSFUL);
                        }
                    }
                }
                Some(rendezvous_message::Union::RequestRelay(rf)) => {
                    if !key.is_empty() && rf.licence_key != key {
                        log::warn!("Relay authentication failed from {} - invalid key", addr);
                        return;
                    }
                    if rf.uuid.is_empty() {
                        return;
                    }
                    let mut peers = PEERS.lock().await;
                    if let Some((_, mut peer)) = peers.remove(&rf.uuid) {
                        drop(peers);
                        atomic_saturating_sub(&PENDING_RELAY_PAIRS, 1);
                        let Some(mut load_guard) = RelayLoadGuard::try_new() else {
                            increment(&ADMISSION_REJECTIONS);
                            return;
                        };
                        log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                        let id = format!("{}:{}", addr.ip(), addr.port());
                        USAGE.write().await.insert(id.clone(), Default::default());
                        if !stream.is_ws() && !peer.is_ws() {
                            peer.set_raw();
                            stream.set_raw();
                            log::info!("Both are raw");
                        } else {
                            // A leg that stays framed now carries session data.
                            peer.set_max_packet_length(usize::MAX);
                            stream.set_max_packet_length(usize::MAX);
                        }
                        if let Err(err) = relay_tracked(
                            addr,
                            &mut stream,
                            &mut peer,
                            limiter,
                            id.clone(),
                            &mut load_guard,
                        )
                        .await
                        {
                            log::info!("Relay of {} closed: {}", addr, err);
                        } else {
                            log::info!("Relay of {} closed", addr);
                        }
                        USAGE.write().await.remove(&id);
                    } else {
                        if !admission_available()
                            || PENDING_RELAY_PAIRS.load(Ordering::SeqCst)
                                >= MAX_RELAY_SESSIONS.load(Ordering::SeqCst).max(1)
                        {
                            increment(&ADMISSION_REJECTIONS);
                            return;
                        }
                        log::info!("New relay request {} from {}", rf.uuid, addr);
                        let generation = Arc::new(());
                        let replaced =
                            peers.insert(rf.uuid.clone(), (generation.clone(), Box::new(stream)));
                        drop(peers);
                        if replaced.is_none() {
                            PENDING_RELAY_PAIRS.fetch_add(1, Ordering::SeqCst);
                        }
                        sleep(30.).await;
                        if expire_waiter(&mut *PEERS.lock().await, &rf.uuid, &generation) {
                            atomic_saturating_sub(&PENDING_RELAY_PAIRS, 1);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Removes a waiting connection only if it still owns the requested pair ID.
fn expire_waiter(peers: &mut HashMap<String, WaitingPeer>, id: &str, generation: &Arc<()>) -> bool {
    if peers.get(id).map(|(current, _)| Arc::ptr_eq(current, generation)).unwrap_or(false) {
        peers.remove(id);
        return true;
    }
    false
}

/// Forwards traffic in both directions while enforcing relay limits and timeouts.
#[cfg(test)]
async fn relay(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
) -> ResultType<()> {
    let mut load_guard = RelayLoadGuard::try_new().expect("test relay admission");
    relay_tracked(addr, stream, peer, total_limiter, id, &mut load_guard).await
}

async fn relay_tracked(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
    load_guard: &mut RelayLoadGuard,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    // The dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d; lists may hold either form.
    let unmapped = hbb_common::try_into_v4(addr).ip().to_string();
    let listed = |list: &HashSet<String>| list.contains(&ip) || list.contains(&unmapped);
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let limiter = <Limiter>::new(sb);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as _);
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100. / 1000.) as usize; // in bit/ms
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        timeout(30_000, stream.send_raw(bytes.into())).await??;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        timeout(30_000, peer.send_raw(bytes.into())).await??;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            if listed(&*BLOCKLIST.read().await) {
                log::info!("{} blocked", ip);
                break;
            }
            blacked = listed(&*BLACKLIST.read().await);
            tm = std::time::Instant::now();
            let speed = total_s / n;
            load_guard.update(speed.saturating_mul(1_000));
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total > elapsed * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStream {
        data: Option<BytesMut>,
        blocked: bool,
    }

    #[async_trait]
    impl StreamTrait for TestStream {
        /// Provides the test stream receive behavior.
        async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
            match self.data.take() {
                Some(data) => Some(Ok(data)),
                None => std::future::pending().await,
            }
        }
        /// Simulates a relay write for the test stream.
        async fn send_raw(&mut self, _: Bytes) -> ResultType<()> {
            if self.blocked { std::future::pending().await } else { Ok(()) }
        }
        /// Uses non-WebSocket framing for the test stream.
        fn is_ws(&self) -> bool { false }
        /// Leaves the test stream unchanged when raw mode is requested.
        fn set_raw(&mut self) {}
        fn set_max_packet_length(&mut self, _: usize) {}
    }

    /// Checks that a blocked relay write ends with a timeout in the selected direction.
    async fn check_blocked_send(from_peer: bool) {
        let mut stream = TestStream {
            data: if from_peer { None } else { Some(BytesMut::from(&b"x"[..])) },
            blocked: from_peer,
        };
        let mut peer: Box<dyn StreamTrait> = Box::new(TestStream {
            data: if from_peer { Some(BytesMut::from(&b"x"[..])) } else { None },
            blocked: !from_peer,
        });
        let result = timeout(35_000, relay(
            "127.0.0.1:1".parse().unwrap(), &mut stream, &mut peer,
            Limiter::new(1_000_000.), "blocked-send-test".to_owned(),
        )).await.expect("a blocked relay write must finish within its deadline");
        let error = result.expect_err("the blocked write must fail");
        assert!(error.downcast_ref::<tokio::time::error::Elapsed>().is_some());
    }

    /// Checks that stalled writes time out in either relay direction.
    #[tokio::test]
    async fn blocked_writes_in_both_directions_time_out() {
        tokio::join!(check_blocked_send(false), check_blocked_send(true));
    }

    #[tokio::test]
    async fn only_a_blocklisted_ipv4_client_on_the_dual_stack_listener_is_cut_off() {
        // The plain form is what `ba` is usually given; the mapped one is what `usage` shows.
        // A client not listed must outlive the first list check, which runs at 3 s.
        for (entry, client, cut_off) in [
            ("192.0.2.55", "[::ffff:192.0.2.55]:1", true),
            ("::ffff:192.0.2.55", "[::ffff:192.0.2.55]:1", true),
            ("192.0.2.55", "[::ffff:192.0.2.56]:1", false),
        ] {
            BLOCKLIST.write().await.insert(entry.to_owned());
            let mut stream = TestStream {
                data: None,
                blocked: false,
            };
            let mut peer: Box<dyn StreamTrait> = Box::new(TestStream {
                data: None,
                blocked: false,
            });
            let result = timeout(
                if cut_off { 10_000 } else { 4_000 },
                relay(
                    client.parse().unwrap(),
                    &mut stream,
                    &mut peer,
                    Limiter::new(1_000_000.),
                    "blocklist-test".to_owned(),
                ),
            )
            .await;
            BLOCKLIST.write().await.remove(entry);
            assert!(
                matches!((cut_off, &result), (true, Ok(Ok(()))) | (false, Err(_))),
                "client {client}, blocklist entry {entry}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_client_blocklisted_in_either_form_is_refused_at_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (entry, refused) in [
            ("192.0.2.57", true),
            ("::ffff:192.0.2.57", true),
            ("192.0.2.58", false),
        ] {
            BLOCKLIST.write().await.insert(entry.to_owned());
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let addr = "[::ffff:192.0.2.57]:1".parse().unwrap();
            handle_connection(stream, addr, &Limiter::new(1_000_000.), "", false).await;
            BLOCKLIST.write().await.remove(entry);
            let read = timeout(1_000, client.read(&mut [0; 1])).await;
            assert!(
                matches!((refused, &read), (true, Ok(Ok(0))) | (false, Err(_))),
                "blocklist entry {entry}: {read:?}"
            );
        }
    }
}

/// Returns the configured relay key or resolves a signing key to its public value.
fn get_server_sk(key: &str) -> ResultType<String> {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300)?;
        key = pk;
    }

    if !key.is_empty() {
        log::info!("Key: {}", key);
    }

    Ok(key)
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
    fn set_max_packet_length(&mut self, n: usize);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }

    fn set_max_packet_length(&mut self, n: usize) {
        self.codec_mut().set_max_packet_length(n);
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self.send(tungstenite::Message::Binary(bytes)).await?)
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}

    fn set_max_packet_length(&mut self, n: usize) {
        self.set_config(|c| {
            c.max_message_size = Some(n.min(WS_DEFAULT_MAX_MESSAGE_SIZE));
            c.max_frame_size = Some(n.min(WS_DEFAULT_MAX_FRAME_SIZE));
        });
    }
}

#[cfg(test)]
mod message_size_tests {
    use super::*;
    use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::Encoder};

    async fn serve_one(ws: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            allow_err!(make_pair(stream, addr, "", <Limiter>::new(f64::INFINITY), ws).await);
        });
        addr
    }

    fn relay_request(uuid: &str) -> Vec<u8> {
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            uuid: uuid.to_owned(),
            ..Default::default()
        });
        msg.write_to_bytes().unwrap()
    }

    #[hbb_common::tokio::test]
    async fn relay_request_over_the_bound_is_refused_on_its_header() {
        let addr = serve_one(false).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let payload_len = MAX_RELAY_REQUEST_LEN + 1;
        let mut frame = BytesMut::new();
        BytesCodec::new()
            .encode(Bytes::from(vec![0u8; payload_len]), &mut frame)
            .unwrap();
        client.write_all(&frame[..frame.len() - payload_len]).await.unwrap();
        let mut byte = [0u8; 1];
        let read = timeout(5_000, client.read(&mut byte))
            .await
            .expect("hbbr waited for the payload of an oversized relay request");
        assert_eq!(read.unwrap(), 0);
    }

    async fn ws_client(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();
        tokio_tungstenite::client_async(format!("ws://{addr}"), stream)
            .await
            .unwrap()
            .0
    }

    #[hbb_common::tokio::test]
    async fn ws_relay_request_over_the_bound_is_refused_on_its_header() {
        let addr = serve_one(true).await;
        let mut ws = ws_client(addr).await;
        let client = ws.get_mut();
        let mut header = vec![0x82, 0xff];
        header.extend_from_slice(&(MAX_RELAY_REQUEST_LEN as u64 + 1).to_be_bytes());
        header.extend_from_slice(&[1, 2, 3, 4]);
        client.write_all(&header).await.unwrap();
        let mut buf = [0u8; 256];
        let closed = timeout(5_000, async {
            while client.read(&mut buf).await.unwrap_or(0) > 0 {}
        })
        .await;
        assert!(closed.is_ok(), "hbbr waited for the payload of an oversized relay request");
    }

    #[hbb_common::tokio::test]
    async fn paired_legs_carry_frames_past_the_relay_request_bound() {
        let uuid = "paired-legs";
        let ws_addr = serve_one(true).await;
        let tcp_addr = serve_one(false).await;
        let mut ws = ws_client(ws_addr).await;
        ws.send(tungstenite::Message::Binary(relay_request(uuid).into()))
            .await
            .unwrap();
        // Park the websocket leg first, so the tcp leg is the one that pairs.
        timeout(5_000, async {
            while !PEERS.lock().await.contains_key(uuid) {
                sleep(0.01).await;
            }
        })
        .await
        .expect("websocket leg never parked");
        let mut tcp = FramedStream::from(TcpStream::connect(tcp_addr).await.unwrap(), tcp_addr);
        tcp.send_bytes(relay_request(uuid).into()).await.unwrap();
        let big = vec![7u8; MAX_RELAY_REQUEST_LEN * 2];
        tcp.send_bytes(big.clone().into()).await.unwrap();
        let got = timeout(5_000, ws.next())
            .await
            .expect("relay did not forward the tcp frame")
            .expect("relay closed the websocket leg")
            .unwrap();
        assert_eq!(got.into_data(), big);
        ws.send(tungstenite::Message::Binary(big.clone().into()))
            .await
            .unwrap();
        let got = tcp
            .next_timeout(5_000)
            .await
            .expect("relay did not forward the websocket message")
            .unwrap();
        assert_eq!(&got[..], &big[..]);
    }
}

#[cfg(test)]
mod waiter_tests {
    use super::*;

    struct TestStream;

    #[async_trait]
    impl StreamTrait for TestStream {
        /// Provides the test stream receive behavior.
        async fn recv(&mut self) -> Option<Result<BytesMut, Error>> { None }
        /// Simulates a relay write for the test stream.
        async fn send_raw(&mut self, _: Bytes) -> ResultType<()> { Ok(()) }
        /// Uses non-WebSocket framing for the test stream.
        fn is_ws(&self) -> bool { false }
        /// Leaves the test stream unchanged when raw mode is requested.
        fn set_raw(&mut self) {}
        fn set_max_packet_length(&mut self, _: usize) {}
    }

    /// Checks that an old timeout cannot remove a replacement waiter.
    #[test]
    fn old_waiter_cannot_expire_a_reused_pair_id() {
        let old = Arc::new(());
        let current = Arc::new(());
        let mut peers: HashMap<String, WaitingPeer> = HashMap::new();
        peers.insert("pair".to_owned(), (current.clone(), Box::new(TestStream)));
        expire_waiter(&mut peers, "pair", &old);
        assert!(peers.contains_key("pair"));
        expire_waiter(&mut peers, "pair", &current);
        assert!(!peers.contains_key("pair"));
    }
}
