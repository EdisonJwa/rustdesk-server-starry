//! Operator-facing health and metrics surface for HBBR.
//!
//! HBBR keeps detailed relay state behind authenticated telemetry. Operators
//! still need a cheap, local probe for supervision (systemd, Kubernetes,
//! load balancers) and a scrape target for Prometheus. This listener is
//! therefore:
//!
//! - **default off**: `STARRY_RELAY_OPS_LISTEN` must name an address;
//! - **loopback by default**: the parser refuses a non-loopback address
//!   unless `STARRY_RELAY_OPS_ALLOW_PUBLIC=1` is set explicitly, because the
//!   payload describes relay capacity and admission pressure;
//! - **read-only**: it serves two fixed routes and never mutates state; and
//! - **dependency free**: it writes HTTP/1.1 by hand, so it adds no crate to
//!   the reviewed dependency graph and no Buildx/binary surface.
//!
//! `/healthz` answers `{"status":"ok",...}` with the same version string the
//! WebSocket capability headers carry. `/metrics` renders Prometheus text
//! format (version 0.0.4) from the atomics the relay already maintains.
//!
//! # Two probes, two questions
//!
//! `/healthz` is **liveness**: is this process alive and serving HTTP? It stays
//! 200 while the relay is draining or full, because the remedy for either is to
//! leave the process alone. A supervisor that restarted a draining relay would
//! undo an operator's deliberate action, and one that restarted a full relay
//! would drop every session on it and change nothing about capacity.
//!
//! `/readyz` is **readiness**: would a new relay session be admitted right now?
//! It answers 503 with the reason when the answer is no, so a load balancer or
//! a service registry can stop sending peers here while existing sessions keep
//! running. Its verdict comes from `relay_server::admission_decision`, the same
//! predicate the data plane uses, so it cannot report "ready" while the peer
//! path refuses the connection.

use hbb_common::{
    log,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    },
};
use std::{net::SocketAddr, time::Duration};

use crate::relay_server::{
    admission_decision, ops_snapshot, Admission, AdmissionBlock, OpsSnapshot,
};

/// Bytes read from one operations request before giving up.
const OPS_REQUEST_LIMIT: usize = 8 << 10;
/// Deadline for reading a request and for writing a response.
const OPS_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves the configured operations address, if any.
///
/// Returns `Err` for a value that parses but is not allowed to bind, so a
/// typo cannot silently expose capacity data on a public interface.
pub(crate) fn configured_listen() -> Result<Option<SocketAddr>, String> {
    let raw = match std::env::var("STARRY_RELAY_OPS_LISTEN") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let address: SocketAddr = trimmed
        .parse()
        .map_err(|_| "STARRY_RELAY_OPS_LISTEN must be ip:port".to_owned())?;
    if !address.ip().is_loopback() && !allow_public() {
        return Err("STARRY_RELAY_OPS_LISTEN must be a loopback address unless \
             STARRY_RELAY_OPS_ALLOW_PUBLIC=1"
            .to_owned());
    }
    Ok(Some(address))
}

fn allow_public() -> bool {
    matches!(
        std::env::var("STARRY_RELAY_OPS_ALLOW_PUBLIC").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Starts the operations listener when it is configured.
///
/// Failures are logged rather than fatal: a misconfigured supervision port
/// must not take the relay down, and the relay itself is the product.
pub(crate) fn spawn() {
    let address = match configured_listen() {
        Ok(Some(address)) => address,
        Ok(None) => return,
        Err(err) => {
            log::error!("Relay operations listener disabled: {err}");
            return;
        }
    };
    tokio::spawn(async move {
        let listener = match TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("Cannot bind relay operations listener {address}: {err}");
                return;
            }
        };
        log::info!("Relay operations listener on http://{address}");
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    tokio::spawn(serve(stream));
                }
                Err(err) => {
                    log::warn!("Relay operations accept failed: {err}");
                    return;
                }
            }
        }
    });
}

async fn serve(mut stream: TcpStream) {
    let Some((method, path)) = read_request_target(&mut stream).await else {
        return;
    };
    let (status, content_type, body) = match path.as_str() {
        "/healthz" => {
            let (status, body) = health_body();
            (status, APPLICATION_JSON, body)
        }
        "/readyz" => {
            let (status, body) = ready_body();
            (status, APPLICATION_JSON, body)
        }
        "/metrics" => ("200 OK", TEXT_PLAIN, metrics_body()),
        _ => ("404 Not Found", TEXT_PLAIN, "unknown endpoint\n".to_owned()),
    };

    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    // HEAD reports the same headers with no body, as HTTP requires.
    let include_body = method == "GET";
    let write = async {
        stream.write_all(head.as_bytes()).await?;
        if include_body {
            stream.write_all(body.as_bytes()).await?;
        }
        stream.flush().await
    };
    if timeout(OPS_IO_TIMEOUT, write).await.is_err() {
        log::debug!("Relay operations response timed out");
    }
}

const APPLICATION_JSON: &str = "application/json";
const TEXT_PLAIN: &str = "text/plain; version=0.0.4";

/// Reads the request method and target from one HTTP/1.1 request line.
///
/// Only GET and HEAD are accepted: the operations surface has no mutable
/// routes, so other methods are refused instead of being answered.
async fn read_request_target(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buffer.len() >= OPS_REQUEST_LIMIT {
            return None;
        }
        let read = timeout(OPS_IO_TIMEOUT, stream.read(&mut chunk)).await;
        let count = match read {
            Ok(Ok(0)) => return None,
            Ok(Ok(count)) => count,
            Ok(Err(err)) => {
                log::debug!("Relay operations read failed: {err}");
                return None;
            }
            Err(_) => return None,
        };
        buffer.extend_from_slice(&chunk[..count]);
        if let Some(end) = find_request_end(&buffer) {
            return request_line(&buffer[..end]);
        }
    }
}

fn find_request_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn request_line(request: &[u8]) -> Option<(String, String)> {
    let line = std::str::from_utf8(request).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method != "GET" && method != "HEAD" {
        return None;
    }
    let path = target.split('?').next().unwrap_or(target);
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    Some((method.to_owned(), path.to_owned()))
}

/// The facts a probe body renders, lifted out of the live snapshot.
///
/// Exists so the renderers are pure: the tests can then assert both probes
/// across every admission state without mutating process-wide counters or
/// environment variables, which is the only way to cover "draining" and "full"
/// in one test binary.
#[derive(Clone, Debug)]
struct ProbeView {
    version: String,
    uptime_seconds: u64,
    active_sessions: u64,
    capacity_sessions: u64,
    admission_rejections: u64,
    admission: Admission,
}

impl ProbeView {
    fn from_snapshot(snapshot: &OpsSnapshot) -> Self {
        // Re-derive from the live counters so the view carries the verdict the
        // data plane would reach, not a second opinion.
        let admission = admission_decision(
            snapshot.draining,
            snapshot.active_sessions as usize,
            snapshot.capacity_sessions as usize,
        );
        Self {
            version: snapshot.version.clone(),
            uptime_seconds: snapshot.uptime_seconds,
            active_sessions: snapshot.active_sessions,
            capacity_sessions: snapshot.capacity_sessions,
            admission_rejections: snapshot.admission_rejections,
            admission,
        }
    }

    #[cfg(test)]
    fn for_test(active: u64, capacity: u64, draining: bool) -> Self {
        Self {
            version: "test-patch-v0".to_owned(),
            uptime_seconds: 1,
            active_sessions: active,
            capacity_sessions: capacity,
            admission_rejections: 0,
            admission: admission_decision(draining, active as usize, capacity as usize),
        }
    }
}

/// Machine-readable liveness and version report.
///
/// Always 200: the process answering this request is, by definition, able to
/// serve HTTP. Whether it can take new sessions is `/readyz`'s question, and
/// conflating the two is what makes a supervisor restart a healthy relay.
fn health_body() -> (&'static str, String) {
    render_health(&ProbeView::from_snapshot(&ops_snapshot()))
}

fn render_health(view: &ProbeView) -> (&'static str, String) {
    (
        "200 OK",
        format!(
            "{{\"status\":\"ok\",\"version\":\"{}\",\"uptime_seconds\":{},\
             \"admission_rejections\":{},\"draining\":{},\"admission_open\":{}}}",
            view.version,
            view.uptime_seconds,
            view.admission_rejections,
            matches!(view.admission, Admission::Blocked(AdmissionBlock::Draining)),
            view.admission.is_open()
        ),
    )
}

/// Readiness report: would a new relay session be admitted?
///
/// 503 carries the reason so an operator does not have to correlate a load
/// metric to understand why the relay is out of rotation.
fn ready_body() -> (&'static str, String) {
    render_ready(&ProbeView::from_snapshot(&ops_snapshot()))
}

fn render_ready(view: &ProbeView) -> (&'static str, String) {
    match view.admission {
        Admission::Open => (
            "200 OK",
            format!(
                "{{\"status\":\"ready\",\"version\":\"{}\",\"active_sessions\":{},\
                 \"capacity_sessions\":{}}}",
                view.version, view.active_sessions, view.capacity_sessions
            ),
        ),
        Admission::Blocked(block) => {
            let reason = match block {
                AdmissionBlock::Draining => "draining",
                AdmissionBlock::AtCapacity => "at_capacity",
            };
            (
                "503 Service Unavailable",
                format!(
                    "{{\"status\":\"not_ready\",\"reason\":\"{reason}\",\"version\":\"{}\",\
                     \"active_sessions\":{},\"capacity_sessions\":{}}}",
                    view.version, view.active_sessions, view.capacity_sessions
                ),
            )
        }
    }
}

/// Renders the Prometheus text exposition of the relay's live state.
fn metrics_body() -> String {
    let snapshot = ops_snapshot();
    let mut out = String::with_capacity(2048);

    gauge(
        &mut out,
        "starry_relay_active_sessions",
        "Relay sessions currently carrying traffic.",
        snapshot.active_sessions,
    );
    gauge(
        &mut out,
        "starry_relay_capacity_sessions",
        "Configured concurrent relay session capacity.",
        snapshot.capacity_sessions,
    );
    gauge(
        &mut out,
        "starry_relay_active_bandwidth_bps",
        "Bandwidth currently in use across relay sessions.",
        snapshot.active_bandwidth_bps,
    );
    gauge(
        &mut out,
        "starry_relay_capacity_bandwidth_bps",
        "Configured total relay bandwidth capacity.",
        snapshot.capacity_bandwidth_bps,
    );
    gauge(
        &mut out,
        "starry_relay_load_basis_points",
        "Higher of session and bandwidth utilisation, in basis points.",
        snapshot.load_basis_points,
    );
    gauge(
        &mut out,
        "starry_relay_pending_pairs",
        "Relay pair IDs waiting for a peer.",
        snapshot.pending_pairs,
    );
    gauge(
        &mut out,
        "starry_relay_uptime_seconds",
        "Seconds since the process started serving.",
        snapshot.uptime_seconds,
    );

    counter_metric(
        &mut out,
        "starry_relay_admission_rejections_total",
        "Relay admissions refused because capacity was exhausted.",
        snapshot.admission_rejections,
    );
    counter_metric(
        &mut out,
        "starry_relay_probes_successful_total",
        "Relay quality probes answered.",
        snapshot.probes_successful,
    );
    counter_metric(
        &mut out,
        "starry_relay_probes_rate_limited_total",
        "Relay quality probes refused by the rate limiter.",
        snapshot.probes_rate_limited,
    );
    counter_metric(
        &mut out,
        "starry_relay_probes_unsupported_total",
        "Relay quality probes refused for an unsupported protocol.",
        snapshot.probes_unsupported,
    );
    counter_metric(
        &mut out,
        "starry_relay_probes_malformed_total",
        "Relay quality probes refused as malformed.",
        snapshot.probes_malformed,
    );
    counter_metric(
        &mut out,
        "starry_relay_telemetry_auth_failures_total",
        "Authenticated telemetry requests refused during the handshake.",
        snapshot.telemetry_auth_failures,
    );
    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

fn counter_metric(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_accepts_get_and_head_only() {
        let get = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
        let end = find_request_end(get).unwrap();
        assert_eq!(
            request_line(&get[..end]),
            Some(("GET".to_owned(), "/metrics".to_owned()))
        );

        let head = b"HEAD /healthz?probe=1 HTTP/1.1\r\n\r\n";
        let end = find_request_end(head).unwrap();
        assert_eq!(
            request_line(&head[..end]),
            Some(("HEAD".to_owned(), "/healthz".to_owned()))
        );

        let post = b"POST /metrics HTTP/1.1\r\n\r\n";
        let end = find_request_end(post).unwrap();
        assert_eq!(request_line(&post[..end]), None);
    }

    #[test]
    fn metrics_render_prometheus_text_format() {
        let body = metrics_body();
        assert!(body.contains("# TYPE starry_relay_active_sessions gauge"));
        assert!(body.contains("# TYPE starry_relay_admission_rejections_total counter"));
        for line in body.lines().filter(|line| !line.starts_with('#')) {
            let (name, value) = line.rsplit_once(' ').expect("name and value");
            assert!(name.starts_with("starry_relay_"), "{line}");
            assert!(value.parse::<u64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn health_body_is_json() {
        let (status, body) = health_body();
        assert_eq!(status, "200 OK");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert!(parsed["version"].as_str().unwrap().contains("-patch-v"));
    }

    /// Liveness must not depend on admission.
    ///
    /// This is the whole point of the split: a relay that is draining or full is
    /// still alive, and restarting it would either undo an operator's decision
    /// or drop live sessions without adding capacity.
    #[test]
    fn healthz_reports_ok_regardless_of_admission() {
        for draining in [false, true] {
            for (active, capacity) in [(0u64, 4u64), (4, 4), (9, 4)] {
                let view = ProbeView::for_test(active, capacity, draining);
                let (status, body) = render_health(&view);
                assert_eq!(status, "200 OK", "draining={draining} {active}/{capacity}");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["status"], "ok");
                assert_eq!(parsed["draining"], draining);
                assert_eq!(parsed["admission_open"], view.admission.is_open());
            }
        }
    }

    #[test]
    fn readyz_answers_for_every_admission_state() {
        let ready = ProbeView::for_test(2, 4, false);
        let (status, body) = render_ready(&ready);
        assert_eq!(status, "200 OK");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["status"],
            "ready"
        );

        let full = ProbeView::for_test(4, 4, false);
        let (status, body) = render_ready(&full);
        assert_eq!(status, "503 Service Unavailable");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["status"], "not_ready");
        assert_eq!(parsed["reason"], "at_capacity");

        let draining = ProbeView::for_test(1, 4, true);
        let (status, body) = render_ready(&draining);
        assert_eq!(status, "503 Service Unavailable");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["reason"],
            "draining"
        );
    }

    #[test]
    fn admission_decision_covers_every_state() {
        assert!(admission_decision(false, 0, 4).is_open());
        assert!(admission_decision(false, 3, 4).is_open());
        assert_eq!(
            admission_decision(false, 4, 4),
            Admission::Blocked(AdmissionBlock::AtCapacity),
            "the last free slot is the one that admits"
        );
        assert_eq!(
            admission_decision(false, 5, 4),
            Admission::Blocked(AdmissionBlock::AtCapacity)
        );
        assert_eq!(
            admission_decision(true, 0, 4),
            Admission::Blocked(AdmissionBlock::Draining)
        );
        // Draining outranks capacity: an operator who drained a busy relay needs
        // to see their own action, not a capacity symptom they cannot act on.
        assert_eq!(
            admission_decision(true, 9, 4),
            Admission::Blocked(AdmissionBlock::Draining)
        );
    }

    /// A configured capacity of zero is clamped to one, matching the data plane.
    ///
    /// `STARRY_RELAY_MAX_SESSIONS` refuses a zero value at startup, so this only
    /// documents what the shared predicate does if it ever sees one: capacity is
    /// floored at a single session rather than blocking every peer outright.
    #[test]
    fn zero_capacity_is_floored_to_one_session() {
        assert!(admission_decision(false, 0, 0).is_open());
        assert_eq!(
            admission_decision(false, 1, 0),
            Admission::Blocked(AdmissionBlock::AtCapacity)
        );
    }
}
