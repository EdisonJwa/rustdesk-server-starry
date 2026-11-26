//! Append-only audit events for connection authentication.
//!
//! The JWT connection-auth layer keeps aggregate counters only. Operators
//! who need per-attempt evidence (who was denied, when, over which
//! transport) enable this module with one variable:
//!
//! - `STARRY_AUDIT_DIR`: directory for `audit-YYYYMMDD.jsonl` files. Empty or
//!   unset keeps the module off, matching the project's default-off posture.
//! - `STARRY_AUDIT_RETENTION_DAYS`: files older than this are pruned at
//!   rotation (default 30, `0` keeps everything).
//! - `STARRY_AUDIT_MAX_FILE_MB`: a day file above this size stops accepting
//!   events until the next day, so an attack cannot fill the disk through the
//!   audit path itself (default 256, `0` disables the cap).
//!
//! The signalling path never blocks on logging: events go through a bounded
//! channel, and a full channel drops the event and counts the drop instead
//! of stalling a connection. One process writes one file at a time; a
//! standalone exporter (`starry-audit-export`) converts JSONL to CSV
//! offline.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hbb_common::{log, tokio::sync::mpsc};

use crate::connection_auth::{AuthDecision, ConnectionAttemptKind, SignalTransport};
use crate::starry_config::ConnectionAuthMode;

/// One connection-authentication decision, as evidence.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub epoch_seconds: u64,
    pub kind: ConnectionAttemptKind,
    pub transport: SignalTransport,
    pub verdict: &'static str,
    pub reason: String,
    pub client_ip: String,
    pub mode: &'static str,
    pub group: String,
}

/// Wire labels match the serde snake_case forms used elsewhere.
pub fn kind_label(kind: &ConnectionAttemptKind) -> &'static str {
    match kind {
        ConnectionAttemptKind::PunchHole => "punch_hole",
        ConnectionAttemptKind::RequestRelay => "request_relay",
    }
}

fn kind_from_label(label: &str) -> Option<ConnectionAttemptKind> {
    Some(match label {
        "punch_hole" => ConnectionAttemptKind::PunchHole,
        "request_relay" => ConnectionAttemptKind::RequestRelay,
        _ => return None,
    })
}

pub fn transport_label(transport: &SignalTransport) -> &'static str {
    match transport {
        SignalTransport::UnsupportedUdp => "unsupported_udp",
        SignalTransport::Tcp => "tcp",
        SignalTransport::SecureTcp => "secure_tcp",
        SignalTransport::WebSocket => "websocket",
    }
}

fn transport_from_label(label: &str) -> Option<SignalTransport> {
    Some(match label {
        "unsupported_udp" => SignalTransport::UnsupportedUdp,
        "tcp" => SignalTransport::Tcp,
        "secure_tcp" => SignalTransport::SecureTcp,
        "websocket" => SignalTransport::WebSocket,
        _ => return None,
    })
}

pub fn mode_label(mode: &ConnectionAuthMode) -> &'static str {
    match mode {
        ConnectionAuthMode::Off => "off",
        ConnectionAuthMode::Audit => "audit",
        ConnectionAuthMode::Enforce => "enforce",
    }
}

fn mode_from_label(label: &str) -> Option<ConnectionAuthMode> {
    Some(match label {
        "off" => ConnectionAuthMode::Off,
        "audit" => ConnectionAuthMode::Audit,
        "enforce" => ConnectionAuthMode::Enforce,
        _ => return None,
    })
}

impl AuditEvent {
    pub fn to_jsonl(&self) -> String {
        // Manual formatting keeps the schema fixed and the writer cheap; the
        // fields are ASCII identifiers and escaped strings only.
        format!(
            "{{\"ts\":{},\"kind\":\"{}\",\"transport\":\"{}\",\"verdict\":\"{}\",\
             \"reason\":\"{}\",\"client_ip\":\"{}\",\"mode\":\"{}\",\"group\":\"{}\"}}\n",
            self.epoch_seconds,
            kind_label(&self.kind),
            transport_label(&self.transport),
            self.verdict,
            json_escape(&self.reason),
            json_escape(&self.client_ip),
            self.mode,
            json_escape(&self.group),
        )
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Default)]
struct AuditCounters {
    written: AtomicU64,
    dropped: AtomicU64,
    pruned_files: AtomicU64,
    overflows: AtomicU64,
}

static COUNTERS: AuditCounters = AuditCounters {
    written: AtomicU64::new(0),
    dropped: AtomicU64::new(0),
    pruned_files: AtomicU64::new(0),
    overflows: AtomicU64::new(0),
};

/// Events queued but not yet written when the channel is full.
const CHANNEL_CAPACITY: usize = 16_384;

struct AuditConfig {
    dir: PathBuf,
    retention_days: u64,
    max_file_bytes: u64,
}

fn load_config() -> Option<AuditConfig> {
    let dir = std::env::var("STARRY_AUDIT_DIR").ok()?;
    let trimmed = dir.trim();
    if trimmed.is_empty() {
        return None;
    }
    let retention_days = std::env::var("STARRY_AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    let max_file_bytes = std::env::var("STARRY_AUDIT_MAX_FILE_MB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(256)
        .saturating_mul(1024 * 1024);
    Some(AuditConfig {
        dir: PathBuf::from(trimmed),
        retention_days,
        max_file_bytes,
    })
}

static WRITER: OnceLock<Option<mpsc::Sender<AuditEvent>>> = OnceLock::new();

/// Queues one decision for the audit writer, if auditing is enabled.
///
/// Called from the connection path: never blocks, never panics, and silently
/// does nothing when `STARRY_AUDIT_DIR` is unset.
pub(crate) fn record(event: AuditEvent) {
    let sender = WRITER.get_or_init(|| {
        let Some(config) = load_config() else {
            return None;
        };
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        std::thread::Builder::new()
            .name("starry-audit-writer".to_owned())
            .spawn(move || writer_task(config, receiver))
            .map(|_| ())
            .expect("spawn the audit writer thread");
        Some(sender)
    });
    if let Some(sender) = sender {
        // try_send: a full channel drops the newest event rather than stalling
        // the signalling path. The drop is counted and visible in /metrics.
        if sender.try_send(event).is_err() {
            COUNTERS.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Emits one event per decision when auditing is enabled.
///
/// Decisions taken while authentication is off are noise, so they are not
/// recorded; enable connection authentication first, audit second.
pub(crate) fn record_decision(
    kind: ConnectionAttemptKind,
    transport: SignalTransport,
    decision: &AuthDecision,
    client_ip: &str,
    group: &str,
) {
    if decision.mode == ConnectionAuthMode::Off {
        return;
    }
    record(AuditEvent {
        epoch_seconds: epoch_seconds(),
        kind,
        transport,
        verdict: decision.verdict,
        reason: decision.reason.to_owned(),
        client_ip: client_ip.to_owned(),
        mode: mode_label(&decision.mode),
        group: group.to_owned(),
    });
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// The blocking half: one thread owns the current day file and applies
/// rotation and retention, so the async side only ever queues.
fn writer_task(config: AuditConfig, mut receiver: mpsc::Receiver<AuditEvent>) {
    if let Err(err) = fs::create_dir_all(&config.dir) {
        log::error!("Cannot create audit directory {}: {err}", config.dir.display());
        // Drain and count so callers see the drop instead of a silent queue.
        while receiver.blocking_recv().is_some() {
            COUNTERS.dropped.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    prune_expired(&config.dir, config.retention_days);

    let mut state: Option<DayState> = None;
    // A short sleep keeps this thread idle-friendly; the channel absorbs
    // bursts and the deadline only bounds rotation checks.
    while let Some(event) = receiver.blocking_recv() {
        let day = event.epoch_seconds / 86_400;
        let needs_new_day = state.as_ref().is_none_or(|state: &DayState| state.day != day);
        if needs_new_day {
            if let Some(mut state) = state.take() {
                state.file.flush().ok();
            }
            prune_expired(&config.dir, config.retention_days);
            match open_day_file(&config.dir, day) {
                Ok(file) => {
                    state = Some(DayState {
                        day,
                        file,
                        written: 0,
                    });
                }
                Err(err) => {
                    log::error!("Cannot open audit day file: {err}");
                    COUNTERS.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }
        let Some(state) = state.as_mut() else {
            continue;
        };
        if config.max_file_bytes > 0 && state.written >= config.max_file_bytes {
            // The day is full: count, drop, and wait for tomorrow rather than
            // letting the audit path consume the disk.
            COUNTERS.overflows.fetch_add(1, Ordering::Relaxed);
            COUNTERS.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let line = event.to_jsonl();
        match state.file.write_all(line.as_bytes()).and_then(|_| state.file.flush()) {
            Ok(()) => {
                state.written += line.len() as u64;
                COUNTERS.written.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                log::error!("Audit write failed: {err}");
                COUNTERS.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct DayState {
    day: u64,
    file: File,
    written: u64,
}

fn day_file_name(day: u64) -> String {
    // Days since epoch to UTC YYYYMMDD, no external date crate.
    let days = day;
    let (year, month, mday) = civil_from_days(days as i64);
    format!("audit-{year:04}{month:02}{mday:02}.jsonl")
}

fn open_day_file(dir: &Path, day: u64) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(day_file_name(day)))
}

/// Deletes day files whose calendar day is older than the retention window.
fn prune_expired(dir: &Path, retention_days: u64) {
    if retention_days == 0 {
        return;
    }
    let today = epoch_seconds() / 86_400;
    let cutoff = today.saturating_sub(retention_days);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(stem) = name.strip_prefix("audit-").and_then(|rest| rest.strip_suffix(".jsonl")) else {
            continue;
        };
        let Some(year) = stem.get(0..4).and_then(|part| part.parse::<i64>().ok()) else {
            continue;
        };
        let Some(month) = stem.get(4..6).and_then(|part| part.parse::<u32>().ok()) else {
            continue;
        };
        let Some(mday) = stem.get(6..8).and_then(|part| part.parse::<u32>().ok()) else {
            continue;
        };
        let Some(file_day) = days_from_civil(year, month, mday) else {
            continue;
        };
        if file_day < cutoff as i64 && fs::remove_file(entry.path()).is_ok() {
            COUNTERS.pruned_files.fetch_add(1, Ordering::Relaxed);
            log::info!("Pruned expired audit file {name}");
        }
    }
}

/// Howard Hinnant's civil-from-days algorithm; no date crate required.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Inverse of [`civil_from_days`]; returns `None` for impossible dates.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe as i64 - 719_468)
}

/// Reads every retained event in the directory, oldest day first.
///
/// Used by the standalone exporter; parsing failures are skipped, not fatal,
/// so one truncated line cannot hide the rest of the evidence.
pub fn read_all_events(dir: &Path) -> Vec<(String, AuditEvent)> {
    let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("audit-") && name.ends_with(".jsonl"))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    let mut events = Vec::new();
    for file in files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            match parse_event(line) {
                Some(event) => events.push((name.clone(), event)),
                None => continue,
            }
        }
    }
    events
}

fn parse_event(line: &str) -> Option<AuditEvent> {
    // Minimal extraction from the fixed field order the writer emits. serde
    // would be fine too, but the parser must accept a partially corrupt line
    // without pulling a dependency into the exporter's error handling.
    let mut fields: [Option<String>; 6] = Default::default();
    for (index, key) in [
        "\"ts\":",
        "\"kind\":\"",
        "\"transport\":\"",
        "\"verdict\":\"",
        "\"reason\":\"",
        "\"client_ip\":\"",
    ]
    .iter()
    .enumerate()
    {
        let start = line.find(key)? + key.len();
        let rest = &line[start..];
        let end = if key.ends_with(':') {
            rest.find([',', '}'])?
        } else {
            // Quoted values may contain escaped quotes; the unescaped span
            // length IS the closing-quote position.
            escaped_until_quote(rest).len()
        };
        fields[index] = Some(rest[..end].to_owned());
    }
    let field = |index: usize| fields[index].clone().unwrap_or_default();
    Some(AuditEvent {
        epoch_seconds: field(0).parse().ok()?,
        kind: kind_from_label(&field(1))?,
        transport: transport_from_label(&field(2))?,
        verdict: leak_verdict(&field(3))?,
        reason: json_unescape(&field(4)),
        client_ip: json_unescape(&field(5)),
        mode: mode_label(&mode_from_label(&extract_field(line, "\"mode\":\"")?)?),
        group: extract_field(line, "\"group\":\"").unwrap_or_else(|| "general".to_owned()),
    })
}

fn leak_verdict(verdict: &str) -> Option<&'static str> {
    Some(match verdict {
        "allow" => "allow",
        "deny" => "deny",
        "would_deny" => "would_deny",
        "skipped" => "skipped",
        _ => return None,
    })
}

fn extract_field(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    Some(escaped_until_quote(&line[start..]).to_owned())
}

/// The span up to the first unescaped closing quote: `\"` inside a value
/// must not terminate extraction.
fn escaped_until_quote(rest: &str) -> &str {
    let bytes = rest.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return &rest[..index],
            _ => index += 1,
        }
    }
    ""
}

fn json_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(code) = u32::from_str_radix(&hex, 16) {
                    if let Some(decoded) = char::from_u32(code) {
                        out.push(decoded);
                    }
                }
            }
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_round_trip_survives_hostile_strings() {
        let event = AuditEvent {
            epoch_seconds: 1_700_000_000,
            kind: ConnectionAttemptKind::RequestRelay,
            transport: SignalTransport::Tcp,
            verdict: "deny",
            reason: "quote \" backslash \\ newline \n tab \t".to_owned(),
            client_ip: "192.0.2.7".to_owned(),
            mode: "enforce",
            group: "contractor".to_owned(),
        };
        let line = event.to_jsonl();
        let parsed = parse_event(line.trim_end()).expect("parse own output");
        assert_eq!(parsed.epoch_seconds, event.epoch_seconds);
        assert_eq!(parsed.reason, event.reason);
        assert_eq!(parsed.client_ip, event.client_ip);
        assert_eq!(kind_label(&parsed.kind), kind_label(&event.kind));
    }

    #[test]
    fn civil_conversion_round_trips_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(days_from_civil(2024, 1, 1), Some(19_723));
        assert_eq!(days_from_civil(2024, 2, 30), None);
        assert_eq!(days_from_civil(2024, 13, 1), None);
    }

    #[test]
    fn day_file_names_are_zero_padded() {
        let (year, month, mday) = civil_from_days(19_723);
        let day = days_from_civil(year, month, mday).unwrap() as u64;
        assert_eq!(day_file_name(day), "audit-20240101.jsonl");
    }

    #[test]
    fn parse_event_rejects_garbage() {
        assert!(parse_event("not json at all").is_none());
        assert!(parse_event("{\"ts\":\"nope\"}").is_none());
    }
}
