//! Converts Starry audit JSONL day files into CSV (or filtered JSONL).
//!
//! The audit writer keeps one `audit-YYYYMMDD.jsonl` file per day. This tool
//! reads a directory of them, optionally filters by inclusive UTC date range,
//! and writes one CSV document with a stable header, so operators can hand a
//! range to whoever asks for evidence without granting access to the server.
//!
//! Usage:
//! ```text
//! starry-audit-export <AUDIT_DIR> [--out FILE] [--from YYYYMMDD] [--to YYYYMMDD]
//!                     [--format csv|jsonl]
//! ```
//! With no `--out`, the CSV lands on stdout.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use hbbs::audit_log::{kind_label, read_all_events, transport_label, AuditEvent};

/// CSV header, fixed on purpose: consumers can rely on column order.
const CSV_HEADER: &str =
    "timestamp_utc,kind,transport,verdict,reason,client_ip,mode,group,source_file";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dir: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut from: Option<String> = None;
    let mut to: Option<String> = None;
    let mut format = "csv".to_owned();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" if index + 1 < args.len() => {
                out = Some(PathBuf::from(&args[index + 1]));
                index += 2;
            }
            "--from" if index + 1 < args.len() => {
                from = Some(args[index + 1].clone());
                index += 2;
            }
            "--to" if index + 1 < args.len() => {
                to = Some(args[index + 1].clone());
                index += 2;
            }
            "--format" if index + 1 < args.len() => {
                format = args[index + 1].clone();
                index += 2;
            }
            other if dir.is_none() && !other.starts_with("--") => {
                dir = Some(PathBuf::from(other));
                index += 1;
            }
            other => {
                eprintln!("unexpected argument: {other}");
                return ExitCode::from(64);
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("usage: starry-audit-export <AUDIT_DIR> [--out FILE] [--from YYYYMMDD] [--to YYYYMMDD] [--format csv|jsonl]");
        return ExitCode::from(64);
    };
    if format != "csv" && format != "jsonl" {
        eprintln!("--format must be csv or jsonl");
        return ExitCode::from(64);
    }
    let from_day = match from.as_deref().map(parse_day) {
        Some(Ok(day)) => Some(day),
        Some(Err(err)) => {
            eprintln!("--from: {err}");
            return ExitCode::from(64);
        }
        None => None,
    };
    let to_day = match to.as_deref().map(parse_day) {
        Some(Ok(day)) => Some(day),
        Some(Err(err)) => {
            eprintln!("--to: {err}");
            return ExitCode::from(64);
        }
        None => None,
    };

    let events = read_all_events(&dir);
    let selected: Vec<_> = events
        .into_iter()
        .filter(|(file_name, event)| {
            let file_day = file_day_from_name(file_name);
            file_day >= from_day.unwrap_or(0) && file_day <= to_day.unwrap_or(u64::MAX)
        })
        .collect();

    let mut output: Box<dyn Write> = match &out {
        Some(path) => match fs::File::create(path) {
            Ok(file) => Box::new(file),
            Err(err) => {
                eprintln!("cannot create {}: {err}", path.display());
                return ExitCode::from(66);
            }
        },
        None => Box::new(std::io::stdout().lock()),
    };

    let write_result = if format == "csv" {
        write_csv(&mut output, &selected)
    } else {
        write_jsonl(&mut output, &selected)
    };
    if let Err(err) = write_result.and_then(|_| output.flush()) {
        eprintln!("write failed: {err}");
        return ExitCode::from(74);
    }
    if let Some(path) = out {
        eprintln!("exported {} events to {}", selected.len(), path.display());
    }
    ExitCode::SUCCESS
}

fn write_csv<W: Write>(out: &mut W, events: &[(String, AuditEvent)]) -> std::io::Result<()> {
    writeln!(out, "{CSV_HEADER}")?;
    for (file_name, event) in events {
        let row = [
            utc_timestamp(event.epoch_seconds),
            kind_label(&event.kind).to_owned(),
            transport_label(&event.transport).to_owned(),
            event.verdict.to_owned(),
            event.reason.clone(),
            event.client_ip.clone(),
            event.mode.to_owned(),
            event.group.clone(),
            file_name.clone(),
        ];
        let line = row
            .iter()
            .map(|field| csv_field(field))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn write_jsonl<W: Write>(out: &mut W, events: &[(String, AuditEvent)]) -> std::io::Result<()> {
    for (_, event) in events {
        writeln!(out, "{}", event.to_jsonl().trim_end())?;
    }
    Ok(())
}

/// RFC 4180: quote fields containing comma, quote, CR, or LF.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// `YYYYMMDD` in the file name to days-since-epoch, for range filtering.
fn file_day_from_name(name: &str) -> u64 {
    let stem = name
        .strip_prefix("audit-")
        .and_then(|rest| rest.strip_suffix(".jsonl"))
        .unwrap_or_default();
    match (stem.get(0..4), stem.get(4..6), stem.get(6..8)) {
        (Some(year), Some(month), Some(day)) => match days_from_civil_parsed(year, month, day) {
            Some(day) => day as u64,
            None => 0,
        },
        _ => 0,
    }
}

fn days_from_civil_parsed(year: &str, month: &str, day: &str) -> Option<i64> {
    let year: i64 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 { month - 3 } else { month + 9 } as u64;
    let doy = (153 * m + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe as i64 - 719_468)
}

fn parse_day(value: &str) -> Result<u64, String> {
    if value.len() != 8 || !value.chars().all(|c| c.is_ascii_digit()) {
        return Err("date must be YYYYMMDD".to_owned());
    }
    let day = days_from_civil_parsed(&value[0..4], &value[4..6], &value[6..8])
        .ok_or("impossible date")?;
    Ok(day as u64)
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ`, no date crate.
fn utc_timestamp(epoch_seconds: u64) -> String {
    let days = (epoch_seconds / 86_400) as i64;
    let seconds_of_day = epoch_seconds % 86_400;
    let (year, month, mday) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{mday:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

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
