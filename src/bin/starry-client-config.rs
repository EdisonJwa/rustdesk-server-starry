//! Generates the client-side server configuration for operators.
//!
//! Deploying a RustDesk client means handing the operator three facts: the ID
//! server address, the relay server address, and the server public key.
//! Doing it by hand leaks mistakes (a rotated key pasted from memory). This
//! tool reads the running server's `id_ed25519.pub` and renders the standard
//! fields as text, a machine-readable JSON document, and the base64 import
//! string in the RustDesk wire format (JSON reversed after encoding).
//!
//! No private material is ever read, and no token is minted: access tokens
//! belong to the operator's identity provider, not to this server.

use serde_json::json;
use std::{fs, io::Write, path::PathBuf, process::ExitCode};

struct Args {
    data_dir: PathBuf,
    id_server: String,
    relay_server: Option<String>,
    group: Option<String>,
    out: Option<PathBuf>,
    format: Format,
}

enum Format {
    Text,
    Json,
}

fn usage() -> &'static str {
    "usage: starry-client-config --data-dir DIR --id-server HOST[:PORT]\n\
       [--relay-server HOST[:PORT]] [--group NAME] [--format text|json]\n\
       [--out FILE]\n\
\n\
     DIR is the HBBS state directory holding id_ed25519.pub.\n\
     The public key is read from that file; private material is never touched."
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        data_dir: PathBuf::new(),
        id_server: String::new(),
        relay_server: None,
        group: None,
        out: None,
        format: Format::Text,
    };
    let mut argv = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    fn take(argv: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
        argv.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--data-dir" => args.data_dir = PathBuf::from(take(&mut argv, &flag)?),
            "--id-server" => args.id_server = take(&mut argv, &flag)?,
            "--relay-server" => args.relay_server = Some(take(&mut argv, &flag)?),
            "--group" => args.group = Some(take(&mut argv, &flag)?),
            "--out" => args.out = Some(PathBuf::from(take(&mut argv, &flag)?)),
            "--format" => {
                args.format = match take(&mut argv, &flag)?.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    other => return Err(format!("unknown --format {other}")),
                }
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    if args.data_dir.as_os_str().is_empty() || args.id_server.is_empty() {
        return Err(usage().to_owned());
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(64);
        }
    };
    let key_path = args.data_dir.join("id_ed25519.pub");
    let public_key = match fs::read_to_string(&key_path).map(|key| key.trim().to_owned()) {
        Ok(key) if !key.is_empty() => key,
        Ok(_) => {
            eprintln!(
                "{} is empty; has the server generated its key yet?",
                key_path.display()
            );
            return ExitCode::from(66);
        }
        Err(err) => {
            eprintln!("cannot read {}: {err}", key_path.display());
            return ExitCode::from(66);
        }
    };

    let import_json = json!({
        "host": args.id_server,
        "relay": args.relay_server,
        "api": "",
        "key": public_key,
    });
    // Wire format: base64(JSON) with the whole string reversed, so scanners
    // do not recognise it as base64. Clients reverse, decode, then parse.
    let import_string: String =
        base64::encode(serde_json::to_vec(&import_json).expect("serialize import config"))
            .chars()
            .rev()
            .collect();

    let rendered = match args.format {
        Format::Json => serde_json::to_string_pretty(&json!({
            "host": args.id_server,
            "relay": args.relay_server,
            "key": public_key,
            "import_string": format!("rustdesk://config?s={import_string}"),
        }))
        .expect("serialize"),
        Format::Text => {
            let mut text = format!(
                "ID Server:      {}\nRelay Server:   {}\nPublic Key:     {}\nStrategy Group: {}\n\n\
                 Import string (client: Settings -> Network -> Import server info,\n\
                 or open as a URL):\nrustdesk://config?s={import_string}\n\n\
                 Manual fields (equivalent): ID Server / Relay Server / Public Key\n\
                 above, then Apply.",
                args.id_server,
                args.relay_server.as_deref().unwrap_or("(same as ID server)"),
                public_key,
                args.group.as_deref().unwrap_or("general"),
            );
            if let Some(group) = &args.group {
                text.push_str(&format!(
                    "\n\nNote: devices named for group `{group}` must be matched by the\nserver strategy document before its policy applies."
                ));
            }
            text
        }
    };

    let write_result = match &args.out {
        Some(path) => fs::write(path, rendered.as_bytes()),
        None => std::io::stdout().write_all(rendered.as_bytes()),
    };
    if let Err(err) = write_result.and_then(|_| std::io::stdout().flush()) {
        eprintln!("write failed: {err}");
        return ExitCode::from(74);
    }
    ExitCode::SUCCESS
}
