use hbb_common::ResultType;
use hbbs::auth_server;
use std::io::Read;
use std::path::{Path, PathBuf};

const HELP: &str = "\
Starry API server (RustDesk-compatible accounts and connection tokens)\n\n\
Usage:\n\
  starry-api [serve]                 Run the HTTP API (default)\n\
  starry-api user add NAME [--admin] [--display-name TEXT] [--scopes \"a b\"]\n\
  starry-api user passwd NAME        Set a new password (revokes old sessions)\n\
  starry-api user enable NAME        Re-enable a disabled account\n\
  starry-api user disable NAME       Disable an account and revoke its sessions\n\
  starry-api user list               List accounts\n\n\
Passwords are read from STARRY_API_NEW_PASSWORD or stdin, never from argv.\n\
The database path comes from STARRY_API_DB (default ./users.db).\n";

fn main() -> ResultType<()> {
    let _logger = flexi_logger::Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .start()?;
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("--help") | Some("-h") => {
            print!("{HELP}");
            Ok(())
        }
        Some("serve") => {
            arguments.remove(0);
            if !arguments.is_empty() {
                return Err(hbb_common::anyhow::anyhow!("serve takes no arguments"));
            }
            serve()
        }
        Some("user") => {
            arguments.remove(0);
            user_command(&arguments)
        }
        None => serve(),
        Some(unknown) if unknown.starts_with('-') => Err(hbb_common::anyhow::anyhow!(
            "unknown option {unknown}; use --help"
        )),
        Some(unknown) => Err(hbb_common::anyhow::anyhow!(
            "unknown command {unknown}; use --help"
        )),
    }
}

fn serve() -> ResultType<()> {
    let config = auth_server::ApiConfig::from_env().map_err(hbb_common::anyhow::Error::msg)?;
    let database = config.db_path.display().to_string();
    let runtime = hbb_common::tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if let Err(err) = auth_server::run(config).await {
            hbb_common::log::error!("starry-api stopped: {err}");
        }
    });
    hbb_common::log::info!("starry-api finished (database {database})");
    Ok(())
}

fn user_command(arguments: &[String]) -> ResultType<()> {
    let Some(action) = arguments.first().map(String::as_str) else {
        return Err(hbb_common::anyhow::anyhow!(
            "expected `user add|passwd|enable|disable|list`"
        ));
    };
    let database_path = cli_database_path();
    let cost = cli_bcrypt_cost();
    let database =
        auth_server::open_database(&database_path).map_err(hbb_common::anyhow::Error::msg)?;
    match action {
        "list" => {
            for (name, enabled, is_admin, auth_version) in
                auth_server::list_users(&database).map_err(hbb_common::anyhow::Error::msg)?
            {
                let state = if enabled { "enabled" } else { "disabled" };
                let role = if is_admin { "admin" } else { "user" };
                println!("{name}\t{state}\t{role}\tauth_version={auth_version}");
            }
            Ok(())
        }
        "add" => {
            let mut name: Option<String> = None;
            let mut display_name: Option<String> = None;
            let mut scopes: Option<String> = None;
            let mut is_admin = false;
            let mut index = 1;
            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--admin" => is_admin = true,
                    "--display-name" => {
                        index += 1;
                        display_name = Some(require_value(arguments, index, "--display-name")?);
                    }
                    "--scopes" => {
                        index += 1;
                        scopes = Some(require_value(arguments, index, "--scopes")?);
                    }
                    value if value.starts_with('-') => {
                        return Err(hbb_common::anyhow::anyhow!("unknown option {value}"));
                    }
                    value => {
                        if name.is_some() {
                            return Err(hbb_common::anyhow::anyhow!("unexpected {value}"));
                        }
                        name = Some(value.to_owned());
                    }
                }
                index += 1;
            }
            let name = name.ok_or_else(|| hbb_common::anyhow::anyhow!("expected a user name"))?;
            let password = read_password()?;
            let id = auth_server::create_user(
                &database,
                &name,
                &password,
                display_name.as_deref(),
                is_admin,
                scopes.as_deref(),
                cost,
            )
            .map_err(hbb_common::anyhow::Error::msg)?;
            println!("created user {name} (id {id})");
            Ok(())
        }
        "passwd" => {
            let name = require_name(arguments)?;
            let password = read_password()?;
            auth_server::set_password(&database, &name, &password, cost)
                .map_err(hbb_common::anyhow::Error::msg)?;
            println!("password updated for {name}; existing sessions were revoked");
            Ok(())
        }
        "enable" | "disable" => {
            let name = require_name(arguments)?;
            auth_server::set_user_status(&database, &name, action == "enable")
                .map_err(hbb_common::anyhow::Error::msg)?;
            println!("{name} is now {action}d");
            Ok(())
        }
        other => Err(hbb_common::anyhow::anyhow!(
            "unknown user action {other}; use add|passwd|enable|disable|list"
        )),
    }
}

fn require_value(arguments: &[String], index: usize, option: &str) -> ResultType<String> {
    arguments
        .get(index)
        .cloned()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("{option} requires a value"))
}

fn require_name(arguments: &[String]) -> ResultType<String> {
    let name = arguments
        .get(1)
        .cloned()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("expected a user name"))?;
    if arguments.len() > 2 {
        return Err(hbb_common::anyhow::anyhow!(
            "unexpected trailing argument {}",
            arguments[2]
        ));
    }
    Ok(name)
}

fn cli_database_path() -> PathBuf {
    let raw = std::env::var("STARRY_API_DB")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "users.db".to_owned());
    std::path::absolute(Path::new(&raw)).unwrap_or_else(|_| PathBuf::from(raw))
}

fn cli_bcrypt_cost() -> u32 {
    std::env::var("STARRY_API_BCRYPT_COST")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|cost| (4..=15).contains(cost))
        .unwrap_or(12)
}

/// Passwords never come from argv: they would land in the process table and
/// shell history.
fn read_password() -> ResultType<String> {
    let password = match std::env::var("STARRY_API_NEW_PASSWORD") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("reading password from stdin (pipe it in; it is not echoed)");
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|err| hbb_common::anyhow::anyhow!("cannot read password: {err}"))?;
            buffer.lines().next().unwrap_or_default().to_owned()
        }
    };
    if password.len() < 8 {
        return Err(hbb_common::anyhow::anyhow!(
            "password must be at least 8 characters"
        ));
    }
    Ok(password)
}
