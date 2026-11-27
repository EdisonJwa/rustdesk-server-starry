// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT, ResultType};
use hbbs::{common::*, *};

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -b, --bind=[IP] 'Sets the IP address to bind to (default: all interfaces)'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] '[DEPRECATED] Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] '[DEPRECATED] Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] '[DEPRECATED] Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        , --starry-config=[FILE(default=starry/config.yaml)] 'Sets the external rustdesk-server-starry config file'
        , --must-login 'Requires configured JWT authentication and enforces it as a startup floor'
        , --webrtc-signal=[Y/N] 'Forwards RustDesk 1.5 WebRTC signalling; default N (also STARRY_WEBRTC_SIGNAL)'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] '[DEPRECATED] Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'",
    );
    init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    // Strategy v1: load the document once at startup; runtime reloads go
    // through local control (`strategy.reload`). A managed deployment must not
    // come up with a broken or missing policy, so `startup()` fails closed when
    // the engine is required; a compatibility deployment only logs.
    if let Err(err) = hbbs::strategy::startup() {
        bail!("Strategy engine startup failed: {err}");
    }
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let bind_addr = parse_bind_address(&get_arg("bind"))?;
    let rmem = get_arg("rmem").parse::<usize>().unwrap_or(RMEM);
    let serial: i32 = get_arg("serial").parse().unwrap_or(0);
    crate::common::check_software_update();
    RendezvousServer::start_with_bind(
        bind_addr,
        port,
        serial,
        &get_arg_or("key", "-".to_owned()),
        rmem,
    )?;
    Ok(())
}
