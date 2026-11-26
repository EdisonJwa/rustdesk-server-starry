use crate::common::*;
use crate::{allocation_explain, connection_auth, fast_relay, geo_relay, local_control, profile_activation, relay_observer, relay_quality, secure_tcp, starry_config, webrtc_signal, websocket_signal};
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    config,
    futures::future::join_all,
    futures_util::{
        stream::StreamExt,
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        *,
    },
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::{mpsc, oneshot, Mutex},
        time::{interval, Duration},
    },
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServersApply {
        relay_servers: String,
        generation: u64,
        ack: oneshot::Sender<Result<RelayApplyAck, String>>,
    },
    RelayServers(RelayServers),
}

#[derive(Debug)]
struct RelayApplyAck {
    previous_relay_servers: String,
    subsystem_ack: starry_config::SubsystemAck,
}

const REG_TIMEOUT: i64 = 30_000;
enum Sink {
    TcpStream(secure_tcp::TcpWriteTransport),
    Ws(websocket_signal::WsWriteTransport),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
const MAX_RELAY_UUID_LEN: usize = 128;

// The peer sends this uuid to whatever relay_server names, so keep control bytes out of it.
fn validate_relay_uuid(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_RELAY_UUID_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid relay UUID");
    }
    Ok(())
}

// A peer acknowledging a RequestRelay leaves both fields empty.
fn validate_relay_response(uuid: &str, relay_server: &str) -> Result<(), &'static str> {
    if uuid.is_empty() && relay_server.is_empty() {
        return Ok(());
    }
    validate_relay_uuid(uuid)
}

// An online query for about 5000 ids is the largest message a client sends here.
const DEFAULT_MAX_MESSAGE_KB: usize = 64;
// A knob that can be turned to unbounded is not a bound.
const MAX_MESSAGE_KB_CAP: usize = 64 << 10;
// tungstenite's default, so raising MAX_MESSAGE_KB does not widen a frame past it.
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
// Every connection pays its read buffer up front, and tungstenite's default is 128 KiB.
const WS_BUFFER_SIZE: usize = 8 << 10;
static MAX_MESSAGE: Lazy<usize> =
    Lazy::new(|| max_message_kb(&get_arg("MAX_MESSAGE_KB")) << 10);

fn max_message_kb(arg: &str) -> usize {
    match arg.parse::<usize>() {
        Ok(kb) if kb > 0 => kb.min(MAX_MESSAGE_KB_CAP),
        _ => DEFAULT_MAX_MESSAGE_KB,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

struct RegisterPkOutcome {
    result: register_pk_response::Result,
    id: String,
    activation: Option<profile_activation::ActivationClaim>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        let upstream_relay_servers = get_arg("relay-servers");
        let config_outcome = starry_config::initialize(&get_arg("starry-config"));
        log::info!("Starry config startup: {}", config_outcome.message);
        if let Some(error) = config_outcome.error.as_deref() {
            bail!("Starry config startup rejected: {error}");
        }
        if config_outcome.accepted {
            let Some(config) = starry_config::snapshot() else {
                bail!("accepted Starry startup config is unavailable");
            };
            let Some(generation) = config_outcome
                .activation_ack
                .as_ref()
                .map(|ack| ack.generation)
            else {
                bail!("Starry startup activation acknowledgement is missing");
            };
            let prepared_geo = match geo_relay::prepare(&config) {
                Ok(prepared) => prepared,
                Err(err) => bail!("Geo startup preparation failed: {err}"),
            };
            let prepared_websocket = match websocket_signal::prepare(
                &config.websocket_signal,
                config.relay_quality.enabled,
            ) {
                Ok(prepared) => prepared,
                Err(err) => bail!("WebSocket startup preparation failed: {err}"),
            };
            let prepared_auth = match connection_auth::prepare(
                &config.connection_auth,
                connection_auth::must_login_floor(),
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(err) => bail!("Connection authentication startup preparation failed: {err}"),
            };
            let relay_servers = config_outcome
                .relay_servers
                .as_deref()
                .unwrap_or(&upstream_relay_servers);
            rs.parse_relay_servers(relay_servers);
            relay_observer::update_configured(rs.relay_servers0.as_ref(), generation);
            let relay_ack = starry_config::SubsystemAck {
                subsystem: "relay_pool".to_owned(),
                accepted: true,
                detail: format!(
                    "applied generation {generation} with {} configured Relay(s)",
                    rs.relay_servers0.len()
                ),
            };
            let geo_ack = match geo_relay::activate_prepared(prepared_geo) {
                Ok(ack) => ack,
                Err(err) => bail!("Geo startup activation failed: {err}"),
            };
            let websocket_ack = match websocket_signal::activate_prepared(prepared_websocket) {
                Ok(ack) => ack,
                Err(err) => bail!("WebSocket startup activation failed: {err}"),
            };
            let secure_tcp_ack = starry_config::SubsystemAck {
                subsystem: "secure_tcp".to_owned(),
                accepted: true,
                detail: "configuration visible to new TCP connections".to_owned(),
            };
            let auth_ack = connection_auth::activate(prepared_auth);
            let ack = match starry_config::acknowledge_active(
                generation,
                vec![relay_ack, geo_ack, websocket_ack, secure_tcp_ack, auth_ack],
            ) {
                Ok(ack) => ack,
                Err(diagnostics) => bail!(
                    "Starry startup acknowledgement failed: {}",
                    diagnostics.summary()
                ),
            };
            log::info!(
                "Starry startup activation acknowledged: generation={}, digest={}",
                ack.generation,
                ack.effective_digest
            );
        } else {
            let disabled_auth = match connection_auth::prepare(
                &starry_config::ConnectionAuthConfig::default(),
                connection_auth::must_login_floor(),
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(err) => bail!("Connection authentication startup preparation failed: {err}"),
            };
            connection_auth::activate(disabled_auth);
            rs.parse_relay_servers(&upstream_relay_servers);
            relay_observer::update_configured(rs.relay_servers0.as_ref(), 0);
            // Run these outside the log macros, whose arguments are skipped
            // when RUST_LOG is above info.
            let geo_startup = geo_relay::reload();
            log::info!("Geo relay startup: {}", geo_startup);
            let websocket_startup = websocket_signal::reconfigure();
            log::info!("WebSocket Signal startup: {}", websocket_startup);
        }
        let mmdb_startup = geo_relay::start_mmdb_updater();
        log::info!("{}", mmdb_startup);
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        log::info!("MAX_MESSAGE_KB={}", *MAX_MESSAGE >> 10);
        let test_addr = get_arg("TEST_HBBS");
        // Configure outside the log macro: its arguments are skipped when the
        // info level is off.
        let webrtc_enabled = webrtc_signal::configure_from_args();
        log::info!(
            "WebRTC signalling: {}",
            if webrtc_enabled { "enabled" } else { "disabled" }
        );
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        let mut relay_quality_deadline_tick = interval(Duration::from_millis(100));
        relay_quality_deadline_tick
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = relay_quality_deadline_tick.tick() => {
                    for dispatch in relay_quality::finalize_expired() {
                        self.dispatch_relay_quality(dispatch).await;
                    }
                }
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => {
                            self.parse_relay_servers(&rs);
                            relay_observer::update_configured(
                                self.relay_servers0.as_ref(),
                                starry_config::runtime_state().generation,
                            );
                        }
                        Data::RelayServersApply { relay_servers, generation, ack } => {
                            let previous_relay_servers = self.relay_servers0.join(",");
                            self.parse_relay_servers(&relay_servers);
                            relay_observer::update_configured(
                                self.relay_servers0.as_ref(),
                                generation,
                            );
                            let detail = format!(
                                "applied generation {generation} with {} configured Relay(s)",
                                self.relay_servers0.len()
                            );
                            let _ = ack.send(Ok(RelayApplyAck {
                                previous_relay_servers,
                                subsystem_ack: starry_config::SubsystemAck {
                                    subsystem: "relay_pool".to_owned(),
                                    accepted: true,
                                    detail,
                                },
                            }));
                        }
                        Data::RelayServers(rs) => {
                            relay_observer::update_native_online(&rs);
                            self.relay_servers = Arc::new(rs);
                        }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        _key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered from {:?}", &addr);
                        let peer_id = rp.id;
                        let serial = rp.serial;
                        match profile_activation::begin_renewal(
                            &peer_id,
                            rp.activation_epoch,
                            &rp.activation_id,
                            &rp.route_lease,
                            rp.route_generation,
                        )
                        .await
                        {
                            Ok(claim) => {
                                let generation = claim.generation();
                                let previous_route = claim.previous_route();
                                let tracked = claim.tracked();
                                let route = profile_activation::RouteKind::Native(addr);
                                if tracked && previous_route != Some(route) {
                                    claim.reject_route_change();
                                    let mut response = RendezvousMessage::new();
                                    response.set_register_peer_response(RegisterPeerResponse {
                                        request_pk: true,
                                        ..Default::default()
                                    });
                                    socket.send(&response, addr).await?;
                                } else if self
                                    .update_addr(peer_id.clone(), addr, generation, socket)
                                    .await?
                                {
                                    claim.commit(route).await;
                                }
                            }
                            Err(_) => {
                                let mut response = RendezvousMessage::new();
                                response.set_register_peer_response(RegisterPeerResponse {
                                    request_pk: true,
                                    ..Default::default()
                                });
                                socket.send(&response, addr).await?;
                            }
                        }
                        if self.inner.serial > serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if let Some(mut outcome) =
                        self.process_register_pk(rk, addr, Some(addr)).await
                    {
                        let mut activation_epoch = 0;
                        let mut activation_id = Bytes::new();
                        let mut route_lease = Bytes::new();
                        let mut route_generation = 0;
                        if outcome.result == register_pk_response::Result::OK {
                            if let Some(claim) = outcome.activation.take() {
                                let generation = claim.generation();
                                let previous_route = claim.previous_route();
                                let tracked = claim.tracked();
                                activation_epoch = claim.activation_epoch();
                                activation_id = claim.activation_id().clone();
                                route_lease = claim.route_lease().clone();
                                if tracked {
                                    route_generation = generation;
                                }
                                self.activate_native_route(&outcome.id, addr, generation)
                                    .await;
                                claim
                                    .commit(profile_activation::RouteKind::Native(addr))
                                    .await;
                                if tracked {
                                    if let Some(profile_activation::RouteKind::WebSocket {
                                        generation: old_generation,
                                        connection_id: old_connection_id,
                                    }) = previous_route
                                    {
                                        websocket_signal::remove_profile_route(
                                            &outcome.id,
                                            old_generation,
                                            old_connection_id,
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                        send_rk_res(
                            socket,
                            addr,
                            outcome.result,
                            activation_epoch,
                            activation_id,
                            route_lease,
                            route_generation,
                        )
                        .await?;
                        if route_generation != 0 {
                            profile_activation::record_ready_ack();
                        }
                    }
                }
                Some(rendezvous_message::Union::DeactivatePeer(request)) => {
                    let activation_epoch = request.activation_epoch;
                    let activation_id = request.activation_id.clone();
                    let route_generation = request.route_generation;
                    let deactivated = self.process_peer_deactivation(request).await;
                    let mut response = RendezvousMessage::new();
                    response.set_deactivate_peer_response(DeactivatePeerResponse {
                        activation_epoch,
                        activation_id,
                        deactivated,
                        route_generation,
                        ..Default::default()
                    });
                    socket.send(&response, addr).await?;
                }
                Some(rendezvous_message::Union::RelayQualityStageReport(report)) => {
                    if let relay_quality::StageReportResolution::Dispatch(dispatch) =
                        relay_quality::handle_stage_report(addr, addr.ip(), report)
                    {
                        self.dispatch_relay_quality(dispatch).await;
                    }
                }
                Some(rendezvous_message::Union::RelayQualityCancel(cancel)) => {
                    if let Some(dispatch) =
                        relay_quality::cancel_allocation(addr, addr.ip(), cancel)
                    {
                        self.dispatch_relay_quality(dispatch).await;
                    }
                }
                Some(rendezvous_message::Union::PunchHoleRequest(_ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn is_verified_fast_registration(&self, rk: &RegisterPk) -> bool {
        if rk.id.len() > MAX_PEER_ID_LEN
            || rk.activation_id.len() != profile_activation::ACTIVATION_ID_BYTES
            || rk.activation_epoch == 0
            || rk.uuid.len() != 16
            || rk.pk.is_empty()
        {
            return false;
        }
        let Some(peer) = self.pm.get(&rk.id).await else {
            return false;
        };
        let peer = peer.read().await;
        !peer.uuid.is_empty() && peer.uuid == rk.uuid && peer.pk == rk.pk
    }

    async fn process_register_pk(
        &mut self,
        rk: RegisterPk,
        effective_addr: SocketAddr,
        native_addr: Option<SocketAddr>,
    ) -> Option<RegisterPkOutcome> {
        if rk.uuid.is_empty() || rk.pk.is_empty() {
            return None;
        }
        let fast_identity_verified = self.is_verified_fast_registration(&rk).await;
        let id = rk.id;
        let ip = effective_addr.ip().to_string();
        if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
            return Some(RegisterPkOutcome {
                result: register_pk_response::Result::UUID_MISMATCH,
                id,
                activation: None,
            });
        }
        if !self.check_ip_blocker(&ip, &id).await {
            return Some(RegisterPkOutcome {
                result: register_pk_response::Result::TOO_FREQUENT,
                id,
                activation: None,
            });
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed, current_addr) = {
            let peer = peer.read().await;
            let current_addr = peer.socket_addr;
            if peer.uuid.is_empty() {
                (true, false, current_addr)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!("Peer identity mismatch after simultaneous IP and key change");
                        return Some(RegisterPkOutcome {
                            result: register_pk_response::Result::UUID_MISMATCH,
                            id,
                            activation: None,
                        });
                    }
                } else {
                    log::warn!("Peer UUID mismatch during registration");
                    return Some(RegisterPkOutcome {
                        result: register_pk_response::Result::UUID_MISMATCH,
                        id,
                        activation: None,
                    });
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                    current_addr,
                )
            }
        };
        let activation = match profile_activation::begin_registration(
            &id,
            &rk.uuid,
            &rk.pk,
            rk.activation_epoch,
            &rk.activation_id,
            fast_identity_verified,
        )
        .await
        {
            Ok(claim) => claim,
            Err(_) => {
                return Some(RegisterPkOutcome {
                    result: register_pk_response::Result::TOO_FREQUENT,
                    id,
                    activation: None,
                });
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if !fast_identity_verified && req_pk.0 > 2 {
            return Some(RegisterPkOutcome {
                result: register_pk_response::Result::TOO_FREQUENT,
                id,
                activation: None,
            });
        }
        req_pk.0 = req_pk.0.saturating_add(1);
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(value) = ips.get_mut(&ip) {
                    *value += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(
                    id.clone(),
                    (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                );
            }
        }
        let result = if changed {
            self.pm
                .update_pk(
                    id.clone(),
                    peer,
                    native_addr.unwrap_or(current_addr),
                    rk.uuid,
                    rk.pk,
                    ip,
                )
                .await
        } else {
            let mut peer = peer.write().await;
            peer.last_reg_time = Instant::now();
            if let Some(addr) = native_addr {
                peer.socket_addr = addr;
            }
            register_pk_response::Result::OK
        };
        Some(RegisterPkOutcome {
            result,
            id,
            activation: (result == register_pk_response::Result::OK).then_some(activation),
        })
    }

    async fn process_peer_deactivation(&mut self, request: DeactivatePeer) -> bool {
        let peer_id = request.id;
        let Ok(claim) = profile_activation::begin_deactivation(
            &peer_id,
            &request.network_identity_uuid,
            request.activation_epoch,
            &request.activation_id,
            &request.route_lease,
            request.route_generation,
        )
        .await
        else {
            return false;
        };
        let route = claim.route();
        let route_removed = match route {
            profile_activation::RouteKind::Native(expected_addr) => {
                if let Some(peer) = self.pm.get_in_memory(&peer_id).await {
                    let mut peer = peer.write().await;
                    if peer.socket_addr == expected_addr
                        && peer.route_generation == claim.generation()
                    {
                        peer.socket_addr =
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                        peer.route_generation = 0;
                        peer.last_reg_time = get_expired_time();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            profile_activation::RouteKind::WebSocket {
                generation,
                connection_id,
            } => {
                let removed = websocket_signal::remove_profile_route(
                    &peer_id,
                    generation,
                    connection_id,
                )
                .await;
                if removed {
                    if let Some(peer) = self.pm.get_in_memory(&peer_id).await {
                        let mut peer = peer.write().await;
                        if peer.route_generation == generation {
                            peer.route_generation = 0;
                            peer.last_reg_time = get_expired_time();
                        }
                    }
                }
                removed
            }
        };
        claim.commit(route_removed).await
    }

    async fn activate_native_route(
        &self,
        peer_id: &str,
        addr: SocketAddr,
        route_generation: u64,
    ) {
        if let Some(peer) = self.pm.get_in_memory(peer_id).await {
            let mut peer = peer.write().await;
            peer.socket_addr = addr;
            peer.route_generation = route_generation;
            peer.last_reg_time = Instant::now();
        }
    }

    async fn activate_websocket_route(&self, peer_id: &str, route_generation: u64) {
        if let Some(peer) = self.pm.get_in_memory(peer_id).await {
            let mut peer = peer.write().await;
            peer.socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            peer.route_generation = route_generation;
            peer.last_reg_time = Instant::now();
        }
    }

    async fn expire_websocket_route(&self, peer_id: &str, route_generation: u64) {
        if let Some(peer) = self.pm.get_in_memory(peer_id).await {
            let mut peer = peer.write().await;
            if peer.route_generation == route_generation {
                peer.route_generation = 0;
                peer.last_reg_time = get_expired_time();
            }
        }
    }

    async fn process_current_websocket_deactivation(
        &mut self,
        request: DeactivatePeer,
        token: &websocket_signal::SessionToken,
    ) -> bool {
        if request.id != token.peer_id || request.route_generation != token.generation {
            return false;
        }
        let Ok(claim) = profile_activation::begin_deactivation(
            &request.id,
            &request.network_identity_uuid,
            request.activation_epoch,
            &request.activation_id,
            &request.route_lease,
            request.route_generation,
        )
        .await
        else {
            return false;
        };
        if claim.route()
            != (profile_activation::RouteKind::WebSocket {
                generation: token.generation,
                connection_id: token.connection_id,
            })
        {
            return false;
        }
        let detached = websocket_signal::detach_profile_route(
            &token.peer_id,
            token.generation,
            token.connection_id,
        )
        .await;
        if detached {
            self.expire_websocket_route(&token.peer_id, token.generation)
                .await;
        }
        claim.commit(detached).await
    }

    async fn touch_registered_peer(&self, peer_id: &str) {
        if let Some(peer) = self.pm.get_in_memory(peer_id).await {
            peer.write().await.last_reg_time = Instant::now();
        }
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        route_addr: SocketAddr,
        effective_addr: SocketAddr,
        key: &str,
        ws: bool,
        signal_transport: connection_auth::SignalTransport,
    ) -> bool {
        let addr = route_addr;
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(mut ph)) => {
                    let target = crate::strategy::check_target(&ph.id);
                    if let Some(reason) = target.deny_reason {
                        log::warn!(
                            "Connection authentication denied: kind=punch_hole transport={:?} reason={}",
                            signal_transport, reason
                        );
                        let mut denied = RendezvousMessage::new();
                        denied.set_punch_hole_response(PunchHoleResponse {
                            failure: punch_hole_response::Failure::OFFLINE.into(),
                            other_failure: "connection authorization failed".to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, denied).await;
                        return false;
                    }
                    let decision = connection_auth::authorize_connection_attempt(
                        &ph.token,
                        connection_auth::ConnectionAttemptKind::PunchHole,
                        signal_transport,
                        effective_addr.ip(),
                        &target,
                    )
                    .await;
                    if decision.verdict == "would_deny" {
                        log::warn!(
                            "Connection authentication audit: kind=punch_hole transport={:?} reason={}",
                            signal_transport,
                            decision.reason
                        );
                    }
                    if !decision.proceed {
                        log::warn!(
                            "Connection authentication denied: kind=punch_hole transport={:?} reason={}",
                            signal_transport,
                            decision.reason
                        );
                        let mut denied = RendezvousMessage::new();
                        denied.set_punch_hole_response(PunchHoleResponse {
                            failure: punch_hole_response::Failure::OFFLINE.into(),
                            other_failure: "connection authorization failed".to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, denied).await;
                        return false;
                    }
                    // A RustDesk 1.5 WebRTC offer is forwarded only when enabled and
                    // only from a secured signalling connection; see webrtc_signal.
                    let secure_signal = matches!(
                        signal_transport,
                        connection_auth::SignalTransport::SecureTcp
                            | connection_auth::SignalTransport::WebSocket
                    );
                    ph.webrtc_sdp_offer = match webrtc_signal::admit_offer(
                        std::mem::take(&mut ph.webrtc_sdp_offer),
                        secure_signal,
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst),
                    ) {
                        Ok(offer) => offer,
                        Err(webrtc_signal::OfferDrop::Empty) => String::new(),
                        Err(reason) => {
                            log::debug!("WebRTC offer from {addr} not forwarded: {reason:?}");
                            String::new()
                        }
                    };
                    // There may be several attempts, so sink can be none.
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(route_addr, effective_addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RelayQualityStageReport(report)) => {
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(route_addr), sink);
                    }
                    if let relay_quality::StageReportResolution::Dispatch(dispatch) =
                        relay_quality::handle_stage_report(
                            route_addr,
                            effective_addr.ip(),
                            report,
                        )
                    {
                        self.dispatch_relay_quality(dispatch).await;
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayQualityCancel(cancel)) => {
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(route_addr), sink);
                    }
                    if let Some(dispatch) = relay_quality::cancel_allocation(
                        route_addr,
                        effective_addr.ip(),
                        cancel,
                    ) {
                        self.dispatch_relay_quality(dispatch).await;
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if let Err(err) = validate_relay_uuid(&rf.uuid) {
                        log::warn!(
                            "Drop RequestRelay from {addr}: {err} (length {})",
                            rf.uuid.len()
                        );
                        return false;
                    }
                    let target = crate::strategy::check_target(&rf.id);
                    if let Some(reason) = target.deny_reason {
                        log::warn!(
                            "Connection authentication denied: kind=request_relay transport={:?} reason={}",
                            signal_transport, reason
                        );
                        let mut denied = RendezvousMessage::new();
                        denied.set_relay_response(RelayResponse {
                            refuse_reason: "connection authorization failed".to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, denied).await;
                        return false;
                    }
                    let decision = connection_auth::authorize_connection_attempt(
                        &rf.token,
                        connection_auth::ConnectionAttemptKind::RequestRelay,
                        signal_transport,
                        effective_addr.ip(),
                        &target,
                    )
                    .await;
                    if decision.verdict == "would_deny" {
                        log::warn!(
                            "Connection authentication audit: kind=request_relay transport={:?} reason={}",
                            signal_transport,
                            decision.reason
                        );
                    }
                    if !decision.proceed {
                        log::warn!(
                            "Connection authentication denied: kind=request_relay transport={:?} reason={}",
                            signal_transport,
                            decision.reason
                        );
                        let mut denied = RendezvousMessage::new();
                        denied.set_relay_response(RelayResponse {
                            refuse_reason: "connection authorization failed".to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, denied).await;
                        return false;
                    }
                    // There may be several attempts, so sink can be none.
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    let peer_id = rf.id.clone();
                    let websocket_route = websocket_signal::route(&peer_id).await;
                    let websocket_target = websocket_route.is_some();
                    let requirement = match (ws, websocket_target) {
                        (true, true) => websocket_signal::RelayRequirement::WebSocketOnly,
                        (true, false) | (false, true) => websocket_signal::RelayRequirement::Mixed,
                        (false, false) => websocket_signal::RelayRequirement::NativeOnly,
                    };
                    let target = if let Some(route) = websocket_route.as_ref() {
                        Some((route.route_addr, route.effective_ip))
                    } else if let Some(peer) = self.pm.get_in_memory(&peer_id).await {
                        let peer_addr = peer.read().await.socket_addr;
                        Some((peer_addr, peer_addr.ip()))
                    } else {
                        None
                    };
                    let server_selected_relay = target.as_ref().map(|(_, target_ip)| {
                        self.get_relay_server(
                            effective_addr.ip(),
                            *target_ip,
                            requirement,
                        )
                    });
                    let quality_resolution = if let Some((_target_route, target_ip)) = target.as_ref() {
                        relay_quality::select_for_request(
                            route_addr,
                            effective_addr.ip(),
                            *target_ip,
                            &rf.uuid,
                            rf.relay_quality_allocation_id.as_ref(),
                            rf.relay_quality_report.clone().into_option(),
                        )
                    } else {
                        relay_quality::RequestResolution::Legacy
                    };
                    let quality_selection = match quality_resolution {
                        relay_quality::RequestResolution::Legacy => None,
                        relay_quality::RequestResolution::Selected(selection) => {
                            rf.relay_server = selection.decision.relay_server.clone();
                            rf.relay_quality_decision =
                                MessageField::some(selection.decision.clone());
                            Some(selection)
                        }
                        relay_quality::RequestResolution::Expanded(dispatch) => {
                            self.dispatch_relay_quality(dispatch).await;
                            return true;
                        }
                        relay_quality::RequestResolution::Pending
                        | relay_quality::RequestResolution::Blocked => return true,
                    };
                    if quality_selection.is_none() && fast_relay::enabled() {
                        if let Some(selected) = server_selected_relay.as_ref() {
                            rf.relay_server = selected.clone();
                        }
                    }
                    let fast_media_endpoint =
                        relay_observer::fast_media_endpoint(&rf.relay_server);
                    rf.fast_relay_authorization = target
                        .as_ref()
                        .and_then(|(_, target_ip)| {
                            fast_relay::authorization_for_request(
                                &rf.uuid,
                                effective_addr.ip(),
                                *target_ip,
                                &rf.relay_server,
                                signal_transport,
                                &decision,
                                quality_selection.as_ref(),
                                fast_media_endpoint,
                                self.inner.sk.as_ref(),
                            )
                        })
                        .unwrap_or_default();
                    let mut msg_out = RendezvousMessage::new();
                    rf.socket_addr = AddrMangle::encode(route_addr).into();
                    msg_out.set_request_relay(rf);
                    if websocket_target {
                        if !websocket_signal::send_to_peer(&peer_id, &msg_out).await {
                            log::warn!("Failed to deliver RequestRelay to current WebSocket route");
                        }
                    } else if let Some(peer) = self.pm.get_in_memory(&peer_id).await {
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    if let Err(err) = validate_relay_response(&rr.uuid, &rr.relay_server) {
                        log::warn!(
                            "Drop RelayResponse from {addr}: {err} (length {})",
                            rr.uuid.len()
                        );
                        return false;
                    }
                    let relay_quality_decision =
                        relay_quality::decision_for_response(&rr.uuid, effective_addr.ip());
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.webrtc_sdp_answer = webrtc_signal::answer_for(
                        try_into_v4(addr_b),
                        std::mem::take(&mut rr.webrtc_sdp_answer),
                    );
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        let controller_effective = websocket_signal::connection_effective(addr_b)
                            .await
                            .unwrap_or(addr_b);
                        let controller_ws = websocket_signal::is_websocket_route(addr_b).await;
                        let requirement = match (ws, controller_ws) {
                            (true, true) => websocket_signal::RelayRequirement::WebSocketOnly,
                            (true, false) | (false, true) => {
                                websocket_signal::RelayRequirement::Mixed
                            }
                            (false, false) => websocket_signal::RelayRequirement::NativeOnly,
                        };
                        if requirement == websocket_signal::RelayRequirement::NativeOnly
                            && self.is_lan(controller_effective)
                        {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(
                                effective_addr.ip(),
                                controller_effective.ip(),
                                requirement,
                            );
                        }
                    }
                    if let Some(quality_decision) = relay_quality_decision {
                        rr.relay_server = quality_decision.relay_server.clone();
                        rr.relay_quality_decision = MessageField::some(quality_decision);
                    }
                    if let Some(server_selected_relay) =
                        fast_relay::selected_relay_for_response(
                            &rr.uuid,
                            effective_addr.ip(),
                        )
                    {
                        rr.relay_server = server_selected_relay;
                    }
                    rr.fast_relay_authorization =
                        fast_relay::authorization_for_response(
                            &rr.uuid,
                            effective_addr.ip(),
                            &rr.relay_server,
                        )
                        .unwrap_or_default();
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::IceCandidate(ice)) => {
                    // Disabled or malformed: close, exactly like any other
                    // message this connection does not handle.
                    if !webrtc_signal::enabled() || !webrtc_signal::candidate_is_valid(&ice) {
                        return false;
                    }
                    self.handle_ice_candidate(ice, route_addr).await;
                    return true;
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::DeactivatePeer(request)) => {
                    let activation_epoch = request.activation_epoch;
                    let activation_id = request.activation_id.clone();
                    let route_generation = request.route_generation;
                    let deactivated = self.process_peer_deactivation(request).await;
                    let mut response = RendezvousMessage::new();
                    response.set_deactivate_peer_response(DeactivatePeerResponse {
                        activation_epoch,
                        activation_id,
                        deactivated,
                        route_generation,
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, response).await;
                    return false;
                }
                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }
                _ => {}
            }
        }
        false
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        route_generation: u64,
        socket: &mut FramedSocket,
    ) -> ResultType<bool> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                if route_generation != 0 {
                    old.route_generation = route_generation;
                }
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await?;
        Ok(!request_pk)
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        mut phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        let target_effective = websocket_signal::connection_effective(addr)
            .await
            .unwrap_or(addr);
        let quality = relay_quality::response_context(
            addr_a,
            addr,
            target_effective.ip(),
            &phs.id,
            phs.relay_quality_report.clone().into_option(),
        );
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let webrtc_sdp_answer = webrtc_signal::answer_for(
            try_into_v4(addr_a),
            std::mem::take(&mut phs.webrtc_sdp_answer),
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            webrtc_sdp_answer,
            relay_quality_offer: MessageField::from_option(quality.offer),
            relay_quality_peer_report: MessageField::from_option(quality.peer_report),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        let target_effective = websocket_signal::connection_effective(addr)
            .await
            .unwrap_or(addr);
        let quality = relay_quality::response_context(
            addr_a,
            addr,
            target_effective.ip(),
            &la.id,
            la.relay_quality_report.clone().into_option(),
        );
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            relay_quality_offer: MessageField::from_option(quality.offer),
            relay_quality_peer_report: MessageField::from_option(quality.peer_report),
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        route_addr: SocketAddr,
        effective_addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        let relay_quality_protocol = ph.relay_quality_protocol;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed for punch-hole request: invalid key");
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        let target_websocket = websocket_signal::route(&id).await;
        if let Some(peer) = self.pm.get(&id).await {
            let (native_peer_addr, native_elapsed) = {
                let peer = peer.read().await;
                (
                    peer.socket_addr,
                    peer.last_reg_time.elapsed().as_millis() as i64,
                )
            };
            let (elapsed, peer_route_addr, peer_effective_addr, target_ws) =
                if let Some(route) = target_websocket {
                    (
                        route.idle_millis as i64,
                        route.route_addr,
                        SocketAddr::new(route.effective_ip, 0),
                        true,
                    )
                } else {
                    (native_elapsed, native_peer_addr, native_peer_addr, false)
                };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }

            // Bounded by MAX_PUNCH_REQUESTS (rustdesk-server#713).
            record_punch_req(
                try_into_v4(effective_addr).ip().to_string(),
                try_into_v4(peer_effective_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let requirement = match (ws, target_ws) {
                (true, true) => websocket_signal::RelayRequirement::WebSocketOnly,
                (true, false) | (false, true) => websocket_signal::RelayRequirement::Mixed,
                (false, false) => websocket_signal::RelayRequirement::NativeOnly,
            };
            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_effective_addr);
            let is_lan = self.is_lan(effective_addr);
            let mut relay_server = self.get_relay_server(
                effective_addr.ip(),
                peer_effective_addr.ip(),
                requirement,
            );
            let force_websocket_relay =
                requirement != websocket_signal::RelayRequirement::NativeOnly;
            if force_websocket_relay && relay_server.is_empty() {
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    other_failure: "no eligible WebSocket relay".to_owned(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                || force_websocket_relay
                || (peer_is_lan ^ is_lan)
            {
                if !force_websocket_relay && peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into();
            }
            let relay_quality_offer = relay_quality::create_offer(
                relay_quality_protocol,
                route_addr,
                effective_addr.ip(),
                peer_route_addr,
                peer_effective_addr.ip(),
                &id,
                requirement,
                ws,
                target_ws,
                &relay_server,
            );
            let same_intranet = !ws
                && !target_ws
                && (peer_is_lan && is_lan || {
                    match (peer_effective_addr, effective_addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(route_addr).into();
            if same_intranet {
                log::debug!("Dispatching FetchLocalAddr over native signalling");
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    relay_quality_offer: MessageField::from_option(
                        relay_quality_offer.clone(),
                    ),
                    ..Default::default()
                });
            } else {
                log::debug!("Dispatching PunchHole with Relay requirement {:?}", requirement);
                // An admitted offer opens the route that keeps this controller
                // connection for trickle ICE; a full route table drops the offer.
                let webrtc_sdp_offer = if !ph.webrtc_sdp_offer.is_empty()
                    && webrtc_signal::open_route(
                        try_into_v4(route_addr),
                        try_into_v4(effective_addr).ip(),
                        &id,
                    )
                {
                    std::mem::take(&mut ph.webrtc_sdp_offer)
                } else {
                    String::new()
                };
                // With an offer, force_relay tells the device which ICE policy the
                // controller's envelope asks for; without one it is not forwarded.
                let force_relay = !webrtc_sdp_offer.is_empty() && ph.force_relay;
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    webrtc_sdp_offer,
                    force_relay,
                    relay_quality_offer: MessageField::from_option(
                        relay_quality_offer,
                    ),
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(native_peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    fn relay_quality_message(
        payload: relay_quality::DispatchPayload,
    ) -> RendezvousMessage {
        let mut message = RendezvousMessage::new();
        match payload {
            relay_quality::DispatchPayload::Offer(offer) => {
                message.set_relay_quality_stage_offer(offer);
            }
            relay_quality::DispatchPayload::Decision(decision) => {
                message.set_relay_quality_stage_decision(decision);
            }
            relay_quality::DispatchPayload::Cancel(cancel) => {
                message.set_relay_quality_cancel(cancel);
            }
        }
        message
    }

    async fn dispatch_relay_quality(
        &mut self,
        dispatch: relay_quality::StageDispatch,
    ) {
        let controller = Self::relay_quality_message(dispatch.controller);
        allow_err!(self.send_to_tcp_sync(controller, dispatch.controller_route).await);
        let target = Self::relay_quality_message(dispatch.target);
        if dispatch.target_websocket {
            if !websocket_signal::send_to_peer(&dispatch.target_id, &target).await {
                log::warn!("Relay Quality stage delivery failed for current WebSocket route");
            }
        } else {
            self.tx.send(Data::Msg(target.into(), dispatch.target_route)).ok();
        }
    }

    /// Sends to a controller whose WebRTC route is live and keeps its
    /// connection for the rest of the trickle-ICE exchange.
    async fn send_to_routed_controller(&mut self, msg: RendezvousMessage, controller: SocketAddr) {
        let mut sink = self.tcp_punch.lock().await.remove(&controller);
        if timeout(5_000, Self::send_to_sink(&mut sink, msg)).await.is_err() {
            log::debug!("WebRTC controller {controller:?} write timed out");
            webrtc_signal::close_route(controller);
            return;
        }
        if let Some(sink) = sink {
            if webrtc_signal::has_route(controller) {
                self.tcp_punch.lock().await.entry(controller).or_insert(sink);
            }
        }
    }

    /// Forwards one trickle-ICE candidate along an existing WebRTC route.
    async fn handle_ice_candidate(&mut self, ice: IceCandidate, from: SocketAddr) {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_ice_candidate(IceCandidate {
            session_key: ice.session_key,
            candidate: ice.candidate,
            ..Default::default()
        });
        if !ice.socket_addr.is_empty() {
            // Device to controller, addressed by PunchHole.socket_addr.
            let controller = try_into_v4(AddrMangle::decode(&ice.socket_addr));
            if !webrtc_signal::allow_to_controller(controller) {
                log::debug!("ICE candidate from {from:?} dropped: no route to {controller:?}");
                return;
            }
            self.send_to_routed_controller(msg_out, controller).await;
        } else if !ice.id.is_empty() {
            // Controller to device, on the connection that carried the offer.
            let controller = try_into_v4(from);
            if !webrtc_signal::allow_to_peer(controller, &ice.id) {
                log::debug!("ICE candidate from {from:?} dropped: not routed to this peer");
                return;
            }
            if websocket_signal::route(&ice.id).await.is_some() {
                if !websocket_signal::send_to_peer(&ice.id, &msg_out).await {
                    log::debug!("ICE candidate to a WebSocket peer was not delivered");
                }
            } else if let Some(peer) = self.pm.get_in_memory(&ice.id).await {
                let peer_addr = peer.read().await.socket_addr;
                self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
            }
        }
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        if webrtc_signal::has_route(try_into_v4(addr)) {
            self.send_to_routed_controller(msg, try_into_v4(addr)).await;
            return;
        }
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        let _ = ws.send_binary(bytes);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        if webrtc_signal::has_route(try_into_v4(addr)) {
            self.send_to_routed_controller(msg, try_into_v4(addr)).await;
            return Ok(());
        }
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        route_addr: SocketAddr,
        effective_addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let target_id = ph.id.clone();
        let websocket_target = websocket_signal::route(&target_id).await.is_some();
        let (msg, to_addr) = self
            .handle_punch_hole_request(route_addr, effective_addr, ph, key, ws)
            .await?;
        if let Some(addr) = to_addr {
            if websocket_target {
                if !websocket_signal::send_to_peer(&target_id, &msg).await {
                    let mut failure = RendezvousMessage::new();
                    failure.set_punch_hole_response(PunchHoleResponse {
                        failure: punch_hole_response::Failure::OFFLINE.into(),
                        other_failure: "WebSocket route closed during dispatch".to_owned(),
                        ..Default::default()
                    });
                    self.send_to_tcp_sync(failure, route_addr).await?;
                }
            } else {
                self.tx.send(Data::Msg(msg.into(), addr))?;
            }
        } else {
            self.send_to_tcp_sync(msg, route_addr).await?;
        }
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    async fn apply_relay_servers_runtime(
        &self,
        relay_servers: String,
        generation: u64,
    ) -> Result<RelayApplyAck, String> {
        let (ack, response) = oneshot::channel();
        self.tx
            .send(Data::RelayServersApply {
                relay_servers,
                generation,
                ack,
            })
            .map_err(|_| "Relay pool apply channel is closed".to_owned())?;
        let response = timeout(5_000, response)
            .await
            .map_err(|_| "Relay pool apply acknowledgement timed out".to_owned())?
            .map_err(|_| "Relay pool apply acknowledgement channel is closed".to_owned())?;
        response
    }

    async fn restore_runtime_subsystems(
        &self,
        previous: Option<&starry_config::StarryConfig>,
        previous_relay_servers: String,
        generation: u64,
    ) -> String {
        let mut failures = Vec::new();
        if let Err(err) = self
            .apply_relay_servers_runtime(previous_relay_servers, generation)
            .await
        {
            failures.push(format!("Relay rollback failed: {err}"));
        }
        if let Some(config) = previous {
            match geo_relay::prepare(config).and_then(geo_relay::activate_prepared) {
                Ok(_) => {}
                Err(err) => failures.push(format!("Geo rollback failed: {err}")),
            }
            match websocket_signal::prepare(
                &config.websocket_signal,
                config.relay_quality.enabled,
            )
                .and_then(websocket_signal::activate_prepared)
            {
                Ok(_) => {}
                Err(err) => failures.push(format!("WebSocket rollback failed: {err}")),
            }
        } else {
            let geo = geo_relay::reload();
            if geo.contains("failed") || geo.contains("rejected") {
                failures.push(geo);
            }
            let websocket = websocket_signal::reconfigure();
            if websocket.contains("failed") || websocket.contains("rejected") {
                failures.push(websocket);
            }
        }
        let previous_auth = previous.map(|config| &config.connection_auth);
        let auth = connection_auth::restore(
            previous_auth,
            connection_auth::must_login_floor(),
        )
        .await;
        if auth.contains("failed") {
            failures.push(auth);
        }
        if failures.is_empty() {
            "runtime subsystems restored".to_owned()
        } else {
            failures.join("; ")
        }
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(
        &self,
        pa: IpAddr,
        pb: IpAddr,
        requirement: websocket_signal::RelayRequirement,
    ) -> String {
        let snapshot = relay_observer::snapshot();
        if !snapshot.is_consistent() {
            log::warn!("Relay selection paused while runtime generations converge");
            return "".to_owned();
        }
        let eligible = snapshot.eligible_relays(requirement);
        if eligible.is_empty() {
            if requirement != websocket_signal::RelayRequirement::NativeOnly {
                log::warn!("No eligible WebSocket Relay for requirement {:?}", requirement);
            }
            return "".to_owned();
        }
        if let Some(selection) = snapshot.select_geo(pa, pb, &eligible, requirement) {
            return selection.relay;
        }
        if eligible.len() == 1 {
            return eligible[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % eligible.len();
        eligible[i].clone()
    }

    fn explain_relay_server(
        &self,
        pa: IpAddr,
        pb: IpAddr,
        requirement: websocket_signal::RelayRequirement,
    ) -> Result<allocation_explain::AllocationTrace, String> {
        let snapshot = relay_observer::snapshot();
        if !snapshot.is_consistent() {
            return Err("Relay pool and active configuration generations are not synchronized".to_owned());
        }
        let configured = snapshot.configured_relays();
        let eligible = snapshot.eligible_relays(requirement);
        let matched_rule = snapshot
            .select_geo(pa, pb, &eligible, requirement)
            .map(|selection| allocation_explain::MatchedRule {
                name: selection.rule_name,
                index: selection.rule_index,
                direction: selection.direction.to_owned(),
                relay_id: selection.relay,
            });
        let exclusion_reasons = snapshot.exclusion_reasons(requirement);
        Ok(allocation_explain::explain_relay_selection(
            &configured,
            &eligible,
            matched_rule,
            ROTATION_RELAY_SERVER.load(Ordering::SeqCst),
            snapshot.config_generation,
            snapshot.health_snapshot_id,
            &exclusion_reasons,
        ))
    }

    async fn reload_starry_runtime(&self) -> Result<starry_config::ActivationAck, String> {
        let candidate = starry_config::load_candidate()
            .map_err(|diagnostics| diagnostics.summary())?;
        let plan = starry_config::plan_activation(&candidate)
            .map_err(|diagnostics| diagnostics.summary())?;
        let previous = starry_config::snapshot();
        let prepared_geo = geo_relay::prepare(&candidate.config)?;
        let prepared_websocket = websocket_signal::prepare(
            &candidate.config.websocket_signal,
            candidate.config.relay_quality.enabled,
        )?;
        let prepared_auth = connection_auth::prepare(
            &candidate.config.connection_auth,
            connection_auth::must_login_floor(),
        )
        .await?;
        let relay_servers = if candidate.config.relay_servers.is_empty() {
            get_arg("relay-servers")
        } else {
            candidate.config.relay_servers.join(",")
        };
        let candidate_generation = plan.base_generation.saturating_add(1);
        let relay_apply = self
            .apply_relay_servers_runtime(relay_servers, candidate_generation)
            .await?;
        let previous_relay_servers = relay_apply.previous_relay_servers.clone();
        let relay_ack = relay_apply.subsystem_ack;

        let geo_ack = match geo_relay::activate_prepared(prepared_geo) {
            Ok(ack) => ack,
            Err(err) => {
                let recovery = self
                    .restore_runtime_subsystems(
                        previous.as_deref(),
                        previous_relay_servers,
                        plan.base_generation,
                    )
                    .await;
                return Err(format!(
                    "Geo apply acknowledgement failed: {err}; recovery={recovery}"
                ));
            }
        };
        let websocket_ack = match websocket_signal::activate_prepared(prepared_websocket) {
            Ok(ack) => ack,
            Err(err) => {
                let recovery = self
                    .restore_runtime_subsystems(
                        previous.as_deref(),
                        previous_relay_servers,
                        plan.base_generation,
                    )
                    .await;
                return Err(format!(
                    "WebSocket apply acknowledgement failed: {err}; recovery={recovery}"
                ));
            }
        };
        let secure_tcp_ack = starry_config::SubsystemAck {
            subsystem: "secure_tcp".to_owned(),
            accepted: true,
            detail: "configuration visible to new TCP connections".to_owned(),
        };
        let auth_ack = connection_auth::activate(prepared_auth);
        match starry_config::activate_if_base_generation(
            candidate,
            vec![relay_ack, geo_ack, websocket_ack, secure_tcp_ack, auth_ack],
            plan.base_generation,
        ) {
            Ok(ack) => Ok(ack),
            Err(diagnostics) => {
                let recovery = self
                    .restore_runtime_subsystems(
                        previous.as_deref(),
                        previous_relay_servers,
                        plan.base_generation,
                    )
                    .await;
                Err(format!(
                    "configuration activation failed: {}; recovery={recovery}",
                    diagnostics.summary()
                ))
            }
        }
    }

    async fn handle_local_control_request(
        &self,
        request: local_control::Request,
    ) -> local_control::Response {
        let request_id = request.request_id.clone();
        let empty_params = request
            .params
            .as_object()
            .map(|params| params.is_empty())
            .unwrap_or(false);
        match request.method.as_str() {
            "capabilities" if empty_params => local_control::Response::success(
                request_id,
                serde_json::json!({
                    "protocol": {"name": "starry-local-control", "version": 1},
                    "methods": [
                        "capabilities",
                        "status",
                        "relays",
                        "peer.verify",
                        "allocation.simulate",
                        "config.runtime_state",
                        "runtime.reload",
                        "strategy.status",
                        "strategy.reload"
                    ],
                    "limits": {"max_frame_bytes": local_control::MAX_FRAME_BYTES}
                }),
            ),
            "status" if empty_params => {
                let config = starry_config::runtime_state();
                let relay = relay_observer::snapshot();
                let auth = connection_auth::status();
                let auth_ready = matches!(auth.verifier_state, "disabled" | "ready");
                local_control::Response::success(
                    request_id,
                    serde_json::json!({
                        "ready": relay.is_consistent() && auth_ready,
                        "config": config,
                        "auth": auth
                    }),
                )
            }
            "relays" if empty_params => {
                let snapshot = relay_observer::snapshot();
                if !snapshot.is_consistent() {
                    local_control::Response::error(
                        request_id,
                        "STARRY_NOT_READY",
                        "Relay pool and active configuration generations are not synchronized",
                        true,
                    )
                } else {
                    match serde_json::to_value(snapshot) {
                        Ok(value) => local_control::Response::success(request_id, value),
                        Err(_) => local_control::Response::error(
                            request_id,
                            "LOCAL_CONTROL_PROTOCOL_ERROR",
                            "cannot serialize Relay runtime snapshot",
                            false,
                        ),
                    }
                }
            }
            "peer.verify" => {
                let peer_id = request.params.get("id").and_then(serde_json::Value::as_str);
                let uuid = request.params.get("uuid").and_then(serde_json::Value::as_str);
                let activation_epoch = request
                    .params
                    .get("activation_epoch")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default();
                let activation_id = request
                    .params
                    .get("activation_id")
                    .and_then(serde_json::Value::as_str);
                let route_leases = request
                    .params
                    .get("route_leases")
                    .and_then(serde_json::Value::as_array);
                let registered = match (peer_id, uuid, activation_id, route_leases) {
                    (Some(peer_id), Some(uuid), Some(activation_id), Some(route_leases))
                        if !peer_id.is_empty()
                            && peer_id.len() <= 128
                            && activation_epoch > 0
                            && !route_leases.is_empty()
                            && route_leases.len() <= 16 =>
                    {
                        let uuid = base64::decode(uuid)
                            .ok()
                            .filter(|value| value.len() == 16)
                            .map(Bytes::from);
                        let activation_id = base64::decode(activation_id)
                            .ok()
                            .filter(|value| value.len() == 16)
                            .map(Bytes::from);
                        let route_leases = route_leases
                            .iter()
                            .map(|value| {
                                value
                                    .as_str()
                                    .and_then(|value| base64::decode(value).ok())
                                    .filter(|value| value.len() == 32)
                                    .map(Bytes::from)
                            })
                            .collect::<Option<Vec<_>>>();
                        match (uuid, activation_id, route_leases) {
                            (Some(uuid), Some(activation_id), Some(route_leases)) => {
                                profile_activation::verify_active(
                                    peer_id,
                                    &uuid,
                                    activation_epoch,
                                    &activation_id,
                                    &route_leases,
                                )
                                .await
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                };
                local_control::Response::success(
                    request_id,
                    serde_json::json!({"registered": registered}),
                )
            }
            "allocation.simulate" => match relay_observer::simulate(
                request.params,
                ROTATION_RELAY_SERVER.load(Ordering::SeqCst),
            ) {
                Ok(trace) => match serde_json::to_value(trace) {
                    Ok(value) => local_control::Response::success(request_id, value),
                    Err(_) => local_control::Response::error(
                        request_id,
                        "LOCAL_CONTROL_PROTOCOL_ERROR",
                        "cannot serialize allocation trace",
                        false,
                    ),
                },
                Err(err) => local_control::Response::error(
                    request_id,
                    err.code,
                    err.detail,
                    err.retryable,
                ),
            },
            "config.runtime_state" if empty_params => {
                match serde_json::to_value(starry_config::runtime_state()) {
                    Ok(value) => local_control::Response::success(request_id, value),
                    Err(_) => local_control::Response::error(
                        request_id,
                        "LOCAL_CONTROL_PROTOCOL_ERROR",
                        "cannot serialize runtime configuration state",
                        false,
                    ),
                }
            }
            "strategy.status" if empty_params => {
                let value = crate::strategy::status();
                local_control::Response::success(request_id, value)
            }
            "strategy.reload" if empty_params => match crate::strategy::reload() {
                Ok(Some((version, digest))) => local_control::Response::success(
                    request_id,
                    serde_json::json!({"ok": true, "version": version, "digest": digest}),
                ),
                Ok(None) => local_control::Response::success(
                    request_id,
                    serde_json::json!({"ok": true, "enabled": false}),
                ),
                Err(err) => local_control::Response::error(
                    request_id,
                    "STRATEGY_INVALID",
                    err,
                    false,
                ),
            },
            "runtime.reload" if empty_params => match self.reload_starry_runtime().await {
                Ok(ack) => match serde_json::to_value(ack) {
                    Ok(value) => local_control::Response::success(request_id, value),
                    Err(_) => local_control::Response::error(
                        request_id,
                        "LOCAL_CONTROL_PROTOCOL_ERROR",
                        "cannot serialize runtime activation acknowledgement",
                        false,
                    ),
                },
                Err(err) => local_control::Response::error(
                    request_id,
                    "CONFIG_INVALID",
                    err,
                    false,
                ),
            },
            "capabilities" | "status" | "relays" | "config.runtime_state"
            | "runtime.reload" | "strategy.status" | "strategy.reload" => local_control::Response::error(
                request_id,
                "REQUEST_INVALID",
                "this local control method does not accept parameters",
                false,
            ),
            _ => local_control::Response::error(
                request_id,
                "REQUEST_INVALID",
                "unknown local control method",
                false,
            ),
        }
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-starry-config(rsc)",
                    "reload-geo(rg)",
                    "websocket-status(ws)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2> [native|wss|mixed]"
                )
            }
            Some("reload-starry-config" | "rsc") => {
                res = match self.reload_starry_runtime().await {
                    Ok(ack) => serde_json::to_string_pretty(&ack)
                        .unwrap_or_else(|_| "runtime activation acknowledgement serialization failed".to_owned()),
                    Err(err) => format!("runtime reload rejected: {err}"),
                };
            }
            Some("reload-geo" | "rg") => {
                res = geo_relay::reload();
            }
            Some("websocket-status" | "ws") => {
                res = websocket_signal::status(self.relay_servers.as_ref()).await;
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(first) = fds.next() {
                    if let Ok(a) = first.parse::<IpAddr>() {
                        let second = fds.next().and_then(|value| value.parse::<IpAddr>().ok());
                        let b = second.unwrap_or(a);
                        match websocket_signal::RelayRequirement::parse(fds.next()) {
                            Some(requirement) => {
                                res = match self.explain_relay_server(a, b, requirement) {
                                    Ok(trace) => serde_json::to_string_pretty(&trace)
                                        .unwrap_or_else(|_| "allocation trace serialization failed".to_owned()),
                                    Err(err) => format!("allocation simulation unavailable: {err}"),
                                };
                            }
                            None => res = "invalid transport; expected native, wss, or mixed".to_owned(),
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// Handles loopback console requests and external NAT or online-status queries.
    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                match local_control::read_request(&mut stream).await {
                    Ok(local_control::IncomingRequest::Framed(request)) => {
                        let response = match local_control::authenticate(&request) {
                            Ok(()) => rs.handle_local_control_request(request).await,
                            Err(err) => local_control::Response::error(
                                request.request_id.clone(),
                                err.code,
                                err.detail,
                                false,
                            ),
                        };
                        if let Err(err) = local_control::write_response(&mut stream, &response).await {
                            log::debug!("Structured local control response failed: {}", err.detail);
                        }
                    }
                    Err(err) if err.framed => {
                        let response = local_control::Response::error(
                            String::new(),
                            err.code,
                            err.detail,
                            false,
                        );
                        let _ = local_control::write_response(&mut stream, &response).await;
                    }
                    Err(err) => {
                        log::debug!("Rejected unframed local control request: {}", err.detail);
                    }
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(*MAX_MESSAGE);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    /// Processes rendezvous messages on an accepted TCP or WebSocket connection.
    async fn handle_websocket_signal(
        &mut self,
        stream: TcpStream,
        route_addr: SocketAddr,
        key: &str,
        config: starry_config::WebSocketSignalConfig,
    ) -> ResultType<()> {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let effective_slot = Arc::new(std::sync::Mutex::new(None));
        let callback_slot = effective_slot.clone();
        let callback_config = config.clone();
        let callback = move |request: &Request, response: Response| {
            match websocket_signal::inspect_upgrade(
                request.uri(),
                request.headers(),
                route_addr,
                &callback_config,
            ) {
                Ok(effective_addr) => {
                    if let Ok(mut slot) = callback_slot.lock() {
                        *slot = Some(effective_addr);
                    }
                    Ok(response)
                }
                Err(reason) => {
                    log::warn!("Rejected WebSocket Signal upgrade: {reason}");
                    Err(http::Response::builder()
                        .status(http::StatusCode::FORBIDDEN)
                        .body(Some("Forbidden".to_owned()))
                        .expect("static WebSocket rejection response"))
                }
            }
        };
        // Same transport bounds as upstream 1.1.17's /ws listener (#722,
        // #747): MAX_MESSAGE_KB caps the frame, 8 KiB socket buffers, and the
        // upgrade handshake must finish within 30 seconds.
        let max_frame_bytes = config.max_frame_bytes.min(*MAX_MESSAGE);
        let parser_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .read_buffer_size(WS_BUFFER_SIZE)
            .write_buffer_size(WS_BUFFER_SIZE)
            .max_message_size(Some(max_frame_bytes))
            .max_frame_size(Some(max_frame_bytes.min(WS_DEFAULT_MAX_FRAME_SIZE)));
        let websocket = timeout(
            30_000,
            tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                callback,
                Some(parser_config),
            ),
        )
        .await??;
        let effective_addr = effective_slot
            .lock()
            .ok()
            .and_then(|slot| *slot)
            .unwrap_or(route_addr);
        let (sink, stream) = websocket.split();
        let connection_id = websocket_signal::next_connection_id();
        let (writer, receiver) =
            websocket_signal::transport(connection_id, config.outbound_queue_capacity);
        let writer_task = writer.clone();
        tokio::spawn(async move {
            websocket_signal::writer_loop(sink, receiver, writer_task).await;
        });
        websocket_signal::register_connection(
            route_addr,
            effective_addr,
            connection_id,
            writer.clone(),
        )
        .await;

        let session = self
            .drive_websocket_signal(
                stream,
                writer.clone(),
                route_addr,
                effective_addr,
                key,
                &config,
            )
            .await;
        if let Some(session) = session.as_ref() {
            if websocket_signal::remove_session(session, "reader closed").await {
                // profile activation cleanup after reader exit
                self.expire_websocket_route(&session.peer_id, session.generation)
                    .await;
            }
        }
        self.tcp_punch.lock().await.remove(&try_into_v4(route_addr));
        webrtc_signal::close_route(try_into_v4(route_addr));
        websocket_signal::remove_connection(route_addr, connection_id).await;
        writer.close();
        Ok(())
    }

    async fn drive_websocket_signal(
        &mut self,
        mut stream: hbb_common::futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<TcpStream>,
        >,
        writer: websocket_signal::WsWriteTransport,
        route_addr: SocketAddr,
        effective_addr: SocketAddr,
        key: &str,
        config: &starry_config::WebSocketSignalConfig,
    ) -> Option<websocket_signal::SessionToken> {
        let registration_started = Instant::now();
        loop {
            let elapsed_ms = u64::try_from(registration_started.elapsed().as_millis())
                .unwrap_or(u64::MAX);
            let remaining_ms = config.registration_timeout_ms.saturating_sub(elapsed_ms);
            if remaining_ms == 0 {
                log::debug!("WebSocket Signal absolute registration deadline elapsed");
                return None;
            }
            let first = match timeout(remaining_ms, stream.next()).await {
                Ok(Some(Ok(message))) => message,
                Ok(Some(Err(err))) => {
                    log::debug!("WebSocket Signal read failed before registration: {err}");
                    return None;
                }
                Ok(None) => return None,
                Err(_) => {
                    log::debug!("WebSocket Signal registration timeout");
                    return None;
                }
            };
            let bytes = match first {
                tungstenite::Message::Binary(bytes) => bytes,
                tungstenite::Message::Ping(bytes) => {
                    if writer.send_pong(bytes.to_vec()).is_err() {
                        return None;
                    }
                    continue;
                }
                tungstenite::Message::Close(_) => return None,
                _ => {
                    log::debug!("WebSocket Signal requires binary protocol frames");
                    return None;
                }
            };
            if bytes.is_empty() {
                continue;
            }
            if bytes.len() > config.max_frame_bytes {
                log::warn!("Rejected oversized WebSocket Signal frame: {} bytes", bytes.len());
                return None;
            }
            let parsed = match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(message) => message,
                Err(err) => {
                    log::debug!("Rejected malformed WebSocket Signal protobuf: {err}");
                    return None;
                }
            };
            match parsed.union {
                Some(rendezvous_message::Union::RegisterPeer(_)) => {
                    let mut response = RendezvousMessage::new();
                    response.set_register_peer_response(RegisterPeerResponse {
                        request_pk: true,
                        ..Default::default()
                    });
                    if let Ok(bytes) = response.write_to_bytes() {
                        if writer.send_binary(bytes).is_err() {
                            return None;
                        }
                    }
                    continue;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if !websocket_signal::relay_ready() {
                        let mut response = RendezvousMessage::new();
                        response.set_register_pk_response(RegisterPkResponse {
                            result: register_pk_response::Result::SERVER_ERROR.into(),
                            ..Default::default()
                        });
                        if let Ok(bytes) = response.write_to_bytes() {
                            let _ = writer.send_binary(bytes);
                        }
                        log::warn!("WebSocket registration rejected: no healthy WSS Relay");
                        return None;
                    }
                    let verified_fast = self.is_verified_fast_registration(&rk).await;
                    if !verified_fast
                        && !websocket_signal::allow_registration(
                            effective_addr.ip(),
                            config.registration_rate_per_minute,
                        )
                        .await
                    {
                        let mut response = RendezvousMessage::new();
                        response.set_register_pk_response(RegisterPkResponse {
                            result: register_pk_response::Result::TOO_FREQUENT.into(),
                            ..Default::default()
                        });
                        if let Ok(bytes) = response.write_to_bytes() {
                            let _ = writer.send_binary(bytes);
                        }
                        return None;
                    }
                    if !websocket_signal::capacity_available(
                        &rk.id,
                        effective_addr.ip(),
                        config,
                    )
                    .await
                    {
                        let mut response = RendezvousMessage::new();
                        response.set_register_pk_response(RegisterPkResponse {
                            result: register_pk_response::Result::TOO_FREQUENT.into(),
                            ..Default::default()
                        });
                        if let Ok(bytes) = response.write_to_bytes() {
                            let _ = writer.send_binary(bytes);
                        }
                        return None;
                    }
                    let Some(mut outcome) =
                        self.process_register_pk(rk, effective_addr, None).await
                    else {
                        return None;
                    };
                    let mut token = None;
                    let mut activation_epoch = 0;
                    let mut activation_id = Bytes::new();
                    let mut route_lease = Bytes::new();
                    let mut route_generation = 0;
                    if outcome.result == register_pk_response::Result::OK {
                        if let Some(claim) = outcome.activation.take() {
                            let generation = claim.generation();
                            let tracked = claim.tracked();
                            match websocket_signal::bind(
                                outcome.id.clone(),
                                writer.clone(),
                                effective_addr.ip(),
                                route_addr,
                                Some(generation),
                                config,
                            )
                            .await
                            {
                                Ok(bound) => {
                                    activation_epoch = claim.activation_epoch();
                                    activation_id = claim.activation_id().clone();
                                    route_lease = claim.route_lease().clone();
                                    if tracked {
                                        route_generation = generation;
                                    }
                                    self.activate_websocket_route(&outcome.id, generation)
                                        .await;
                                    claim
                                        .commit(profile_activation::RouteKind::WebSocket {
                                            generation,
                                            connection_id: bound.connection_id,
                                        })
                                        .await;
                                    token = Some(bound);
                                }
                                Err(err) => {
                                    log::warn!("WebSocket registration capacity rejection: {err}");
                                    outcome.result = register_pk_response::Result::TOO_FREQUENT;
                                }
                            }
                        }
                    }
                    let keep_alive = (config.idle_timeout_ms / 1_500)
                        .clamp(1, i32::MAX as u64) as i32;
                    let mut response = RendezvousMessage::new();
                    response.set_register_pk_response(RegisterPkResponse {
                        result: outcome.result.into(),
                        keep_alive,
                        activation_epoch,
                        activation_id,
                        route_lease,
                        route_generation,
                        ..Default::default()
                    });
                    let sent = response
                        .write_to_bytes()
                        .ok()
                        .and_then(|bytes| writer.send_binary(bytes).ok())
                        .is_some();
                    if outcome.result != register_pk_response::Result::OK || !sent {
                        if let Some(token) = token.as_ref() {
                            if websocket_signal::remove_session(
                                token,
                                "registration response failed",
                            )
                            .await
                            {
                                self.expire_websocket_route(
                                    &token.peer_id,
                                    token.generation,
                                )
                                .await;
                            }
                        }
                        return None;
                    }
                    if route_generation != 0 {
                        profile_activation::record_ready_ack();
                    }
                    let Some(token) = token else {
                        return None;
                    };
                    self.touch_registered_peer(&token.peer_id).await;
                    return self
                        .run_registered_websocket(
                            stream,
                            writer,
                            route_addr,
                            effective_addr,
                            key,
                            config,
                            token,
                        )
                        .await;
                }
                Some(_) => {
                    let mut sink = Some(Sink::Ws(writer.clone()));
                    let mut keep_reading = self.handle_tcp(
                        &bytes,
                        &mut sink,
                        route_addr,
                        effective_addr,
                        key,
                        true,
                        connection_auth::SignalTransport::WebSocket,
                    )
                    .await;
                    while keep_reading {
                        match timeout(config.idle_timeout_ms, stream.next()).await {
                            Ok(Some(Ok(tungstenite::Message::Binary(bytes)))) => {
                                if bytes.len() > config.max_frame_bytes {
                                    break;
                                }
                                if bytes.is_empty() {
                                    continue;
                                }
                                let mut sink = Some(Sink::Ws(writer.clone()));
                                keep_reading = self
                                    .handle_tcp(
                                        &bytes,
                                        &mut sink,
                                        route_addr,
                                        effective_addr,
                                        key,
                                        true,
                                        connection_auth::SignalTransport::WebSocket,
                                    )
                                    .await;
                            }
                            Ok(Some(Ok(tungstenite::Message::Ping(bytes)))) => {
                                if writer.send_pong(bytes.to_vec()).is_err() {
                                    break;
                                }
                            }
                            Ok(Some(Ok(tungstenite::Message::Close(_))))
                            | Ok(None)
                            | Err(_) => break,
                            Ok(Some(Ok(_))) | Ok(Some(Err(_))) => break,
                        }
                    }
                    return None;
                }
                None => return None,
            }
        }
    }

    async fn run_registered_websocket(
        &mut self,
        mut stream: hbb_common::futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<TcpStream>,
        >,
        writer: websocket_signal::WsWriteTransport,
        route_addr: SocketAddr,
        effective_addr: SocketAddr,
        key: &str,
        config: &starry_config::WebSocketSignalConfig,
        token: websocket_signal::SessionToken,
    ) -> Option<websocket_signal::SessionToken> {
        let mut heartbeat = interval(Duration::from_millis(config.keepalive_interval_ms));
        heartbeat.tick().await;
        loop {
            tokio::select! {
                incoming = stream.next() => {
                    match incoming {
                        Some(Ok(tungstenite::Message::Binary(bytes))) => {
                            if bytes.len() > config.max_frame_bytes {
                                log::warn!("Closing WebSocket Signal session after oversized frame");
                                break;
                            }
                            token.touch();
                            profile_activation::touch_route(
                                &token.peer_id,
                                profile_activation::RouteKind::WebSocket {
                                    generation: token.generation,
                                    connection_id: token.connection_id,
                                },
                            )
                            .await;
                            self.touch_registered_peer(&token.peer_id).await;
                            if bytes.is_empty() {
                                continue;
                            }
                            let parsed = match RendezvousMessage::parse_from_bytes(&bytes) {
                                Ok(parsed) => parsed,
                                Err(_) => {
                                    log::debug!("Closing registered WebSocket Signal session after malformed protobuf");
                                    break;
                                }
                            };
                            if let Some(rendezvous_message::Union::DeactivatePeer(request)) =
                                parsed.union
                            {
                                let activation_epoch = request.activation_epoch;
                                let activation_id = request.activation_id.clone();
                                let route_generation = request.route_generation;
                                let deactivated = self
                                    .process_current_websocket_deactivation(request, &token)
                                    .await;
                                let mut response = RendezvousMessage::new();
                                response.set_deactivate_peer_response(DeactivatePeerResponse {
                                    activation_epoch,
                                    activation_id,
                                    deactivated,
                                    route_generation,
                                    ..Default::default()
                                });
                                if let Ok(bytes) = response.write_to_bytes() {
                                    if writer.send_binary(bytes).is_err() {
                                        break;
                                    }
                                }
                                if deactivated {
                                    return None;
                                }
                                continue;
                            }
                            let mut sink = Some(Sink::Ws(writer.clone()));
                            self.handle_tcp(
                                &bytes,
                                &mut sink,
                                route_addr,
                                effective_addr,
                                key,
                                true,
                                connection_auth::SignalTransport::WebSocket,
                            ).await;
                        }
                        Some(Ok(tungstenite::Message::Ping(bytes))) => {
                            if writer.send_pong(bytes.to_vec()).is_err() {
                                break;
                            }
                        }
                        Some(Ok(tungstenite::Message::Pong(_))) => token.touch(),
                        Some(Ok(tungstenite::Message::Close(_))) | None => break,
                        Some(Ok(_)) => break,
                        Some(Err(err)) => {
                            log::debug!("WebSocket Signal reader closed: {err}");
                            break;
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    if writer.is_closed() {
                        break;
                    }
                    if token.idle_for() >= Duration::from_millis(config.idle_timeout_ms) {
                        break;
                    }
                    profile_activation::touch_route(
                        &token.peer_id,
                        profile_activation::RouteKind::WebSocket {
                            generation: token.generation,
                            connection_id: token.connection_id,
                        },
                    )
                    .await;
                    if writer.send_binary(Vec::new()).is_err() {
                        break;
                    }
                }
            }
        }
        Some(token)
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let signal_transport;
        if ws {
            let ws_config = websocket_signal::config();
            if ws_config.enabled {
                return self.handle_websocket_signal(stream, addr, key, ws_config).await;
            }
            log::debug!("WebSocket Signal listener is disabled; closing admission");
            return Ok(());
        } else {
            let mut secure_config = starry_config::snapshot()
                .map(|config| config.secure_tcp.clone())
                .unwrap_or_default();
            // Never accept larger frames than upstream MAX_MESSAGE_KB allows
            // (rustdesk-server#747), whatever secure_tcp.max_frame_bytes says.
            secure_config.max_frame_bytes = secure_config.max_frame_bytes.min(*MAX_MESSAGE);
            let negotiated = secure_tcp::negotiate(
                stream,
                self.inner.sk.as_ref(),
                &secure_config,
            )
            .await?;
            let secure_tcp::NegotiatedTcp {
                sink: tcp_sink,
                stream: mut tcp_stream,
                first_plaintext,
                secured,
            } = negotiated;
            signal_transport = if secured {
                connection_auth::SignalTransport::SecureTcp
            } else {
                connection_auth::SignalTransport::Tcp
            };
            if secured {
                log::debug!("Secure TCP connection established for {addr}");
            }
            sink = Some(Sink::TcpStream(tcp_sink));
            let mut keep_reading = true;
            if let Some(bytes) = first_plaintext {
                keep_reading = self.handle_tcp(&bytes, &mut sink, addr, addr, key, ws, signal_transport).await;
            }
            while keep_reading {
                match timeout(secure_config.idle_timeout_ms, tcp_stream.next()).await {
                    Ok(Some(Ok(bytes))) => {
                        keep_reading = self.handle_tcp(&bytes, &mut sink, addr, addr, key, ws, signal_transport).await;
                    }
                    _ => break,
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        webrtc_signal::close_route(try_into_v4(addr));
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::rendezvous_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
    activation_epoch: u64,
    activation_id: Bytes,
    route_lease: Bytes,
    route_generation: u64,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        activation_epoch,
        activation_id,
        route_lease,
        route_generation,
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_kb_falls_back_to_default_and_is_capped() {
        assert_eq!(max_message_kb(""), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("0"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("abc"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("256"), 256);
        assert_eq!(max_message_kb(&usize::MAX.to_string()), MAX_MESSAGE_KB_CAP);
    }

    #[test]
    fn default_message_bound_holds_an_online_query_for_5000_ids() {
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            id: "1234567890".to_owned(),
            peers: (0..5000).map(|i| format!("{i:010}")).collect(),
            ..Default::default()
        });
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= DEFAULT_MAX_MESSAGE_KB << 10, "{len}");
    }

    #[test]
    fn relay_uuid_validation() {
        let uuid = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
        assert_eq!(validate_relay_response(uuid, "relay.example"), Ok(()));
        assert_eq!(validate_relay_response("", ""), Ok(()));
        let max_len = "a".repeat(128);
        for value in [
            uuid,
            "E4C181D0-41C7-4AE6-8EF0-36581B6B2B12",
            "e4c181d041c74ae68ef036581b6b2b12",
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "a_b-c",
            max_len.as_str(),
        ] {
            assert_eq!(validate_relay_uuid(value), Ok(()), "rejected {value:?}");
        }
        let too_long = "a".repeat(129);
        for value in [
            "",
            "\r\nPING\r\n",
            "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12\n",
            "e4c181d0 41c7",
            "{e4c181d0-41c7-4ae6-8ef0-36581b6b2b12}",
            "e4c181d0\0",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_relay_uuid(value).is_err(), "accepted {value:?}");
            assert!(validate_relay_response(value, "relay.example").is_err());
        }
    }

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }
}


#[cfg(test)]
mod starry_allocation_tests {
    use super::*;

    #[test]
    fn allocation_simulation_does_not_advance_production_rotation() {
        let original = ROTATION_RELAY_SERVER.swap(23, Ordering::SeqCst);
        let configured = vec!["relay-a".to_owned(), "relay-b".to_owned()];
        let exclusion_reasons = std::collections::HashMap::new();
        let trace = allocation_explain::explain_relay_selection(
            &configured,
            &configured,
            None,
            ROTATION_RELAY_SERVER.load(Ordering::SeqCst),
            7,
            "health-11".to_owned(),
            &exclusion_reasons,
        );
        assert_eq!(trace.selection.kind, "rotation_prediction");
        assert_eq!(ROTATION_RELAY_SERVER.load(Ordering::SeqCst), 23);
        ROTATION_RELAY_SERVER.store(original, Ordering::SeqCst);
    }
}
