//! Opt-in WebRTC signalling for RustDesk 1.5 clients.
//!
//! A 1.5 controller that wants WebRTC puts an SDP offer in its
//! `PunchHoleRequest`. HBBS hands the offer to the device in `PunchHole`; the
//! device's answer comes back in `PunchHoleSent` or `RelayResponse` and goes to
//! the controller in `PunchHoleResponse`/`RelayResponse`. Both sides then
//! trickle `IceCandidate` messages through HBBS until a connection forms:
//!
//! - controller to device: on the controller's own signalling connection,
//!   addressed by the device `id`;
//! - device to controller: on a connection of the device, addressed by the
//!   controller's `socket_addr` from `PunchHole`.
//!
//! The controller's connection therefore has to outlive the first reply. A
//! route records that one controller connection carried an admitted offer to
//! one device. Only a connection that opened a route can send candidates, only
//! to that device, and only a routed controller can receive candidates, so no
//! direction can be aimed at an arbitrary address. Everything is bounded:
//! offer/answer/candidate sizes, routes in total and per IP, candidates per
//! route and direction, and a route lifetime.
//!
//! Disabled by default. While disabled, offers and answers are stripped and
//! `IceCandidate` is ignored, so the server behaves exactly as before.
//!
//! Offers are only admitted from Secure TCP or WebSocket signalling: the SDP
//! carries the DTLS fingerprints that bind the WebRTC channel to the peer
//! identity, and a plaintext TCP hop could swap them.

use hbb_common::rendezvous_proto::IceCandidate;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

/// A route lives this long after the latest offer. The client gives the
/// whole exchange about 18 seconds, punch retries included.
pub const ROUTE_TTL: Duration = Duration::from_secs(60);
/// Routes held at once; a new offer past this goes on without WebRTC.
pub const MAX_ROUTES: usize = 4_096;
/// Routes held at once for one controller IP.
pub const MAX_ROUTES_PER_IP: usize = 64;
/// Candidates per route and direction. Clients cap their own queues at 64.
pub const MAX_CANDIDATES: u32 = 64;
/// An offer or answer: an envelope around an SDP of about a kilobyte. The
/// offer reaches a natively registered device inside a UDP `PunchHole`.
pub const MAX_SDP_LEN: usize = 8 * 1024;
/// One `a=candidate` line.
pub const MAX_CANDIDATE_LEN: usize = 2 * 1024;
/// The session key identifies the WebRTC session on both ends.
pub const MAX_SESSION_KEY_LEN: usize = 256;

static ENABLED: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    static ref ROUTES: Mutex<Routes> = Mutex::new(Routes::default());
}

/// Reads `--webrtc-signal` / `STARRY_WEBRTC_SIGNAL` (Y/N) once at startup.
pub fn configure_from_args() -> bool {
    let value = crate::common::get_arg("webrtc-signal");
    let value = if value.is_empty() {
        crate::common::env_var("STARRY_WEBRTC_SIGNAL").unwrap_or_default()
    } else {
        value
    };
    let enabled = matches!(
        value.trim().to_ascii_uppercase().as_str(),
        "Y" | "YES" | "TRUE" | "1"
    );
    set_enabled(enabled);
    enabled
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::SeqCst);
    if !enabled {
        if let Ok(mut routes) = ROUTES.lock() {
            routes.map.clear();
        }
    }
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// Why an offer was not passed on; logged at debug level only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDrop {
    Empty,
    Disabled,
    InsecureTransport,
    AlwaysRelay,
    TooLarge,
}

/// The offer to put in `PunchHole`, or why there is none. `secure_transport`
/// is true for Secure TCP and WebSocket signalling.
pub fn admit_offer(
    offer: String,
    secure_transport: bool,
    always_use_relay: bool,
) -> Result<String, OfferDrop> {
    if offer.is_empty() {
        Err(OfferDrop::Empty)
    } else if !enabled() {
        Err(OfferDrop::Disabled)
    } else if !secure_transport {
        Err(OfferDrop::InsecureTransport)
    } else if always_use_relay {
        // A WebRTC pair can connect directly, which ALWAYS_USE_RELAY forbids.
        Err(OfferDrop::AlwaysRelay)
    } else if offer.len() > MAX_SDP_LEN {
        Err(OfferDrop::TooLarge)
    } else {
        Ok(offer)
    }
}

/// Opens (or renews) the route for a controller connection whose offer is
/// about to be forwarded to `peer_id`. False means the offer must be dropped.
///
/// `controller` is the signalling connection (the route key); `client_ip` is
/// the controller's effective address, which differs from the connection
/// behind a trusted WebSocket proxy, so the per-IP bound applies per client
/// rather than to the proxy.
pub fn open_route(controller: SocketAddr, client_ip: IpAddr, peer_id: &str) -> bool {
    ROUTES
        .lock()
        .map(|mut routes| routes.open(controller, client_ip, peer_id, Instant::now()))
        .unwrap_or(false)
}

/// The answer to hand to `controller`; empty unless a live route exists.
pub fn answer_for(controller: SocketAddr, answer: String) -> String {
    if answer.is_empty() || !enabled() || answer.len() > MAX_SDP_LEN || !has_route(controller) {
        return String::new();
    }
    answer
}

/// Whether the controller connection at `controller` must be kept open.
pub fn has_route(controller: SocketAddr) -> bool {
    enabled()
        && ROUTES
            .lock()
            .map(|mut routes| routes.get(controller, Instant::now()).is_some())
            .unwrap_or(false)
}

/// The controller connection closed; its route goes with it.
pub fn close_route(controller: SocketAddr) {
    if let Ok(mut routes) = ROUTES.lock() {
        routes.map.remove(&controller);
    }
}

pub fn candidate_is_valid(ice: &IceCandidate) -> bool {
    !ice.candidate.is_empty()
        && ice.candidate.len() <= MAX_CANDIDATE_LEN
        && !ice.session_key.is_empty()
        && ice.session_key.len() <= MAX_SESSION_KEY_LEN
}

/// May the controller connection `controller` send a candidate to `peer_id`?
pub fn allow_to_peer(controller: SocketAddr, peer_id: &str) -> bool {
    enabled()
        && ROUTES
            .lock()
            .map(|mut routes| routes.allow_to_peer(controller, peer_id, Instant::now()))
            .unwrap_or(false)
}

/// May a device deliver a candidate to `controller`?
pub fn allow_to_controller(controller: SocketAddr) -> bool {
    enabled()
        && ROUTES
            .lock()
            .map(|mut routes| routes.allow_to_controller(controller, Instant::now()))
            .unwrap_or(false)
}

/// Live routes, for status output.
pub fn route_count() -> usize {
    ROUTES
        .lock()
        .map(|mut routes| {
            let now = Instant::now();
            routes.map.retain(|_, route| route.expires > now);
            routes.map.len()
        })
        .unwrap_or(0)
}

struct Route {
    peer_id: String,
    client_ip: IpAddr,
    expires: Instant,
    to_peer: u32,
    to_controller: u32,
}

#[derive(Default)]
struct Routes {
    map: HashMap<SocketAddr, Route>,
}

impl Routes {
    fn open(
        &mut self,
        controller: SocketAddr,
        client_ip: IpAddr,
        peer_id: &str,
        now: Instant,
    ) -> bool {
        if let Some(route) = self.map.get_mut(&controller) {
            if route.peer_id == peer_id && route.client_ip == client_ip && route.expires > now {
                // A punch retry renews the route and keeps its budgets.
                route.expires = now + ROUTE_TTL;
                return true;
            }
            self.map.remove(&controller);
        }
        let same_ip = |map: &HashMap<SocketAddr, Route>| {
            map.values()
                .filter(|route| route.client_ip == client_ip)
                .count()
        };
        if self.map.len() >= MAX_ROUTES || same_ip(&self.map) >= MAX_ROUTES_PER_IP {
            self.map.retain(|_, route| route.expires > now);
            if self.map.len() >= MAX_ROUTES || same_ip(&self.map) >= MAX_ROUTES_PER_IP {
                return false;
            }
        }
        self.map.insert(
            controller,
            Route {
                peer_id: peer_id.to_owned(),
                client_ip,
                expires: now + ROUTE_TTL,
                to_peer: 0,
                to_controller: 0,
            },
        );
        true
    }

    fn get(&mut self, controller: SocketAddr, now: Instant) -> Option<&mut Route> {
        if self
            .map
            .get(&controller)
            .map(|route| route.expires <= now)
            .unwrap_or(false)
        {
            self.map.remove(&controller);
        }
        self.map.get_mut(&controller)
    }

    fn allow_to_peer(&mut self, controller: SocketAddr, peer_id: &str, now: Instant) -> bool {
        match self.get(controller, now) {
            Some(route) if route.peer_id == peer_id && route.to_peer < MAX_CANDIDATES => {
                route.to_peer += 1;
                true
            }
            _ => false,
        }
    }

    fn allow_to_controller(&mut self, controller: SocketAddr, now: Instant) -> bool {
        match self.get(controller, now) {
            Some(route) if route.to_controller < MAX_CANDIDATES => {
                route.to_controller += 1;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], port))
    }

    #[test]
    fn candidates_only_flow_along_an_open_route() {
        let mut routes = Routes::default();
        let now = Instant::now();
        let controller = addr(1, 4000);
        assert!(!routes.allow_to_peer(controller, "device", now));
        assert!(!routes.allow_to_controller(controller, now));
        assert!(routes.open(controller, controller.ip(), "device", now));
        assert!(routes.allow_to_peer(controller, "device", now));
        assert!(!routes.allow_to_peer(controller, "another-device", now));
        assert!(!routes.allow_to_peer(addr(2, 4000), "device", now));
        assert!(routes.allow_to_controller(controller, now));
        assert!(!routes.allow_to_controller(addr(2, 4000), now));
    }

    #[test]
    fn candidate_budget_is_per_direction() {
        let mut routes = Routes::default();
        let now = Instant::now();
        let controller = addr(1, 4000);
        assert!(routes.open(controller, controller.ip(), "device", now));
        for _ in 0..MAX_CANDIDATES {
            assert!(routes.allow_to_peer(controller, "device", now));
        }
        assert!(!routes.allow_to_peer(controller, "device", now));
        for _ in 0..MAX_CANDIDATES {
            assert!(routes.allow_to_controller(controller, now));
        }
        assert!(!routes.allow_to_controller(controller, now));
        // A retry of the same offer renews the route but not the budget.
        assert!(routes.open(controller, controller.ip(), "device", now));
        assert!(!routes.allow_to_peer(controller, "device", now));
        // An offer to another device starts over.
        assert!(routes.open(controller, controller.ip(), "another-device", now));
        assert!(routes.allow_to_peer(controller, "another-device", now));
        assert!(!routes.allow_to_peer(controller, "device", now));
    }

    #[test]
    fn routes_expire_and_stay_bounded() {
        let mut routes = Routes::default();
        let now = Instant::now();
        assert!(routes.open(addr(1, 4000), addr(1, 4000).ip(), "device", now));
        let later = now + ROUTE_TTL + Duration::from_millis(1);
        assert!(!routes.allow_to_peer(addr(1, 4000), "device", later));
        assert!(routes.map.is_empty());

        for port in 0..MAX_ROUTES_PER_IP as u16 {
            assert!(routes.open(
                addr(7, 10_000 + port),
                addr(7, 10_000 + port).ip(),
                "device",
                now
            ));
        }
        assert!(!routes.open(addr(7, 20_000), addr(7, 20_000).ip(), "device", now));
        assert!(routes.open(addr(8, 20_000), addr(8, 20_000).ip(), "device", now));
        // Expired routes free their slots.
        assert!(routes.open(addr(7, 20_000), addr(7, 20_000).ip(), "device", later));

        let mut full = Routes::default();
        for index in 0..MAX_ROUTES {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000_u32 + index as u32);
            assert!(full.open(SocketAddr::from((ip, 4000)), ip.into(), "device", now));
        }
        assert!(!full.open(addr(9, 4000), addr(9, 4000).ip(), "device", now));
        assert_eq!(full.map.len(), MAX_ROUTES);
    }

    #[test]
    fn per_ip_bound_follows_the_client_not_the_proxy_connection() {
        let mut routes = Routes::default();
        let now = Instant::now();
        let proxy = std::net::Ipv4Addr::new(10, 0, 0, 1);
        // Many WSS clients arrive through one proxy address.
        for client in 0..(MAX_ROUTES_PER_IP as u8 + 8) {
            let connection = SocketAddr::from((proxy, 20_000 + client as u16));
            assert!(routes.open(connection, addr(client, 1).ip(), "device", now));
        }
        // One client still cannot exceed its own bound.
        let client = addr(200, 1).ip();
        for port in 0..MAX_ROUTES_PER_IP as u16 {
            assert!(routes.open(
                SocketAddr::from((proxy, 30_000 + port)),
                client,
                "device",
                now
            ));
        }
        assert!(!routes.open(SocketAddr::from((proxy, 40_000)), client, "device", now));
    }

    #[test]
    fn offers_need_the_switch_a_secure_transport_and_a_bound() {
        set_enabled(false);
        assert_eq!(
            admit_offer("sdp".into(), true, false),
            Err(OfferDrop::Disabled)
        );
        set_enabled(true);
        assert_eq!(
            admit_offer(String::new(), true, false),
            Err(OfferDrop::Empty)
        );
        assert_eq!(
            admit_offer("sdp".into(), false, false),
            Err(OfferDrop::InsecureTransport)
        );
        assert_eq!(
            admit_offer("sdp".into(), true, true),
            Err(OfferDrop::AlwaysRelay)
        );
        assert_eq!(
            admit_offer("x".repeat(MAX_SDP_LEN + 1), true, false),
            Err(OfferDrop::TooLarge)
        );
        assert_eq!(admit_offer("sdp".into(), true, false), Ok("sdp".to_owned()));
        set_enabled(false);
    }

    #[test]
    fn candidate_shape_is_bounded() {
        let valid = IceCandidate {
            candidate: "candidate:1 1 udp 2122260223 192.0.2.1 50000 typ host".into(),
            session_key: "session".into(),
            ..Default::default()
        };
        assert!(candidate_is_valid(&valid));
        for invalid in [
            IceCandidate {
                candidate: String::new(),
                ..valid.clone()
            },
            IceCandidate {
                session_key: String::new(),
                ..valid.clone()
            },
            IceCandidate {
                candidate: "x".repeat(MAX_CANDIDATE_LEN + 1),
                ..valid.clone()
            },
            IceCandidate {
                session_key: "x".repeat(MAX_SESSION_KEY_LEN + 1),
                ..valid.clone()
            },
        ] {
            assert!(!candidate_is_valid(&invalid));
        }
    }
}
