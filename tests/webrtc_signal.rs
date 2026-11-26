//! End-to-end WebRTC signalling (RustDesk 1.5) against a real HBBS process.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::{
        register_pk_response, rendezvous_message, IceCandidate, KeyExchange, PunchHole,
        PunchHoleRequest, PunchHoleSent, RegisterPeer, RegisterPk, RendezvousMessage,
    },
    timeout,
    tokio::{
        net::TcpStream,
        runtime::Builder,
        time::{sleep, Duration},
    },
    tokio_util::codec::Framed,
    udp::FramedSocket,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const OFFER: &str = "webrtc://offer-envelope-for-test";
const ANSWER: &str = "webrtc://answer-envelope-for-test";
const SESSION: &str = "dtls-fingerprint-session-key";

struct ServerProcess {
    child: Child,
    state_dir: PathBuf,
}

impl ServerProcess {
    /// The generated server key; clients send it as `licence_key`.
    async fn key(&self) -> String {
        for _ in 0..100 {
            if let Ok(key) = fs::read_to_string(self.state_dir.join("id_ed25519.pub")) {
                return key.trim().to_owned();
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("HBBS did not write its public key");
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.state_dir);
    }
}

fn start_hbbs(webrtc: &str, first_port: u16) -> (ServerProcess, u16) {
    // Each test scans its own range, so parallel tests never race for ports.
    let port = reserve_hbbs_ports(first_port);
    let state_dir =
        std::env::temp_dir().join(format!("starry-webrtc-{}-{port}", std::process::id()));
    let _ = fs::remove_dir_all(&state_dir);
    fs::create_dir_all(&state_dir).unwrap();
    let config_path = state_dir.join("config.yaml");
    fs::write(
        &config_path,
        "version: 3\nrelay_servers:\n  - relay.example.test:21117\nsecure_tcp:\n  mode: auto\n",
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .arg("--port")
        .arg(port.to_string())
        .arg(format!("--starry-config={}", config_path.display()))
        .env(
            "RUST_LOG",
            std::env::var("STARRY_TEST_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .env("STARRY_WEBRTC_SIGNAL", webrtc)
        .current_dir(&state_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    (ServerProcess { child, state_dir }, port)
}

#[test]
fn enabled_server_routes_offer_answer_and_trickle_ice_along_one_session() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            sodiumoxide::init().unwrap();
            let (server, port) = start_hbbs("Y", 31_001);
            wait_until_listening(SocketAddr::from(([127, 0, 0, 1], port))).await;
            let key = server.key().await;
            let device_id = "webrtc-device";
            let mut device = register_native_peer(port, device_id).await;

            // A plaintext TCP controller never gets its offer forwarded.
            let mut plain = plain_session(port).await;
            plain
                .send(&punch_with_offer(device_id, &key))
                .await
                .unwrap_or_default();
            let punch = expect_punch(&mut device).await;
            assert!(
                punch.webrtc_sdp_offer.is_empty(),
                "offer forwarded from plain TCP"
            );
            assert!(!punch.force_relay);
            drop(plain);

            // A Secure TCP controller does.
            let mut controller = SecureSession::connect(port).await;
            controller.send(&punch_with_offer(device_id, &key)).await;
            let punch = expect_punch(&mut device).await;
            assert_eq!(punch.webrtc_sdp_offer, OFFER);
            assert!(punch.force_relay);

            // The device answers over its own TCP connection.
            let mut device_tcp = plain_session(port).await;
            let mut sent = RendezvousMessage::new();
            sent.set_punch_hole_sent(PunchHoleSent {
                socket_addr: punch.socket_addr.clone(),
                id: device_id.to_owned(),
                webrtc_sdp_answer: ANSWER.to_owned(),
                ..Default::default()
            });
            device_tcp.send(&sent).await.unwrap();
            match controller.recv().await.union {
                Some(rendezvous_message::Union::PunchHoleResponse(response)) => {
                    assert_eq!(response.webrtc_sdp_answer, ANSWER);
                }
                other => panic!("expected PunchHoleResponse, got {other:?}"),
            }

            // Controller -> device candidate, on the connection that carried the offer.
            controller
                .send(&candidate_to_peer(device_id, "candidate-to-device"))
                .await;
            match recv_udp(&mut device, 3_000)
                .await
                .map(|message| message.union)
            {
                Some(Some(rendezvous_message::Union::IceCandidate(ice))) => {
                    assert_eq!(ice.candidate, "candidate-to-device");
                    assert_eq!(ice.session_key, SESSION);
                }
                other => panic!("device did not get the candidate: {other:?}"),
            }

            // Device -> controller candidate, on a fresh device connection (HBBS
            // closes the one that carried PunchHoleSent, as upstream does). The
            // response did not close the controller's route.
            let mut device_tcp = plain_session(port).await;
            let mut ice = RendezvousMessage::new();
            ice.set_ice_candidate(IceCandidate {
                socket_addr: punch.socket_addr.clone(),
                session_key: SESSION.to_owned(),
                candidate: "candidate-to-controller".to_owned(),
                ..Default::default()
            });
            device_tcp.send(&ice).await.unwrap();
            match controller.recv().await.union {
                Some(rendezvous_message::Union::IceCandidate(ice)) => {
                    assert_eq!(ice.candidate, "candidate-to-controller");
                    assert!(ice.socket_addr.is_empty() && ice.id.is_empty());
                }
                other => panic!("controller did not get the candidate: {other:?}"),
            }

            // A connection without a route cannot aim candidates at the device.
            let mut stranger = SecureSession::connect(port).await;
            stranger
                .send(&candidate_to_peer(device_id, "unrouted"))
                .await;
            assert!(
                recv_udp(&mut device, 500).await.is_none(),
                "an unrouted candidate reached the device"
            );

            // Once the controller disconnects, its route is gone too.
            drop(controller);
            sleep(Duration::from_millis(200)).await;
            device_tcp.send(&ice).await.unwrap();
            let mut second_device_tcp = plain_session(port).await;
            second_device_tcp.send(&ice).await.unwrap();
            assert!(recv_udp(&mut device, 300).await.is_none());
        });
}

#[test]
fn disabled_server_strips_offers_answers_and_refuses_candidates() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            sodiumoxide::init().unwrap();
            let (server, port) = start_hbbs("N", 45_001);
            wait_until_listening(SocketAddr::from(([127, 0, 0, 1], port))).await;
            let key = server.key().await;
            let device_id = "webrtc-disabled-device";
            let mut device = register_native_peer(port, device_id).await;

            let mut controller = SecureSession::connect(port).await;
            controller.send(&punch_with_offer(device_id, &key)).await;
            let punch = expect_punch(&mut device).await;
            assert!(punch.webrtc_sdp_offer.is_empty());
            assert!(!punch.force_relay);

            let mut device_tcp = plain_session(port).await;
            let mut sent = RendezvousMessage::new();
            sent.set_punch_hole_sent(PunchHoleSent {
                socket_addr: punch.socket_addr.clone(),
                id: device_id.to_owned(),
                webrtc_sdp_answer: ANSWER.to_owned(),
                ..Default::default()
            });
            device_tcp.send(&sent).await.unwrap();
            match controller.recv().await.union {
                Some(rendezvous_message::Union::PunchHoleResponse(response)) => {
                    assert!(response.webrtc_sdp_answer.is_empty());
                }
                other => panic!("expected PunchHoleResponse, got {other:?}"),
            }

            // Upstream behaviour: an unhandled message closes the connection.
            let mut candidate_sender = plain_session(port).await;
            candidate_sender
                .send(&candidate_to_peer(device_id, "ignored"))
                .await
                .unwrap();
            let closed = timeout(3_000, candidate_sender.framed.next()).await;
            assert!(matches!(closed, Ok(None) | Ok(Some(Err(_)))), "{closed:?}");
            assert!(recv_udp(&mut device, 300).await.is_none());
        });
}

fn punch_with_offer(id: &str, key: &str) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: key.to_owned(),
        webrtc_sdp_offer: OFFER.to_owned(),
        force_relay: true,
        ..Default::default()
    });
    message
}

fn candidate_to_peer(id: &str, candidate: &str) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_ice_candidate(IceCandidate {
        id: id.to_owned(),
        session_key: SESSION.to_owned(),
        candidate: candidate.to_owned(),
        ..Default::default()
    });
    message
}

async fn expect_punch(device: &mut FramedSocket) -> PunchHole {
    match recv_udp(device, 3_000).await.map(|message| message.union) {
        Some(Some(rendezvous_message::Union::PunchHole(punch))) => punch,
        other => panic!("device did not get PunchHole: {other:?}"),
    }
}

async fn recv_udp(socket: &mut FramedSocket, ms: u64) -> Option<RendezvousMessage> {
    let (bytes, _) = socket.next_timeout(ms).await?.ok()?;
    RendezvousMessage::parse_from_bytes(&bytes).ok()
}

struct PlainSession {
    framed: Framed<TcpStream, BytesCodec>,
}

impl PlainSession {
    async fn send(&mut self, message: &RendezvousMessage) -> Result<(), std::io::Error> {
        self.framed
            .send(Bytes::from(message.write_to_bytes().unwrap()))
            .await
    }
}

/// Native TCP that ignores the Secure TCP offer and talks plaintext.
async fn plain_session(port: u16) -> PlainSession {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut framed = Framed::new(stream, BytesCodec::new());
    let offer = framed.next().await.unwrap().unwrap();
    let offer = RendezvousMessage::parse_from_bytes(&offer).unwrap();
    assert!(matches!(
        offer.union,
        Some(rendezvous_message::Union::KeyExchange(_))
    ));
    PlainSession { framed }
}

struct SecureSession {
    framed: Framed<TcpStream, BytesCodec>,
    key: secretbox::Key,
    send_seq: u64,
    recv_seq: u64,
}

impl SecureSession {
    async fn connect(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut framed = Framed::new(stream, BytesCodec::new());
        let offer = framed.next().await.unwrap().unwrap();
        let offer = RendezvousMessage::parse_from_bytes(&offer).unwrap();
        let Some(rendezvous_message::Union::KeyExchange(exchange)) = offer.union else {
            panic!("server did not offer Secure TCP");
        };
        let signed = &exchange.keys[0];
        assert!(signed.len() >= sign::SIGNATUREBYTES + box_::PUBLICKEYBYTES);
        let mut server_public = [0_u8; box_::PUBLICKEYBYTES];
        server_public.copy_from_slice(&signed[signed.len() - box_::PUBLICKEYBYTES..]);
        let server_public = box_::PublicKey(server_public);
        let (client_public, client_secret) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(
            &key.0,
            &box_::Nonce([0_u8; box_::NONCEBYTES]),
            &server_public,
            &client_secret,
        );
        let mut response = RendezvousMessage::new();
        response.set_key_exchange(KeyExchange {
            keys: vec![client_public.0.to_vec().into(), sealed.into()],
            ..Default::default()
        });
        framed
            .send(Bytes::from(response.write_to_bytes().unwrap()))
            .await
            .unwrap();
        Self {
            framed,
            key,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    fn nonce(seq: u64) -> secretbox::Nonce {
        let mut nonce = secretbox::Nonce([0_u8; secretbox::NONCEBYTES]);
        nonce.0[..8].copy_from_slice(&seq.to_le_bytes());
        nonce
    }

    async fn send(&mut self, message: &RendezvousMessage) {
        self.send_seq += 1;
        let sealed = secretbox::seal(
            &message.write_to_bytes().unwrap(),
            &Self::nonce(self.send_seq),
            &self.key,
        );
        self.framed.send(Bytes::from(sealed)).await.unwrap();
    }

    async fn recv(&mut self) -> RendezvousMessage {
        let encrypted = timeout(3_000, self.framed.next())
            .await
            .expect("Secure TCP response timed out")
            .unwrap()
            .unwrap();
        self.recv_seq += 1;
        let plaintext = secretbox::open(&encrypted, &Self::nonce(self.recv_seq), &self.key)
            .expect("Secure TCP frame did not decrypt");
        RendezvousMessage::parse_from_bytes(&plaintext).unwrap()
    }
}

async fn register_native_peer(port: u16, id: &str) -> FramedSocket {
    // A different loopback address, so HBBS does not treat both ends as one
    // intranet and answer with FetchLocalAddr instead of PunchHole.
    let mut socket = FramedSocket::new("127.0.0.2:0").await.unwrap();
    let server = SocketAddr::from(([127, 0, 0, 1], port));
    let mut register_peer = RendezvousMessage::new();
    register_peer.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    socket.send(&register_peer, server).await.unwrap();
    socket.next_timeout(3_000).await.unwrap().unwrap();
    let mut register_pk = RendezvousMessage::new();
    register_pk.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: Bytes::from(vec![0x55; 16]),
        pk: Bytes::from(vec![0x55; 32]),
        ..Default::default()
    });
    socket.send(&register_pk, server).await.unwrap();
    let (bytes, _) = socket.next_timeout(3_000).await.unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::RegisterPkResponse(response))
            if response.result.enum_value().ok() == Some(register_pk_response::Result::OK)
    ));
    socket
}

fn reserve_hbbs_ports(first_port: u16) -> u16 {
    for port in (first_port..first_port + 14_000).step_by(7) {
        let Ok(nat) = StdTcpListener::bind(("127.0.0.1", port - 1)) else {
            continue;
        };
        let Ok(tcp) = StdTcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        let Ok(udp) = StdUdpSocket::bind(("127.0.0.1", port)) else {
            continue;
        };
        let Ok(websocket) = StdTcpListener::bind(("127.0.0.1", port + 2)) else {
            continue;
        };
        drop((websocket, udp, tcp, nat));
        return port;
    }
    panic!("no free HBBS port set");
}

async fn wait_until_listening(address: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("HBBS did not listen on {address}");
}
