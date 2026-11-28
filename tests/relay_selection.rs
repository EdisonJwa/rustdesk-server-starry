//! End-to-end gate for server-selected relays.
//!
//! A RustDesk client whose relay field is empty (the documented setup) relies on
//! hbbs telling it which relay to dial. This test runs a real hbbs next to a
//! real, reachable hbbr and asserts the controlled peer receives that address in
//! the forwarded RequestRelay.
//!
//! Regression this covers: the address used to be filled in only when
//! fast_relay was enabled. With the production default the peer was handed a
//! RequestRelay with no relay address, so the relay leg could never be dialled
//! and the controller failed with "deadline has elapsed" — while neither relay
//! logged anything, because nothing ever reached them.

use base64::{encode_config, URL_SAFE_NO_PAD};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::{
        register_pk_response, rendezvous_message, RegisterPeer, RegisterPk, RendezvousMessage,
        RequestRelay,
    },
    tokio::{
        net::TcpStream,
        runtime::Builder,
        time::{sleep, Duration},
    },
    tokio_util::codec::Framed,
    udp::FramedSocket,
};
use serde_json::json;
use sodiumoxide::crypto::sign;
use std::{
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
};

static GATE_LOCK: Mutex<()> = Mutex::new(());

struct Guard {
    children: Vec<Child>,
    directory: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn reserve_hbbs_ports() -> u16 {
    for port in 30_001..60_000u16 {
        let Ok(nat) = StdTcpListener::bind(("127.0.0.1", port - 1)) else {
            continue;
        };
        let Ok(tcp) = StdTcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        let Ok(websocket) = StdTcpListener::bind(("127.0.0.1", port + 2)) else {
            continue;
        };
        drop(websocket);
        drop(tcp);
        drop(nat);
        return port;
    }
    panic!("no free HBBS port set");
}

/// hbbs binds port-1 (NAT), port, and port+2 (websocket), so the relay must
/// stay clear of that triple or the two processes fight over one socket.
fn reserve_relay_port(hbbs_port: u16) -> u16 {
    let taken = [hbbs_port - 1, hbbs_port, hbbs_port + 1, hbbs_port + 2];
    for port in 30_001..60_000u16 {
        if taken.contains(&port) {
            continue;
        }
        let Ok(listener) = StdTcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        drop(listener);
        return port;
    }
    panic!("no free relay port");
}

#[test]
fn a_blank_client_relay_is_filled_with_a_reachable_server_choice() {
    let _guard = GATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    sodiumoxide::init().unwrap();
    let hbbs_port = reserve_hbbs_ports();
    let relay_port = reserve_relay_port(hbbs_port);
    let directory = std::env::temp_dir().join(format!(
        "starry-relay-choice-{}-{hbbs_port}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();

    // A real hbbr, so the server's reachability probe marks it online and there
    // is an address it can legitimately hand out.
    let relay = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .arg("--port")
        .arg(relay_port.to_string())
        .env("RUST_LOG", "warn")
        .current_dir(&directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let (public, _secret) = sign::gen_keypair();
    fs::create_dir_all(directory.join("auth")).unwrap();
    fs::write(
        directory.join("auth/jwks.json"),
        serde_json::to_vec(&json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
                "kid": "relay-choice-key",
                "x": encode_config(public.0, URL_SAFE_NO_PAD)
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let config_path = directory.join("config.yaml");
    fs::write(
        &config_path,
        format!(
            "version: 3\n\
             relay_servers:\n  - 127.0.0.1:{relay_port}\n\
             secure_tcp:\n  mode: auto\n\
             websocket_signal:\n  enabled: true\n  relay_health:\n    endpoints:\n      - relay: 127.0.0.1:{relay_port}\n        url: wss://localhost:9/ws/relay\n\
             connection_auth:\n  mode: audit\n  issuer: https://api.example.test\n  audience: rustdesk-connect\n  token_use: access\n  required_scope: connect:initiate\n  jwks:\n    file: auth/jwks.json\n"
        ),
    )
    .unwrap();

    // Give the relay a moment to bind before hbbs probes it.
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", relay_port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let hbbs = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .arg("--port")
        .arg(hbbs_port.to_string())
        .arg(format!("--starry-config={}", config_path.display()))
        .env("RUST_LOG", "warn")
        .current_dir(&directory)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _guard = Guard {
        children: vec![relay, hbbs],
        directory,
    };

    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // The relay comes up first so hbbs's very first reachability probe
            // sees it listening.
            wait_until_listening(SocketAddr::from(([127, 0, 0, 1], relay_port))).await;
            wait_until_listening(SocketAddr::from(([127, 0, 0, 1], hbbs_port))).await;
            // hbbs probes relays on its 3 s timer; wait for a probe to land
            // before asking it to choose one.
            sleep(Duration::from_millis(4_000)).await;

            let target_id = "relay-choice-target";
            let mut target = register_peer(hbbs_port, target_id).await;

            // A controller that left its relay field empty, like the documented
            // client setup that ships with an empty relay.
            let stream = TcpStream::connect(("127.0.0.1", hbbs_port)).await.unwrap();
            let mut framed = Framed::new(stream, BytesCodec::new());
            let greeting = framed.next().await.unwrap().unwrap();
            let greeting = RendezvousMessage::parse_from_bytes(&greeting).unwrap();
            assert!(matches!(
                greeting.union,
                Some(rendezvous_message::Union::KeyExchange(_))
            ));
            let mut request = RendezvousMessage::new();
            request.set_request_relay(RequestRelay {
                id: target_id.to_owned(),
                uuid: "relay-choice-probe".to_owned(),
                ..Default::default()
            });
            framed
                .send(Bytes::from(request.write_to_bytes().unwrap()))
                .await
                .unwrap();

            let forwarded = target
                .next_timeout(5_000)
                .await
                .expect("the controlled peer never received the RequestRelay")
                .unwrap();
            let (payload, _) = forwarded;
            let forwarded = RendezvousMessage::parse_from_bytes(&payload).unwrap();
            let Some(rendezvous_message::Union::RequestRelay(relay)) = forwarded.union else {
                panic!("the controlled peer did not receive a RequestRelay");
            };
            assert!(
                !relay.relay_server.is_empty(),
                "a blank client relay must be replaced by the server's choice, got empty"
            );
            assert_eq!(
                relay.relay_server,
                format!("127.0.0.1:{relay_port}"),
                "the server must hand out the relay it actually verified as reachable"
            );
            assert_eq!(relay.uuid, "relay-choice-probe");
        });
}

async fn wait_until_listening(address: SocketAddr) {
    for _ in 0..300 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing listened on {address}");
}

async fn register_peer(port: u16, id: &str) -> FramedSocket {
    let mut socket = FramedSocket::new("0.0.0.0:0").await.unwrap();
    let server = SocketAddr::from(([127, 0, 0, 1], port));
    let mut register_peer = RendezvousMessage::new();
    register_peer.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    socket.send(&register_peer, server).await.unwrap();
    let (payload, _) = socket.next_timeout(3_000).await.unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&payload).unwrap();
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::RegisterPeerResponse(response)) if response.request_pk
    ));

    let mut register_pk = RendezvousMessage::new();
    register_pk.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: Bytes::from(vec![0x55; 16]),
        pk: Bytes::from(vec![0x55; 32]),
        ..Default::default()
    });
    socket.send(&register_pk, server).await.unwrap();
    let (payload, _) = socket.next_timeout(3_000).await.unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&payload).unwrap();
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::RegisterPkResponse(response))
            if response.result.enum_value().ok() == Some(register_pk_response::Result::OK)
    ));
    socket
}
