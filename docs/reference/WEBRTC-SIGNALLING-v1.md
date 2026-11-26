# WebRTC signalling v1

**English** | [简体中文](WEBRTC-SIGNALLING-v1.zh-CN.md)

RustDesk 1.5 clients can open a WebRTC connection between controller and
device. HBBS does not carry the media; it only relays the signalling: an SDP
offer, an SDP answer, and trickle ICE candidates. Starry implements this relay
as an opt-in, bounded feature.

The official rustdesk-server does not relay these messages. With the feature
off (the default), Starry behaves exactly like it: offers and answers are
stripped and an `IceCandidate` closes the connection, so clients fall back to
the ordinary punch-hole/Relay path.

## Enabling

| Setting | Value |
| --- | --- |
| `hbbs --webrtc-signal=Y` | Enable for this process. |
| `STARRY_WEBRTC_SIGNAL=Y` | Same, from the environment or `.env`. |

The command-line flag takes precedence. The startup log prints
`WebRTC signalling: enabled` or `disabled`.

The feature is not yet part of the Starry configuration schema (v5), so the
Control API cannot change it; a later schema version will add it.

## Message flow

| Step | Message | Path |
| --- | --- | --- |
| 1 | `PunchHoleRequest.webrtc_sdp_offer` | Controller → HBBS on its signalling connection. |
| 2 | `PunchHole.webrtc_sdp_offer` (+ `force_relay`) | HBBS → device, over UDP or the device's WebSocket session. |
| 3 | `PunchHoleSent.webrtc_sdp_answer` or `RelayResponse.webrtc_sdp_answer` | Device → HBBS on a device TCP/WebSocket connection. |
| 4 | `PunchHoleResponse.webrtc_sdp_answer` or `RelayResponse.webrtc_sdp_answer` | HBBS → controller. |
| 5 | `IceCandidate` with `id` | Controller → HBBS on the connection that carried the offer; forwarded to that device. |
| 6 | `IceCandidate` with `socket_addr` | Device → HBBS, addressed by `PunchHole.socket_addr`; forwarded to that controller. |

Forwarded candidates carry only `session_key` and `candidate`.

## Routes

When HBBS forwards an admitted offer in step 2 it opens a **route** keyed by
the controller's signalling connection. The route:

- keeps that connection open after the answer, so candidates can reach it;
- allows candidates from that connection only to the device it punched;
- allows candidates to that controller only while it exists;
- ends when the controller disconnects or 60 seconds after the latest offer.

A punch retry to the same device renews the route without resetting its
candidate budgets; an offer to another device replaces it.

## Admission and bounds

An offer is forwarded only if every condition holds:

- the feature is enabled;
- it arrived over **Secure TCP or WebSocket**. The SDP carries the DTLS
  fingerprints that bind the WebRTC channel to the peer identity, and a
  plaintext TCP hop could swap them;
- `ALWAYS_USE_RELAY` is off, because a WebRTC pair may connect directly;
- the controller passed the normal checks (key, connection authentication,
  device online) and HBBS sends a `PunchHole` rather than `FetchLocalAddr`;
- a route slot is available.

| Limit | Value |
| --- | --- |
| Offer or answer size | 8 KiB |
| Candidate line | 2 KiB |
| Session key | 256 bytes |
| Routes in total | 4,096 |
| Routes per controller IP | 64 |
| Candidates per route and direction | 64 |
| Route lifetime after the latest offer | 60 s |

The per-IP limit uses the controller's effective IP (from a trusted WebSocket
proxy where configured), so clients behind one reverse proxy do not share it.
An answer is forwarded only to a controller with a live route. Candidates
outside a route, over budget, or malformed are dropped; a malformed candidate
also closes the sending connection.

## Security notes

- A device or any host that learns a controller's signalling address can send
  up to 64 candidates to it during the route's lifetime. Candidates alone do
  not let anyone join the session: the DTLS fingerprints in the signed offer
  and answer still have to match.
- Answers follow the same trust model as `PunchHoleSent` today: HBBS cannot
  tell which device sent a `PunchHoleSent`, only which controller it is for.
- No SDP, candidate, or key is logged.

## Compatibility

Older clients never set these fields, so nothing changes for them. A 1.5
client that gets no answer falls back to the normal connection path. The
vendored `hbb_common` (see `libs/hbb_common.VENDORED`) carries the 1.5
protocol fields; Starry's own protobuf extensions use tags 60+ and 100+ and do
not collide with them.

The design follows the independent implementations in
[bropines/rustdesk-server](https://github.com/bropines/rustdesk-server) and
[CortenDesk Server](https://github.com/marcpope/cortendesk-server); the code is
Starry's own.
