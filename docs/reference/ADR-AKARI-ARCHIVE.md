# ADR: archiving the Akari extensions (FND-03)

Status: analysis complete, extraction not started
English | [简体中文](ADR-AKARI-ARCHIVE.zh-CN.md)

## Decision to be recorded

Whether, and in what order, to remove the client-extension protocol paths
(`relay_quality` active probing, `fast_relay` grants, `fast_media_relay` UDP data
plane, `profile_activation` leases) from the main line, while keeping the generic
server mechanisms they currently share code with.

This document is the dependency inventory FND-04 needs before anyone deletes a
module. It is read-only analysis against `d9ede12`; nothing has been archived or
removed.

## Why the question needs an inventory at all

The roadmap itself gives the reason: the extension modules are not leaves. Four
of the couplings are load-bearing for features that work without any extension
client:

| Coupling | Where | Why deleting the module breaks it |
| --- | --- | --- |
| Telemetry freshness | `relay_observer.rs:320-325`, `relay_health.rs:986-989`, `relay_health.rs:879` | `max_telemetry_age_seconds` lives in `RelayQualityConfig`. Relay health staleness and `relay_observer::snapshot()` read it. Removing `relay_quality` removes the staleness bound the generic relay pool uses. |
| Telemetry schema | `relay_server.rs:69` | `STARRY_RELAY_TELEMETRY_SCHEMA` is *defined as* `fast_media_relay::TELEMETRY_SCHEMA_VERSION`. HBBR's authenticated telemetry version would vanish with the UDP data plane. |
| Observer snapshot | `relay_observer.rs:127-129, 659-661` | The snapshot struct embeds `relay_quality`, `fast_relay` and `profile_activation` runtime snapshots, which `control_agent` and `/healthz` consume. |
| Relay selection | `rendezvous_server.rs:1310` | `server_selects_relay(.., fast_relay::enabled())` decides whether a client-supplied relay is overridden. The blank-relay half is generic and must stay; only the fast_relay override half is extension-specific. |

## What stock clients actually exercise

Each extension is configuration-gated and returns a "legacy" answer when off, so
an unmodified RustDesk client never enters the extension paths:

| Module | Lines | Gate | Stock-client behaviour |
| --- | --- | --- | --- |
| `relay_quality` | 2630 | `config.relay_quality.enabled`, **default false** (`starry_config.rs:349`) | `select_for_request` returns `RequestResolution::Legacy` |
| `fast_relay` | 806 | `fast_compat_enabled \|\| fast_media_v1_enabled`, **both default false** | `enabled()` false; no grant is signed or attached |
| `fast_media_relay` | 1497 | `Config::from_env` requires `STARRY_RELAY_FAST_MEDIA_UDP_PORT` **and** a public endpoint | `spawn()` returns immediately; no UDP listener |
| `profile_activation` | 1343 | Not gated, but an unmodified client sends empty `activation_id`/`activation_epoch` | `begin_registration` yields an untracked claim; registration proceeds as before |

`profile_activation` is the one that runs unconditionally, which is why it has 29
call sites. The inventory below shows it is a strict superset of the stock
registration path rather than a replacement for it.

## Production reality

The live deployment (`149.104.1.168`, `starry-hbbr` on `175.178.125.23`) has none
of these enabled:

- `relay_quality.enabled` absent from `config.yaml` (defaults false)
- `fast_mode` absent (both flags default false)
- No `STARRY_RELAY_FAST_MEDIA_*` in either systemd unit
- `relays` local-control output reports `fast_relay.disabled = 1`

So archiving would not change behaviour on the running servers. The argument for
doing it is maintenance surface, not user-visible change — and the argument
against doing it hastily is the four couplings above.

## Coupling inventory

### `relay_quality` — 2630 lines, 23 call sites in `rendezvous_server`

Two distinct halves:

- **Extension protocol** (archive): `RelayProbeRequest`/`Response`,
  `RelayQualityOffer`/`Decision`/`Cancel`, stage reports, `select_for_request`
  allocation state, probe scheduling, `create_offer`, `response_context`.
- **Reusable algorithm** (extract): score normalisation, hysteresis, TTL-bounded
  caches, capacity bounds, `max_telemetry_age_seconds` as a *generic* telemetry
  knob.

The extraction target is a `telemetry` module owning freshness policy, so
`relay_observer` and `relay_health` stop reaching into `RelayQualityConfig`.

### `fast_relay` — 806 lines, 6 call sites

- **Extension protocol** (archive): `authorization_for_request`,
  `authorization_for_response`, `selected_relay_for_response`, grant signing.
- **Generic** (keep): `server_selects_relay`'s blank-client-relay behaviour.
  `fast_relay::enabled()` is currently also passed as the "server overrides a
  client-supplied relay" flag; that flag must survive as an independent
  configuration bit if the module goes, or relay selection changes for
  deployments that never enabled fast_relay.

### `fast_media_relay` — 1497 lines, 4 call sites in `relay_server`

- **Extension data plane** (archive): AKR1 UDP listener, grants, binds, replay
  limits, rate limits.
- **Generic** (keep): the telemetry schema version. Move
  `TELEMETRY_SCHEMA_VERSION` into the telemetry module rather than deriving
  HBBR's schema from the UDP module.

### `profile_activation` — 1343 lines, 29 call sites

The roadmap says `ARCHIVE + EXTRACT`, and the call sites confirm why: it sits on
`RegisterPeer`, `RegisterPk`, `DeactivatePeer`, WebSocket routing, and the TCP
heartbeat — all stock paths.

- **Private protocol** (archive): `activation_epoch`/`activation_id`/`route_lease`
  handling, ready-ACK accounting, lease renewal, `next_route_generation`.
- **Generic security semantics to keep**: registration burst limiting
  (`BURST_LIMIT`/`BURST_WINDOW`), per-peer route generation, route-change
  rejection, stale-route cleanup on disconnect.

This is the largest and riskiest item. Removing it means re-implementing the
generic subset inside the registration path, with the existing e2e suite
(`tests/connection_auth_transport.rs`, `tests/websocket_signal.rs`) as the
regression gate.

### Protobuf surface

Private tags live at 100+ and 60+, distinct from upstream's ≤29:

| Message | Extension fields |
| --- | --- |
| `PunchHoleRequest` | `relay_quality_protocol = 100` |
| `PunchHole` / `PunchHoleSent` | `relay_quality_offer = 100` |
| `RequestRelay` | `relay_quality_report = 100`, `relay_quality_decision = 101`, `relay_quality_allocation_id = 102`, `fast_relay_authorization = 64` |
| `RelayResponse` | `relay_quality_offer = 100`, `relay_quality_peer_report = 101`, `relay_quality_decision = 102` |
| `RendezvousMessage` | `relay_quality_stage_{report,offer,decision}` = 102/103/104, `relay_quality_cancel = 105`, `deactivate_peer{,_response}` = 62/63 |
| `RegisterPeer` (tail) | `route_generation = 60`, `activation_epoch = 61`, `route_lease = 62`, `activation_id = 63` |
| `RegisterPk` (tail) | `activation_epoch = 61`, `activation_id = 63` |
| `DeactivatePeer` | `activation_epoch = 3`, `activation_id = 4`, `route_lease = 5`, `route_generation = 6` |

Note the `DeactivatePeer` fields are 3–6, low numbers inside a message upstream
does not define, not high tags. Upstream's own highest tag in the shared messages
is 29, so 60+ and 100+ are free — but the `DeactivatePeer` message itself is the
extension, so archiving it means the whole message becomes inert, not just some
fields.

Per the roadmap: do not renumber, and do not reuse a tag that a deployed client
might still send. Archiving means the server stops *acting* on them, not that the
wire numbers become available.

## Recommended sequencing

The roadmap's own order (FND-03 → FND-04 → FND-05) is correct, but the risk is
concentrated in `profile_activation`, so the extraction should be staged so that
the safe work lands first and the risky work lands behind a regression gate:

1. **Extract the telemetry policy** out of `RelayQualityConfig` into its own
   module. Pure refactor, no wire change; `relay_observer` and `relay_health`
   stop depending on an archived module. Verify with the existing relay tests.
2. **Decouple the telemetry schema constant** from `fast_media_relay`.
3. **Split `server_selects_relay`'s two reasons**: blank client value (generic)
   vs fast_relay override (extension). Behaviour must stay identical; the
   `tests/relay_selection.rs` gate already covers the generic half.
4. **Archive the wire protocol** for `relay_quality` and `fast_relay` behind a
   config switch defaulting to off, keeping the algorithms.
5. **Archive `fast_media_relay`** once nothing derives from it.
6. **`profile_activation` last**, as its own PR: extract the generic subset into
   the registration path, prove it with the full transport e2e suite, then remove
   the lease protocol.

Steps 1–3 are refactors that change no behaviour and can be reviewed by
inspection. Steps 4–6 remove code and need the e2e evidence the roadmap demands
for FND-05.

## What this document does not decide

- Whether to archive at all. That is a product decision; this only records what
  it would cost.
- The archive ref name and whether history is tagged. The roadmap leaves the name
  to the maintainer.
- Any production change. Nothing here has been deployed or is scheduled to be.

## Verification notes for whoever executes this

Two traps found while taking this inventory, both already recorded in the tests:

- A relay pool with a single entry was never health-probed (`7290f29`), so relay
  behaviour must be verified with the real `tests/relay_selection.rs` harness, not
  by inspection.
- The audit writer is a process-wide `OnceLock`; whichever test emits first fixes
  the output directory. Audit assertions cannot span two tests in one binary.
