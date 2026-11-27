# Changelog

**English** | [简体中文](CHANGELOG.zh-CN.md)

This file records Starry overlay changes. The full artifact version combines
the official RustDesk Server version with the Starry patch version, for example
`1.1.16-patch-v1.3.1`.

## Unreleased — standalone server, upstream 1.1.17, WebRTC

### Changed

- **Starry is now its own server source tree.** The overlay patcher
  (`scripts/apply_overlay.py`, 6,700 lines) is retired; `src/`, `tests/`,
  `Cargo.toml`/`Cargo.lock` and `libs/hbb_common/` are tracked directly. CI
  builds exactly `git archive HEAD`.
- `UPSTREAM` records the last reviewed rustdesk-server commit (`680b603`,
  Cargo version 1.1.17, untagged). Upstream fixes are ported by hand; CI only
  reports when upstream master moves ahead.
- `libs/hbb_common` is vendored from rustdesk/hbb_common `bb416bc` (the
  RustDesk 1.5 client protocol: `IceCandidate`, `webrtc_sdp_*`, KeyExchange v2
  fields). Starry's edits are exactly `libs/hbb_common.starry.patch`, and CI
  reproduces the vendored tree from the recorded commit plus that patch.
  `IdPk` moved into `rendezvous.proto` upstream with an identical wire format.
- WebSocket support uses upstream's `rustdesk-org` tokio-tungstenite and
  tungstenite 0.29 forks.
- Starry settings read from `.env`/`-c` files honour upstream's argument
  aliases (`STARRY_FOO` and `STARRY-FOO`) through `common::env_var`.
- Contract checks now require every contract-defined protobuf message to
  appear verbatim in the vendored `rendezvous.proto`.

### Added

- `starry-client-config`: generates the client-side configuration (ID server,
  relay server, public key, strategy group annotation) straight from the
  server's key material as text, JSON, or a base64 import string. Reads only
  `id_ed25519.pub`; never mints tokens.
- Strategy engine v1: a versioned device-group policy document
  (`STARRY_STRATEGY_FILE`) with per-group connection JWT scope overrides and
  group deny verdicts, enforced inside HBBS before any signalling work and
  recorded in the audit log with the group attached. Reloadable at runtime
  through local control (`strategy.status` / `strategy.reload`). Server-side
  enforcement only — client settings sync remains an API-layer concern. See
  [Strategy v1](../reference/STRATEGY-v1.md).
- Connection audit log: HBBS records every connection-authentication decision
  as append-only JSONL evidence (kind, transport, verdict, reason, client
  address, mode) behind `STARRY_AUDIT_DIR`. Default off; day rotation, retention
  pruning, and a per-day size cap bound the storage; the signalling path never
  blocks on logging. The bundled `starry-audit-export` tool converts day files
  to RFC 4180 CSV with inclusive UTC date filtering. See
  [Connection audit log](../reference/AUDIT-LOG.md).
- `starry-relay-entrypoint` and HBBR expose an opt-in, loopback-only operations
  endpoint (`STARRY_RELAY_OPS_LISTEN`, off by default) serving `/healthz` and
  Prometheus `/metrics` with the same numbers authenticated telemetry reports.
- Opt-in RustDesk 1.5 WebRTC signalling (`--webrtc-signal=Y` or
  `STARRY_WEBRTC_SIGNAL=Y`, default off): SDP offer/answer and trickle ICE
  along bounded per-connection routes, offers only from Secure TCP or
  WebSocket. See [WebRTC signalling](../reference/WEBRTC-SIGNALLING-v1.md).
- `starry-api`: a RustDesk-compatible API server (port 21114) with SQLite
  accounts (bcrypt), the contract the official 1.5 client parses
  (`/api/login-options`, `/api/login`, `/api/currentUser`, `/api/logout`), and
  Ed25519 connection tokens that clients replay verbatim as the rendezvous
  credential. Publishes the JWKS HBBS verifies
  (`connection_auth.jwks.file`) together with a digest-bound freshness stamp
  renewed on a heartbeat; `starry-api user add|passwd|enable|disable|list`
  manages accounts, with passwords accepted only from stdin or the environment.
  See [Auth server v1](../reference/AUTH-SERVER-v1.md).

### Kept from upstream 1.1.17 inside Starry's rewritten paths

- HBBR: 128 KiB bound on the opening relay request, lifted after pairing;
  30 s bounded WebSocket handshake with 64 KiB buffers; forwarded-IP port
  preservation; upstream's generation-guarded waiter expiry
  (`WaitingPeer`/`expire_waiter`); 30 s deadlines on stalled relay writes.
- HBBS: `validate_relay_uuid`/`validate_relay_response` before every Starry
  relay step; `MAX_PEER_ID_LEN` on RegisterPeer and RegisterPk (Starry's
  `process_register_pk` had lost it); the bounded `record_punch_req` log
  (Starry's punch-hole handler still used the old unbounded push);
  `MAX_MESSAGE_KB` caps Secure TCP and `/ws/id` frames; `/ws/id` upgrades
  finish within 30 s and use 8 KiB buffers.

### Fixed

- Geo rules and WebSocket Signal were not initialised at startup without a
  Starry config when `RUST_LOG` was above `info`: the calls sat inside
  `log::info!` arguments, which are skipped at that level.
- A JWKS published as a local file was stamped only once at startup, so HBBS in
  `enforce` mode reported `key_stale` for every connection after
  `max_stale_seconds` (one hour by default) while the issuer was healthy. HBBS
  now re-reads the file on its refresh interval and adopts the issuer's stamp,
  and a keyset that does not parse never replaces a working one.

### Security

- The lockfile updates axum 0.5.17, openssl 0.10.82, quick-xml 0.41 (via
  wayland-scanner), anyhow, bumpalo, rand 0.8.8, crossbeam and ahash within
  semver, and replaces hbb_common's unmaintained, unsound `users` 0.11 with the
  API-compatible `uzers` fork (RUSTSEC-2023-0040, -2023-0059, -2025-0040).
  `cargo audit --deny unsound --deny yanked` passes.

### Removed

- Building on top of an upstream checkout, and support for upstream 1.1.16.

## patch-v1.3.1 — preview

Release notes: [`RELEASE-NOTES-patch-v1.3.1.md`](RELEASE-NOTES-patch-v1.3.1.md)

### Added

- Role-bound FastRelayAuthorization fields 7–12 and independent default-off
  schema-v5 FastCompat/FastMediaV1 policy.
- HBBR AKR1 UDP cookie/bind/forward/rebind data plane with bounded grants,
  lifetimes, replay, traffic, cleanup, and authenticated telemetry schema 2.
- Server-selected FastCompat/FastMedia grants for quality decisions and safe
  ordinary GEO/failover fallback; clients never select the signed Relay.
- Starry Pairing v1, Control Agent pair/adopt/rotate, bounded Relay enrollment,
  and the separate `starry-relayctl` utility.
- Explicit persistent container/native/DEB identity layouts and a no-side-
  effect schema-v5 to schema-v4 downgrade preview/export with drain and
  90-day certificate-window gates.

### Fixed

- Permit only a legitimate native initial `PunchHoleSent`/`LocalAddr` target
  source-port change under the complete frozen Relay Quality binding; exact
  top-level report/controller-route and conflicting-duplicate checks remain.
- Drain the Control Agent cleanly on termination instead of leaving a
  diagnostic container with an ambiguous forced-stop status.
- Keep generated HBBR test signing keys out of child-process arguments.
- Replace the yanked locked `chacha20 0.10.1` with non-yanked `0.10.2`, and
  make CI reject yanked dependencies as well as vulnerabilities and unsound
  advisories.

### Compatibility and status

- Relay Quality v1 protobuf, digest, scoring, telemetry, hysteresis, privacy,
  and fallback semantics are unchanged.
- Official clients, six-field FastCompat grants, manual Agent/Relay setup, and
  ordinary Native/WSS Relay remain compatible. All new switches default off.
- The protocol-level Akari harness now proves dual-role forwarding, reliable
  fallback, and same-session automatic re-entry against the candidate HBBR.
  The default-off preview is approved; stable publication still requires the
  real two-client GUI/signalling, device/NAT/fault, and production PKI gates.

## patch-v1.3.0 — development

Release notes: [`RELEASE-NOTES-patch-v1.3.0.md`](RELEASE-NOTES-patch-v1.3.0.md)

### Added

- Private additive protobuf v1 fields for Akari Relay-quality capability
  negotiation, candidate offers, dual-end reports, scores, and decisions. All
  quality additions use tags 100+; the ordinary `relay_server` remains
  authoritative for official clients.
- Bounded TCP/WSS HBBR active-probe responses with echoed nonces, exact Starry
  version, active sessions, capacity, current bandwidth, and load basis points.
- Explicit HBBR `relay_probe_protocol=1` / `relay_load_protocol=1` capability
  negotiation, freshness-bounded telemetry, bounded-concurrent HBBS health
  probes, and legacy fallback nodes that never consume quality-candidate slots.
- HBBS selection using effective dual-end RTT, jitter, loss, trusted Relay
  load, missing-report penalties, symmetric network-prefix cache, and
  configurable hysteresis.
- Schema v4 `relay_quality` settings and Control API v1 inventory telemetry for
  Kessoku, without creating a client-to-Control-Agent path.
- A server-enforced allocation report deadline independent of cleanup TTL,
  feasibility validation for ordered samples, stable decision reason codes,
  and aggregate accepted/late/invalid/binding-mismatch counters.
- Default-off schema v4 `fast_mode` policy and additive tag 64 authorization
  bytes in `RequestRelay`/`RelayResponse`. HBBS signs `FastCompat` only after
  exact auth allow and final quality selection, binds/cache-limits the grant,
  and sends identical bytes to both Akari endpoints.
- Control capability `fast_relay_authorization: 1` and bounded `/relays`
  issuance, reuse, delivery, and fail-closed counters. patch-v1.3.0 always
  signs `allow_fast_media_v1 = false` and adds no Relay UDP media path.
- Profile Activation Lease v1 for Akari: 16-byte client activation IDs,
  matching Ready ACKs, 32-byte node-local route leases, and one shared route
  generation authority across Native UDP/TCP and WSS.
- Exact-current `DeactivatePeer`, generation-safe disconnect cleanup, a
  45-second crash-fallback TTL, and a 12-per-30-second verified rapid
  re-registration burst keyed by peer ID, network identity UUID, and public
  key. HBBR data messages remain unchanged.
- Control capability `profile_activation_lease: 1`, aggregate `/relays`
  lifecycle/rejection counters, and exact current-lease `/peers:verify` support
  for per-instance Kessoku reconciliation.

### Compatibility

- Schema v1-v3 remain accepted. Relay quality is disabled unless a schema v4
  configuration enables it and the initiating client opts into protocol v1.
- Official clients continue to receive one legacy `relay_server`; official
  Relay forwarding semantics and ports are unchanged. Unknown tag 64 is
  ignored, while HBBS clears any client-supplied authorization bytes.
- Official/legacy HBBR can be named in `legacy_fallback_relays` for ordinary
  fallback, but missing explicit capability or fresh load always excludes them
  from quality offers. Fewer than two compatible candidates disables the offer
  and preserves the full traditional Geo/failover path.
- Akari force-Relay mode performs the same quality-capable PunchHole preflight
  before `RequestRelay`; a direct RequestRelay without an offer retains the
  legacy selection path.
- FastCompat remains disabled unless schema v4 explicitly enables it together
  with Relay quality, connection authentication, and secure signalling. Any
  missing prerequisite falls back to the standard Relay flow without a grant.
- Official registration messages omit Profile activation fields and retain
  their current path. Akari commits a Profile only after a successful ACK
  echoes its exact activation ID/epoch and supplies a valid lease/generation;
  older servers therefore fail closed to the previous committed Profile.

## patch-v1.2.2 — 2026-08-29

Release notes: [`RELEASE-NOTES-patch-v1.2.2.md`](RELEASE-NOTES-patch-v1.2.2.md)

### Added

- A private, read-only Control API endpoint that verifies an exact RustDesk
  ID/machine-UUID pair against the HBBS registry without exposing peer data.
- Scoped service-only authorization for Kessoku background device discovery.

## patch-v1.2.1 — 2026-08-28

Release notes: [`RELEASE-NOTES-patch-v1.2.1.md`](RELEASE-NOTES-patch-v1.2.1.md)

### Added

- Relay version reporting from the HBBR WebSocket handshake through HBBS
  health observation to the Control API v1 Relay inventory.

## patch-v1.2.0 — 2026-08-20

Release notes: [`RELEASE-NOTES-patch-v1.2.0.md`](RELEASE-NOTES-patch-v1.2.0.md)

### Added

- Schema v3 and strict Ed25519 connection-JWT verification for controller
  `PunchHoleRequest` and direct `RequestRelay` across native TCP, Secure TCP,
  and WSS, with `off`, `audit`, and `enforce` modes.
- Atomic last-known-good JWKS refresh, bounded token/introspection caches,
  mandatory exclusive-CA mTLS for configured remote JWKS and introspection,
  and fail-closed stale/error/subject handling.
- Immutable Relay runtime snapshots and side-effect-free allocation simulation
  with structured decision traces.
- A framed, bounded, loopback-only local control protocol.
- Optional Linux `starry-control-agent` with mandatory mTLS, URI-SAN allowlist,
  short-lived scoped service JWTs, fixed Control API v1, and a safe read-only
  default profile.
- Optimistic, idempotent configuration plan/apply/rollback operations with
  exact-byte ETags, durable audit records, revision history, atomic writes,
  runtime activation acknowledgements, and recovery blocking on uncertainty.
- Versioned OpenAPI 3.1, JSON/UI Schema, JWT/protocol fixtures, Control Agent
  Compose/systemd/DEB assets, and security-focused integration tests.

### Fixed

- Advance `health_snapshot_id` when Relay probe data or readiness changes, so
  Relay inventory and a corresponding allocation simulation identify the
  actual health snapshot rather than only the health-configuration generation.
- Limit the remote JWKS/introspection mTLS HTTP pool idle lifetime to 15
  seconds, preventing reuse of keep-alive connections already closed by
  Kessoku's shorter server idle timeout while preserving last-known-good and
  fail-closed behavior.

### Dependency and build integrity

- The reviewed Cargo graph is locked and copied into the patched upstream tree
  before any locked metadata, test, or release build runs. Upstream and
  `hbb_common` source commits are recorded with candidate inputs.
- Replaced the obsolete SQLx/deadpool SQLite path with bundled
  `tokio-rusqlite`, removed the unpinned Git `reqwest` input, and modernized the
  TLS, WebSocket, JWT, protobuf, and CLI dependency paths.
- The fixed RustSec audit reports no vulnerability, unsound, or yanked crate.
  One upstream-core `sodiumoxide 0.2.7` unmaintained warning remains disclosed
  for explicit release risk review.
- Candidate CI fixes Rust, cross, cross images, advisory data, scanners, base
  images, and every Action to immutable reviewed inputs; Debian packages are
  built twice and compared byte for byte before publication can be approved.

### Compatibility and safety

- Schema v1 and v2 remain accepted; connection authentication is off unless a
  schema v3 document enables it or the deployment `--must-login` floor requires
  enforce mode.
- Invalid reloads retain the active last-known-good generation instead of
  clearing Starry runtime state.
- Authentication uses existing RustDesk protobuf fields; no `.proto` file is
  changed. UDP connection initiation remains unsupported and cannot allocate.
- Native controlled-endpoint registration/heartbeats still use UDP with
  official 1.1.16; TCP/Secure TCP coverage applies to controller initiation.
  A controlled endpoint that must disable UDP needs WSS registration and must
  not treat the upstream TCP `NOT_SUPPORT` response as authentication
  regression or TCP-only registration support.
- HBBR and account/API responsibilities remain unchanged. The Control Agent is
  a separate management component, not an account API or an HBBR proxy.
- Writable Control Agent transactions are supported and release-tested on
  Linux only for patch-v1.2.0; no Windows Agent artifact is published.

## patch-v1.1.0

Release notes: [`RELEASE-NOTES-patch-v1.1.0.md`](RELEASE-NOTES-patch-v1.1.0.md)

### Added

- Optional persistent `/ws/id` signalling compatible with RustDesk client
  identity registration.
- WSS-to-WSS and WSS-to-native signalling with explicit Relay-only routing
  whenever either endpoint uses WebSocket.
- Transport-aware Relay selection for `native`, `wss`, and `mixed` sessions.
- Certificate- and hostname-verified `wss://.../ws/relay` health probes.
- Schema v2 fields for trusted proxy CIDRs, exact Origin allow-listing,
  session/queue/rate limits, and Relay endpoint coverage.
- `websocket-status` management command.
- Optional transport argument for `test-geo <IP_A> <IP_B>
  [native|wss|mixed]`.
- Real-process WebSocket and official-HBBR mixed-transport integration tests.

### Compatibility

- Schema v1 remains accepted and keeps WebSocket Signal disabled.
- Native/P2P behaviour remains the default when the client WebSocket switch is
  off.
- HBBR is not modified by this patch.
- Rolling back to patch-v1.0.0 requires restoring a schema v1 configuration.

## patch-v1.0.0

### Added

- External, strictly validated Starry YAML configuration with safe all-or-none
  fallback to upstream behaviour.
- Ordered Relay selection using both endpoints' country, city, subdivision,
  GeoNames ID, ASN, and ISP facts.
- Nested GEO expressions using `/` (OR), `+` (AND), parentheses, and quoted
  values.
- Symmetric and direction-sensitive endpoint rules.
- MMDB download scheduling, size/marker/readability validation, atomic
  replacement, and last-known-good retention.
- RustDesk-compatible HBBS Secure TCP negotiation and Secretbox transport on
  native `21116/TCP`, with authenticated failure handling and compatible
  plaintext-first-frame fallback.
- Local configuration reload, Relay listing, Geo reload, and two-IP rule test
  management commands.

### Compatibility

- Empty, unparseable, or invalid Starry configuration leaves HBBS on official
  command-line behaviour.
- No matching rule, missing required MMDB, or unavailable rule Relay continues
  through later rules and finally official Relay selection.
- The overlay modifies HBBS only.

## Versioning policy

- `X`: incompatible Starry configuration or behaviour change, or a major new
  feature family.
- `Y`: backwards-compatible feature release.
- `Z`: urgent correction to the current patch line.
- The official prefix changes whenever the pinned upstream RustDesk Server
  release changes, even when the Starry patch version does not.

Read [`Upgrade and rollback`](https://github.com/q1ngyang/rustdesk-server-starry/wiki/Upgrade-and-Rollback)
before changing either part of the version.
