# Client code analysis — what we do not implement, and what we could improve

Status: analysis complete (2026-11-28)
Subject: `github.com/rustdesk/rustdesk` @ `104ef2a` (master)
Method: full clone (not sampled), every `/api/` path and rendezvous message enumerated, each
endpoint's contract read at its call site

English | [简体中文](CLIENT-GAP-ANALYSIS.zh-CN.md)

## 1. Method and boundary

**Done**: cloned the whole client repository; enumerated `src/` (Rust, including all 2002 lines
of `hbbs_http`) and `flutter/lib/` (142 Dart files) exhaustively; went back to every call site
to read the real contract rather than trusting documentation.

**Not done**: did not analyse platform-private APIs (`/api/winuser/...` and friends — those are
Windows SDK function names appearing in doc links, not HTTP endpoints); did not analyse the
private Akari branch.

**One conclusion first, because everything else depends on it**: the client probes each optional
endpoint with **404**. `/api/ab/personal` returning 404 makes it fall back to the legacy address
book; `/api/ab/settings` returning 404 means "server does not support shared books". So our
current absence of these endpoints is **safe** — the client does not error, the feature is
merely invisible. It also means each endpoint we add lights up its UI with no client change.

## 2. Endpoint inventory

Legend: ✅ implemented　⬜ not implemented (404; client degrades)　➖ not applicable (Pro cloud only)

### 2.1 Authentication and issuance — complete

| Endpoint | Method | Status | Note |
| --- | --- | --- | --- |
| `/api/login` | POST | ✅ | access_token *is* the connection credential |
| `/api/login-options` | GET | ✅ | array; `common-oidc/` supported |
| `/api/currentUser` | GET/POST | ✅ | capital U |
| `/api/logout` | POST | ✅ | |
| `/api/oidc/auth` | POST | ✅ | |
| `/api/oidc/auth-query` | GET | ✅ | `{"body":...}` wrapper |
| `/oidc/callback` | GET | ✅ | browser half |
| `/api/connection-token` | POST | ✅ | client does not call it (self-check) |
| `/api/introspect` | POST | ✅ | RFC 7662, used by hbbs |

### 2.2 Address book — legacy (1 endpoint, implemented)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/ab` | GET / POST | ✅ whole document `{tags,peers,tag_colors}` |

**This is the only address book shape currently lit up.**

### 2.3 Address book — non-legacy (10 endpoints, none implemented)

The client POSTs `/api/ab/personal` first; **a 404 there switches the whole feature back to
legacy**. So this group is all-or-nothing. Contracts from `flutter/lib/models/ab_model.dart`:

| Endpoint | Method | Contract | Status |
| --- | --- | --- | --- |
| `/api/ab/personal` | POST | → `{guid}` for the personal book | ⬜ |
| `/api/ab/settings` | POST | → `{max_peer_one_ab}` | ⬜ |
| `/api/ab/shared/profiles` | POST | `?current=&pageSize=` → `{total,data:[AbProfile]}` | ⬜ |
| `/api/ab/peers` | POST | `?current=&pageSize=&ab=<guid>` → `{total,data:[Peer]}` | ⬜ |
| `/api/ab/tags/{guid}` | POST | → `[AbTag]` bare array (not enveloped) | ⬜ |
| `/api/ab/peer/add/{guid}` | POST | `{id,alias,hash,tags,...}` one at a time | ⬜ |
| `/api/ab/peer/update/{guid}` | PUT | `{id,tags}` / `{id,alias}` / `{id,note}` / `{id,hash}` | ⬜ |
| `/api/ab/peer/{guid}` | DELETE | `["id1","id2"]` bare array | ⬜ |
| `/api/ab/tag/add/{guid}` | POST | `{name,color}` one at a time | ⬜ |
| `/api/ab/tag/rename/{guid}` | PUT | `{old,new}` | ⬜ |
| `/api/ab/tag/update/{guid}` | PUT | `{name,color}` | ⬜ |
| `/api/ab/tag/{guid}` | DELETE | `["tag1"]` bare array | ⬜ |

**Value**: the non-legacy shape adds **shared address books** (one book, many people) and
pagination. Legacy is one book per account with no sharing. This group is Pro's "Address book
sharing".

**Risk**: `peer/update` multiplexes four meanings onto one path, distinguished by body fields;
`hash` is a client-generated password hash the server must store verbatim (an established
principle here).

### 2.4 Device groups and users (3 endpoints, none implemented)

| Endpoint | Method | Contract | Status |
| --- | --- | --- | --- |
| `/api/device-group/accessible` | GET | `?current=&pageSize=` → `{total,data:[{name,...}]}` | ⬜ |
| `/api/users` | GET | `?current=&pageSize=&accessible=&status=1` → `{total,data:[UserPayload]}` | ⬜ |
| `/api/peers` | GET | same → `{total,data:[Peer]}` | ⬜ |

**Note**: `/api/users` needs `is_admin` or answers `{"error":"Admin required!"}`, and the
client treats `ambiguous column name: status` as "server too old". Both strings are part of the
contract.

**Value**: device groups are the data source for the client's grouped view; without them the
client shows a flat device list. `/api/peers` is the server-wide counterpart of
`/api/ab/peers` (administrator view across accounts).

### 2.5 Strategy delivery (3 endpoints, none implemented) — **the most important finding**

The client polls `/api/heartbeat` every three seconds, and the response may carry `strategy`:

| Endpoint | Method | Contract | Status |
| --- | --- | --- | --- |
| `/api/heartbeat` | POST | `{id,uuid,ver,conns,modified_at}` → `{sysinfo?,disconnect?,strategy?,modified_at?}` | ⬜ |
| `/api/sysinfo` | POST | device info → text `SYSINFO_UPDATED` / `ID_NOT_FOUND` | ⬜ |
| `/api/sysinfo_ver` | POST | → version string, used to skip unchanged uploads | ⬜ |

The `strategy` shape (`StrategyOptions`):

```json
{"strategy":{"config_options":{"key":"value"},"extra":{"k":"v"}}}
```

`config_options` lands in the client's `Config::set_options`, meaning **the server can change
client settings remotely**. `handle_config_options` has a rejection path for protected options
and the client logs `Strategy update rejected`.

**This is not the same chain as our `STARRY_STRATEGY_FILE`**: our strategy engine decides, on
the hbbs side, whether a given connection is allowed. The client's strategy is how the client is
configured. The two are complementary, not duplicative.

**Value**: this is Pro's "Strategy/security settings sync". It lets an operator disable a
transport, pin a relay, or enforce a password policy fleet-wide without touching each device.

**Risk (high)**: `config_options` is **remote client configuration mutation**. It must have an
allow-list of keys, be unavailable before authentication, and depend on an established JWT.
Otherwise it is a privilege-escalation surface.

### 2.6 Audit and recording (3 endpoints, none implemented)

| Endpoint | Method | Contract | Status |
| --- | --- | --- | --- |
| `/api/audit/{typ}` | POST | client **uploads** audit events to the server | ⬜ |
| `/api/audit` | PUT | `{guid,note}` adds a note to one session | ⬜ |
| `/api/record` | POST | `?type=new\|frame&file=` session recording chunk upload | ⬜ |

**Key distinction**: our `STARRY_AUDIT_DIR` is **server-side** audit (who connected to whom,
what the strategy decided). `/api/audit/{typ}` is **client-side** audit (what the user did on
their own machine). Different sources; neither replaces the other.

**`/api/record` is privacy-sensitive**: it uploads session video, i.e. screen content. It must
be off by default, explicitly enabled, with a declared storage location and retention period.

### 2.7 Device registration and grants (4 endpoints, partly related)

| Endpoint | Method | Contract | Status |
| --- | --- | --- | --- |
| `/api/devices/deploy` | POST | `Bearer token` + `{id,uuid,pk}` → `{result:"OK"}` | ⬜ |
| `/api/devices/cli` | POST | same + various `*_name` fields | ⬜ |
| `/api/switch-grant` | POST | Ed25519-signed device switch grant `{id,switch_code_verifier,timestamp,signature}` | ⬜ |
| `/api/heartbeat` (above) | POST | also carries `disconnect` commands | ⬜ |

`/api/devices/deploy` is **pre-provisioned deployment**: an administrator issues a token, the
new device registers with it and binds an ID. It is the same goal as our
`starry-client-config` by another route — we generate static configuration, it does online
registration. Implementing it enables "one-time token, device self-enrols".

`/api/switch-grant` signs with the device private key and the server verifies. It runs parallel
to our JWT system and belongs to the device-identity layer.

## 3. Protocol layer (rendezvous)

Of the 19 union members in `libs/hbb_common/protos/rendezvous.proto`:

| Message | Server | Note |
| --- | --- | --- |
| `register_peer` / `register_pk` / `register_peer_response` | ✅ | |
| `punch_hole_request` / `punch_hole` / `punch_hole_sent` / `punch_hole_response` | ✅ | |
| `request_relay` / `relay_response` | ✅ | |
| `fetch_local_addr` / `local_addr` | ✅ | via a dispatch branch |
| `configure_update` | ✅ | |
| `software_update` | ✅ | |
| `test_nat_request` / `test_nat_response` | ✅ | |
| `online_request` / `online_response` | ✅ | |
| `key_exchange` | ✅ | `secure_tcp.rs` |
| **`http_proxy_request` / `http_proxy_response`** | ⬜ | see below |
| **`health_check` (`hc`)** | ⬜ | see below |
| **`peer_discovery`** | ⬜ | LAN discovery |
| `relay_probe_*` / `relay_quality_*` | ✅ | Starry extensions |

### 3.1 `HttpProxyRequest` — API proxying through hbbs

When the client has `USE_RAW_TCP_FOR_API=Y` and no WebSocket, it sends API requests **over its
hbbs TCP connection** to the API server (`src/common.rs:1469`). Reason: a client that can only
reach hbbs ports (21116/21117) on a restricted network can still use `/api/*`.

**Value**: reachability on restricted networks. **Risk**: hbbs becomes an arbitrary HTTP proxy —
it needs a strict allow-list (only the configured API host, only the `/api/` prefix, bounded
response size, no redirects).

### 3.2 `HealthCheck` — keep-alive during a session

`src/client.rs:5296`: the client periodically sends `hc{token}` while connected. We do not
implement it, so that path waits for a timeout. Effect: keep-alive during long sessions relies
on retry rather than server-pushed liveness. **Worth confirming this is actually perceptible.**

### 3.3 `PeerDiscovery` — LAN discovery

`src/lan.rs`: devices on the same subnet discover each other for direct LAN connections (no
relay). The server is not strictly needed (multicast). **Lowest priority**, but it is the entry
point for "prefer same-subnet direct".

## 4. Improvement opportunities (in what we already have)

Ordered by user-visibility:

| # | Where | Today | Improvement | Benefit |
| --- | --- | --- | --- | --- |
| O1 | `/api/ab` legacy | whole 4 MiB document, last write wins | document-level ETag / `If-Match`, answer 409 on conflict instead of silently overwriting | two devices pushing alternately stop eating each other's data |
| O2 | `/api/ab` legacy | single `document text` row | split into an `ab_peers` table with indexes, reusable by the future `/api/ab/peers` | groundwork for 2.3, avoids a second migration |
| O3 | `/api/login` | password + OIDC | `tfa_type`/`secret` are returned but always empty | TOTP is what actually makes those fields real |
| O4 | all APIs | no request id, no structured timing | `X-Request-Id` plus duration logging | production debugging becomes lookup, not guesswork |
| O5 | `/api/ab` | reads 4 MiB into memory then validates JSON | stream-validate, or check `Content-Length` first | large documents stop costing double memory |
| O6 | `oidc_links` | bound on `(provider,subject)` | audit table for e-mail changes | identity drift becomes traceable |
| O7 | `/api/login-options` | no cache headers | add `Cache-Control` | fewer requests per client start |
| O8 | hbbs audit | per-line flush (crash consistency) | batch with a configurable fsync interval | fewer IOPS under load (deliberately unchanged; needs measurement) |

**Deliberately not doing**: server-side encryption of `/api/ab`. The document already contains
client-generated password hashes; encrypting it server-side only relocates the key-management
problem and breaks the "the client owns the shape" contract.

## 5. Deliberately out of scope (with reasons, so it stops coming up)

| Item | Reason |
| --- | --- |
| `/api/winuser/*` etc. | not HTTP endpoints; Windows SDK function names |
| Akari private protocol beyond `relay_quality_*` | official client does not implement it; frozen |
| Building our own web client | clients are the official Flutter app; competitors build web UIs precisely because they lack one |
| Rebuilding accounts beyond OIDC | OIDC + local passwords cover it; LDAP/TOTP are scheduled |

## 6. Conclusion

**Implemented**: the authentication loop (password + OIDC), legacy address book, relay
selection, the strategy engine (hbbs side), audit, and the ops surface. Together these cover
"can connect, stays connected, is observable".

**Largest gaps by value**:
1. **`/api/heartbeat` strategy delivery** — the only channel that can change client settings
   remotely; a Pro headline feature
2. **Non-legacy address book (10 endpoints)** — shared books; Pro's address book sharing
3. **`/api/users` + `/api/peers` + `/api/device-group`** — grouped views, the basis of any
   management UI
4. **`/api/devices/deploy`** — device self-enrolment
5. **`/api/record`** — session recording (privacy-sensitive; needs governance first)
6. **`HttpProxyRequest`** — reachability on restricted networks

**The one to be most careful about**: `config_options` in `/api/heartbeat` is remote
configuration delivery. Decide the security boundary before writing the code, not after.
