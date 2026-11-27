# Development plan — derived from the official client code analysis

Status: plan (2026-11-28)
Basis: [Client code analysis](CLIENT-GAP-ANALYSIS.md) (rustdesk @ `104ef2a`)

English | [简体中文](DEVELOPMENT-PLAN.zh-CN.md)

## How to read this

- **Priority**: P0 a gap users can feel / P1 completes a Pro headline feature / P2 enhancement /
  P3 optional
- **Effort**: S (≤1 day) / M (2–4 days) / L (1–2 weeks). Estimates include tests and docs.
- **Gate for every item**: (1) unit tests pinning the contract shape; (2) an e2e that drives the
  real binary; (3) a mutation proving the test actually catches the regression; (4) bilingual
  docs. Missing any one means it is not done.
- **Dependencies** are listed with arrows.

## 1. Overview

| # | Phase | Endpoints / scope | Priority | Effort | Depends on |
| --- | --- | --- | --- | --- | --- |
| P0-1 | Heartbeat and strategy delivery | `/api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver` | P0 | L | security boundary first |
| P0-2 | Non-legacy address book | 10 `/api/ab/*` endpoints | P0 | L | O2 table split |
| P0-3 | Device groups and users | `/api/device-group/accessible`, `/api/users`, `/api/peers` | P0 | M | P0-2's peer table |
| P1-1 | Device self-enrolment | `/api/devices/deploy`, `/api/devices/cli` | P1 | M | auth (have it) |
| P1-2 | TOTP second factor | `tfa_type` / `secret` on `/api/login` | P1 | M | none |
| P1-3 | Address book conflict semantics | ETag / 409 on `/api/ab` | P1 | S | none |
| P2-1 | Client audit upload | `/api/audit/{typ}`, `PUT /api/audit` | P2 | M | governance |
| P2-2 | API proxy on restricted networks | `HttpProxyRequest` | P2 | M | allow-list design |
| P2-3 | Session recording | `/api/record` | P2 | L | **governance first** |
| P3-1 | Session keep-alive | `HealthCheck` | P3 | S | confirm it matters |
| P3-2 | LAN discovery | `PeerDiscovery` | P3 | S | none |
| P3-3 | Device switch grant | `/api/switch-grant` | P3 | M | device identity design |

## 2. P0-1 — Heartbeat and strategy delivery

**Why P0**: this is the only channel that can change client settings remotely, and it is a Pro
headline feature we do not have at all. The client polls every three seconds; without it,
configuration is per-device manual work.

**Contract** (`src/hbbs_http/sync.rs`):

```
POST /api/heartbeat
req:  {id, uuid, ver, conns?, modified_at}
resp: {sysinfo?, disconnect?, strategy?, modified_at?}
       strategy = {config_options:{k:v}, extra:{k:v}}
```

**Steps**

1. **Write the security boundary document first, with no code.** `config_options` mutates client
   configuration. It must enumerate (a) a key allow-list; (b) a key deny-list — anything
   affecting authentication, encryption or updates; (c) what an attacker gains if the channel is
   tampered with. **No implementation until this review passes.**
2. Schema: `device_heartbeats` (presence) + `strategy_documents` (versioned strategy)
3. `POST /api/heartbeat`: authenticate (bearer or device signature), record presence, return
   `strategy` and `modified_at`
4. `disconnect`: instruct listed `conns` to drop, coordinated with hbbs
5. `/api/sysinfo` and `/api/sysinfo_ver`: device info archive plus the version-based skip
6. Document the relationship to `STARRY_STRATEGY_FILE`: **hbbs strategy decides whether a
   connection is allowed; client strategy decides how the client is configured.** No overlap.

**Gates**
- Unit: keys outside the allow-list are dropped and logged; an unchanged `modified_at` does not
  re-deliver
- e2e: real `starry-api` plus a simulated polling client; assert the delivered strategy applies
- Mutation: remove the allow-list check so a deny-listed key is delivered → the test must fail
- Security review: a human sign-off is required; this one cannot be automated

**Risk**: the highest-risk item in the project. If a trustworthy delivery boundary cannot be
established, **do P1 items instead of this one.**

## 3. P0-2 — Non-legacy address book

**Why P0**: Pro's address book sharing. Legacy is one book per account, no sharing, no
pagination. All ten endpoints are required, because a 404 on `/api/ab/personal` switches the
client back to legacy wholesale.

**Steps**

1. **Do O2 first**: split `address_books.document` into `ab_books` + `ab_peers` + `ab_tags` with
   an **online migration** (parse legacy documents into rows, keep the original column for
   rollback)
2. `/api/ab/personal` → this user's personal book guid
3. `/api/ab/settings` → `{max_peer_one_ab}` (reuse the high `licensed_devices` strategy)
4. `/api/ab/shared/profiles` → paginated `{total,data}`
5. `/api/ab/peers` → paginated, filtered by `ab`
6. `/api/ab/tags/{guid}` → bare array
7. Peer trio: add (POST) / update (PUT, four body meanings) / delete (DELETE with a bare array)
8. Tag quartet: add / rename / update / delete
9. Sharing semantics: who may read or write a given book (`ShareRule`: read/write)

**Gates**
- Migration test: legacy document → rows → re-serialise must be **byte-for-byte identical**.
  That is the only criterion for whether the migration is safe.
- e2e: both address book models work; a legacy user still works after migration
- Mutation: remove the `hash` branch from `peer/update` → password hashes are lost → test fails
- Pagination edges: `pageSize=100`, `total` of 0, `current` out of range

**Risk**: the migration must be reversible. Keep the old `document` column for at least one
release cycle.

## 4. P0-3 — Device groups and users

**Contract**: all three are `{total,data:[...]}` paginated envelopes. `/api/users` needs admin
or answers `{"error":"Admin required!"}`; the client treats `ambiguous column name: status` as
"server too old".

**Steps**

1. `device_groups` plus membership
2. `/api/device-group/accessible` (`GET`, only groups the caller may see)
3. `/api/users` (admin sees all; a normal user sees only themselves)
4. `/api/peers` (cross-account device view, admin)
5. Align with the existing strategy grouping: **a strategy group name should resolve to a device
   group**, or operators will maintain the same concept in two places

**Gates**: a non-admin hitting `/api/users` gets the exact expected error string; pagination;
empty groups do not error.

## 5. P1-1 — Device self-enrolment

`/api/devices/deploy`: an administrator issues a one-time token, the new device POSTs
`{id,uuid,pk}` and binds. It coexists with `starry-client-config`: that one generates a static
string, this one does online registration.

**Gates**: the token is single-use (replay fails); `pk` matches the key that later registers; a
failure leaves no half-created device.

## 6. P1-2 — TOTP second factor

The client already implements the whole two-step flow: when login answers with
`type != access_token` and `tfa_type` of `tfa_check` / `email_check`, it shows a verification
dialog and posts again with `verificationCode`. We return empty `tfa_type` / `secret`, so that
path has never lit up.

**Steps**
1. Add `totp_secret` to `users` (encrypted at rest) plus `tfa_type` state
2. First login answers `tfa_type:"tfa_check"` and a one-time `secret`, with no access token
3. Second login carries `verificationCode`; validate the TOTP window (±1 step)
4. Recovery codes plus an admin reset
5. Interaction with OIDC: whether SSO users must also pass TOTP (recommendation: only if the
   provider asserts `acr`, and not stacked by default)

**Gates**: replaying an old code fails; out-of-window fails; `auth_version` bump invalidates old
tokens.

## 7. P1-3 — Address book conflict semantics (small but worth it)

Today `/api/ab` is last-write-wins, so two devices pushing alternately eat each other's data.
Add `If-Match`/ETag and answer 409 on conflict; the client **already** supports this (its
`pushAb` surfaces a failure). Effort S, direct benefit.

## 8. P2 / P3

- **P2-1 client audit upload**: merge with our server-side audit into one query surface. First
  decide whether client audit is trustworthy (a client can forge it). Recommendation: treat it
  as advisory, never as a verdict.
- **P2-2 `HttpProxyRequest`**: allow-list only the API host and the `/api/` prefix, bound the
  response size, and refuse redirects.
- **P2-3 `/api/record`**: **governance before code** — who authorises, where it is stored, how
  long it is kept, who may view it. Not started until that exists.
- **P3-1 `HealthCheck`**: measure whether long sessions actually time out first.
- **P3-2 `PeerDiscovery`**: the server is not strictly required; this is mostly client-side.
- **P3-3 `/api/switch-grant`**: a second trust model parallel to JWT, so it needs its own design.

## 9. Cross-cutting work (carried with each item, not scheduled separately)

| Item | Content |
| --- | --- |
| O4 request tracing | `X-Request-Id` plus duration logging on every API; do it with the first new endpoint |
| Bilingual docs | every item gets `docs/reference/*.md` and `.zh-CN.md`, enforced by `check_docs.py` |
| Contract registry | register every new endpoint in the client contract doc so the next analysis does not start over |

## 10. Suggested order and milestones

```
M1 (1 week)   P1-3 conflict semantics  →  O2 table split  →  P0-2 address book (first half)
M2 (1 week)   P0-2 complete  →  P0-3 groups and users
M3 (1 week)   P1-2 TOTP  →  P1-1 device enrolment
M4 (1–2 weeks) P0-1 strategy delivery (starts only after the security review passes)
M5            as needed: P2-1 / P2-2 / P2-3, each after its own governance decision
```

**Why P0-1 is scheduled last instead of first**: it has the highest value and the highest risk.
M1–M3 stand up the three legs — address book, devices, authentication. P0-1 then gets a
dedicated stretch so its security review is not interrupted.

## 11. Explicitly out of scope

See [section 5 of the analysis](CLIENT-GAP-ANALYSIS.md). The two worth repeating: **no
home-grown web client** (the official client is enough), and **no re-architected account system**
(OIDC plus local passwords already cover it).
