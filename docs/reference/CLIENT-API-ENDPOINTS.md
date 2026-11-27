# Client API endpoints — what Starry now serves

Status: implemented (2026-11-28)
Companion to: [Client gap analysis](CLIENT-GAP-ANALYSIS.md)

Everything here was implemented against the contract read at the client's own call
site, and every endpoint has an e2e test in `tests/api_endpoints.rs` that drives the
real `starry-api` binary over HTTP.

## Address book, structured form

The client POSTs `/api/ab/personal` first and falls back to the legacy single
document only on a **404**, so these are all-or-nothing.

| Endpoint | Method | Body | Answer |
| --- | --- | --- | --- |
| `/api/ab/personal` | POST | empty | `{guid}` |
| `/api/ab/settings` | POST | empty | `{max_peer_one_ab}` |
| `/api/ab/shared/profiles` | POST | empty, `?current=&pageSize=` | `{total, data:[AbProfile]}` |
| `/api/ab/peers` | POST | empty, `?current=&pageSize=&ab=` | `{total, data:[Peer]}` |
| `/api/ab/tags/{guid}` | POST | empty | `[AbTag]` — bare array |
| `/api/ab/peer/add/{guid}` | POST | `Peer` | `null` |
| `/api/ab/peer/update/{guid}` | PUT | `{id, tags\|alias\|note\|hash\|password}` | `null` |
| `/api/ab/peer/{guid}` | DELETE | `["id","id"]` — bare array | `null` |
| `/api/ab/tag/add/{guid}` | POST | `{name, color}` | `null` |
| `/api/ab/tag/rename/{guid}` | PUT | `{old, new}` | `null` |
| `/api/ab/tag/update/{guid}` | PUT | `{name, color}` | `null` |
| `/api/ab/tag/{guid}` | DELETE | `["tag"]` — bare array | `null` |

Wire details that are load-bearing:

- Those "empty" bodies are POSTs with `Content-Length: 0`. The server treats an absent
  body as valid; requiring JSON there breaks the client.
- `Peer` has 16 fields and `forceAlwaysRelay` is a **string** (`"true"`/`"false"`),
  because the client's `toJson` calls `toString()` on a bool.
- `total` is the **unpaged** count. The client loops `while current * pageSize <
  total`, so reporting a page length silently truncates the list.
- `rename` rewrites every peer's tag array in the same transaction, or the client
  shows a tag that no longer exists.
- Store `hash` verbatim. It is a client-generated password hash and the server must
  never interpret it.

## Device directory

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/device-group/accessible` | GET | `{total, data:[{name}]}` |
| `/api/users` | GET | `{total, data:[UserPayload]}` — admin only |
| `/api/peers` | GET | `{total, data:[Peer]}` — admin only |

`/api/users` answers the literal `{"error":"Admin required!"}` for a non-admin. The
client compares that string to choose its message.

`/api/peers` reports an empty page today: the device registry lives in the rendezvous
database, and this endpoint reads the API database. Empty is the honest answer, not a
404, so the client renders "no devices" instead of an error.

## Heartbeat and client strategy

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/heartbeat` | POST | `{sysinfo?, disconnect?, strategy?, modified_at}` |
| `/api/sysinfo` | POST | text `SYSINFO_UPDATED` / `ID_NOT_FOUND` |
| `/api/sysinfo_ver` | POST | the server version string |

`strategy.config_options` reaches the client's `Config::set_options`. The allow-list
and the four rules are in [CLIENT-STRATEGY-SECURITY](CLIENT-STRATEGY-SECURITY.md);
that document is binding and this table only describes the transport.

`modified_at` carries the **stored** stamp, not the client's echo. The client saves
what it receives and sends it back; echoing it would make an unchanged strategy look
new on every poll.

## Device enrolment

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/devices/deploy` | POST `Bearer <token>` `{id, uuid, pk}` | `{"result": "OK"\|"NOT_ENABLED"\|"INVALID_INPUT"\|"ID_TAKEN"}` |

That is the client's whole closed set; anything else becomes a user-visible error.
The token is single-use, time-limited, and stored only as a SHA-256 fingerprint. A
second enrolment of an existing id with a different key is `ID_TAKEN`, so a token
cannot hijack a device.

Enabled by pointing `STARRY_ENROLMENT_FILE` at an existing file. Mint tokens with
`POST /api/admin/enrolment-token`.

## Client audit and recording

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/audit/{typ}` | POST | `null` |
| `/api/audit` | PUT `{guid, note}` | `null` |
| `/api/record?type=new\|frame&file=` | POST | `null` |

Both are **off by default** and answer `501 NotEnabled` until switched on
(`STARRY_CLIENT_AUDIT_FILE`, `STARRY_RECORDING_FILE`).

Client audit is stored in its own table and is never merged with the server audit
trail. A client can forge any event, so client audit is advisory: it may be read,
never used as a verdict. Recording counts chunk bytes; it does not store screen
contents in the metadata database, which would be the wrong place for megabytes.

## Operator surface

Not used by the client. Added because otherwise an operator — and the tests — write
`client_strategies` and `user_totp` rows by hand, reimplementing a secret's encoding
per caller.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/admin/client-strategy` | GET / PUT | read or replace what would be delivered |
| `/api/admin/totp` | POST `{secret?}` | enrol a second factor, returns `otpauth://` |
| `/api/admin/totp` | DELETE | remove the second factor |
| `/api/admin/enrolment-token` | POST | mint a one-time device token |
| `/api/admin/disconnect/{peer_id}` | POST `{ids}` | queue a session teardown |

All require an administrator bearer token.

## Rendezvous extras

- **`HealthCheck` (`hc`)** is now answered with an empty frame, which is what the
  client's keep-alive loop expects. Without it a session waits for
  `keep_alive * 1.5` and drops.
- **`HttpProxyRequest`** is allow-listed, off by default, and now performs the
  request rather than merely checking whether it may. Two variables configure it:

  | Variable | Meaning |
  | --- | --- |
  | `STARRY_HTTP_PROXY_ALLOW` | comma-separated `host[:port]` this may be proxied to; unset means the feature is off |
  | `STARRY_HTTP_PROXY_TARGET` | the API base URL to send the request to; unset answers `proxy_target_unconfigured` |

  Rules: exact host match (no wildcard, no suffix match), `/api/` paths only, and
  dot segments, a bare `.`, repeated slashes, backslashes and `%2e` are refused
  rather than resolved. `Host` and `Content-Length` from the client are dropped —
  the HTTP client sets those itself. The response is capped at 1 MiB, because an
  allow-listed host can still be hostile or merely verbose.
- **`PeerDiscovery`** needs no server code: it is multicast between peers.

## Gates

`tests/api_endpoints.rs`, 13 tests over the real binary:
structured address book exists and is idempotent, peer round-trips all 16 fields, tag
rename follows through to peers, unauthenticated calls are 401, `/api/users` carries
the admin error string, heartbeat without auth carries no strategy, heartbeat with
auth passes the allow-list and honours `modified_at`, audit and recording are off by
default, enrolment is `NOT_ENABLED` by default, enrolment is single-use with
`ID_TAKEN`, and TOTP takes two steps with an unforgeable handle and a single-use code.

Mutation-verified three ways: dropping the allow-list fails the heartbeat test with
the leaked key named; allowing a spent token fails the enrolment test; accepting a
replayed TOTP step fails both the unit test and the e2e.
