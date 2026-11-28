# Device identity layer — designing `/api/switch-grant`

Status: design (2026-11-28)
Conclusion: **safe to implement, but its value is audit, not authorisation.** No gate is
proposed, because the client never reads the result.

English | [简体中文](DEVICE-IDENTITY-GRANT.zh-CN.md)

## 1. What this endpoint is in the protocol

Verified against rustdesk master (`src/hbbs_http/sync.rs:410-505`, `src/ipc.rs:1184-1194`).

### When it fires

The user clicks "switch sides" inside an established session. The controlled side does three
things:

```rust
Data::SwitchSidesRequest(id) => {
    let uuid = uuid::Uuid::new_v4();                          // one-shot
    crate::server::insert_switch_sides_uuid(id, uuid.clone()); // kept locally
    crate::hbbs_http::sync::register_switch_grant(uuid.to_string()); // reported to the server
    stream.send(&Data::SwitchSidesRequest(uuid.to_string()))  // sent to the peer
}
```

So `switch_uuid` identifies **this one switching action**. It is also handed to the peer, which
uses it to connect back.

### What is reported

```
POST /api/switch-grant
{"id":"<device id>","switch_code_verifier":"<b64>","timestamp":"<unix seconds>","signature":"<b64>"}
```

| Field | How it is derived |
| --- | --- |
| `switch_code` | `base64(sha256(the switch_uuid string))` |
| `switch_code_verifier` | `base64(sha256(b"switch-grant-verifier\0" \|\| switch_code))` |
| signed message | `b"switch-grant\0" \|\| id \|\| 0x00 \|\| verifier \|\| 0x00 \|\| timestamp` |
| `signature` | Ed25519 over that, with the **device's own** `id_ed25519` secret key |

Note the verifier is a second, prefixed hash. Neither the raw `switch_uuid` nor `switch_code`
appears in the request: the server only ever receives an irreversible second hash.

### The answer

```json
{"accepted": true}
```

Or, **when the device clock is outside the window the server accepts**:

```json
{"accepted": false, "server_time": 1795820751}
```

On `accepted: false` with a `server_time`, the client re-signs with the server's clock and sends
**once** more. That is the only retry path, which tells us the protocol's author expected clock
skew to be the main failure.

### Who consumes it

**Nobody.** I searched the whole client: `register_switch_grant` has one caller in `ipc.rs` and
is `tokio::spawn`ed fire-and-forget —

```rust
// Fire-and-forget by design: the switch flow must not block on this POST.
```

The server never hands a grant back to anyone, and whether the switch succeeds does not depend on
this report at all.

## 2. What that means it can and cannot do

| Intent | Possible | Why |
| --- | --- | --- |
| Record "this device initiated a switch at this time" | **Yes** | The signature is verifiable, so the event is auditable |
| Stop an unauthorised switch | **No** | Switching happens over P2P or a relay, not through the API; the server cannot intercept it |
| Issue a credential for the switch | **No** | The client reads only `accepted` and `server_time` from the answer |
| Treat a device key as a connection credential | **No** | Connection auth is JWT (`connection_auth`); this is a parallel chain |

**It is an audit channel, not an authorisation one.** Any design that presents it as a device
gate is wrong, because it would suggest switching is controlled when it is not.

## 3. Security boundary

This is the project's first endpoint that does **not** use a bearer token: authentication comes
entirely from a device Ed25519 signature. So the boundary has to be stated here rather than
inherited.

### 3.1 Where the device identity comes from

The signature uses the device secret key; verification needs the **public** key. It must not come
from the request, or anyone could claim to be any device. The only trustworthy source is an
existing registration.

**Constraint, and the answer to it**: the signing key is `Config::get_key_pair().0` and the
reported public key is the same pair's `.1` — `src/ui_interface.rs:1149` sends exactly that to
`/api/devices/deploy`:

```rust
let pk = crate::encode64(Config::get_key_pair().1);
```

So both paths use **the same device key**, and `enrolled_devices` already stores it:

```sql
create table if not exists enrolled_devices (
    peer_id text primary key, uuid text not null default '', pk text not null, ...
);
```

**No new table and no new enrolment flow is needed.** `enrolled_devices.pk` is the whole
verification input, and it is populated by an administrator with a one-time token
(`/api/devices/deploy`), which is the boundary this design wants.

One gap: `enrolled_devices` only covers devices that came through the deploy flow. Older devices
whose ID was typed in by hand are not there, and their grants would fail verification. That is
acceptable — those devices are outside Starry's management — and if it ever matters the answer is
to extend the deploy flow, not to add a second one.

### 3.2 Replay

`timestamp` is inside the signed message, so it cannot be altered. But **the same signature can
be sent repeatedly**: a server that only verifies would record one event many times, or let
someone infer device presence.

Required:

- `(id, switch_code_verifier)` is unique: one device's one switch is accepted once.
- `timestamp` within `now ± 300` seconds. Slightly wider than the client's single retry needs.
- On skew, **answer `server_time` so the client retries**, as the contract specifies. Do not
  reject outright.

### 3.3 Information disclosure

- `switch_code_verifier` is an irreversible second hash with no `switch_uuid` in it, so storing
  it is safe.
- But the `(id, time)` series reveals *when* a device switched. That is behavioural metadata at
  the same level as our audit log, so it must be off by default, share the
  `STARRY_AUDIT_RETENTION_DAYS` policy, and never appear on a non-administrator endpoint.

### 3.4 The refusal answer

- Bad signature, unregistered `id`, replay → `{"accepted": false}`, **without** `server_time`.
  Including it would make the client retry a request that cannot succeed.
- Clock skew → `{"accepted": false, "server_time": <now>}`.

## 4. Implementation plan, if approved

| Step | Content | Gate |
| --- | --- | --- |
| 1 | Verify against `enrolled_devices.pk` | An unregistered device is refused rather than erroring |
| 2 | `POST /api/switch-grant`: verify, clock window, dedupe | A replay is refused; skew answers `server_time` and the retry succeeds |
| 3 | A **byte-exact** test of the signed message | Use the client's own vector, `test_switch_grant_signed_msg_layout` |
| 4 | Audit persistence, off by default | With it off the endpoint still answers but persists nothing |

**There is no step 0 (create a table)**, because `enrolled_devices` already suffices. That moves
the estimate from L to M.

The gate that matters most: the signed-message layout must be compared against the client
repository's own test vector rather than re-derived by me. The client has
`test_switch_grant_signed_msg_layout`, whose expected value
`b"switch-grant\0id1\0c1\01700000000"` is the only external ground truth.

## 5. Relationship to the existing chains

```
Connection authorisation   JWT (connection_auth)   → hbbs decides "may this connect"
Device enrolment           Bearer deploy token     → starry-api decides "who owns this id"
This endpoint              Ed25519 device signature → starry-api records "who switched sides"
```

None substitutes for another. In particular: **passing this verification does not mean the device
may connect**, and does not mean its id is authorised. This has to be written down, or a reader
will assume it is a fourth kind of authorisation.

## 6. Recommendation

**Implementable, but it needs a decision first: do we want device-level audit at all?**

The technical prerequisites are met — the public key is in `enrolled_devices`, the signed-message
layout is pinned by the client's own vector, and dedupe plus the clock window have clear rules.
What is missing is not capability but **need**:

- If we want a "which device switched sides, when" trail → implement it. Effort M, clear gates.
- If not → **do not implement it, and remove it from the plan.** The only consumer does not care
  about the result, so writing it produces a table with a writer and no reader: pure operational
  cost.

My judgement: **defer until there is a real audit requirement.** This system's actual blind spot
is not a missing event — it is elsewhere, for instance that two address book shapes coexist.
Effort spent there pays more.

If someone argues for it on the grounds that "Pro has switch-grant", the correct answer is: Pro's
implementation lets the client switch sides; our clients can already switch. This endpoint is
optional telemetry, not the feature.
