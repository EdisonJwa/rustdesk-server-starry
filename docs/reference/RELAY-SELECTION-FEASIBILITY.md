# Can we pick the best relay? — a study of what the protocol permits

Status: study complete (2026-11-28)
Conclusion: **for official clients we can distribute and exclude, not measure-and-pick.** The
limitation is the protocol, not the implementation.

English | [简体中文](RELAY-SELECTION-FEASIBILITY.zh-CN.md)

## 1. The question splits in two

"Pick the best" can mean two different things, and they are achievable to very different degrees:

| Meaning | Requires | Can we |
| --- | --- | --- |
| **A. Distribution**: send different clients to different nodes so none idles | client IP, GEO rules, rotation | **Yes, already** |
| **B. Measured selection**: one client compares nodes and takes the fastest now | client measures candidates and reports | **No, for official clients** |

B is the interesting one, because A is configuration work.

## 2. Why B is impossible for official clients

### 2.1 The protocol carries one address

Every `relay_server` field in `libs/hbb_common/protos/rendezvous.proto` is a single `string`,
with **no candidate-list field anywhere**:

```
PunchHoleResponse.relay_server = 4   string
RelayResponse.relay_server    = 4   string
```

Client, `src/client.rs:1028`:

```rust
relay_server = ph.relay_server;   // one address, used directly
```

`src/client.rs:1359` hands it to connection setup. **There is no "choose among several" branch.**
The server names one relay and the client dials it.

### 2.2 The official client does not measure relay quality

This is decisive. It has two probes, neither about relays:

| Probe | Measures | When | Result used for |
| --- | --- | --- | --- |
| `TestNatRequest` | the **NAT mapping port**, not latency | before connecting | UDP punch port discovery only |
| `TestDelay` | **end-to-end round trip** (including the server's event loop) | after connecting, on the session | displayed to the user; not used for selection |

`src/client.rs:5478` says as much:

```rust
// The punch port must come only from the rendezvous server's TestNatResponse, which
// observes THIS socket's public mapping.
```

**So the client holds no "how fast is this relay right now" information** and cannot choose.

### 2.3 Our existing `relay_quality` is exactly B, and it needs the client

`src/relay_quality.rs` (~1000 lines) already implements the full scheme: the server offers
candidates, the client measures each, the server ranks by RTT, jitter and loss.

**It requires `client_protocol == 1`, and the official client has no reference to
`relay_quality` anywhere.** It is a Starry-private protocol.

## 3. So where is the achievable boundary

### 3.1 Achievable: distribute by client attributes (today)

Rules match in order and the first match wins, so a country with several relays can be split into
finer rules:

```yaml
geo:
  rules:
    - name: CN Guangdong → Guangzhou
      match: { client_a: CN, client_a_isp: "China Telecom Guangdong" }
      relays: [117.78.7.96:21117]
    - name: rest of CN → Shanghai
      match: { client_a: CN }
      relays: [cn-2:21117, 117.78.7.96:21117]
```

By country, province, ISP or ASN. **This is real distribution and it works for official clients.**

Limit: clients on the same ISP still all land on one node, and it needs a MMDB that actually
distinguishes ISPs.

### 3.2 Achievable: stable rotation, turning hot standby into sharing

Today a rule always takes `first()`, so the second relay is used only when the first is TCP
unreachable. A stable client hash changes that:

```rust
let index = stable_hash(&client_addr) % candidates.len();
```

- Gain: several relays in one country share the load instead of one idling.
- About 50 lines plus tests.
- A given client stays on one relay, so connection reuse is unaffected.

### 3.3 Achievable: exclude a degraded node, with a precondition

hbbs can probe quality of its own `relay_servers`, but **only to exclude, never to rank**:

**The fundamental limit**: a Hong Kong hbbs measuring a Guangzhou node and a Shanghai node
measures **its own position**, not a mainland user's. Ranking on that systematically prefers
relays near the hub, which has nothing to do with the user's experience.

So the sound form is a threshold:

```
loss > 20% or RTT > 3× the group median  →  mark degraded and drop from the candidate set
everything else keeps configured order
```

That rescues the "half-dead node" case without inheriting the hub's vantage point.

### 3.4 Not achievable: fine-grained latency ranking

Same reason: no client-side data. Any fine ranking from the hub's view is **pseudo-selection** —
it looks like picking the best while actually picking the nearest to hbbs.

## 4. An easily overlooked option: the config generator

We already ship `starry-client-config`, which emits an import string. **It can emit a different
string per user**:

```json
{"host":"rustdesk.edison.network","relay":"117.78.7.96:21117","api":"...","key":"..."}
```

If the operator knows a group of users is in one region, they can be given a string that **pins a
specific relay**. Not automatic selection, but deterministic distribution, and it needs no protocol
change at all.

- Gain: staged rollouts, pinning a large customer to a dedicated node, migrating a group during an
  incident.
- Cost: zero, the tool exists.
- Limit: manual grouping; a user changing machines needs a new string.

## 5. Conclusion and recommendation

| Capability | Official client | Needs |
| --- | --- | --- |
| Distribute by region or ISP | ✅ | configuration |
| Pin a relay per user group | ✅ | an import string |
| Share load within a group | ✅ | ~50 lines |
| Exclude a degraded node | ✅ | server probe plus a threshold |
| Rank by measured latency | ❌ | a private client protocol |
| Offer several candidates | ❌ | a protocol change the client would not read |

**Suggested order**:

1. **Stable rotation** (3.2) — smallest change, puts the idle second relay to work.
2. **Rule split** (3.1) — configuration only, usable immediately.
3. **Threshold exclusion** (3.3) — protects against a half-dead node without the hub's bias.
4. Skip 3.4's fine ranking unless we also maintain a client fork.

**In one sentence**: for official clients we can turn hot standby into sharing, and drop the bad
ones, but we cannot pick the fastest per connection. That is not an effort problem — the protocol
has no field for it.

## 6. If we ever do want real selection

The only path is to maintain a client ourselves. At that point the existing `relay_quality` is
directly usable — it is written and tested (protocol version 1, `max_candidates` 1–5, with
hysteresis against flapping). So not doing it now does not waste it: it is the prerequisite for
that path, and it is off by default so it affects nobody.
