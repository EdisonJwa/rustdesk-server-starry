# Choosing among several relays in one country — how it works today, and what could change

Status: current behaviour verified (2026-11-28); option B implemented as an opt-in flag
Applies to: `geo_relay` / `relay_observer` / `relay_quality`

English | [简体中文](MULTI-NODE-SELECTION.zh-CN.md)

## 1. The answer first

**There is no measured "best of several" today.** With several relays in one country, the
default selection is the **stable intersection in configured order**:

```
a GEO rule matches
  → take its relays list
  → intersect with the relays whose TCP handshake succeeds right now (configured order kept)
  → take the first
```

Three things affect the outcome: which GEO rule the client's IP lands in, the order the relays
were written in that rule, and whether each relay's TCP handshake succeeds at this moment.
**Latency, load, bandwidth and past success rate play no part.**

That default makes a rule's list a preference order, with the second relay hot standby.
Setting `STARRY_RELAY_SPREAD=1` turns the list into a shared pool instead by hashing the
client address into it — that is option B below, and it is still not quality-aware.

## 2. The chain, at code level

### 2.1 An intersection that preserves configured order

`src/geo_relay/rules.rs:446`:

```rust
fn select_ordered(configured_relays: &[String], online_relays: &[String]) -> Vec<String> {
    configured_relays
        .iter()
        .filter_map(|configured| {
            online_relays
                .iter()
                .find(|online| online.eq_ignore_ascii_case(configured))
                .cloned()
        })
        .collect()
}
```

It walks the **configured** list and keeps what is online, so the order is the configured order
rather than a measured one.

### 2.2 Where "online" comes from

`check_relay_servers` in `rendezvous_server.rs` TCP-connects every entry of `relay_servers` every
three seconds; only those that answer enter `native_online`, and `relay_observer.rs:497` uses
that to decide whether `eligible_for` contains `native`.

**It is a binary verdict (reachable or not) with no quality dimension.** A relay dropping 30% of
packets but completing a TCP handshake is indistinguishable from a healthy one.

### 2.3 First candidate wins

`rules.rs:55`:

```rust
let candidates = select_ordered(&rule.relays, online_relays);
if let Some(relay) = candidates.first().cloned() { ... }
```

The rest of `candidates` is not used by the primary path — it is only handed to adaptive probing
when `relay_quality` is on.

### 2.4 There is a real "best of several" layer, behind conditions

`rendezvous_server.rs:1416`:

```rust
if let Some(server_selected_relay) = fast_relay::selected_relay_for_response(...) {
    rr.relay_server = server_selected_relay;
}
```

`relay_quality` (`src/relay_quality.rs`, ~1000 lines) is genuine selection: the server offers
candidates, the client measures each, and the server ranks by RTT, jitter and loss.

**But it has three preconditions and none currently holds:**

| Precondition | Today |
| --- | --- |
| `relay_quality.enabled: true` | **defaults to false**; the production config has no such section |
| `client_protocol == 1` | the official client does not know this protocol at all (`grep relay_quality` over the whole client: no hits) |
| `max_candidates >= 2` | default 3, and the GEO primary must be a `quality_candidate` |

The second is decisive: **this is a Starry-private protocol.** Official RustDesk clients can
never take this path.

## 3. Evidence from production

`allocation.simulate`, CN↔CN:

```json
{"candidates": [
  {"configured_order": 1, "eligible": true, "priority": 1, "relay_id": "117.78.7.96:21117"},
  {"configured_order": 2, "eligible": true, "priority": 2, "relay_id": "149.104.1.168:21117"}],
 "matched_rule": {"name": "CN devices use CN relay"},
 "selection": {"kind": "geo_rule", "relay_id": "117.78.7.96:21117"}}
```

`priority` is the configured index and `kind` is `geo_rule`: no trace of quality ranking.

## 4. What that means with several relays in one country

| Situation | Outcome |
| --- | --- |
| Both healthy | The configured-first relay is **always** chosen; the other only when the first is unreachable |
| First healthy but slow | Still used. Slow is not "unavailable" |
| First losing packets badly | Still used. Loss is not "unavailable" |
| First at capacity | Still used. Load is not consulted |
| First down | `check_relay_servers` marks it unavailable within three seconds; traffic moves to the second |

**So it is hot standby, not selection.** With several relays per country that wastes redundancy:
the second is idle until a failure. Option B removes that waste, but only when a deployment
opts in, because it changes which site serves whom.

## 5. Improvement options, by feasibility

### Option A — split into more rules (zero code, available today)

Rules match in order and the first match wins, so one country can be split into finer rules:

```yaml
geo:
  rules:
    - name: CN south goes to Guangzhou
      match: { client_a: CN, client_a_isp: "China Telecom Guangdong" }
      relays: [117.78.7.96:21117]
    - name: CN rest goes to Shanghai
      match: { client_a: CN }
      relays: [new-cn-2:21117, 117.78.7.96:21117]
```

- **Gain**: clients are split across nodes by ISP and province — geographic and carrier-level
  distribution.
- **Cost**: no code, pure configuration.
- **Limit**: this is distribution, not selection. Clients on the same ISP still all land on one
  node, and it needs a MMDB that actually distinguishes ISPs.

**This is the only option that works for official clients today.**

### Option B — weighted rotation (small effort, server-side)

`ROTATION_RELAY_SERVER` only rotates when no GEO rule matches. Let a GEO hit rotate over its
candidates as well:

```rust
// not first() but an index derived from the client, so one client stays on one relay
let index = stable_hash(&client_addr) % candidates.len();
```

- **Gain**: several relays in a country **share the load instead of one idling**.
- **Cost**: small (about 50 lines plus tests). A given client stays on one relay, so connection
  reuse is unaffected.
- **Limit**: still not quality-aware — but it removes the most visible waste.

**Implemented, behind `STARRY_RELAY_SPREAD=1`.** `pick_within` in `rendezvous_server.rs` hashes
the client address (FNV-1a, IPv4 in full and IPv6 by /64) into the candidates that the health
probe already kept. It is not the default: a rule's second entry is often a different site with
its own bandwidth cost, and where many clients share one NAT address the hash would pin a whole
building onto one relay. Leave the flag unset and a rule behaves exactly as in section 4.

### Option C — passive measurement from the server (medium effort)

Leave `relay_quality` off (it needs a private client) and measure server-side instead:

1. hbbs probes its own `relay_servers` for quality, not just a TCP handshake;
2. that feeds RTT and loss into `RelayRuntimeView` in `relay_observer`;
3. GEO selection ranks within a rule's candidates and takes the best.

- **Gain**: works for official clients, and is genuine quality selection.
- **Cost**: medium. Probe traffic must stay tiny or it becomes relay bandwidth, and ordering needs
  hysteresis or clients will flap between nodes.
- **Risk, and the fundamental limit**: **hbbs→relay RTT is not client→relay RTT.** A Hong Kong
  hbbs measuring a Guangzhou node and a Shanghai node measures its own position, not a mainland
  user's.

  Mitigation: use it only to **exclude clearly degraded** nodes (loss above a threshold), never
  for fine ranking.

### Option D — client-side measurement reported back (large, needs a client)

That is what `relay_quality` is, and official clients will not implement it. Unless we also
maintain a client fork, this path is closed.

## 6. Recommendation

| Step | Option | Why |
| --- | --- | --- |
| 1 | **A (rule split)** | Zero risk, zero code, immediately makes several relays share |
| 2 | **B (weighted rotation)** — done, opt-in | ~50 lines, turns hot standby into sharing; enable with `STARRY_RELAY_SPREAD=1` |
| 3 | the "exclude degraded" subset of C | threshold only, no fine ranking — this avoids the hbbs-vantage limitation |
| not | D | official clients cannot use it; keep the existing code and keep it off |

## 7. Questions that decide the configuration

These decide how to configure, not how to implement:

1. **Are the relays in one country the same size?** Equal size means equal weights; otherwise
   option B needs a per-relay weight.
2. **Are client egress IPs stable?** If many clients share a NAT address, hashing by IP pins a
   whole building onto one relay.
3. **Relay cost against experience**: option C's probe traffic is small but, if relays are billed
   by traffic, its acceptance has to be confirmed.

**Because 2 is unanswered, B ships off by default.** The mechanism is in place and tested, but
turning it on for a country is a deployment decision: it needs the egress addresses of that
country's clients to be spread out, and it needs the second relay to be a place you are willing
to send half the traffic to.
