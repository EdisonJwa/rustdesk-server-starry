# Relay operations surface — `/healthz`, `/readyz`, `/metrics`

Status: implemented
[简体中文](RELAY-OPS-SURFACE.zh-CN.md)

## What it is

HBBR exposes a read-only HTTP listener for supervision. It is **off by default**
and must be enabled by naming an address:

```
STARRY_RELAY_OPS_LISTEN=127.0.0.1:21120
```

Three constraints are deliberate:

- **Off unless configured.** A relay with no supervisor should not open a port.
- **Loopback unless explicitly widened.** The payload describes capacity and
  admission pressure, so a non-loopback address is refused unless
  `STARRY_RELAY_OPS_ALLOW_PUBLIC=1` is also set.
- **Read-only.** Both methods are `GET`/`HEAD`; other methods are refused rather
  than answered with an error body, because there is nothing mutable to protect.

## Two probes, two questions

The distinction is the whole point of the endpoint. Conflating them is a common
and expensive mistake:

| Endpoint | Question | 200 | 503 |
| --- | --- | --- | --- |
| `/healthz` | Is the process alive and serving HTTP? | always | never |
| `/readyz` | Would a new relay session be admitted now? | admission open | draining or at capacity |

`/healthz` **always** returns 200. A relay that is draining or full is still
alive, and restarting it would either undo an operator's deliberate action or
drop every live session without adding a single slot of capacity.

`/readyz` returns 503 with a `reason` so a load balancer or service registry can
stop routing new peers here while existing sessions keep running.

```json
// GET /readyz — admission open
{"status":"ready","version":"1.1.17-patch-v1.3.1","active_sessions":3,"capacity_sessions":10000}

// GET /readyz — draining
{"status":"not_ready","reason":"draining","version":"...","active_sessions":0,"capacity_sessions":10000}

// GET /readyz — every slot taken
{"status":"not_ready","reason":"at_capacity","version":"...","active_sessions":10000,"capacity_sessions":10000}
```

`/healthz` reports admission state as fields without changing its status code,
so one scrape answers both questions:

```json
{"status":"ok","version":"...","uptime_seconds":42,"admission_rejections":0,"draining":false,"admission_open":true}
```

## Why the verdict cannot drift from the data plane

Both `/readyz` and the session guard call `relay_server::admission_decision`.
If the probe re-derived the rule, a relay could report "ready" while
`RelayLoadGuard::try_new` refused the peer — the load balancer would keep sending
traffic that gets dropped.

`admission_decision(draining, active, capacity)` takes its inputs as arguments
rather than reading globals, which is what makes the four states testable in one
binary without mutating process state.

Draining outranks capacity when both are true: an operator who drained a busy
relay needs to see their own action, not a capacity symptom they cannot fix by
waiting.

## Draining a relay

Two equivalent switches, both read on every admission decision:

```
STARRY_RELAY_DRAINING=1              # environment, set at unit start
STARRY_RELAY_DRAINING_FILE=/path     # a file whose existence means draining
```

The file form is what a deploy script uses: create the file, watch `/readyz`
turn 503, wait for `starry_relay_active_sessions` to reach zero, then stop the
process. Existing sessions are never interrupted — draining only refuses new
ones.

## Metrics

`/metrics` renders Prometheus text format (0.0.4) from the atomics the relay
already maintains:

| Metric | Type | Meaning |
| --- | --- | --- |
| `starry_relay_active_sessions` | gauge | Sessions carrying traffic now |
| `starry_relay_capacity_sessions` | gauge | Configured concurrent session limit |
| `starry_relay_active_bandwidth_bps` | gauge | Bandwidth in use |
| `starry_relay_capacity_bandwidth_bps` | gauge | Configured total bandwidth |
| `starry_relay_load_basis_points` | gauge | Higher of the two utilisations |
| `starry_relay_pending_pairs` | gauge | Pair IDs waiting for a second peer |
| `starry_relay_uptime_seconds` | gauge | Seconds since start |
| `starry_relay_admission_rejections_total` | counter | Admissions refused at capacity |
| `starry_relay_probes_*_total` | counter | Relay-quality probes answered / rate-limited / unsupported / malformed |
| `starry_relay_telemetry_auth_failures_total` | counter | Authenticated telemetry refused at handshake |

## Gates

- `src/ops_surface.rs` unit tests — `/healthz` stays 200 across every admission
  state, `/readyz` answers 200/503 with the right `reason`, and
  `admission_decision` covers open, last-free-slot, at-capacity, draining, and
  draining-while-full.
- Mutation-verified: making capacity never block fails
  `admission_decision_covers_every_state`,
  `readyz_answers_for_every_admission_state`, and
  `zero_capacity_is_floored_to_one_session`, while
  `healthz_reports_ok_regardless_of_admission` still passes — which is exactly
  the property the split exists to guarantee.
