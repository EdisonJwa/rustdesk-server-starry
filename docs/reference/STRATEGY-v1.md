# Strategy v1 — device groups and server-enforced access policy

Status: draft for implementation (route T1)
English | [简体中文](STRATEGY-v1.zh-CN.md)

## Problem

RustDesk Server Pro sells *strategy*: centrally decided policy that governs
which devices a connection may touch. The community has nothing comparable,
and the upstream protocol has no strategy channel: the only server-to-client
policy-like message, `ConfigUpdate`, carries exactly `serial` and
`rendezvous_servers` (fields 1 and 2 of the vendored `rendezvous.proto`).
Official clients apply nothing else from that message, and the Pro client
settings sync runs over the account/API layer, which Starry deliberately does
not include.

## Scope decision

Strategy v1 is therefore **server-enforced policy** — decisions HBBS itself
makes and can prove — not client settings sync:

- Devices are assigned to **groups** by their registered ID (exact match or
  prefix), evaluated statelessly at request time from the strategy document;
  no new persistence and no schema migration.
- Each group carries a **required scope override** for connection JWTs and an
  optional **deny** verdict.
- Denials happen inside HBBS before any signalling work, are recorded in the
  connection audit log with the group attached, and are indistinguishable on
  the wire from any other authorization denial (no target-existence leaks).

Client settings sync is explicitly **out of scope for v1**. Two extension
paths are reserved for v2: additive protobuf fields (tags 100+) on
`ConfigUpdate` for Starry-aware clients, and delivery through an account/API
layer for official clients.

## Strategy document

A separate YAML document, located by `STARRY_STRATEGY_FILE` (unset disables
the engine; every device then belongs to the implicit `general` group with no
overrides):

```yaml
version: 1
default_group: general
groups:
  - name: general
  - name: contractors
    id_prefixes: ["tmp-"]
    require_scope: "connect:initiate:contractor"
  - name: retired
    ids: ["legacy-box-1"]
    deny: true
```

- `groups[].name` must be unique; `ids` are exact matches, `id_prefixes` are
  prefix matches; the most specific rule wins (exact over prefix, longer
  prefix over shorter); unmatched devices fall into `default_group`.
- `require_scope` replaces the connection-auth `required_scope` for requests
  **targeting** that group's devices; a token without it is denied with
  reason `missing_group_scope`.
- `deny: true` refuses every request targeting the group's devices with
  reason `strategy_group_denied`, before JWT evaluation.

The document is loaded at startup and re-read on demand (`strategy.reload`
local-control method, mirroring `runtime.reload`); the content hash is
reported by `/healthz` and `strategy.status`.

## Enforcement points

1. `PunchHoleRequest` and `RequestRelay` arms resolve
   `strategy::check_target(id)` first. A deny verdict short-circuits into the
   standard denial path (audited, counted). Otherwise the group's required
   scope is passed to the connection-authority override.
2. `connection_auth::authorize_connection_attempt` gains a target check
   parameter; the inner scope validation uses the override when present and
   reports `missing_group_scope` for group-scope shortfalls, keeping the
   global `missing_scope` reason for the unscoped configuration.
3. Audit events gain a `group` field (additive; existing consumers ignore
   unknown fields). The CSV exporter's column set is unchanged in v1.

## Non-goals

- No client settings sync (see scope decision).
- No per-user policy: users live in the account layer.
- No group persistence: group membership is derived from IDs and the current
  document, so a strategy edit takes effect on reload without touching
  device state.

## Gates

- Unit tests: document parsing and validation, matching precedence, override
  propagation, deny short-circuit.
- Integration test: a registered device inside a `require_scope` group
  rejects a token without the group scope (`missing_group_scope`) and accepts
  a token with it; a denied-group target never reveals existence.
