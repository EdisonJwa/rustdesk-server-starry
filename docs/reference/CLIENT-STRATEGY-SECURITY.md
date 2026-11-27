# Client strategy delivery — security boundary

Status: **binding constraint** (2026-11-28)
Applies to: `/api/heartbeat` and everything that writes `client_strategies`

[简体中文](CLIENT-STRATEGY-SECURITY.zh-CN.md) | English

## What this is

The client polls `POST /api/heartbeat` every three seconds. When the answer carries
`strategy.config_options`, the client feeds those keys through its own
`Config::set_options`. That is **server-initiated client configuration**, and it is
the only such channel in the protocol.

The plan for this feature says the boundary has to exist before the code. This
document is that boundary. The implementation below follows it literally; anything
the document does not permit is not implemented.

## Threat model

| Actor | Capability | Consequence if the channel is unguarded |
| --- | --- | --- |
| Anyone who can reach the API | `POST /api/heartbeat` | Without authentication, anyone can impersonate a device and receive a strategy meant for someone else |
| A compromised account holder | Read their own strategy | Acceptable — the strategy is configuration, not a secret |
| A compromised server database | Write `client_strategies` | Attacker controls client configuration fleet-wide; the allow-list is what bounds the damage |
| A network attacker | Modify the response | TLS terminates at Caddy; the client validates nothing, so integrity rests entirely on transport |

## The four rules

### 1. Only authenticated devices receive a strategy

The heartbeat request identifies a device, and only its owner may receive that
device's strategy. An unauthenticated heartbeat is still accepted — the protocol
requires an answer so the client does not retry — but it carries **no** `strategy`
and no `sysinfo` instruction. It answers only `modified_at`.

If a deployment has no authentication configured at all, strategy delivery is
disabled rather than anonymous. A server that cannot tell who is asking cannot
safely answer "how should you be configured".

### 2. `config_options` is allow-listed, and the allow-list is the union of keys
   that cannot weaken security

Permitted keys, and why each is safe:

| Key | Why it is safe |
| --- | --- |
| `relay-server` | Redirects media through an operator-chosen relay. Cannot grant access. |
| `rendezvous-server` | Same, for signalling. A wrong value breaks connectivity, it does not widen it. |
| `api-server` | Points the client at this server. Already trusted. |
| `allow-auto-record-incoming` | Recording policy. Privacy-relevant, but bounded to the user's own machine. |
| `enable-audio` | Feature toggle. |
| `enable-clipboard` | Feature toggle. |
| `enable-file-transfer` | Feature toggle. |
| `enable-remote-printer` | Feature toggle. |
| `use-webrtc` | Transport selection. |
| `allow-remote-config-modification` | Whether this channel may act at all. Sending `N` disables it, which is strictly narrowing. |
| `verification-method` | Which second factors to offer. |

**Every key not in this table is dropped, and the drop is logged at `warn` with the
key name.** The list is exhaustive by construction: `strategy::ALLOWED_KEYS` is the
single source, and a test asserts that a document containing a non-listed key
delivers the listed ones and nothing else.

Explicitly forbidden, with reasons:

| Key family | Why never |
| --- | --- |
| `password`, `key`, `secret`, `token`, `private-key` | Credentials. A remote write here is credential injection. |
| `whitelist`, `allow-*` other than the recording and remote-config toggles | Access widening. Any `allow-` key that grants a capability is excluded by default; the three listed above are toggles for features that already require the user's own consent. |
| `deny-*` / blocklists | Removing an operator's blocklist is a widening action. |
| `custom-rendezvous-server` with `is-public` semantics | Would let a deployment move a client to an attacker-controlled rendezvous. |
| `stop-service` | Turns the client off. Availability, not security, but a remote kill switch is out of scope. |

### 3. The strategy is bound to its account, and delivery is by `modified_at`

`client_strategies` is keyed by `user_id`. A device receives the strategy of the
account that authenticated the heartbeat. There is no "global strategy" that all
devices receive, because that would make every authentication equal to every other.

`modified_at` narrowing is a correctness property, not an optimisation: the client
stores the value it last saw and sends it back, and re-delivering an unchanged
document makes the client re-apply options on every poll.

### 4. `disconnect` is separate from `strategy` and carries no configuration

`disconnect` is a list of connection ids to drop. It changes no configuration and
cannot be used to widen access, so it does not need the allow-list — but it does
need the same authentication, because forcing another account's sessions closed is
a denial-of-service primitive.

## What this channel is not

- **Not an authorisation channel.** It does not decide whether a connection is
  allowed; `STARRY_STRATEGY_FILE` on hbbs does that. Nothing delivered here can
  make hbbs accept a connection it would otherwise refuse.
- **Not a credential channel.** No key here may carry a secret.
- **Not durable.** A client that never polls simply keeps its last configuration;
  delivery is pull, so a device offline during a rollout picks the change up when
  it returns.

## Gates

- `strategy::filter_config_options` unit tests: every listed key survives, every
  forbidden key is dropped, an unknown key is dropped, and the function is pure.
- A test asserts `ALLOWED_KEYS` and `FORBIDDEN_KEYS` are disjoint — a key in both
  would make the answer depend on iteration order.
- e2e: an authenticated heartbeat receives its strategy; an unauthenticated one
  receives `modified_at` only and no `strategy`.
- Mutation: making the filter pass everything through fails the e2e that asserts a
  forbidden key is absent.
