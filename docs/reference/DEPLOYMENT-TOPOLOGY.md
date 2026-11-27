# Deployment Topology — which component lives on which host

Status: current
[简体中文](DEPLOYMENT-TOPOLOGY.zh-CN.md)

## Why this document exists

A relay node is one binary. The centre is three. Confusing the two produces a
second account store that nothing can reach, or a second rendezvous that splits
peer registrations. This page states the rule so a node is never provisioned by
guesswork.

## The rule

| Role | Runs | Does not run |
| --- | --- | --- |
| Centre | `hbbs`, `hbbr`, `starry-api`, a TLS terminator | — |
| Relay node | `hbbr` | `hbbs`, `starry-api` |

- **`hbbs` is unique.** It owns rendezvous: peer registration, `PunchHole`,
  `RequestRelay`. Two of them sharing a key would let a peer register on either
  and a controller's punch reach neither.
- **`hbbr` is replicable.** It pairs two peers that a `hbbs` already told about
  each other. Any number can run, and the pool in `relay_servers` is what makes
  them reachable.
- **`starry-api` belongs where clients point.** It serves login, the address
  book and token issuance. Clients reach it through the host named in their
  import string, so a second copy on a relay node is a divergent database behind
  a loopback listener.

## Reference layout

```
                    client import string
        {"host":"rustdesk.edison.network","api":"https://rustdesk.edison.network"}
                                |
                                v
  ┌───────────────── centre: 149.104.1.168 ─────────────────┐
  │  caddy  :80 :443                                        │
  │    ├── rustdesk.edison.network ──> 127.0.0.1:21114      │
  │    ├── meet / whiteboard       ──> 127.0.0.1:8081       │
  │    └── ACME for every name above                        │
  │                                                         │
  │  starry-api  127.0.0.1:21114   login, address book,     │
  │                               JWKS issuer               │
  │  starry-hbbs :21115 :21116    rendezvous                │
  │  starry-hbbr :21117 :21119    relay (also a pool member)│
  └─────────────────────────────────────────────────────────┘
                                |
                     relay_servers + GEO rules
                                |
        ┌───────────────────────┴────────────────────────┐
        v                                                v
  117.78.7.96 (CN)                              175.178.125.23 (CN)
  starry-hbbr :21117 :21119                     starry-hbbr :21117 :21119
  hbbr only                                     hbbr only
```

The centre's `starry-hbbr` is a pool member like the others. A CN client is
handed `117.78.7.96:21117` first and falls back to the centre.

## How the pool reaches clients

`relay_servers` is the configured intent; the set handed out is narrower.

1. `hbbs` TCP-connects each configured relay every three seconds
   (`check_relay_servers`).
2. Only relays that answer become `native`-eligible
   (`relay_observer.rs` — `eligible_for` is built from the probe result).
3. GEO rules choose among **eligible** relays, not configured ones
   (`select_relay_explained_from` takes `eligible_relays`).

So a relay named in a GEO rule but unreachable from the centre is never handed
out: the rule cannot select outside the eligible set. It drops to the next
candidate instead of black-holing the client.

This matters because 175.178.125.23 currently has no path from the centre while
remaining healthy from mainland China. Listing it costs nothing and serves CN
clients as soon as the path returns.

## Provisioning a relay node

```
BIN_SRC=/tmp CENTER_PUBKEY="<centre id_ed25519.pub>" NODE_ADDR=1.2.3.4:21117 \
  bash deploy/systemd/install-relay-node.sh
```

The installer writes `hbbr` and its unit only, and retires any `starry-api`
left by an earlier version of the script into `/root/starry-retired` rather than
deleting it.

Build on a host with cores to spare and copy the binary; both ends must share a
glibc major/minor, and building on the oldest one in the fleet is always safe.

## Checks after provisioning

```
# relay pairs two peers (run from anywhere that can reach the node)
python probe-relay.py <node> 21117        # expect RELAY_PAIRS_PEERS

# the node is reachable as a relay from the centre
ssh <centre> 'timeout 5 bash -c "cat </dev/null >/dev/tcp/<node>/21117" && echo TCP_OK'

# the node serves nothing else
ssh <node> 'ss -ltn'                      # only 21117, 21119, and the loopback 21120
```
