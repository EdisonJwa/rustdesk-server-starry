# Kubernetes deployment (Helm)

**English** | [简体中文](HELM-DEPLOYMENT.zh-CN.md)

The chart under [`deploy/helm/rustdesk-server-starry`](../../deploy/helm/rustdesk-server-starry)
runs the Starry data plane: HBBS for signalling and HBBR for Relay traffic.

## Shape

One release runs **one HBBS and one HBBR in a shared pod with host
networking**, because both bind the canonical RustDesk ports (21115, 21116
tcp+udp, 21117). A second replica on the same node would collide, so scale out
by adding nodes and one release per node, not by raising `replicas`.

Both containers keep their state on PersistentVolumeClaims: HBBS owns
`id_ed25519`, its public key, the database, and the Starry configuration
document; HBBR owns its Starry relay identity layout under `RELAY_DATA_DIR`.

## Install

```sh
helm install starry deploy/helm/rustdesk-server-starry \
  --namespace rustdesk --create-namespace \
  --set image.digest=sha256:<release-digest>
```

Pin `image.digest` in production: the tag must name the exact artifact the
centre runs, and the digest is what makes that verifiable.

### Enable Starry features

Starry stays disabled until `hbbs.config` holds a configuration document:

```sh
helm upgrade starry deploy/helm/rustdesk-server-starry \
  --reuse-values --set-file hbbs.config=config/config.geo-basic.yaml
```

The schema reference is [`docs/reference`](../reference) and the shipped
examples live in [`config/`](../../config).

### Supervision and metrics

HBBR exposes the read-only operations endpoint, enabled by default on
loopback:

- `hbbr.operations.listen` (default `127.0.0.1:21120`) is where it listens;
- both the liveness and readiness probes use `/healthz`, which is why the
  endpoint is on by default here — clear the setting to fall back to a TCP
  probe;
- `hbbr.serviceMonitor.enabled=true` adds a `ServiceMonitor` and a headless
  `Service` so the Prometheus Operator scrapes `/metrics` every
  `hbbr.serviceMonitor.interval`. It requires the operator CRDs.

Keep the listener on loopback. It refuses a public address unless
`hbbr.operations.allowPublic=true` is set, because the payload describes
capacity and admission pressure; a public scrape should go through a proxy
with its own access control.

`/metrics` reports the same numbers as authenticated telemetry: active and
capacity sessions, active and capacity bandwidth, load basis points, pending
pairs, uptime, and counters for admission rejections, probe outcomes, and
telemetry authentication failures.

## Volume ownership

Images that do not run as root need `securityContext.volumeOwner.uid` and
`volumeOwner.gid` set to the runtime user, because the `prepare-state` init
container applies that ownership to both claims before either server writes key
material.

## Upgrades and rollback

`Recreate` is used deliberately: two pods cannot hold the same host ports.
During an upgrade the node's RustDesk service is therefore briefly unavailable,
so drain clients with the Starry draining file before upgrading a busy node.

Roll back with `helm rollback`. A rollback that also changes the Starry schema
needs the downgrade export described in
[`Upgrade and rollback`](https://github.com/q1ngyang/rustdesk-server-starry/wiki/Upgrade-and-Rollback).

## Verified in this repository

`helm lint` passes, and the rendered manifests validate against the upstream
Kubernetes schemas for every shipped object with `kubeconform -strict`. The
release workflow re-runs `helm lint` plus assertion checks on the rendered
object count, the two claims, the operations variable, and the optional
`ServiceMonitor`.
