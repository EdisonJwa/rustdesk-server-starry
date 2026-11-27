# Connection audit log

**English** | [简体中文](AUDIT-LOG.zh-CN.md)

HBBS can record every connection-authentication decision as append-only JSONL
evidence: who attempted to punch or request a relay, over which transport,
what the enforcer decided, and why. Detailed relay state stays behind
authenticated telemetry; this module covers the signalling authorization side.

## Enable

The audit log is off unless a directory is named:

```sh
docker run ... -e STARRY_AUDIT_DIR=/var/lib/rustdesk-server-starry/audit \
  -e STARRY_AUDIT_RETENTION_DAYS=90 ... hbbs
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `STARRY_AUDIT_DIR` | unset (off) | Directory holding `audit-YYYYMMDD.jsonl` day files. |
| `STARRY_AUDIT_RETENTION_DAYS` | `30` | Day files older than this are pruned at rotation. `0` keeps everything. |
| `STARRY_AUDIT_MAX_FILE_MB` | `256` | A day file above this size stops accepting events until the next day, so an attack cannot fill the disk through the audit path. `0` disables the cap. |

Events are recorded only while connection authentication is active (audit or
enforce); with authentication off every decision is a no-op and logging it
would be noise.

## Event format

One JSON object per line, fixed field order:

```json
{"ts":1735000000,"kind":"punch_hole","transport":"tcp","verdict":"deny","reason":"missing_token","client_ip":"192.0.2.7","mode":"enforce"}
```

- `kind`: `punch_hole` or `request_relay`.
- `transport`: `tcp`, `secure_tcp`, `websocket`, or `unsupported_udp` (UDP
  initiation is refused before it can allocate, and the refusal is logged).
- `verdict`: `allow`, `deny`, or `would_deny` (audit mode).
- `reason`: the exact enforcer reason, such as `missing_token`,
  `expired_token`, or `allow`.
- `client_ip`: the effective client address; IPv4 clients may appear in
  IPv4-mapped IPv6 form depending on the listening socket family.
- `mode`: the effective mode at decision time.

## Guarantees

- **Never blocks signalling.** Events go through a bounded channel; a full
  channel drops the newest event and counts it rather than stalling a
  connection. Writes happen on a dedicated thread that owns the day file.
- **Bounded by construction.** Day rotation, retention pruning, and the
  per-day size cap bound the storage no matter what the traffic does.
- **One line per decision, including denials.** Denials are the events that
  matter for evidence; audit mode records `would_deny` without refusing the
  connection.

## Export

The repository ships `starry-audit-export`, a standalone converter that reads
a directory of audit day files and writes CSV (or filtered JSONL):

```sh
starry-audit-export /var/lib/rustdesk-server-starry/audit \
  --out audit-2024Q4.csv --from 20241001 --to 20241231
```

Columns are fixed: `timestamp_utc,kind,transport,verdict,reason,client_ip,
mode,group,source_file`; fields containing commas or quotes follow RFC 4180.
Range filters are inclusive UTC calendar days. `group` is the strategy group the
target resolved to (or the string produced by the resolver, e.g. `general` when
no policy is loaded).

## Kubernetes

Set `STARRY_AUDIT_DIR` under the HBBS state volume and add
`extraEnv` entries in the Helm chart; the volume is already persistent, and
retention keeps the growth bounded.
