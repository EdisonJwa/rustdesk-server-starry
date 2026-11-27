# Client configuration generator

**English** | [简体中文](CLIENT-CONFIG-GENERATOR.zh-CN.md)

`starry-client-config` renders the three facts a RustDesk client needs — ID
server, relay server, and the server public key — straight from the running
server's key material, so operators stop pasting rotated keys from memory.
It is the lightweight counterpart of Pro's custom client generator: it hands
out configuration; it does not build a client.

## Usage

```sh
starry-client-config \
  --data-dir /var/lib/rustdesk-server-starry/hbbs \
  --id-server id.example.test:21116 \
  --relay-server relay.example.test:21117 \
  --group contractors
```

- `--data-dir` points at the HBBS state directory; only `id_ed25519.pub` is
  read. Private material is never touched.
- `--format text` (default) renders every form at once; `--format json`
  prints just the machine-readable document.
- The **import string** uses the RustDesk wire format: the JSON payload
  \{"host", "relay", "api", "key"\} is base64-encoded and the whole string
  reversed (leading `==` is normal), so scanners do not recognise it as
  base64. Clients reverse, decode, then parse it.
- `--group NAME` annotates the output with the strategy group the device
  belongs to. The server strategy document must match the device ID for the
  group's policy to apply; the annotation is a reminder, not enforcement.
- `--out FILE` writes the result instead of stdout (handy with
  `--format json` for scripts).

## Honesty boundary

The tool never mints access tokens: connection tokens belong to the
operator's identity provider, which is the whole point of the JWT
connection-auth design.
