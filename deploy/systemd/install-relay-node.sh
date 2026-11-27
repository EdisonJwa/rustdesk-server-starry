#!/usr/bin/env bash
# Installs a Starry relay node that shares the centre's key pair.
#
# Run this ON the node, with the three binaries already copied to BIN_SRC.
#
# Two things this script deliberately does NOT do:
#   * start hbbs — a relay node does not own rendezvous, and two hbbs sharing one
#     relay pool would let peers register on either;
#   * touch any firewall, TLS certificate or container that was already on the
#     host. Only the three Starry units and /var/lib/starry are written.
#
# Build the binaries on a machine with cores to spare, then copy them here. Both
# ends must run the same glibc major/minor: an older target rejects a binary built
# against a newer one, but the reverse is fine, so build on the oldest glibc in
# the fleet you intend to deploy to.
set -euo pipefail

BIN_SRC=${BIN_SRC:-/tmp}
CENTER_PUBKEY=${CENTER_PUBKEY:?set CENTER_PUBKEY to the centre's id_ed25519.pub contents}
NODE_ADDR=${NODE_ADDR:?set NODE_ADDR to this node's public host:port form, e.g. 1.2.3.4:21117}
OTHER_RELAYS=${OTHER_RELAYS:-}

BIN=/opt/starry/bin
DATA=/var/lib/starry/data
API_STATE=/var/lib/starry/api

install -d -m 0755 "$BIN" "$DATA/starry/auth" /var/lib/starry/audit
install -d -m 0700 "$API_STATE"

for binary in hbbs hbbr starry-api; do
  install -m 0755 "$BIN_SRC/$binary" "$BIN/$binary"
done

# The key pair must match the centre or clients cannot verify either one.
# id_ed25519 is the base64 64-byte secret; the public file is its last 32 bytes.
if [ ! -s "$DATA/id_ed25519" ]; then
  echo "missing $DATA/id_ed25519 — copy the centre's private key here first" >&2
  exit 1
fi
printf '%s' "$CENTER_PUBKEY" > "$DATA/id_ed25519.pub"
chmod 0600 "$DATA/id_ed25519"
chmod 0644 "$DATA/id_ed25519.pub"

{
  echo "version: 3"
  echo "relay_servers:"
  echo "  - $NODE_ADDR"
  for relay in $OTHER_RELAYS; do
    echo "  - $relay"
  done
  echo "secure_tcp:"
  echo "  mode: auto"
} > "$DATA/starry/config.yaml"
chmod 0644 "$DATA/starry/config.yaml"

cat > /etc/systemd/system/starry-hbbr.service <<'UNIT'
[Unit]
Description=Starry HBBR (relay node)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/var/lib/starry/data
Environment=RUST_LOG=info
Environment=STARRY_RELAY_OPS_LISTEN=127.0.0.1:21120
LimitNOFILE=524288
ExecStart=/opt/starry/bin/hbbr
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

if [ ! -s "$API_STATE/initial-admin-password" ]; then
  umask 077
  openssl rand -base64 24 | tr -d '\n' > "$API_STATE/initial-admin-password"
fi

cat > /etc/systemd/system/starry-api.service <<'UNIT'
[Unit]
Description=Starry API (address book and accounts)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/var/lib/starry/api
Environment=RUST_LOG=info
# Loopback only: the login endpoint carries passwords, so a TLS terminator must
# sit in front before any client is pointed here.
Environment=STARRY_API_LISTEN=127.0.0.1:21114
Environment=STARRY_API_DB=/var/lib/starry/api/users.db
Environment=STARRY_API_KEY_FILE=/var/lib/starry/api/api-signing-key
Environment=STARRY_API_JWKS_FILE=/var/lib/starry/data/starry/auth/jwks.json
Environment=STARRY_API_ISSUER=https://starry-audit-observer.local
Environment=STARRY_API_AUDIENCE=rustdesk-connect
Environment=STARRY_API_SCOPE=connect:initiate
Environment=STARRY_API_JWKS_HEARTBEAT_SECONDS=300
Environment=STARRY_API_BCRYPT_COST=12
ExecStart=/opt/starry/bin/starry-api serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --quiet starry-hbbr.service starry-api.service
systemctl restart starry-hbbr.service starry-api.service
sleep 2

echo "== verification =="
systemctl is-active starry-hbbr starry-api
sha256sum "$DATA/id_ed25519.pub"
curl -fsS --max-time 4 http://127.0.0.1:21114/healthz && echo
ss -ltn | grep -E ':2111[1479]' || true
