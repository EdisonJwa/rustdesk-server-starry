#!/usr/bin/env bash
# Installs a Starry relay node: hbbr and nothing else.
#
# Run this ON the node, with the binary already copied to BIN_SRC.
#
# What this script deliberately does NOT do:
#   * start hbbs — a relay node does not own rendezvous, and two hbbs sharing one
#     relay pool would let peers register on either;
#   * install starry-api — accounts and the address book are the centre's, and a
#     second copy on a relay node listens on loopback where nothing ever reaches
#     it, while holding a divergent users.db;
#   * touch any firewall, TLS certificate or container that was already on the
#     host. Only the hbbr unit and /var/lib/starry/data are written.
#
# Build the binary on a machine with cores to spare, then copy it here. Both ends
# must run the same glibc major/minor: an older target rejects a binary built
# against a newer one, but the reverse is fine, so build on the oldest glibc in
# the fleet you intend to deploy to.
set -euo pipefail

BIN_SRC=${BIN_SRC:-/tmp}
CENTER_PUBKEY=${CENTER_PUBKEY:?set CENTER_PUBKEY to the centre's id_ed25519.pub contents}
NODE_ADDR=${NODE_ADDR:?set NODE_ADDR to this node's public host:port form, e.g. 1.2.3.4:21117}
OTHER_RELAYS=${OTHER_RELAYS:-}

BIN=/opt/starry/bin
DATA=/var/lib/starry/data

install -d -m 0755 "$BIN" "$DATA/starry/auth"

install -m 0755 "$BIN_SRC/hbbr" "$BIN/hbbr"

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

systemctl daemon-reload
systemctl enable --quiet starry-hbbr.service

# A node provisioned by an older version of this script also carries a
# starry-api unit. Retire it rather than leaving a loopback-only account
# database running: nothing can reach it, and its users.db diverges from the
# centre's. The files are kept so the decision is reversible.
if [ -f /etc/systemd/system/starry-api.service ] || [ -x "$BIN/starry-api" ]; then
  install -d -m 0700 /root/starry-retired
  systemctl disable --now starry-api.service 2>/dev/null || true
  mv -f /etc/systemd/system/starry-api.service /root/starry-retired/ 2>/dev/null || true
  mv -f "$BIN/starry-api" /root/starry-retired/ 2>/dev/null || true
  systemctl daemon-reload
  echo "retired a pre-existing starry-api unit into /root/starry-retired"
fi

systemctl restart starry-hbbr.service
sleep 2

echo "== verification =="
systemctl is-active starry-hbbr
sha256sum "$DATA/id_ed25519.pub"
ss -ltn | grep -E ':2111[79]' || true
