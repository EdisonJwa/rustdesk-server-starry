#!/usr/bin/env bash
# Installs starry-api (and optionally a freshly built hbbs) on a native
# (non-container) deployment. Idempotent: re-running after a rebuild replaces
# the binaries and leaves accounts, the signing key, and the JWKS untouched.
#
#   sudo deploy/systemd/install-starry-api.sh [--bin-dir DIR]
#
# Expects hbbs and starry-api binaries in DIR (default: the release build of
# this repository, target/release/).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN_SRC="$ROOT/target/release"
INSTALL_DIR=/opt/starry/bin
API_STATE=/var/lib/starry/api
JWKS=/var/lib/starry/data/starry/auth/jwks.json
PASSWORD_FILE=$API_STATE/initial-admin-password
INSTALL_HBBS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) BIN_SRC=$2; shift 2 ;;
    --no-hbbs) INSTALL_HBBS=0; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

install -d -m 0755 "$INSTALL_DIR"
install_binary() {
  local name=$1
  test -x "$BIN_SRC/$name" || { echo "missing $BIN_SRC/$name" >&2; exit 1; }
  if [ -e "$INSTALL_DIR/$name" ]; then
    cp -a "$INSTALL_DIR/$name" "$INSTALL_DIR/$name.prev-$(date +%Y%m%d%H%M%S)"
  fi
  install -m 0755 "$BIN_SRC/$name" "$INSTALL_DIR/$name"
  echo "installed $name"
}
install_binary starry-api
if [ "$INSTALL_HBBS" -eq 1 ]; then
  install_binary hbbs
fi

install -d -m 0700 "$API_STATE"
if [ ! -s "$PASSWORD_FILE" ]; then
  umask 077
  openssl rand -base64 24 | tr -d '\n' > "$PASSWORD_FILE"
fi

if ! STARRY_API_DB=$API_STATE/users.db "$INSTALL_DIR/starry-api" user list 2>/dev/null | grep -q '^admin'; then
  umask 077
  STARRY_API_DB=$API_STATE/users.db STARRY_API_BCRYPT_COST=12 \
    STARRY_API_NEW_PASSWORD=$(cat "$PASSWORD_FILE") \
    "$INSTALL_DIR/starry-api" user add admin --admin --display-name admin
  echo "created the admin account; its password is in $PASSWORD_FILE"
fi

install -m 0644 "$ROOT/deploy/systemd/starry-api.service" /etc/systemd/system/starry-api.service
systemctl daemon-reload
systemctl enable --quiet starry-api.service
systemctl restart starry-api.service

for _ in $(seq 1 50); do
  [ -s "$JWKS" ] && break
  sleep 0.2
done
test -s "$JWKS" || { echo "starry-api did not publish $JWKS" >&2; exit 1; }

if [ "$INSTALL_HBBS" -eq 1 ]; then
  # hbbs loads the file-published keyset at boot and re-reads it on its refresh
  # interval, so a restart is only needed when the binary itself changed.
  systemctl restart starry-hbbs.service
fi

echo "starry-api: $(systemctl is-active starry-api.service)"
curl -fsS --max-time 3 http://127.0.0.1:21114/healthz && echo
