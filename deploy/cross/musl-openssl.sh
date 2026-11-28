#!/usr/bin/env bash
# Cross-compile a static OpenSSL for the musl release binaries.
#
# Run by cross as a `pre-build` hook, inside the target image, before cargo.
#
# Why this file exists at all
# ---------------------------
# `native-tls` is an unconditional dependency of the vendored hbb_common:
# `src/proxy.rs` uses `tokio_native_tls`, and both tungstenite crates enable
# their `native-tls` feature. So `openssl-sys` is in the graph even though the
# server's own TLS is rustls, and the static musl binaries must link OpenSSL.
#
# Three things were tried before this, each rejected on evidence:
#
#   1. `[target.'cfg(target_env = "musl")'.dependencies]` with feature
#      `vendored`. `cargo tree --target ... -e features` showed the feature, but
#      the cross build reported "could not find system library 'openssl'" and
#      never compiled openssl-src.
#   2. The same with explicit triples. Same outcome, while the identical tree
#      built for musl on the host did compile openssl-src.
#   3. A plain unconditional dependency, relying on feature unification. Same
#      outcome again: the CI log shows `/target/release/build/openssl-sys-...`,
#      with no triple directory, so the container's cargo resolves its own graph.
#
# Why not let openssl-src do it here: the image installs no perl and no build
# tools (`grep -c perl Dockerfile.x86_64-unknown-linux-musl` is 0), so the
# vendored build cannot run in-place. Installing them first is the difference
# between this working and the earlier attempts.
#
# Why not build it on the runner and pass OPENSSL_DIR: cross mounts only the
# project and cargo directories, so a path under $RUNNER_TEMP does not exist
# inside the container.
set -euo pipefail

: "${CROSS_MUSL_SYSROOT:?cross must set the musl sysroot}"
: "${CC:?cross must set CC for the target}"

OPENSSL_VERSION=3.3.2
PREFIX=/opt/musl-openssl
STAMP="$PREFIX/.stamp-${OPENSSL_VERSION}"

# The hook runs per target; OpenSSL does not need rebuilding for each.
if [ -f "$STAMP" ]; then
  echo "openssl ${OPENSSL_VERSION} already built"
  exit 0
fi

# Debian base image: apt is present, and perl is what OpenSSL's Configure needs.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends perl make ca-certificates curl >/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

curl -fsSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -o openssl.tar.gz
mkdir src
tar -xzf openssl.tar.gz -C src --strip-components=1
cd src

case "$(uname -m)" in
  x86_64) openssl_target=linux-x86_64 ;;
  aarch64) openssl_target=linux-aarch64 ;;
  *) echo "unsupported build architecture $(uname -m)" >&2; exit 1 ;;
esac

# `no-shared` because the release binaries are fully static; a dynamic OpenSSL
# would not exist on the host that runs them. `no-tests` keeps the build short.
# CC/CXX come from cross and already point at the musl toolchain, so the
# resulting library is musl-linked rather than glibc.
./Configure "$openssl_target" \
  no-shared no-tests no-legacy \
  --prefix="$PREFIX" \
  --openssldir="$PREFIX/ssl"
make -j"$(nproc)" build_libs >/dev/null
make install_sw >/dev/null

touch "$STAMP"
echo "static OpenSSL ${OPENSSL_VERSION} installed under $PREFIX"
