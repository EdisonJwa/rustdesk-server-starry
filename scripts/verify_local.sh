#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 WORKSPACE [BASE]" >&2
    echo "  WORKSPACE  directory holding the upstream checkout" >&2
    echo "  BASE       release (default) gates the full suite; master gates only anchors" >&2
    exit 64
fi

workspace=$1
base=${2:-release}
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ ! -f "$workspace/Cargo.toml" ]; then
    echo "not an upstream checkout: $workspace" >&2
    exit 66
fi

echo "== static gates =="
python3 "$repo_root/scripts/check_contracts.py"
python3 "$repo_root/scripts/check_docs.py"
python3 "$repo_root/scripts/check_workflows.py"

echo "== apply the overlay twice and require idempotence =="
python3 "$repo_root/scripts/apply_overlay.py" "$workspace"
first=$(
    find "$workspace/src" "$workspace/tests" "$workspace/contracts" \
        "$workspace/libs/hbb_common/protos" "$workspace/PATCH_VERSION" \
        "$workspace/libs/hbb_common/src" "$workspace/Cargo.toml" \
        "$workspace/Cargo.lock" "$workspace/Cross.toml" \
        "$workspace/libs/hbb_common/Cargo.toml" \
        -type f ! -name version.rs -print0 \
        | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
)
python3 "$repo_root/scripts/apply_overlay.py" "$workspace"
second=$(
    find "$workspace/src" "$workspace/tests" "$workspace/contracts" \
        "$workspace/libs/hbb_common/protos" "$workspace/PATCH_VERSION" \
        "$workspace/libs/hbb_common/src" "$workspace/Cargo.toml" \
        "$workspace/Cargo.lock" "$workspace/Cross.toml" \
        "$workspace/libs/hbb_common/Cargo.toml" \
        -type f ! -name version.rs -print0 \
        | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
)
if [ "$first" != "$second" ]; then
    echo "the overlay is not idempotent on $base" >&2
    exit 1
fi
echo "idempotent: $first"

if [ "$base" = master ]; then
    if cmp -s "$repo_root/overlay/Cargo.lock" "$workspace/Cargo.lock"; then
        echo "the reviewed Cargo.lock also satisfies master"
    else
        echo "note: the reviewed Cargo.lock targets the formal release, so master"
        echo "      needs a regenerated lock when upstream cuts the next tag."
        echo "      Anchors above already carry forward."
    fi
    exit 0
fi

echo "== reviewed dependency graph =="
cmp "$repo_root/overlay/Cargo.lock" "$workspace/Cargo.lock"
cargo metadata --manifest-path "$workspace/Cargo.toml" --format-version 1 --locked >/dev/null

echo "== compile =="
cargo check --manifest-path "$workspace/Cargo.toml" --workspace --locked

echo "== test =="
cargo test --manifest-path "$workspace/Cargo.toml" --locked

echo "== lint =="
cargo clippy --manifest-path "$workspace/Cargo.toml" --locked --all-targets -j 1

echo "== binaries =="
cargo check --manifest-path "$workspace/Cargo.toml" --locked --bins

echo "all local gates passed on $base"
