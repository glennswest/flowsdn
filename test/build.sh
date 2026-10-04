#!/usr/bin/env bash
# Stage flowsdn's test image for the commit checked out (#303).
#
#   test/build.sh [target]        default x86_64-unknown-linux-musl
#
# Per stormcentral docs/test-standard.md the runner calls this in the checkout
# on the build box, then runs `podman build -f test/Containerfile` with the repo
# root as context. It builds, from this commit:
#   - the BPF objects (pinned nightly from crates/flowsdn-bpf/rust-toolchain.toml
#     and bpf-linker 0.11.1, SHA-256 checked; both fetched if absent),
#   - the agent, CNI, kernel fixtures and /test (static musl),
# and stages them in test/.stage. It does not build the image itself.
set -euo pipefail
target=${1:-x86_64-unknown-linux-musl}
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-$root/tmp}
mkdir -p "$tmp"
source "$HOME/.cargo/env" 2>/dev/null || true

nightly=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/crates/flowsdn-bpf/rust-toolchain.toml")
if ! rustup toolchain list | grep -q "^$nightly"; then
    rustup toolchain install "$nightly" --profile minimal --component rust-src
fi

if ! command -v bpf-linker >/dev/null; then
    version=0.11.1
    sha=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8
    [ "$(uname -m)" = x86_64 ] || { echo "test/build.sh: no pinned bpf-linker for $(uname -m)" >&2; exit 1; }
    dir="$tmp/bpf-linker-$version"
    archive="$dir/bpf-linker.tar.zst"
    mkdir -p "$dir"
    curl -fsSL -o "$archive" \
        "https://github.com/aya-rs/bpf-linker/releases/download/v$version/bpf-linker-x86_64-unknown-linux-musl.tar.zst"
    echo "$sha  $archive" | sha256sum -c --quiet -
    tar --zstd -xf "$archive" -C "$dir"
    linker=$(find "$dir" -type f -name bpf-linker | head -n1)
    [ -n "$linker" ] || { echo "test/build.sh: bpf-linker not in the release archive" >&2; exit 1; }
    chmod +x "$linker"
    PATH="$(dirname "$linker"):$PATH"
fi

bpf_target=${CARGO_TARGET_DIR:-$root/crates/flowsdn-bpf/target}
CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS='-C debuginfo=2 -C link-arg=--btf' \
    cargo "+$nightly" build --manifest-path "$root/crates/flowsdn-bpf/Cargo.toml" \
    --target bpfel-unknown-none -Z build-std=core --release --locked \
    --target-dir "$bpf_target"

fixtures=(flowsdn-bpftest flowsdn-endpoint-test agent-runtime cni-runtime loader-features
    native-routing packet-ingress socket-live uplink-ingress)
cargo build --manifest-path "$root/Cargo.toml" --release --locked --target "$target" \
    -p flowsdn-agent -p flowsdn-cni -p flowsdn-bpftest -p flowsdn-test
out=${CARGO_TARGET_DIR:-$root/target}/$target/release

stage="$root/test/.stage"
rm -rf "$stage"
mkdir -p "$stage/opt/flowsdn/bin" "$stage/opt/flowsdn/fixtures" "$stage/opt/flowsdn/bpf"
cp "$out/flowsdn-test" "$stage/test"
cp "$out/flowsdn-agent" "$out/flowsdn-cni" "$stage/opt/flowsdn/bin/"
for f in "${fixtures[@]}"; do cp "$out/$f" "$stage/opt/flowsdn/fixtures/"; done
for o in smoke local-delivery loader-features socket-context; do
    cp "$bpf_target/bpfel-unknown-none/release/$o" "$stage/opt/flowsdn/bpf/"
done
for f in "$stage/test" "$stage"/opt/flowsdn/bin/* "$stage"/opt/flowsdn/fixtures/*; do
    if file "$f" | grep -q 'dynamically linked'; then
        echo "test/build.sh: $f is not static" >&2
        exit 1
    fi
done
du -sh "$stage"
echo "staged $stage"
