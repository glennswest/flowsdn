#!/usr/bin/env bash
# Build flowsdn's BPF objects (crates/flowsdn-bpf) reproducibly.
#
#   tools/build-bpf.sh OUT_DIR
#
# Uses the nightly pinned in crates/flowsdn-bpf/rust-toolchain.toml (installed
# through rustup if absent) and bpf-linker 0.11.1 (downloaded and SHA-256
# checked if not on PATH). Build paths are remapped, so the code sections are
# the same wherever the commit is built (debug info still carries a hash of the
# checkout path). The agent embeds local-delivery
# (crates/flowsdn-agent/bpf/local-delivery) and socket-lb; test/build.sh rebuilds them and
# refuses a copy whose code differs. Copies smoke, local-delivery, loader-features,
# socket-context, skb-ctx and socket-lb into OUT_DIR.
set -euo pipefail
out=${1:?usage: tools/build-bpf.sh OUT_DIR}
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-$root/tmp}
mkdir -p "$tmp" "$out"
source "$HOME/.cargo/env" 2>/dev/null || true

nightly=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/crates/flowsdn-bpf/rust-toolchain.toml")
if ! rustup toolchain list | grep -q "^$nightly"; then
    rustup toolchain install "$nightly" --profile minimal --component rust-src
fi
# A toolchain installed by someone else (a build VM image, a rust-toolchain.toml
# auto-install) may lack rust-src, which -Z build-std needs. Adding it is a no-op
# when present.
rustup component add rust-src --toolchain "$nightly"

if ! command -v bpf-linker >/dev/null; then
    version=0.11.1
    sha=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8
    [ "$(uname -m)" = x86_64 ] || { echo "build-bpf: no pinned bpf-linker for $(uname -m)" >&2; exit 1; }
    dir="$tmp/bpf-linker-$version"
    archive="$dir/bpf-linker.tar.zst"
    mkdir -p "$dir"
    curl -fsSL -o "$archive" \
        "https://github.com/aya-rs/bpf-linker/releases/download/v$version/bpf-linker-x86_64-unknown-linux-musl.tar.zst"
    echo "$sha  $archive" | sha256sum -c --quiet -
    tar --zstd -xf "$archive" -C "$dir"
    linker=$(find "$dir" -type f -name bpf-linker | head -n1)
    [ -n "$linker" ] || { echo "build-bpf: bpf-linker not in the release archive" >&2; exit 1; }
    chmod +x "$linker"
    PATH="$(dirname "$linker"):$PATH"
fi

target=${CARGO_TARGET_DIR:-$root/crates/flowsdn-bpf/target}
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf \
--remap-path-prefix=$root=/flowsdn --remap-path-prefix=$cargo_home=/cargo \
--remap-path-prefix=$rustup_home=/rustup --remap-path-prefix=$target=/target" \
    cargo "+$nightly" build --manifest-path "$root/crates/flowsdn-bpf/Cargo.toml" \
    --target bpfel-unknown-none -Z build-std=core --release --locked \
    --target-dir "$target"
for o in smoke local-delivery loader-features socket-context skb-ctx socket-lb; do
    cp "$target/bpfel-unknown-none/release/$o" "$out/"
done
