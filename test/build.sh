#!/usr/bin/env bash
# Stage flowsdn's test image for the commit checked out (#303).
#
#   test/build.sh [target]        default x86_64-unknown-linux-musl
#
# Per stormcentral docs/test-standard.md the runner calls this in the checkout
# on the build box, then runs `podman build -f test/Containerfile` with the repo
# root as context. It builds, from this commit:
#   - the BPF objects, with tools/build-bpf.sh (pinned nightly and bpf-linker),
#     and checks the agent's embedded local-delivery is this commit's,
#   - the agent, CNI, kernel fixtures and /test (static musl),
# and stages them in test/.stage. It does not build the image itself.
set -euo pipefail
target=${1:-x86_64-unknown-linux-musl}
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-$root/tmp}
mkdir -p "$tmp"
source "$HOME/.cargo/env" 2>/dev/null || true

stage="$root/test/.stage"
rm -rf "$stage"
mkdir -p "$stage/opt/flowsdn/bin" "$stage/opt/flowsdn/fixtures" "$stage/opt/flowsdn/bpf"
"$root/tools/build-bpf.sh" "$stage/opt/flowsdn/bpf"
# The agent embeds local-delivery; a copy older than this commit's BPF source
# would ship a datapath nobody built from it.
if ! cmp -s "$stage/opt/flowsdn/bpf/local-delivery" "$root/crates/flowsdn-agent/bpf/local-delivery"; then
    echo "test/build.sh: crates/flowsdn-agent/bpf/local-delivery is stale;" \
        "run tools/build-bpf.sh and commit the new local-delivery" >&2
    exit 1
fi

fixtures=(flowsdn-bpftest flowsdn-endpoint-test agent-runtime cni-runtime loader-features
    native-routing packet-ingress socket-live uplink-ingress)
cargo build --manifest-path "$root/Cargo.toml" --release --locked --target "$target" \
    -p flowsdn-agent -p flowsdn-cni -p flowsdn-bpftest -p flowsdn-test
out=${CARGO_TARGET_DIR:-$root/target}/$target/release

cp "$out/flowsdn-test" "$stage/test"
cp "$out/flowsdn-agent" "$out/flowsdn-cni" "$stage/opt/flowsdn/bin/"
for f in "${fixtures[@]}"; do cp "$out/$f" "$stage/opt/flowsdn/fixtures/"; done
for f in "$stage/test" "$stage"/opt/flowsdn/bin/* "$stage"/opt/flowsdn/fixtures/*; do
    if file "$f" | grep -q 'dynamically linked'; then
        echo "test/build.sh: $f is not static" >&2
        exit 1
    fi
done
du -sh "$stage"
echo "staged $stage"
