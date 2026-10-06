#!/usr/bin/env bash
# Stage flowsdn's test image for the commit checked out (#303).
#
#   test/build.sh [target]        default x86_64-unknown-linux-musl
#
# Per stormcentral docs/test-standard.md the runner calls this in the checkout
# on the build box, then runs `podman build -f test/Containerfile` with the repo
# root as context. It builds, from this commit:
#   - the BPF objects, with tools/build-bpf.sh (pinned nightly and bpf-linker),
#     and checks them and the agent's embedded copies against bpf-objects.lock,
#   - the agent, CNI, kernel fixtures and /test (static musl),
#   - flowsdn-perf, the perf suite (GNU, Fedora OpenSSL),
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
# bpf-objects.lock pins every object's code (#245), and the agent embeds
# local-delivery and socket-lb; a lock or embedded copy that is not this
# commit's build would ship a datapath nobody built from it.
"$root/tools/bpf-objects-lock.sh" check "$stage/opt/flowsdn/bpf"

fixtures=(flowsdn-bpftest flowsdn-endpoint-test agent-runtime cni-runtime loader-features
    native-routing packet-ingress socket-live socket-lb-live uplink-ingress skb-ctx-matrix)
cargo build --manifest-path "$root/Cargo.toml" --release --locked --target "$target" \
    -p flowsdn-agent -p flowsdn-cni -p flowsdn-bpftest -p flowsdn-test
out=${CARGO_TARGET_DIR:-$root/target}/$target/release

cp "$out/flowsdn-test" "$stage/test"
# The perf suite (#321) talks to the Kubernetes API over Fedora system OpenSSL
# (ADR-0016), so it is a GNU binary; the image carries openssl-libs.
gnu=x86_64-unknown-linux-gnu
cargo build --manifest-path "$root/Cargo.toml" --release --locked --target "$gnu" -p flowsdn-perf
cp "${CARGO_TARGET_DIR:-$root/target}/$gnu/release/flowsdn-perf" "$stage/opt/flowsdn/bin/"
cp "$out/flowsdn-agent" "$out/flowsdn-cni" "$stage/opt/flowsdn/bin/"
for f in "${fixtures[@]}"; do cp "$out/$f" "$stage/opt/flowsdn/fixtures/"; done
for f in "$stage/test" "$stage"/opt/flowsdn/bin/flowsdn-{agent,cni} "$stage"/opt/flowsdn/fixtures/*; do
    if file "$f" | grep -q 'dynamically linked'; then
        echo "test/build.sh: $f is not static" >&2
        exit 1
    fi
done
du -sh "$stage"
echo "staged $stage"
