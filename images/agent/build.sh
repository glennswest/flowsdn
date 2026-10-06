#!/usr/bin/env bash
# Build the flowsdn agent image for the standalone chart (#294).
#
#   images/agent/build.sh [OUT_DIR]
#
# Builds the GNU Kubernetes-mode agent and the static CNI for x86_64 from this
# commit, then `podman build` with the repository root as context, tagged
# localhost/flowsdn-agent:<version>. With OUT_DIR it also writes
# OUT_DIR/flowsdn-agent-<version>-amd64.oci.tar. It pushes nothing.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${1:-}
source "$HOME/.cargo/env" 2>/dev/null || true
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
revision=$(git -C "$root" rev-parse HEAD)
target_dir=${CARGO_TARGET_DIR:-$root/target}
cargo build --manifest-path "$root/Cargo.toml" --release --locked \
    --target x86_64-unknown-linux-gnu -p flowsdn-agent --features flowsdn-agent/kubernetes
cargo build --manifest-path "$root/Cargo.toml" --release --locked \
    --target x86_64-unknown-linux-musl -p flowsdn-cni
stage="$root/images/agent/.stage"
rm -rf "$stage"
mkdir -p "$stage"
cp "$target_dir/x86_64-unknown-linux-gnu/release/flowsdn-agent" "$stage/"
cp "$target_dir/x86_64-unknown-linux-musl/release/flowsdn-cni" "$stage/"
image="localhost/flowsdn-agent:$version"
podman build -f "$root/images/agent/Containerfile" --build-arg "VERSION=$version" \
    --build-arg "REVISION=$revision" -t "$image" "$root"
podman run --rm --entrypoint /usr/bin/flowsdn-agent "$image" --version
if [ -n "$out" ]; then
    mkdir -p "$out"
    podman save --format oci-archive -o "$out/flowsdn-agent-$version-amd64.oci.tar" "$image"
    echo "image: $out/flowsdn-agent-$version-amd64.oci.tar"
fi
