#!/usr/bin/env bash
# Build flowsdn's standalone release artifacts (#294, ADR-0019).
#
#   deploy/release/build.sh OUT_DIR [TARGET...]
#       TARGET defaults to x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#
# For each target it builds the static agent (BPF objects embedded) and CNI
# from this commit and writes OUT_DIR/flowsdn-<version>-<arch>.tar.gz, then
# OUT_DIR/SHA256SUMS over every archive. These are for clusters that do not
# run stormcos. They are not part of the stormcos flowsdn golden, which stormcos
# composes from the binaries it builds itself, and nothing here uploads them:
# publishing a GitHub Release is a separate, recorded step (spec 22 §3.9.4).
#
# The archives are deterministic for a given set of binaries (sorted names,
# mtimes from the commit, root ownership, gzip without a name or time), and the
# binaries are built with remapped paths and SOURCE_DATE_EPOCH (spec 22 §3.8.7).
# Byte-identical binaries across machines are not claimed until two builds have
# been compared.
set -euo pipefail
out=${1:?usage: deploy/release/build.sh OUT_DIR [TARGET...]}
shift
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=${TMPDIR:-$root/tmp}
mkdir -p "$tmp" "$out"
out=$(cd "$out" && pwd)
source "$HOME/.cargo/env" 2>/dev/null || true

if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
    echo "release: the checkout has uncommitted changes" >&2
    exit 1
fi
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
revision=$(git -C "$root" rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git -C "$root" show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH CARGO_INCREMENTAL=0
cargo_home=${CARGO_HOME:-$HOME/.cargo}
target_dir=${CARGO_TARGET_DIR:-$root/target}
remap="--remap-path-prefix=$root=/flowsdn --remap-path-prefix=$cargo_home=/cargo"

# Every binary this ships is static musl; the Kubernetes-mode agent links
# Fedora's OpenSSL (ADR-0016) and is not a portable artifact.
for target in "${targets[@]}"; do
    case "$target" in
    x86_64-unknown-linux-musl) arch=amd64 ;;
    aarch64-unknown-linux-musl)
        arch=arm64
        # rustc links musl's own crt and libc; the GNU cross driver only links.
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-aarch64-linux-gnu-gcc}
        ;;
    *) echo "release: unsupported target $target" >&2; exit 1 ;;
    esac
    RUSTFLAGS="${RUSTFLAGS:-} $remap" cargo build --manifest-path "$root/Cargo.toml" \
        --release --locked --target "$target" -p flowsdn-agent -p flowsdn-cni
    name="flowsdn-$version-$arch"
    stage="$tmp/release/$name"
    rm -rf "$stage"
    mkdir -p "$stage"
    for bin in flowsdn-agent flowsdn-cni; do
        cp "$target_dir/$target/release/$bin" "$stage/"
        if file "$stage/$bin" | grep -q 'dynamically linked'; then
            echo "release: $target $bin is not static" >&2
            exit 1
        fi
    done
    cp "$root/bpf-objects.lock" "$root/LICENSE" "$root/NOTICE" "$stage/"
    cat >"$stage/README" <<EOF
flowsdn $version ($arch), source revision $revision.

flowsdn-agent   the endpoint agent; its BPF objects (bpf-objects.lock) are embedded
flowsdn-cni     the CNI plugin; 'flowsdn-cni install' copies it into /opt/cni/bin
                (as flowsdn-cni, flowsdn and loopback) and writes
                /etc/cni/net.d/00-flowsdn.conflist

Configuration and limits: https://github.com/glennswest/flowsdn/blob/$revision/docs/runtime.md
EOF
    printf '%s\n' "$revision" >"$stage/REVISION"
    find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
        -C "$tmp/release" -cf - "$name" | gzip -n -9 >"$out/$name.tar.gz"
    echo "release: $out/$name.tar.gz"
done
(cd "$out" && sha256sum flowsdn-*.tar.gz >SHA256SUMS && cat SHA256SUMS)
