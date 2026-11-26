#!/usr/bin/env bash
# The `flowsdn` golden — the flowsdn edition's pod network: the agent, the CNI
# plugin and the edition's manifests — built here, from this checkout, and
# nowhere else (#598, stormcentral#1836: "do repos, repos are not expensive";
# stormcos's stage mode is retired).
#
#   deploy/build-image.sh flowsdn OUT
#
# stormcentral's component build runs it for the `flowsdn` component (kind
# `tree`: `deploy/build-golden.sh flowsdn OUT`, which execs this) in a checkout
# fetched at the exact commit, on a fresh build VM, as root of the build's own
# user namespace. OUT is copied into the sealed read-only golden
# `golden-flowsdn-<build>`, sized from the content, with `SBOM/crates.csv`
# added by the platform. It is the `flowsdn` member of the flowsdn flavor's
# system pallet (stormcos deploy/image.toml, `edition = "flowsdn"`), laid at
# /pallets/flowsdn; the apiserver applies manifests/flowsdn.yaml through
# stormcos's link 60-flowsdn.yaml, and the DaemonSet runs `image: flowsdn`.
#
# The tree, as stormcos's deploy/build-goldens.sh staged it until 2026-11-26
# (its "flowsdn — the pod network, built rather than pulled" recipe, moved
# here with its content unchanged):
#
#   flowsdn-agent           the agent. With the `kubernetes` feature (always,
#                           since #171): GNU/glibc, linked to Fedora's
#                           OpenSSL (ADR-0016), so the golden carries its
#                           runtime below
#   opt/cni/bin/flowsdn     the CNI plugin, static x86_64 musl (it links no
#                           TLS). The `install-cni` init container copies it
#                           to the node's /opt/cni/bin
#   usr/sbin/nft            the build box's nft, for the masquerade (#261)
#   usr/lib64/…, lib64 -> usr/lib64
#                           every library the agent and nft load, the ELF
#                           interpreter included: one copy each (#825);
#                           libssl/libcrypto and the OpenSSL providers are the
#                           fetched Fedora pair the agent was built against
#   etc/pki/tls/openssl.cnf, etc/crypto-policies/…, usr/share/crypto-policies/…
#                           OpenSSL's config and what it includes
#   etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, etc/pki/tls/certs/ca-bundle.crt
#                           the CA trust
#   usr/share/flowsdn/runtime-rpms.txt
#                           each runtime file with the RPM it came from
#   manifests/flowsdn.yaml  deploy/stormcos/manifests-kubernetes/*.yaml, in
#                           order, one file (#264): the same commit as the
#                           binaries, so the two always match
#   proc/ sys/ dev/ tmp/    the mount points every container root needs (tmp
#                           1777), as the stage's golden_from_dir made them
#
# The profile is the rule stage and component builds share: `dist` when
# Cargo.toml defines one, else `release`. The musl build is the stage's
# `-p flowsdn-agent -p flowsdn-cni` (one cargo invocation, so the CNI's
# features unify as they did); its musl agent is replaced by the GNU one, as
# the stage replaced it.
#
# Needs on the build VM, as the stage did: cargo (with the musl and gnu
# targets), dnf (download only: nothing is installed), rpm, rpm2cpio, cpio,
# ldd, nft. x86_64 only, as in stage mode: any other GOLDEN_ARCH is refused.
# deploy/check-image.sh OUT checks the tree (the stage's flowsdn checks).
set -euo pipefail
name=${1:?usage: deploy/build-image.sh flowsdn OUT}
out=${2:?usage: deploy/build-image.sh flowsdn OUT}
[ "$name" = flowsdn ] || { echo "build-image: this repo builds only 'flowsdn', not '$name'" >&2; exit 2; }
arch=${GOLDEN_ARCH:-x86_64}
[ "$arch" = x86_64 ] || { echo "build-image: flowsdn is built for x86_64 only (GOLDEN_ARCH=$arch)" >&2; exit 2; }
cd "$(dirname "$0")/.."
src=$PWD
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
MUSL=x86_64-unknown-linux-musl
GNU=x86_64-unknown-linux-gnu
if command -v rustup >/dev/null 2>&1; then
    rustup target add "$MUSL" "$GNU" >/dev/null 2>&1 || true
fi
target_dir=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || true)
[ -n "$target_dir" ] || target_dir="$src/target"
commit=$(git rev-parse HEAD)
profile=release; grep -q '^\[profile\.dist\]' Cargo.toml && profile=dist
pflag=--release; [ "$profile" = dist ] && pflag="--profile dist"
work=$(mktemp -d "${TMPDIR:-/tmp}/flowsdn-image.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
chmod 0755 "$out"

# The two binaries, static musl, as the stage's COMPONENTS row built them
# (`flowsdn|…|flowsdn-agent flowsdn-cni|yes|flowsdn-agent flowsdn-cni`).
echo "==> cargo build $pflag --locked --target $MUSL -p flowsdn-agent -p flowsdn-cni ($commit)"
# shellcheck disable=SC2086
cargo build $pflag --quiet --locked --target "$MUSL" -p flowsdn-agent -p flowsdn-cni
mkdir -p "$out/opt/cni/bin"
cp "$target_dir/$MUSL/$profile/flowsdn-agent" "$out/flowsdn-agent"
cp "$target_dir/$MUSL/$profile/flowsdn-cni" "$out/opt/cni/bin/flowsdn"
chmod 755 "$out/flowsdn-agent" "$out/opt/cni/bin/flowsdn"

# The Kubernetes-connected agent and its Fedora runtime (#171 part B).
# OpenSSL: the current openssl-devel and openssl-libs from Fedora, fetched as
# a pair onto the build's drive (nothing is installed on the box), built
# against and shipped together, so headers and libraries always match.
kube=""
manifests="$src/deploy/stormcos/manifests"
if grep -q '^kubernetes *=' crates/flowsdn-agent/Cargo.toml; then
    kube=yes
    ossl="$work/openssl"; mkdir -p "$ossl/rpm" "$ossl/root" "$ossl/lib" "$work/dnf/log" "$work/dnf/cache" "$work/dnf/persist"
    ( cd "$ossl/rpm" && dnf -q --setopt=cachedir="$work/dnf/cache" --setopt=persistdir="$work/dnf/persist" \
          --setopt=logdir="$work/dnf/log" --setopt=countme=0 download --arch=x86_64 openssl-devel openssl-libs ) > "$ossl/dnf.out" 2>&1 \
        || { echo "build-image: cannot fetch openssl-devel and openssl-libs:" >&2; tail -n 8 "$ossl/dnf.out" | sed 's/^/     /' >&2; exit 1; }
    for r in "$ossl"/rpm/*.rpm; do ( cd "$ossl/root" && rpm2cpio "$r" | cpio -idm --quiet ); done
    osslv=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$ossl"/rpm/openssl-libs-*.rpm 2>/dev/null | head -1)
    ln -s "$ossl/root/usr/lib64/libssl.so.3" "$ossl/lib/libssl.so"
    ln -s "$ossl/root/usr/lib64/libcrypto.so.3" "$ossl/lib/libcrypto.so"
    echo "==> cargo build $pflag --locked --target $GNU -p flowsdn-agent --features kubernetes (OpenSSL $osslv)"
    # shellcheck disable=SC2086
    if ! OPENSSL_NO_VENDOR=1 OPENSSL_INCLUDE_DIR="$ossl/root/usr/include" OPENSSL_LIB_DIR="$ossl/lib" \
           cargo build $pflag --quiet --locked --target "$GNU" -p flowsdn-agent --features kubernetes > "$ossl/build.log" 2>&1; then
        echo "build-image: the Kubernetes agent did not build:" >&2; tail -n 15 "$ossl/build.log" | sed 's/^/     /' >&2; exit 1
    fi
    cp "$target_dir/$GNU/$profile/flowsdn-agent" "$out/flowsdn-agent"; chmod 755 "$out/flowsdn-agent"
    # nft, for the edition's masquerade (the node provides it: docs/runtime.md; #261).
    nftbin=$(command -v nft) || { echo "build-image: no nft on the build box" >&2; exit 1; }
    mkdir -p "$out/usr/sbin"; cp "$nftbin" "$out/usr/sbin/nft"
    # The runtime closure: every library the two binaries load, at its own
    # path, and the files OpenSSL reads. One copy of each library (#825):
    # /lib64 is a link to usr/lib64 from the start (as on Fedora), every path
    # is taken as its /usr one, and the box's libssl/libcrypto are never
    # copied, since the fetched pair below replaces them.
    rt="$out/usr/share/flowsdn/runtime-rpms.txt"; mkdir -p "$(dirname "$rt")"; : > "$rt"
    mkdir -p "$out/usr/lib64"; ln -sfn usr/lib64 "$out/lib64"
    {
        for b in "$out/flowsdn-agent" "$out/usr/sbin/nft"; do
            ldd "$b" | awk '/=> \//{print $3} /^\t\/lib64\/ld-linux/{print $1}'
        done
        echo /etc/pki/tls/openssl.cnf
        find /etc/crypto-policies/back-ends /usr/share/crypto-policies/back-ends/DEFAULT -maxdepth 1 2>/dev/null
        find /usr/lib64/ossl-modules -maxdepth 1 -type f 2>/dev/null
        echo /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    } | sed 's#^/lib64/#/usr/lib64/#' | sort -u | while read -r f; do
        [ -e "$f" ] || continue
        case "${f##*/}" in libssl.so.3*|libcrypto.so.3*) continue ;; esac
        mkdir -p "$out$(dirname "$f")"
        cp -aL "$f" "$out$f" 2>/dev/null || cp -L "$f" "$out$f"
        printf '%s\t%s\n' "$f" "$(rpm -qf "$f" 2>/dev/null | head -1)" >> "$rt"
    done
    # libssl/libcrypto and the providers are the fetched pair, not the box's.
    # As shipped: the versioned file, and .so.3 the RPM's own link to it.
    for f in "$ossl"/root/usr/lib64/libssl.so.3* "$ossl"/root/usr/lib64/libcrypto.so.3*; do
        [ -e "$f" ] || continue
        rm -f "$out/usr/lib64/$(basename "$f")"
        cp -a "$f" "$out/usr/lib64/$(basename "$f")"
    done
    if [ -d "$ossl/root/usr/lib64/ossl-modules" ]; then
        mkdir -p "$out/usr/lib64/ossl-modules"; cp -L "$ossl"/root/usr/lib64/ossl-modules/* "$out/usr/lib64/ossl-modules/"
    fi
    sed -i '/libssl\.so\.3\|libcrypto\.so\.3\|ossl-modules/d' "$rt"
    for f in libssl.so.3 libcrypto.so.3; do
        printf '/usr/lib64/%s\t%s\n' "$f" "$(basename "$ossl"/rpm/openssl-libs-*.rpm .rpm)" >> "$rt"
    done
    mkdir -p "$out/etc/pki/tls/certs"
    ln -sfn /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem "$out/etc/pki/tls/certs/ca-bundle.crt"
    echo "==> flowsdn: Kubernetes agent (GNU, Fedora OpenSSL $osslv), runtime $(wc -l < "$rt") files from $(cut -f2 "$rt" | sort -u | grep -c .) RPMs; nft $(nft --version 2>/dev/null | awk '{print $2}')"
    # With the Kubernetes agent, its own set (#291).
    [ -d "$src/deploy/stormcos/manifests-kubernetes" ] && manifests="$src/deploy/stormcos/manifests-kubernetes"
fi

# The edition's manifests (#264): one file, in order, so the apiserver's
# single link to it never goes stale when one is renamed. The header names
# deploy/stormcos/manifests/ for every file, as the stage wrote it.
ls "$manifests"/*.yaml > /dev/null 2>&1 || { echo "build-image: no manifests at $manifests" >&2; exit 1; }
mkdir -p "$out/manifests"
for f in $(ls "$manifests"/*.yaml | LC_ALL=C sort); do
    printf -- '---\n# from flowsdn deploy/stormcos/manifests/%s\n' "$(basename "$f")"
    cat "$f"
    echo
done > "$out/manifests/flowsdn.yaml"
echo "==> flowsdn: manifests $(ls "$manifests"/*.yaml | xargs -n1 basename | tr '\n' ' ')"

# The mount points every container runtime expects (the stage's golden_from_dir).
mkdir -p "$out/proc" "$out/sys" "$out/dev" "$out/tmp"
chmod 1777 "$out/tmp"

# Read back what was copied: a short copy is never sealed (stormcentral#716).
if [ -n "$kube" ]; then
    [ "$(sha256sum < "$out/flowsdn-agent")" = "$(sha256sum < "$target_dir/$GNU/$profile/flowsdn-agent")" ] \
        || { echo "build-image: flowsdn-agent does not read back as built" >&2; exit 1; }
fi
[ "$(sha256sum < "$out/opt/cni/bin/flowsdn")" = "$(sha256sum < "$target_dir/$MUSL/$profile/flowsdn-cni")" ] \
    || { echo "build-image: opt/cni/bin/flowsdn does not read back as built" >&2; exit 1; }

echo "==> flowsdn golden tree in $out at $commit (${kube:+kubernetes, }profile $profile)"
(cd "$out" && find . -mindepth 1 -maxdepth 3 -printf '%M %10s %P\n' | LC_ALL=C sort -k3)
sha256sum "$out/flowsdn-agent" "$out/opt/cni/bin/flowsdn" "$out/manifests/flowsdn.yaml" | sed "s|$out/||"
