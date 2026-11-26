#!/usr/bin/env bash
# Check a `flowsdn` golden tree that deploy/build-image.sh wrote (#598):
#
#   deploy/check-image.sh OUT
#
# The checks stormcos's deploy/test/stage-build.sh ran on the staged golden
# (its `flowsdn` case), moved here with the recipe, plus what the recipe
# itself promises: the agent is this checkout's version, the manifests are
# this checkout's, and other names and architectures are refused.
set -euo pipefail
out=${1:?usage: deploy/check-image.sh OUT}
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
# chroot needs root; as the build user, root of a user namespace of our own.
in_root() {
    if [ "$(id -u)" = 0 ]; then chroot "$out" "$@"; else unshare --map-root-user chroot "$out" "$@"; fi
}
dynamic() { python3 -c 'import sys; d=open(sys.argv[1],"rb").read(4096); sys.exit(0 if b"ld-linux" in d or b"ld-musl" in d else 1)' "$1"; }

# The CNI plugin stays static musl: it links no TLS (#171).
f="$out/opt/cni/bin/flowsdn"
[ -x "$f" ] || fail "no executable opt/cni/bin/flowsdn"
dynamic "$f" && fail "the CNI plugin is dynamically linked (#171)"
version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# The Kubernetes agent is GNU/glibc with Fedora's OpenSSL, so it must start
# inside the golden's own root with only what the golden carries (#171).
if [ -s "$out/usr/share/flowsdn/runtime-rpms.txt" ]; then
    v=$(in_root /flowsdn-agent --version 2>&1) || fail "the agent does not start in its own root: $v"
    n=$(in_root /usr/sbin/nft --version 2>&1) || fail "nft does not start in its own root: $n"
    [ -f "$out/etc/pki/tls/openssl.cnf" ] && [ -s "$out/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" ] \
        || fail "no OpenSSL config or CA trust in the golden (#171)"
    # One copy of libssl/libcrypto (#825): lib64 a link, .so.3 a link to the
    # one real file each.
    [ -L "$out/lib64" ] || fail "lib64 is a directory, not a link to usr/lib64 (#825)"
    for l in libssl libcrypto; do
        nreal=$(find "$out" -name "$l.so.3*" -type f | wc -l)
        [ "$nreal" = 1 ] || fail "$nreal real copies of $l.so.3 (#825)"
    done
    # Every runtime row names a file the tree has.
    while IFS="$(printf '\t')" read -r path rpm; do
        [ -e "$out$path" ] || fail "runtime-rpms.txt names $path ($rpm), not in the tree"
    done < "$out/usr/share/flowsdn/runtime-rpms.txt"
    echo "   flowsdn: agent in its own root: $v; $n; runtime from $(cut -f2 "$out/usr/share/flowsdn/runtime-rpms.txt" | sort -u | tr '\n' ' ')"
else
    dynamic "$out/flowsdn-agent" && fail "a dynamic agent with no runtime in the golden (#171)"
    v=$("$out/flowsdn-agent" --version 2>&1) || fail "the agent does not start: $v"
fi
case "$v" in *"$version"*) ;; *) fail "the agent says '$v', Cargo.toml says $version" ;; esac
# flowsdn's own manifests ride in its golden (#264): the agent DaemonSet, and
# the config with egress: stack (Services through the host, #265).
fm="$out/manifests/flowsdn.yaml"
grep -q '^kind: DaemonSet' "$fm" && grep -q '"egress": "stack"' "$fm" \
    || fail "no manifests/flowsdn.yaml with the agent DaemonSet and egress: stack (#264)"
set="deploy/stormcos/manifests"
[ -s "$out/usr/share/flowsdn/runtime-rpms.txt" ] && [ -d deploy/stormcos/manifests-kubernetes ] && set=deploy/stormcos/manifests-kubernetes
want=$(ls "$set"/*.yaml | LC_ALL=C sort | xargs -n1 basename | tr '\n' ' ')
got=$(sed -n 's|^# from flowsdn deploy/stormcos/manifests/||p' "$fm" | tr '\n' ' ')
[ "$want" = "$got" ] || fail "manifests/flowsdn.yaml holds '$got', $set has '$want'"
echo "   flowsdn: manifests/flowsdn.yaml from $set, $(grep -c '^kind:' "$fm") objects"
for d in proc sys dev tmp; do [ -d "$out/$d" ] || fail "no /$d mount point"; done
[ "$(stat -c %a "$out/tmp")" = 1777 ] || fail "/tmp is not 1777"

# Refusals: another name, another architecture.
set +e
deploy/build-image.sh flowsdn-other "$(mktemp -d)" > /dev/null 2>&1; a=$?
GOLDEN_ARCH=aarch64 deploy/build-image.sh flowsdn "$(mktemp -d)" > /dev/null 2>&1; b=$?
set -e
[ "$a" = 2 ] || fail "another name exits $a, not 2"
[ "$b" = 2 ] || fail "GOLDEN_ARCH=aarch64 exits $b, not 2"
echo "   flowsdn: other names and GOLDEN_ARCH=aarch64 refused (exit 2)"
echo "PASS: flowsdn golden tree $out"
