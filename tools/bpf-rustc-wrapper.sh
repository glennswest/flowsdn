#!/usr/bin/env bash
# rustc wrapper for tools/build-bpf.sh. Makes the BPF objects independent of
# the directory the commit is built in:
#
# - It appends the build-path remaps (FLOWSDN_BPF_REMAP, one flag per line) to
#   each compilation. They are not in RUSTFLAGS because cargo hashes RUSTFLAGS
#   into every crate's -C metadata (test image 3937417bc1, #292).
# - It replaces cargo's -C metadata for flowsdn's own crates (those whose
#   CARGO_MANIFEST_DIR is under FLOWSDN_BPF_ROOT) with a hash of the crate
#   name, its manifest directory relative to the checkout and the rest of the
#   compile arguments. flowsdn-bpf-abi lies outside the crates/flowsdn-bpf
#   workspace, so cargo hashes its absolute path into its metadata, and every
#   flowsdn-bpf binary inherits that hash. The metadata seeds rustc's crate
#   ids, and with them LLVM's stack-slot assignment: the same commit built in
#   /work/job/src and in a test-image directory gave local-delivery objects
#   that differed in stack offsets (#292, test images db5d9fc564, 52ddea67d7).
#   -C extra-filename (the output file names cargo links by) is left as is.
set -euo pipefail
rustc=$1
shift
is_compile=0
for arg in "$@"; do
    [ "$arg" = --crate-name ] && is_compile=1
done
[ "$is_compile" = 1 ] || exec "$rustc" "$@"

mapfile -t remap <<<"${FLOWSDN_BPF_REMAP:-}"
root=${FLOWSDN_BPF_ROOT:-}
manifest=${CARGO_MANIFEST_DIR:-}
if [ -z "$root" ] || [ -z "$manifest" ] || [[ "$manifest/" != "$root/"* ]]; then
    exec "$rustc" "$@" "${remap[@]}"
fi

# Path-free inputs: the manifest directory relative to the checkout, and the
# crate name, type, edition, target, cfgs and source file. (--extern paths are
# left out: their file names carry cargo's path-dependent hashes.)
rel=${manifest#"$root"}
key="manifest=$rel"
args=("$@")
for i in "${!args[@]}"; do
    a=${args[$i]}
    case "$a" in
    --crate-name | --crate-type | --edition | --cfg | --target)
        key+=$'\n'"$a=${args[$((i + 1))]:-}" ;;
    --edition=* | --target=*) key+=$'\n'"$a" ;;
    *.rs) key+=$'\n'"src=${a#"$root"}" ;;
    esac
done
meta=$(printf '%s' "$key" | sha256sum | cut -c1-16)

out=()
skip_next=0
for i in "${!args[@]}"; do
    a=${args[$i]}
    if [ "$skip_next" = 1 ]; then skip_next=0; continue; fi
    case "$a" in
    -C)
        next=${args[$((i + 1))]:-}
        if [[ "$next" == metadata=* ]]; then
            out+=(-C "metadata=$meta")
            skip_next=1
            continue
        fi
        ;;
    -Cmetadata=*) out+=("-Cmetadata=$meta"); continue ;;
    esac
    out+=("$a")
done
exec "$rustc" "${out[@]}" "${remap[@]}"
