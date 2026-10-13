#!/usr/bin/env bash
# rustc wrapper for tools/build-bpf.sh: appends the build-path remaps
# (FLOWSDN_BPF_REMAP, one flag per line) to each compilation. They are not in
# RUSTFLAGS because cargo hashes RUSTFLAGS into every crate's -C metadata, so
# the checkout, target and home paths changed symbol hashes and, with them,
# the linked code: the same commit built in two directories gave two
# local-delivery objects (#292, test image 3937417bc1).
set -euo pipefail
rustc=$1
shift
for arg in "$@"; do
    if [ "$arg" = --crate-name ]; then
        mapfile -t remap <<<"${FLOWSDN_BPF_REMAP:-}"
        exec "$rustc" "$@" "${remap[@]}"
    fi
done
exec "$rustc" "$@"
