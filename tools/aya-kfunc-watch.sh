#!/usr/bin/env bash
# Does aya relocate kfunc calls yet? (#315)
#
#   tools/aya-kfunc-watch.sh [--load] [--file-issue] [SOURCE...]
#
# SOURCE is `release` (the latest aya on crates.io), `main` (aya's main
# branch) or `pinned` (the aya the workspace uses); default: release main.
# The loader-kfunc object (iter/tcp calling bpf_sock_destroy) is built by
# tools/build-bpf.sh with the pinned bpf-linker and, if newer, with the latest
# bpf-linker release: a Rust object needs the linker to emit the extern in a
# `.ksyms` BTF datasec before any aya can resolve it. For each object and
# SOURCE it builds tools/aya-kfunc-watch against that aya and loads the
# object. Relocation needs no privileges; --load also loads the program into
# the kernel (privileged; never attached or run).
#
# Exit 0: no combination relocates the kfunc yet; nothing to do.
# Exit 3: some aya does: switch socket termination to bpf_sock_destroy (#315).
# Exit 1: the check is broken (an aya the probe does not build against, an
#         unexpected load error): look at it.
# --file-issue: on exit 3, open (or comment on) the P1 issue
# "aya relocates kfuncs: switch socket termination to bpf_sock_destroy"
# with gh; it needs gh authenticated for this repository.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=${TMPDIR:-$root/tmp}/aya-kfunc-watch
load=() file_issue=0 sources=()
for arg in "$@"; do
    case $arg in
        --load) load=(--load) ;;
        --file-issue) file_issue=1 ;;
        release | main | pinned) sources+=("$arg") ;;
        *) echo "usage: $0 [--load] [--file-issue] [release|main|pinned]..." >&2; exit 1 ;;
    esac
done
[ ${#sources[@]} -gt 0 ] || sources=(release main)
rm -rf "$work"
mkdir -p "$work"
source "$HOME/.cargo/env" 2>/dev/null || true

# Build loader-kfunc with the bpf-linker on PATH (or the pinned download).
build_object() { # NAME
    local target="$work/bpf-target-$1"
    if ! CARGO_TARGET_DIR="$target" "$root/tools/build-bpf.sh" "$work/bpf-$1" >&2; then
        return 1
    fi
    echo "$target/bpfel-unknown-none/release/loader-kfunc"
}
pinned_linker=v$(sed -n 's/^    version=\(.*\)$/\1/p' "$root/tools/build-bpf.sh")
objects=() linkers=()
if object=$(build_object pinned) && [ -f "$object" ]; then
    objects+=("$object") linkers+=("bpf-linker $pinned_linker")
else
    echo "aya-kfunc-watch: broken: tools/build-bpf.sh failed" >&2
    exit 1
fi
latest_linker=$(curl -fsSL https://api.github.com/repos/aya-rs/bpf-linker/releases/latest |
    sed -n 's/^  "tag_name": "\(.*\)",$/\1/p')
if [ -z "$latest_linker" ]; then
    echo "aya-kfunc-watch: broken: cannot read the latest bpf-linker release" >&2
    exit 1
elif [ "$latest_linker" != "$pinned_linker" ]; then
    # A watch, not a shipped build: the latest release is not checksum-pinned.
    dir="$work/bpf-linker-$latest_linker"
    mkdir -p "$dir"
    if curl -fsSL "https://github.com/aya-rs/bpf-linker/releases/download/$latest_linker/bpf-linker-x86_64-unknown-linux-musl.tar.zst" |
        tar --zstd -x -C "$dir" && linker=$(find "$dir" -type f -name bpf-linker | head -n1) &&
        [ -n "$linker" ] && chmod +x "$linker" &&
        object=$(PATH="$(dirname "$linker"):$PATH" build_object latest) && [ -f "$object" ]; then
        objects+=("$object") linkers+=("bpf-linker $latest_linker")
    else
        echo "aya-kfunc-watch: broken: cannot build with bpf-linker $latest_linker" >&2
        exit 1
    fi
fi

dependency() {
    case $1 in
        release) echo 'aya = "*"' ;;
        main) echo 'aya = { git = "https://github.com/aya-rs/aya", branch = "main" }' ;;
        pinned) sed -n 's/^aya = \(".*"\)$/aya = \1/p' "$root/crates/flowsdn-bpftest/Cargo.toml" ;;
    esac
}

overall=0 summary=""
for src in "${sources[@]}"; do
    dir="$work/$src"
    cp -r "$root/tools/aya-kfunc-watch" "$dir"
    rm -f "$dir/Cargo.lock"
    dep=$(dependency "$src")
    sed -i "s|^aya = .*# aya-kfunc-watch: replaced per run$|$dep|" "$dir/Cargo.toml"
    # pinned: the repository's toolchain; release/main: the latest stable,
    # since aya main follows new rustc releases (it needed 1.98 on 2026-10-05).
    if [ "$src" = pinned ]; then
        toolchain=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml")
    else
        toolchain=stable
        rustup toolchain list | grep -q '^stable' ||
            rustup toolchain install stable --profile minimal >&2
    fi
    if ! cargo "+$toolchain" build --release --quiet --manifest-path "$dir/Cargo.toml" \
        --target-dir "$work/target-$src" >"$work/$src.build" 2>&1; then
        entry="$src aya (did not build): broken: the probe does not build against this aya: $(tail -n 20 "$work/$src.build")"
        echo "aya-kfunc-watch: $entry"
        summary+="- $entry"$'\n'
        [ "$overall" = 3 ] || overall=1
        continue
    fi
    version=$(awk '/^name = "aya"$/{getline; v=$3; getline; s=$3; print v, s; exit}' \
        "$dir/Cargo.lock" | tr -d '"')
    for i in "${!objects[@]}"; do
        line=$("$work/target-$src/release/flowsdn-aya-kfunc-watch" "${objects[$i]}" "${load[@]}")
        rc=$?
        entry="$src aya ${version:-?}, ${linkers[$i]}: $line"
        echo "aya-kfunc-watch: $entry"
        summary+="- $entry"$'\n'
        if [ "$rc" = 3 ]; then
            overall=3
        elif [ "$rc" != 0 ] && [ "$overall" != 3 ]; then
            overall=1
        fi
    done
done

if [ "$overall" = 3 ] && [ "$file_issue" = 1 ]; then
    title="aya relocates kfuncs: switch socket termination to bpf_sock_destroy"
    body="tools/aya-kfunc-watch.sh found an aya that relocates the \`bpf_sock_destroy\` kfunc call (#315):

$summary
Switch (#315 part 2): bump aya, use \`bpf_sock_destroy\` from eBPF for policy-driven socket termination, keep netlink SOCK_DIAG/SOCK_DESTROY as the fallback for kernels without the kfunc, and test each path."
    existing=$(gh issue list --state open --search "\"$title\" in:title" --json number -q '.[0].number')
    if [ -n "$existing" ]; then
        gh issue comment "$existing" --body "$body"
    else
        gh issue create --title "$title" --label priority/P1 --body "$body"
    fi
fi
exit "$overall"
