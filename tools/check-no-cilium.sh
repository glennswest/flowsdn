#!/usr/bin/env bash
# Refuse "cilium" (any case) in what flowsdn ships (#330; owner: "no cilium in
# flowsdn period"): binaries, BPF objects, archives' contents, manifests and
# chart files. Pass files or directories; directories are searched
# recursively. Binaries are searched as bytes, so a map, pin, config key or
# message name in an executable or object fails too. Exit 1 names each file.
# NOTICE and LICENSE* are skipped: Apache-2.0 attribution for material derived
# from the reference project must travel with it, and is not a flowsdn name.
set -euo pipefail
if [ "$#" -eq 0 ]; then
    echo "usage: tools/check-no-cilium.sh FILE_OR_DIR..." >&2
    exit 2
fi
found=0
while IFS= read -r -d '' file; do
    if LC_ALL=C grep -aqi cilium "$file"; then
        echo "check-no-cilium: $file: $(LC_ALL=C grep -aoi '[[:alnum:]_./:-]*cilium[[:alnum:]_./:-]*' "$file" | sort -u | head -5 | tr '\n' ' ')" >&2
        found=1
    fi
done < <(find "$@" -type f ! -name NOTICE ! -name 'LICENSE*' -print0)
if [ "$found" -ne 0 ]; then
    echo "check-no-cilium: shipped artifacts name Cilium (#330)" >&2
    exit 1
fi
echo "check-no-cilium: $(find "$@" -type f ! -name NOTICE ! -name 'LICENSE*' | wc -l) files clean"
