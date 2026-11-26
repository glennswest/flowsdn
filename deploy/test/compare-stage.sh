#!/usr/bin/env bash
# The cutover check for #598: build the `flowsdn` golden both ways at this
# commit, with this repo's deploy/build-image.sh and with stormcos's stage
# mode (deploy/test/stage-build.sh, ONLY=flowsdn EDITION=flowsdn, pinned to
# this commit), check both, and compare the trees path by path: type, mode,
# link target and content.
#
#   sc-build 'bash deploy/test/compare-stage.sh [stormcos-rev]'
set -euo pipefail
cd "$(dirname "$0")/../.."
rev=$(git rev-parse HEAD)
stormcos_rev=${1:-main}
w=$(mktemp -d "${TMPDIR:-/tmp}/flowsdn-compare.XXXXXX")
echo "== recipe: deploy/build-image.sh flowsdn at $rev"
bash deploy/build-image.sh flowsdn "$w/recipe"
bash deploy/check-image.sh "$w/recipe"
echo "== stage: stormcos $stormcos_rev deploy/test/stage-build.sh, flowsdn pinned to $rev"
git clone -q https://github.com/glennswest/stormcos.git "$w/stormcos"
git -C "$w/stormcos" checkout -q "$stormcos_rev"
echo "   stormcos at $(git -C "$w/stormcos" rev-parse --short HEAD)"
# stage-build.sh deletes its WORK at exit; keep a copy of the golden first.
sed 's|^trap cleanup EXIT$|trap '"'"'cp -a "$OUT/flowsdn" "$KEEP" 2>/dev/null; cleanup'"'"' EXIT|' \
    "$w/stormcos/deploy/test/stage-build.sh" > "$w/stormcos/deploy/test/stage-build-keep.sh"
grep -q 'KEEP' "$w/stormcos/deploy/test/stage-build-keep.sh" || { echo "compare: cannot hook stage-build.sh's cleanup" >&2; exit 1; }
( cd "$w/stormcos" && KEEP="$w/stage" WORK="$w/stagework" ONLY=flowsdn EDITION=flowsdn PIN="flowsdn=$rev" \
      bash deploy/test/stage-build-keep.sh ) > "$w/stage.log" 2>&1 \
    || { echo "compare: the stage failed:" >&2; tail -n 30 "$w/stage.log" >&2; exit 1; }
grep -E '^   flowsdn|^PASS|^FAIL' "$w/stage.log" || true
[ -d "$w/stage" ] || { echo "compare: the stage kept no golden" >&2; exit 1; }
echo "== compare"
listing() { (cd "$1" && find . -mindepth 1 -printf '%P\t%y\t%m\t%l\n' | LC_ALL=C sort); }
sums() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum); }
diff <(listing "$w/stage") <(listing "$w/recipe") > "$w/listing.diff" && same_list=yes || same_list=no
diff <(sums "$w/stage") <(sums "$w/recipe") > "$w/sums.diff" && same_sums=yes || same_sums=no
echo "   stage: $(listing "$w/stage" | wc -l) paths; recipe: $(listing "$w/recipe" | wc -l) paths"
echo "   paths, types, modes, links identical: $same_list"; [ "$same_list" = yes ] || head -n 40 "$w/listing.diff"
echo "   contents identical: $same_sums"; [ "$same_sums" = yes ] || head -n 40 "$w/sums.diff"
rm -rf "$w"
[ "$same_list" = yes ] && [ "$same_sums" = yes ] && echo "PASS: the recipe's tree is the stage's, byte for byte"
