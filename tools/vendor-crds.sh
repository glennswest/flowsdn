#!/usr/bin/env bash
# Copy the 22 reference CRD documents into crates/flowsdn-k8s/crds (spec 13 §3.1).
#
#   tools/vendor-crds.sh REFERENCE_CHECKOUT
#
# REFERENCE_CHECKOUT is a cilium/cilium checkout at the pinned commit (a sparse
# checkout of pkg/k8s/apis/cilium.io/client/crds is enough). The files are
# copied byte for byte and crds/SHA256SUMS is regenerated; the flowsdn-k8s
# tests refuse a vendored file that does not match it. Changing the pin is a
# deliberate schema change: bump flowsdn_k8s::SCHEMA_VERSION and the changelog.
set -euo pipefail
pin=7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc
ref=${1:?usage: tools/vendor-crds.sh REFERENCE_CHECKOUT}
root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/crates/flowsdn-k8s/crds"
head=$(git -C "$ref" rev-parse HEAD)
[ "$head" = "$pin" ] || { echo "vendor-crds: $ref is at $head, not $pin" >&2; exit 1; }
src="$ref/pkg/k8s/apis/cilium.io/client/crds"
for version in v2 v2alpha1; do
    rm -rf "${dest:?}/$version"
    mkdir -p "$dest/$version"
    cp "$src/$version"/*.yaml "$dest/$version/"
done
(cd "$dest" && find v2 v2alpha1 -name '*.yaml' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS)
echo "vendored $(wc -l <"$dest/SHA256SUMS") CRDs from $pin"
