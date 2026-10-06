#!/usr/bin/env bash
# Check the flowsdn chart (#294): lint, render, versions, guards, names.
#
#   install/kubernetes/check.sh
#
# Needs helm. Renders with an example image (no image is published) and fails
# on a chart version that differs from the workspace, a render that names
# Cilium, or a guard that does not refuse what it should.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
chart="$root/install/kubernetes/flowsdn"
tmp=${TMPDIR:-$root/tmp}
mkdir -p "$tmp"
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
grep -qx "version: $version" "$chart/Chart.yaml" || { echo "check: Chart.yaml version is not $version" >&2; exit 1; }
grep -qx "appVersion: \"$version\"" "$chart/Chart.yaml" || { echo "check: Chart.yaml appVersion is not $version" >&2; exit 1; }
set=(--set image.repository=registry.example/flowsdn-agent)
helm lint --strict "$chart" "${set[@]}"
render="$tmp/chart-render.yaml"
helm template flowsdn "$chart" --namespace kube-system --include-crds "${set[@]}" >"$render"
helm template flowsdn "$chart" --namespace kube-system "${set[@]}" \
    --set agent.ipv4Pool=10.244.0.0/16 --set agent.ipv4Gateway=10.244.0.1 \
    --set agent.ipv6Pool=fd00:10::/64 --set agent.ipv6Gateway=fd00:10::1 \
    --set agent.bpfPinRoot=/sys/fs/bpf/flowsdn --set agent.httpListen= >"$tmp/chart-render-fixed.yaml"
if grep -qi cilium "$render" "$tmp/chart-render-fixed.yaml"; then
    grep -ni cilium "$render" "$tmp/chart-render-fixed.yaml" | head >&2
    echo "check: the rendered chart names Cilium" >&2
    exit 1
fi
crds=$(grep -c '^kind: CustomResourceDefinition$' "$render")
[ "$crds" = 22 ] || { echo "check: $crds CRDs rendered, not 22" >&2; exit 1; }
for kind in ServiceAccount ClusterRole ClusterRoleBinding ConfigMap DaemonSet; do
    grep -q "^kind: $kind$" "$render" || { echo "check: no $kind rendered" >&2; exit 1; }
done
refuse() {
    local why=$1
    shift
    if out=$(helm template flowsdn "$chart" "$@" 2>&1); then
        echo "check: rendered although $why" >&2
        exit 1
    fi
    echo "refused ($why): $(echo "$out" | grep -o 'error.*' | head -1)"
}
refuse "no image.repository"
refuse "fixed pool without gateway" "${set[@]}" --set agent.ipv4Pool=10.244.0.0/16
refuse "no pool" "${set[@]}" --set agent.ipv4Pool=
refuse "bad egress" "${set[@]}" --set agent.egress=tunnel
echo "chart flowsdn $version: lint, render (22 CRDs), guards and names pass"
