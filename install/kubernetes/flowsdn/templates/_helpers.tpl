{{- define "flowsdn.labels" -}}
app.kubernetes.io/part-of: flowsdn
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "flowsdn.image" -}}
{{- $repository := required "image.repository is required: the registry holding the flowsdn agent image (images/agent)" .Values.image.repository -}}
{{ $repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "flowsdn.config" -}}
{{- $a := .Values.agent -}}
{{- $k := dict "auto-direct-node-routes" $a.autoDirectNodeRoutes "direct-routing-skip-unreachable" $a.directRoutingSkipUnreachable "service-lb" $a.serviceLB "cgroup-root" "/run/flowsdn/cgroupv2" -}}
{{- $c := dict "socket-path" "/var/run/flowsdn/flowsdn.sock" "delete-queue" "/var/run/flowsdn/deleteQueue" "state-dir" "/var/lib/flowsdn" "egress" $a.egress "device-mtu" $a.deviceMTU "route-mtu" $a.routeMTU "endpoint-id-max" $a.endpointIdMax "kubernetes" $k -}}
{{- if not (or $a.ipv4Pool $a.ipv6Pool) -}}
{{- fail "agent.ipv4Pool or agent.ipv6Pool must be set" -}}
{{- end -}}
{{- range $family := list "ipv4" "ipv6" -}}
{{- $pool := get $a (printf "%sPool" $family) -}}
{{- $gateway := get $a (printf "%sGateway" $family) -}}
{{- if $pool -}}
{{- $_ := set $c (printf "%s-pool" $family) $pool -}}
{{- if and (ne $pool "auto") (not $gateway) -}}
{{- fail (printf "agent.%sGateway is required with a fixed agent.%sPool" $family $family) -}}
{{- end -}}
{{- if $gateway -}}
{{- $_ := set $c (printf "%s-gateway" $family) $gateway -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $a.httpListen -}}
{{- $_ := set $c "http-listen" $a.httpListen -}}
{{- end -}}
{{- if $a.bpfPinRoot -}}
{{- $_ := set $c "bpf-pin-root" $a.bpfPinRoot -}}
{{- end -}}
{{- if not (has $a.egress (list "stack" "fib")) -}}
{{- fail "agent.egress must be stack or fib" -}}
{{- end -}}
{{- toPrettyJson (mergeOverwrite $c $a.extraConfig) -}}
{{- end -}}
