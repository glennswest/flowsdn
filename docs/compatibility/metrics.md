# Operator metrics and dashboard changes

This is the dashboard migration contract for a Cilium-compatible flowsdn
operator (spec12 §8.1, decision #163). The current operator crate contains
planning primitives only: it does not yet expose a metrics server or runtime
collectors. Apply these dashboard changes when deploying that server; an empty
panel today is not evidence of a running operator.

Application metrics retain the `cilium_operator_*` names, types and labels in
[the operator specification](../spec/12-operator.md#81-metrics). Preserve their
queries. Do not rename them to `flowsdn_operator_*` or change label names such
as identity GC's `status` versus `outcome`.

| Existing panel or alert query | flowsdn dashboard change | Meaning and limits |
|---|---|---|
| `go_goroutines` or `cilium_operator_go_goroutines` | Remove or hide the panel and its threshold alert for flowsdn targets | No equivalent is promised; Tokio tasks are not goroutines |
| `go_memstats_*` or `cilium_operator_go_memstats_*` | Remove Go heap/allocation/GC panels and alerts | Rust allocator data cannot reproduce the Go memory model |
| `go_gc_duration_seconds*`, `go_threads`, `go_info` and their operator-prefixed forms | Remove Go-specific rows and recording rules for flowsdn targets | Neither GC behavior nor a Go version exists for this runtime |
| `cilium_operator_process_resident_memory_bytes` | `process_resident_memory_bytes{job="flowsdn-operator"}` | Resident process memory, not managed heap usage |
| `cilium_operator_process_cpu_seconds_total` | `rate(process_cpu_seconds_total{job="flowsdn-operator"}[5m])` | CPU seconds per second; retune thresholds from measured workload |
| `cilium_operator_process_open_fds` / `cilium_operator_process_max_fds` | `process_open_fds{job="flowsdn-operator"} / process_max_fds{job="flowsdn-operator"}` | Open-file ratio where both process collectors are available |
| `cilium_operator_process_start_time_seconds` | `time() - process_start_time_seconds{job="flowsdn-operator"}` | Process uptime in seconds; deployment restarts remain visible |

These `process_*` names are the required future Linux process-collector
contract. They are not aliases for the removed Go metrics. Substitute the
actual scrape job label for `flowsdn-operator` in the examples. In a mixed
rollout, separate target sets explicitly: keep Go panels scoped to reference
operator jobs and process panels scoped to flowsdn jobs. Avoid broad name regex
queries or unconditional unions that double-count both collectors.

Use `up{job="flowsdn-operator"} == 0` for scrape failure after the scrape target
exists. Do not use missing `go_*` series as an operator-down alert, and do not
fill missing runtime data with zero: that would report a healthy measurement
that was never collected. Before rollout, audit recording rules and alerts as
well as visible panels for both unprefixed and `cilium_operator_go_*` names.

Helm compatibility guidance must link this document. A dashboard/collector
integration test must verify the process series, unchanged application labels,
and absence of synthetic Go series before claiming monitoring compatibility.
No dashboard JSON or collector implementation is shipped by this document.
