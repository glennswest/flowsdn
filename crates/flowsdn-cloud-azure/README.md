# Azure ARM contracts

Transport-independent request planner for all 13 methods inventoried in spec 07,
with explicit Network `2024-03-01` and Compute `2024-07-01` API pins. A recoverable
LRO state machine distinguishes operation-status polling, Location polling,
resource polling, final resource fetch and confirmed terminal outcomes. It keeps
ownership on HTTP/parse errors, preserves initial and subsequent Retry-After,
and rejects polling/pagination URLs outside the selected cloud authority.

This crate sends no requests. It has no credentials, SDK pipeline, durable store,
scheduler, distributed VMSS lock or live Azure validation. Checkpoints contain
resource URLs, not bearer tokens; only trusted local persistence may restore them.
The caller must durably retain uncertain operations (including a rejected initial
response after a write may have reached Azure), enforce per-VMSS ownership,
schedule delays and retry budgets, disable automatic cross-origin redirects,
recover before issuing further writes, and obtain fresh credentials per request.
Numeric Retry-After seconds are supported; HTTP-date values return an error with
ownership retained. Names outside the conservative unescaped resource-name
subset are rejected rather than incorrectly encoded.

`tests/fixtures` are original synthetic protocol cases, not recorded cloud traffic.
They test all route pins, three cloud endpoints, async-header precedence,
initial delay, throttling, Location completion, terminal failures, restart,
malformed responses, URL confinement and final GET. ADR-0007 recorded cloud
replay and live drift checks remain separate acceptance gates.

## SDK evaluation (#105)

Audited published `azure_mgmt_network =0.21.0` and `azure_mgmt_compute =0.21.0`
archives, both `.cargo_vcs_info.json` commit
`893f50dae35f4fdf48c3c190e17d967b173533dc`, MIT license, `azure_core =0.21`
semver dependency. Network exposes package `2024-03`; Compute defaults to
`2024-07-01`. They do expose the required routes and raw-response `send()` APIs;
this audit does not classify them as unmaintained. However the generated NIC
`create_or_update::RequestBuilder::into_future` immediately issues its first
status GET without using the initial Retry-After and encloses progress in a
future with no restart checkpoint. A generated raw-send wrapper could correct
both, but would still require an application-owned polling protocol. Compute
`virtual_machine_scale_set_v_ms::update::RequestBuilder::into_future` also
re-enters `send()` on each nonterminal iteration, issuing another PUT rather
than a monitoring GET. That is an additional concrete reason to own polling.

Choose application-owned ARM REST operations and polling, with an `azure_core`
pipeline/`azure_identity` transport to be integrated and exactly pinned in a
separate dependency validation step. Neither Azure crate is added transitively
by this prototype. This is a source-audited generated-client comparison and a
REST-contract prototype (Linux validation is required), not a compiled generated-SDK experiment.

Sources (accessed 2026-09-22):

- [Network 0.21.0 source](https://docs.rs/crate/azure_mgmt_network/0.21.0/source/)
- [Compute 0.21.0 source](https://docs.rs/crate/azure_mgmt_compute/0.21.0/source/)
- [Official ARM asynchronous operation protocol](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations)
- [Official Azure Rust SDK](https://github.com/Azure/azure-sdk-for-rust)

No upstream executable source or fixtures were copied.
