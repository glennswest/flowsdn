# ADR-0004: No Hive, no StateDB. Explicit composition and a small table crate.

Date: 2026-09-07. Status: accepted.

## Context

The reference agent and operator are built on two in-house frameworks:

- **Hive** (`github.com/cilium/hive`): a dependency-injection "cell" system.
  ~90 cells are composed in `daemon/cmd/cells.go`; startup order, health
  reporting, config flag registration and lifecycle hooks all flow through it.
- **StateDB** (`github.com/cilium/statedb`): an in-memory, transactional,
  multi-index table store with revisions and watch channels. Load balancing,
  devices/routes, node addresses, and several reconcilers are written as
  StateDB tables plus a generic reconciler that pushes rows to BPF maps.

Four inventories (04 load balancer, 06 agent core, 08 operator, 09 Hubble)
independently recommend not porting either wholesale.

## Decision

1. **No dependency-injection framework.** Components are constructed
   explicitly in `main` (or a `build()` function per binary) and wired by
   passing handles. Startup ordering is expressed with a small `Fence`
   barrier type (a one-shot watch that dependents await) mirroring the
   ordering constraints documented in inventory 06. Per-module health is a
   registry the status endpoint reads; modules report into it directly.

2. **A small shared table crate** (`flowsdn-table`) replaces StateDB:
   in-memory tables with a primary key, optional secondary indexes, a
   monotonically increasing revision per write, and `watch()` returning a
   stream of changes since a revision. Snapshot reads are cheap (persistent
   map, e.g. `im`/`imbl`). No query language, no transactions spanning
   tables, no HTTP dump. Reconcilers are ordinary async tasks that consume a
   watch stream and apply the row to a BPF map or netlink object with retry
   and backoff.

3. **Config is a typed struct**, populated once at startup from the same
   sources the reference uses (config-dir file-per-key, environment, flags)
   and validated. Cells registering their own flags are replaced by one flag
   registry that knows all 539 keys (inventory 06) so `cilium-config`
   ConfigMaps remain compatible.

## Consequences

- The StateDB HTTP dump, hive shell (`shell.sock`) and hive script commands
  are not provided. `cilium-dbg statedb ...` is unsupported; the equivalent
  information is exposed through the REST API and `tokio-console`/`tracing`.
- Reconciler semantics that inventories rely on (revision-based
  incremental updates, "pending/done/error" per row, prune on full sync)
  are provided by the table crate and one generic reconciler helper, so the
  load balancer, device, route and node-address areas share one mechanism.
- The table crate is the first shared crate to write; everything in the
  agent that mirrors k8s or kernel state builds on it.
