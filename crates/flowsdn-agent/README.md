# Agent endpoint ownership

The initial library owns primary endpoint IDs, published endpoint state,
host-scope allocations and live endpoint maps/attachments. Creation stages
state before installing the datapath and publishes it after installation.
Deletion retains ownership on failure so the operation can be retried.
Restore validates saved host interface identity and address ownership before
rebuilding maps and attachments in a fresh object.

State storage holds an exclusive agent lock, ignores incomplete regeneration
directories, rejects mismatched IDs and duplicate attachments, and preserves
unknown JSON fields. New IDs use the lowest free number in 1–4095; restore
can reserve historical nonzero u16 IDs.

This is a library, not a deployable agent daemon. API serving, allocation
expiration, identity/policy reconciliation, Kubernetes watches and stale-pod
garbage collection remain outstanding. Persisted stale host links fail restore
until the caller decides how to handle them. The initial state parser accepts
primary workload endpoints; host/ingress endpoint handling is not yet included.
