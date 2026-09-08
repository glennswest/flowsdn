# Module health

Reporters publish immutable rows in a health table and derive child scopes.
New scopes remain unknown until their first report. Stopping preserves the last
reported level and records a separate stop reason; reporting again resumes it.
Closing removes only that scope, while dropping a cloned handle changes nothing.

Readiness evaluation follows the foundation probe/fence failure priorities.
Module degradation produces a warning with HTTP200. Callers supply coherent
probe observations; this crate does not run an HTTP server, detect probe staleness
or schedule probes. Snapshot metrics are exposed as values, without registering
an exporter. Health-history persistence and rotation remain forthcoming.
