# flowsdn velocity ledger

Usage cutoff: **2026-09-09T12:55:18.196Z**. Milestone 0.11.0 started
**2026-09-09T12:46:19Z** and is **awaiting validation**. Elapsed through the token cutoff is
**539.196 seconds**. Later activity bounds are reported separately below.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 119,862,213 |
| Cached input (subset) | 116,833,664 |
| Uncached input | 3,028,549 |
| Output | 543,096 |
| Reasoning output (subset) | 132,323 |
| Total processed | 120,405,309 |

Milestone usage is **10,015,230 processed tokens** across root
and three agents, deduplicated by response ID. The combined baseline uses
responses strictly before the milestone start; the root baseline is the latest
sample at or before start. The superseded after-start sample remains in the
milestone audit metadata. Repeated context counts as input, and these figures
do not establish subscription dollar usage. Per-agent cutoffs are retained in
[subagents.json](subagents.json).

Seven closed reported windows total **1,229 agent-window seconds**
(**0.341389 hours**), with a **593-second project interval union**. Script
implementation ended at **12:56:41 UTC** after 577 elapsed seconds, including
its review fix. A separate 66-second script review ended at 12:56:00 UTC.
These completion bounds follow the fixed token cutoff; their later usage is
not inferred. All active-work fields remain unknown.

Focused validation passed **33 ABI tests, 62 reconciler tests and Clippy**
for both crates. Script work adds 14 tests awaiting full validation. Full
workspace checks began at **12:57:10 UTC**, when milestone elapsed reached
**651 seconds**; no complete-suite pass is claimed. Cleanup and publication
are pending. Issue #13 was confirmed closed. [Milestone 0.11](0.11.0.json)
records the separate usage/activity bounds; prior releases remain preserved in
[0.10](0.10.0.json) and the ledger. Usage after the cutoff is excluded.

A later validation checkpoint at **13:00:47 UTC** passed all **286 debug tests**,
formatting, Clippy and both Linux musl compile checks against `7972548`.
Release tests and dependency policy remain pending. This checkpoint is after
the usage cutoff above.

## Recording rules

1. At work start, record UTC time, task ID, owner agent, primary crate or
   project/shared scope, current revision, and the latest cumulative token sample.
2. At scope changes, close the old interval and open the next. Record build/test,
   troubleshooting and approval intervals when observable. Never infer active
   work time by subtracting guessed delays.
3. At completion, capture UTC end time and counters, compute deltas, and link
   the commit, release and validation outcomes. Record missing counters as null.
4. For multiple agents, use one ledger per session/agent. Sum unique response
   usage once; project elapsed is the interval union, not summed agent-hours.
   Record agent-hours separately. A shared task gets one scope, not every crate.
5. Keep input, cached input and output distinct. Do not add cached input to
   input, or reasoning output to output. Token totals count repeated context,
   not unique words or code, and do not establish dollar cost. See
   [OpenAI prompt caching documentation](https://developers.openai.com/api/docs/guides/prompt-caching).
6. Commit only timestamps, counters, IDs, scope, outcomes and provenance. Never
   commit raw session transcripts, prompts, tool payloads or credentials.
7. Commit ledger updates through GitHub; maintain release notes and cleanup as
   required by AGENTS.md. Runtime usage can lag the in-progress response; label
   every report with its cutoff. This snapshot does not include its own final
   commit or all subsequent reporting work.

[Machine-readable ledger](ledger.json) · [Sanitized token samples](token-samples.json)
