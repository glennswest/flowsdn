# flowsdn velocity ledger

Usage cutoff: **2026-09-09T12:55:18.196Z**. Milestone 0.11.0 started
**2026-09-09T12:46:19Z** and remains **in progress**. Elapsed through the
cutoff is **539.196 seconds**. Full validation,
cleanup and release publication remain pending.

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

Five closed reported windows total **586 agent-window seconds**
(**0.162778 hours**), with a **388-second project interval union**.
Script work began at **12:47:04 UTC** and is still ongoing; its elapsed endpoint
and active time are unknown, so it is excluded from the closed-window total.
All active-work fields remain unknown.

Focused validation passed **33 ABI tests and ABI Clippy**. The reconciler has
12 newly added observer tests awaiting validation. Issue #13 was reported
closed; prior issue-count snapshots remain historical. [Milestone 0.11](0.11.0.json)
records current scope and counters; [milestone 0.10](0.10.0.json) and the ledger
preserve previous releases and outcomes. The reporting gap is recorded with
root-only counters and explicit sample boundaries. Usage after the cutoff,
including these ledger edits and subsequent reporting, is excluded.

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
