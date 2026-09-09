# flowsdn velocity ledger

Usage cutoff: **2026-09-09T13:16:55.369Z**. Milestone 0.12.0 started
**2026-09-09T13:10:31Z** and remains **in progress**, with
**384.369 seconds elapsed** through the cutoff.
Validation, cleanup and release publication remain pending.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 138,342,036 |
| Cached input (subset) | 135,150,848 |
| Uncached input | 3,191,188 |
| Output | 596,719 |
| Reasoning output (subset) | 148,719 |
| Total processed | 138,938,755 |

Milestone usage is **7,591,456 processed tokens** across root
and three agents, deduplicated by response ID. The root baseline at
**2026-09-09T13:10:30.966Z** precedes milestone start; all comparisons use parsed
timestamps. Historical per-response cumulative counters remain preserved.
Repeated context counts as input and these figures do not establish dollar usage.
Per-agent cutoffs are in [subagents.json](subagents.json).

Two closed reported windows total **145 agent-window seconds**
(**0.040278 hours**), also a **145-second project interval union**.
Reconciler work began at **13:11:49 UTC** and remains ongoing; unobserved
endpoints and active time remain unknown. Script adapter work began at
**13:12:05 UTC** and remains ongoing. Root loader coding began approximately
13:12 UTC; no exact exclusive coding duration is inferred.

Six endpoint ABI tests and six loader-planning tests were added and are
**not yet validated**. [Milestone 0.12](0.12.0.json) preserves current counters
and work windows; [0.11](0.11.0.json) and the ledger retain validated release
history. Later usage, including ledger edits and reporting, is excluded.

Later checkpoint at **13:20:01 UTC**: **45 focused map tests** and Clippy
passed against `45beab7`; script validation is running and health integration
is still under review. This checkpoint is after the usage cutoff above.

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
