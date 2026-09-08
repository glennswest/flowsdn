# flowsdn velocity ledger

Snapshot: **2026-09-08T19:44:44.028Z**. Root session measurement began
2026-09-08T16:11:13.415Z; earlier specification effort is excluded.

| Measure | Value |
|---|---:|
| Elapsed wall-clock | 3.56 hours |
| Active coding time | Not measured |
| Input tokens (including cached) | 13,381,894 |
| Cached input (subset) | 13,115,264 |
| Uncached input | 266,630 |
| Output tokens | 68,033 |
| Total processed tokens | 13,449,927 |
| Validated tests in debug and release | 28 |

The machine-readable ledger preserves per-crate delivery windows and disjoint
root-session usage windows. Table and harvester integration are shared scope;
exclusive crate tokens and active time remain unknown. Do not sum overlapping
crate elapsed windows. Wall time includes waits and unmeasured idle periods.
Three subagents have just started; their usage is not included in this snapshot.
Token counts include repeated context and do not establish subscription dollars.
The validated v0.3.0 candidate is commit `addeffa`; publication is pending.

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
