# flowsdn velocity ledger

Root snapshot: **2026-09-08T20:10:06.335Z**. Measurement began
2026-09-08T16:11:13.415Z; earlier specification effort is excluded.

| Measure | Value |
|---|---:|
| Project elapsed wall-clock | 3.98 hours |
| Active coding time | Not measured |
| Root processed tokens | 16,582,646 |
| Subagent processed tokens | 3,419,746 |
| Combined unique-response input | 19,896,134 |
| Combined cached input (subset) | 19,431,680 |
| Combined output | 106,258 |
| Combined processed tokens | 20,002,392 |

Three subagent sessions are recorded in [sanitized subagent usage](subagents.json),
each with its own completion cutoff. Root and child sessions are distinct;
combined totals sum unique completed responses, not cumulative parent counters.
Table/config implementation windows overlap: do not sum them as project time.
Exclusive active coding time and agent-hours are unknown. Root integration
includes approvals, waits, status answers and release work. Tokens include
repeated context and do not establish subscription dollars.

v0.3.0 is published at `382bc9d`; v0.4.0 combined validation passed 51 tests in each profile plus both target checks.
The JSON ledger retains historical per-crate windows and task phase attribution.

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
