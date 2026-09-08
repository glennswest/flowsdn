# flowsdn velocity ledger

Root snapshot: **2026-09-08T20:29:20.692Z**. Session elapsed: **4.30 hours**.
Earlier specification effort is excluded. Active coding time is unmeasured.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 27,774,411 |
| Cached input (subset) | 27,184,256 |
| Output | 137,740 |
| Total processed | 27,912,151 |

Includes root and three subagents, deduplicated by response ID. Each agent's
cutoff is preserved in [subagents.json](subagents.json). Tokens include repeated
context and do not establish subscription dollars. Task windows overlap and
must not be summed as project wall time; active agent-hours remain unknown.
The [ledger](ledger.json) records per-crate implementation windows, shared root
integration time, releases and validation. v0.5.0 validation passed 71 tests per profile and all required checks.
Cleanup reclaimed 1.1 GiB after this milestone; release history and closure
results are recorded in the ledger. Later reporting is outside this cutoff.

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
