# flowsdn velocity ledger

Snapshot: **2026-09-08T20:59:07.218Z**. Session elapsed: **4.80 hours**.
The 0.6.0 milestone spans **14.8 minutes**, with
**11,196,203 processed tokens** across root and three agents.
Active coding time and active agent-hours remain unmeasured.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 40,069,434 |
| Cached input (subset) | 39,309,056 |
| Uncached input | 760,378 |
| Output | 188,450 |
| Total processed | 40,257,884 |

Each agent's cutoff is preserved in [subagents.json](subagents.json). All totals
are deduplicated by response ID. Tokens include repeated context and do not
establish subscription dollars. Overlapping crate windows must not be summed as
project wall time. [Milestone 0.6](0.6.0.json) and [ledger](ledger.json) record
scope, validated outcomes and cleanup. 110 tests pass per profile; 1.4 GiB of
build output was removed. Release publication and later reporting are outside
this measurement cutoff.

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
