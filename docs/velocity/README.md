# flowsdn velocity ledger

Milestone [0.14.0](0.14.0.json) started **2026-09-09T15:42:01Z**.
Usage cutoff: **2026-09-09T15:55:23Z**; observed elapsed **802 seconds**.
Validation is in progress; prior release records remain available in the ledger.

Milestone processed usage: **16,799,354 tokens** across root and
three agents, deduplicated by response ID. Repeated context is included; these
counters do not measure subscription dollar usage. Root coding and coordination
remain project/shared. Unknown active work time is null.

| Combined lifetime usage | Tokens |
|---|---:|
| Input | 190,126,047 |
| Cached input (subset) | 186,168,704 |
| Uncached input | 3,957,343 |
| Output | 742,602 |
| Reasoning output (subset) | 178,651 |
| Total processed | 190,868,649 |

Reported agent windows total **1105 seconds**;
these overlap project elapsed. Per-crate delivery windows and counter baselines
are recorded in the milestone. Shared usage is counted once. This fixed cutoff
excludes subsequent publication and reporting work.

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
