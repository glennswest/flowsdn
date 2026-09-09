# flowsdn velocity ledger

Milestone [0.14.0](0.14.0.json) started **2026-09-09T15:42:01Z**.
Usage cutoff: **2026-09-09T16:01:17Z**; observed elapsed **1156 seconds**.
Validation and cleanup completed in **19 minutes 16 seconds** (1,156 seconds).
All **377 tests** passed in debug and release, with formatting, Clippy, both
Linux musl compile checks, dependency policy and identity no-default-features
compilation. Cleanup removed **13,452 files / 3.8 GiB** and seven task logs.
One issue closed; totals are **20 closed / 270 open**. Source validation is
recorded in `5ec0cb3`; publication is pending. Prior releases remain in the ledger.

Milestone processed usage: **19,368,222 tokens** across root and
three agents, deduplicated by response ID. Repeated context is included; these
counters do not measure subscription dollar usage. Root coding and coordination
remain project/shared. Unknown active work time is null.

| Combined lifetime usage | Tokens |
|---|---:|
| Input | 192,688,524 |
| Cached input (subset) | 188,719,616 |
| Uncached input | 3,968,908 |
| Output | 748,993 |
| Reasoning output (subset) | 181,690 |
| Total processed | 193,437,517 |

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
