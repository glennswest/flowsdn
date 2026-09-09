# flowsdn velocity ledger

Milestone [0.13.0](0.13.0.json) started **2026-09-09T13:41:34Z**.
Usage cutoff: **2026-09-09T13:53:40Z**; observed elapsed **726 seconds**.
Validation is in progress; the previous completed release is [0.12.0](0.12.0.json).

Milestone processed usage: **16,229,592 tokens** across root and
three agents, deduplicated by response ID. This includes repeated context and
is not subscription dollar usage. Root coding and coordination are recorded
under project/shared; active work time remains unknown.

| Combined lifetime usage | Tokens |
|---|---:|
| Input | 170,497,818 |
| Cached input (subset) | 166,855,296 |
| Uncached input | 3,642,522 |
| Output | 685,329 |
| Reasoning output (subset) | 167,491 |
| Total processed | 171,183,147 |

Reported agent windows total **1195 seconds**;
they overlap project elapsed and are not added to it. Individual windows and
per-crate delivery counters are in the milestone record. Shared usage is counted
once. Token counters exclude work after this fixed cutoff.

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
