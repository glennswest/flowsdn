# flowsdn velocity ledger

Milestone [0.14.0](0.14.0.json) started **2026-09-09T15:42:01Z**. Identity
filtering, CIDR labels, wire codecs and loader layout planning are in progress.
The counters below remain the completed 0.13 snapshot until the next boundary.

Milestone [0.13.0](0.13.0.json) started **2026-09-09T13:41:34Z**.
Usage cutoff: **2026-09-09T13:58:06Z**; observed elapsed **992 seconds**.
Validation and cleanup completed in **16 minutes 32 seconds** (992 seconds).
All **341 tests** passed in debug and release, with formatting, Clippy, both
Linux musl compile checks, dependency policy and full harvester reproduction.
Cleanup removed **12,845 files / 3.4 GiB**, five logs and the generated inventory.
Eight issues closed; repository totals are **19 closed / 271 open**. Foundation
prerelease [v0.13.0](https://github.com/glennswest/flowsdn/releases/tag/v0.13.0)
was published at **13:59:22 UTC**, **17 minutes 48 seconds** after milestone
start (1,068 elapsed seconds). Source validation is recorded in `619908e`;
release commit is `762bf4c`. Publication and subsequent ledger work are outside
the fixed usage cutoff. A 17 MiB pinned reference
cache is retained for future audits; compiler output was cleaned.

Milestone processed usage: **18,068,981 tokens** across root and
three agents, deduplicated by response ID. This includes repeated context and
is not subscription dollar usage. Root coding and coordination are recorded
under project/shared; active work time remains unknown.

| Combined lifetime usage | Tokens |
|---|---:|
| Input | 172,332,590 |
| Cached input (subset) | 168,673,536 |
| Uncached input | 3,659,054 |
| Output | 689,946 |
| Reasoning output (subset) | 168,993 |
| Total processed | 173,022,536 |

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
