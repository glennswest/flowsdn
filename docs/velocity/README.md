# flowsdn velocity ledger

Usage cutoff: **2026-09-09T12:11:00.810Z**. Validation and cleanup observed complete **2026-09-09T12:11:00.810Z**.
Milestone v0.9.0 elapsed **19m 36s**, with **13,835,412 processed tokens**
across root and three agents through the cutoff. Active work time is unknown.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 96,937,804 |
| Cached input (subset) | 94,395,264 |
| Uncached input | 2,542,540 |
| Output | 429,944 |
| Reasoning output (subset) | 110,418 |
| Total processed | 97,367,748 |

Totals are deduplicated by response ID and include repeated context; they do not
establish subscription dollars. [Subagent records](subagents.json) preserve each
cutoff. Observed agent windows total **1,427 seconds**
(**0.396 agent-window hours**) with overlapping
project time kept separate. These windows include coordination, not measured
active coding time.

Commit `48a7d19` passed **211 tests in debug and release with all features**,
formatting, Clippy, both Linux musl compile checks and dependency policy.
Cleanup removed **11,035 files / 3.1 GiB**. Release candidate v0.9.0 awaits
publication. Repository issue counts remain **10 closed / 280 open**.
[Milestone details](0.9.0.json) retain crate windows, baseline/endpoint counters
and validation. Later publication and reporting are outside this cutoff.

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
