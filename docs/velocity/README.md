# flowsdn velocity ledger

v0.11.0 started at **2026-09-09T12:46:19Z**; [its work record](0.11.0.json)
contains the baseline. The completed milestone and usage snapshot below remain
v0.10.0 until the next measured work boundary.

Usage cutoff and observed completion: **2026-09-09T12:36:15Z**.
Milestone **v0.10.0 is validated, cleaned up and published**.
Elapsed project time was **857 seconds (14m 17s)**, with
**9,609,372 processed tokens** across root and three agents
through the cutoff. Active work time is unknown.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 108,054,580 |
| Cached input (subset) | 105,227,008 |
| Uncached input | 2,827,572 |
| Output | 492,314 |
| Reasoning output (subset) | 122,407 |
| Total processed | 108,546,894 |

Totals are deduplicated by response ID across root and three agent sessions and
include repeated context; they do not establish subscription dollars.
[Subagent records](subagents.json) preserve sanitized counters and cutoffs.
Closed observed agent windows total **1,025 seconds (0.284722 agent-window
hours)**; their project interval union is **429 seconds**. These are separate
from the 857-second milestone wall time and are not measured active coding hours.
The root's approximate CT/NAT start is not assigned an exact crate-only window.
An additional 173-second validation checkpoint interval is recorded separately;
the actual build began slightly before that observed checkpoint.

Source commit `cc9ec2c` passed **247 unique tests in both debug and release with
all features**, formatting, Clippy, both Linux musl compile checks and dependency
policy. Validation was observed complete at **12:35:45 UTC** and recorded in
`c590a07`. Cleanup removed **9,880 files / 2.7 GiB** and the five task logs;
completion was observed at **12:36:15 UTC**. Device and before/after disk checks
passed. [v0.10.0](https://github.com/glennswest/flowsdn/releases/tag/v0.10.0)
was published at **12:38:42 UTC**, after the usage cutoff. The issue count
remains **10 closed / 280 open**.
[Milestone details](0.10.0.json) retain baselines, endpoints, crate windows and
validation evidence. Later publication and reporting are outside this cutoff.

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
