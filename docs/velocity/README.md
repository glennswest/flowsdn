# flowsdn velocity ledger

Usage cutoff: **2026-09-09T12:32:20.664Z**. Milestone **v0.10.0 is in progress**;
full validation, cleanup and publication are pending.
Observed project elapsed through the cutoff is **622.664 seconds**,
with **7,816,962 processed tokens** across root and three
agents during this milestone. Active work time is unknown.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 106,266,509 |
| Cached input (subset) | 103,463,424 |
| Uncached input | 2,803,085 |
| Output | 487,975 |
| Reasoning output (subset) | 121,303 |
| Total processed | 106,754,484 |

Totals are deduplicated by response ID across the root and three agent sessions
and include repeated context; they do not establish subscription dollars.
[Subagent records](subagents.json) retain sanitized counters and cutoff timestamps.
Closed observed agent windows total **1025 seconds**
(**0.284722 agent-window hours**). Overlapping agent windows are
kept separate from project wall-clock elapsed; these are not measured active
coding hours. The root's approximate CT/NAT start is not presented as an exact
crate-only interval.

The coordinator reported 14 new ABI tests plus six existing tests and focused
Clippy passing. Full checks are running; no v0.10.0 validation outcome or release
is claimed. [Milestone details](0.10.0.json) record the baseline, provisional
endpoint and reported crate windows. The latest validated release remains
[v0.9.0](https://github.com/glennswest/flowsdn/releases/tag/v0.9.0), with
[its validation record](0.9.0.json). Later work is outside this cutoff.

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
