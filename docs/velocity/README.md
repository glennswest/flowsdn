# flowsdn velocity ledger

Usage cutoff: **2026-09-09T11:41:38.751Z**. Validation and cleanup completed
**2026-09-09T11:43:30Z**. Milestone v0.8.0 elapsed **10h 11m 4s**, including an
observed **35,576.259-second inter-response gap**.
That gap includes a reported capacity interruption and later continuation;
it is not active coding time. Active work remains unknown.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 81,250,842 |
| Cached input (subset) | 79,116,800 |
| Uncached input | 2,134,042 |
| Output | 357,034 |
| Reasoning output (subset) | 88,440 |
| Total processed | 81,607,876 |

The milestone accounts for **15,788,690 processed tokens**
across root and three agents through the cutoff. These are deduplicated response
counters, include repeated context, and do not establish subscription dollars.
Per-agent cutoffs are in [subagents.json](subagents.json). Reported parallel
windows total **0.532 agent-window hours**;
they include coordination and cannot be added as project wall time.

Commit `ea7cbea` passed **180 tests in both debug and release**, formatting,
Clippy, both Linux musl compile checks and dependency policy. Cleanup removed
**10,012 files / 2.4 GiB**. Release candidate v0.8.0 awaits publication.
Issue #122 closed; repository totals are **10 closed / 280 open**.
[Milestone details](0.8.0.json) retain crate windows, baseline and endpoint
counters, validation and interruption bounds. Usage after the cutoff, including
final reporting and publication, is excluded.

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
