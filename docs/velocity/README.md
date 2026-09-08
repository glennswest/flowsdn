# flowsdn velocity ledger

Usage cutoff: **2026-09-08T21:53:08.201Z**. Validation and cleanup completed
**2026-09-08T21:55:39Z**. Session elapsed at completion: **5.74 hours**.
The 0.7.0 milestone took **39 minutes 32 seconds**, with **19,708,877 processed
tokens** measured through the earlier usage cutoff across root and three agents.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 60,685,267 |
| Cached input (subset) | 59,603,200 |
| Uncached input | 1,082,067 |
| Output | 270,991 |
| Reasoning output (subset of output) | 64,904 |
| Total processed | 60,956,258 |

Each agent's distinct cutoff is preserved in [subagents.json](subagents.json).
Totals are deduplicated by response ID across all four sessions. They include
repeated context and do not establish subscription dollar usage.
[Milestone 0.7](0.7.0.json) records implementation, review and fix windows. Their
per-agent interval unions total **0.851 observed agent-window hours**, including
waits; active work and active agent-hours remain unknown. Overlapping windows
must not be added as project wall-clock time.

Commit `a98a068` passed **149 tests per debug/release profile**, formatting,
Clippy, both Linux musl compile checks and cargo-deny. Cleanup removed **9,195
files / 2.3 GiB**. Release candidate **v0.7.0** awaits publication. The ledger
records six issues closed this session; the repository has nine closed and 281
open issues at completion. Usage after the earlier cutoff—including the final
validation, cleanup, ledger edits and reporting—is excluded from token totals.

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
