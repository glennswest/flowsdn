# flowsdn velocity ledger

Milestone [0.13.0](0.13.0.json) started at **2026-09-09T13:41:34Z**; identity
encoding, labels and BPF case classifications are in progress. Counters below
remain the completed 0.12 snapshot until the next measurement boundary.

Usage cutoff and cleanup completion: **2026-09-09T13:31:33Z**. Milestone 0.12.0
started at **13:10:31 UTC** and completed in **21 minutes 2 seconds**
(**1,262 elapsed seconds**) through validation and cleanup. The foundation
prerelease [v0.12.0](https://github.com/glennswest/flowsdn/releases/tag/v0.12.0)
was published at **13:34:15 UTC**, **23 minutes 44 seconds**
(**1,424 elapsed seconds**) after milestone start.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 151,328,845 |
| Cached input (subset) | 148,069,888 |
| Uncached input | 3,258,957 |
| Output | 625,385 |
| Reasoning output (subset) | 159,746 |
| Total processed | 151,954,230 |

Milestone usage is **20,606,931 processed tokens** across root
and three agents, deduplicated by response ID. Root baseline
**2026-09-09T13:10:30.966Z** precedes milestone start; combined baseline uses unique
responses strictly before start. Historical cumulative counters remain in
[subagents.json](subagents.json). Repeated context counts as input; these figures
do not establish subscription dollar usage.

Seven reported windows total **1,157 agent-window seconds** (**0.321389 hours**),
with a **544-second project interval union**. Observed validation spans were
**137 seconds** through the debug/release transition and **260 seconds** through
final checks, followed by **41 seconds** of cleanup. These windows are nested
within milestone elapsed and are not added to it. Root loader coding began at
an approximate time only; exclusive coding time and active agent-hours remain
unknown.

Commit `c267aec` passed **320 all-features tests in each debug/release profile**,
formatting, Clippy, both Linux musl compile checks and dependency policy;
`978aa64` records validation. Test counts: script 92, reconciler 72, config 51,
ABI 39, table 30, health 7, fence 7, selector 7, loader 6, version 5 and harvester 4.
Validation completed at **13:30:52 UTC**. Cleanup removed **12,819 files / 3.9 GiB**
and six task logs; the device check passed. No issues closed this milestone;
repository totals remain **11 closed / 279 open**. Release commit: `a803972`.

[Milestone 0.12](0.12.0.json) retains detailed counters, scopes and checkpoints;
[0.11](0.11.0.json) and the ledger preserve prior releases. Usage after the fixed
cutoff, including these ledger edits and publication, is excluded.

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
