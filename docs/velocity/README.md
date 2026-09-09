# flowsdn velocity ledger

Usage cutoff and cleanup completion: **2026-09-09T13:04:59Z**. Milestone 0.11.0
started at **12:46:19 UTC** and completed in **18 minutes 40 seconds**
(**1,120 elapsed seconds**). Source is validated; release publication is pending.

| Combined unique-response usage | Tokens |
|---|---:|
| Input | 127,502,211 |
| Cached input (subset) | 124,422,912 |
| Uncached input | 3,079,299 |
| Output | 559,066 |
| Reasoning output (subset) | 138,986 |
| Total processed | 128,061,277 |

Milestone usage is **17,671,198 processed tokens** across root
and three agents, deduplicated by response ID. The combined baseline uses
responses strictly before start; root uses the latest sample at or before start.
The superseded after-start sample remains only as audit metadata. Repeated
context counts as input; these figures do not establish subscription dollars.
Per-agent cutoffs and cumulative counters remain in [subagents.json](subagents.json).

Seven reported windows total **1,229 agent-window seconds** (**0.341389 hours**),
with a **593-second project interval union**. Observed validation windows are
**217 seconds** through the debug/release transition and **217 seconds** through
final checks, followed by **35 seconds** of cleanup. These are nested elapsed
windows, not exclusive processing time, and are not added to milestone elapsed.
Active work and active agent-hours remain unknown.

Commit `7972548` passed **286 all-features tests in each debug/release profile**,
formatting, Clippy, both Linux musl compile checks and dependency policy;
`7952174` records validation. Test counts: script 80, reconciler 62, config 51,
ABI 33, table 30, health 7, fence 7, selector 7, version 5 and harvester 4. Validation
completed at **13:04:24 UTC**. Cleanup removed **11,693 files / 3.3 GiB** and
seven task logs; the device check passed. Issue #13 closed; repository totals
are **11 closed / 279 open**. Release publication is pending.

[Milestone 0.11](0.11.0.json) preserves timing, counters and validation details;
[0.10](0.10.0.json) and the ledger retain prior history. Usage after the fixed
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
