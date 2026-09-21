# flowsdn velocity ledger

Milestone [0.14.0](0.14.0.json) started **2026-09-09T15:42:01Z**.
Usage cutoff: **2026-09-09T16:01:17Z**; observed elapsed **1156 seconds**.
Validation and cleanup completed in **19 minutes 16 seconds** (1,156 seconds).
All **377 tests** passed in debug and release, with formatting, Clippy, both
Linux musl compile checks, dependency policy and identity no-default-features
compilation. Cleanup removed **13,452 files / 3.8 GiB** and seven task logs.
One issue closed; totals are **20 closed / 270 open**. Source validation is
recorded in `5ec0cb3`. Foundation prerelease
[v0.14.0](https://github.com/glennswest/flowsdn/releases/tag/v0.14.0) was published
at **16:03:02 UTC**, **21 minutes 1 second** after milestone start (1,261 seconds).
Release commit: `9dfc33b`. Publication and final reporting are outside the fixed
usage cutoff. Prior releases remain in the ledger.

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

## Four-milestone planning update

2026-09-09T16:59:58Z: created four GitHub milestones and the remaining-scope plan in
`docs/milestones.md`. Observed planning interval: 113 seconds;
initial review preceded that interval. Root-only processed-token delta: 224,961
through 2026-09-09T16:59:58.614Z. No builds, release, or billable-dollar estimate.
The prior release totals above retain their original cutoff. Detailed counters
are in the `four-milestone-plan` ledger phase.

## Milestone 1: kernel smoke checkpoint

2026-09-09T17:33:16Z: Rust BPF kernel execution and isolated live UDP pass/drop/cleanup
validated, with no new release. One root agent; elapsed 503.4 seconds,
2,262,288 processed tokens through 2026-09-09T17:33:15.329Z.
Counters include cached/repeated context and do not measure account allowance.
See `m1-kernel-smoke` in the ledger and
[validation](../validation/m1-kernel-smoke.md). Milestone 1 remains in progress.

## Milestone 1: local endpoints and CNI integration

2026-09-09T18:36:48Z: integrated endpoint delivery, IPAM and CNI rollback
validated at `446964c`. Elapsed: 1620.1 seconds. Root
processed tokens: 5,261,185; allocator agent: 332,630
through their recorded cutoffs. Agent observed elapsed was 246 seconds and
overlaps project elapsed. Counters include repeated/cached context, not dollars.
Milestone 1 continues into native routing; no release was made.

## Milestone 1: native routing and executable CNI

Cutoff 2026-09-09T19:22:09Z; elapsed 2721 seconds (45m21s) since
the previous integration boundary. Root processed tokens: 12,875,856;
shared coding agent: 8,715,057. Counter windows and unknown
agent elapsed bounds are in `m1-native-routing-cni-runtime`. This includes
cached context and early daemon preparation, not account dollars.
[Validation](../validation/m1-cni-routing.md) is committed at `4b8f8ca`.
Cleanup removed 11,106 files / 3.5 GiB and one failed-test socket.
No release; milestone 1 continues into standalone daemon integration.

## Issue-driven cycle: 2026-09-21

20:07:01 UTC–2026-09-21T21:11:32.977159Z: **3872.0 seconds** (64.5 minutes).
Root and three bounded review agents resolved **101 of 270 existing issues**
(37.4%), closed dependency remediation #295, and created open milestone acceptance
trackers #291–#294. Final totals: **173 open / 122 closed**. Design closures do
not claim feature delivery; implementation obligations remain in the trackers.

Source `dd65674` passes **428 workspace tests**, Clippy, formatting, both musl
architecture compile checks and dependency policy. Standalone agent restart,
offline deletion and partial teardown checks pass. Cleanup removed 18,889 files /
6.7 GiB and six task logs. No release was made.

Processed tokens: **25,151,714**, including
**24,503,296 cached input**. Preferred
`token_usage_record` telemetry is deduplicated by response ID across all four
threads; initial-response usage is included, superseding the interim token-count
estimate. Baselines, per-thread endpoints and subsets are in the ledger. Counts
include repeated context and do not measure account cost; this cutoff excludes
its own commit and subsequent reporting.

Known overlapping agent windows total 1,130 seconds (0.314 hours); later review
windows are incompletely observed and not added to that time sum. Their token
usage is included once. Active work time remains null. Final validation intervals
are nested within project elapsed, never added to it.
