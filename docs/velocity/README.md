# flowsdn velocity ledger

Snapshot: **2026-09-08T18:26:03.474Z** (UTC). Measured session began
2026-09-08T16:11:13.415Z. This excludes the earlier specification phase, whose effort was
not measured here. Refresh at work-item boundaries and before releases.

## Project elapsed time and usage

| Measure | Value |
|---|---:|
| Elapsed wall-clock time | 2h 14m 50s |
| Active work time | Not measured |
| Input tokens (includes cached input) | 5,906,449 |
| Cached input tokens (subset of input) | 5,761,280 |
| Uncached input tokens | 145,169 |
| Output tokens | 30,157 |
| Reasoning output (subset of output) | 5,204 |
| Total processed tokens (input + output) | 5,936,606 |
| Completed response usage records | 69 |
| Validated source prereleases | 2 |
| Unique tests (each passed in debug and release) | 15 |
| Parsed archives / embedded files / commands | 168 / 1,444 / 3,537 |
| Networking scenarios executed | 0 |

## Per-crate delivery windows

| Crate | Elapsed since first source write | Dedicated tokens | Token window | Delivered |
|---|---:|---|---|---|
| flowsdn-fence | 0h 13m 44s | Not separately measured | foundation | v0.1.0 |
| xtask | 0h 14m 54s | Not separately measured | foundation | v0.1.0 |
| flowsdn-scripttest | 1h 37m 46s | Not separately measured | parser | v0.2.0 |

These are measured delivery windows, not active coding hours or estimates of a
complete crate. Design before the first source write is outside a crate window.
Waits, approvals, tests and infrastructure troubleshooting are inside it.
The fence and xtask windows overlap: **do not sum per-crate elapsed times**.
Dedicated historical token counts are unknown; no proportional allocation is used.

## Disjoint work windows

Tokens are assigned by response completion time to these delivery windows. They
are measured usage during a window, not a claim that every token edited its crate.
Boundary samples can precede a commit by part of one response; the JSON records
both the wall-clock boundaries and token sample timestamps.

| Window | Elapsed | Input | Cached input | Output | Total |
|---|---:|---:|---:|---:|---:|
| foundation | 0h 19m 41s | 1,732,345 | 1,656,320 | 12,179 | 1,744,524 |
| parser | 1h 50m 51s | 2,785,086 | 2,739,968 | 12,221 | 2,797,307 |
| measurement | 0h 04m 18s | 1,389,018 | 1,364,992 | 5,757 | 1,394,775 |

## Initial throughput

Over this observed session window: **0.89 validated prereleases/hour**,
**6.67 newly passing tests/hour**, and **13,420
output tokens/hour**. These are descriptive baseline rates, not forecasts for
BPF, policy or a finished networking stack. The denominator includes the host
/dev/null incident and approval delays. Parser coverage is not networking coverage.

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
