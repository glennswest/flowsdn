# flowsdn-cloud-fixture

Recorded-response cloud fixtures for cloud IPAM tests
([ADR-0007](../../docs/decisions/0007-cloud-recorded-fakes.md), spec 07 §9.1).
This crate is the provider-independent half. It holds no credentials and sends
nothing to a provider.

| Module | What it does |
|---|---|
| `fixture` | The layout `tests/cloud/<provider>/<scenario>/` (`scenario.toml` plus `001-<operation>.json`, `002-…`, no gaps). `load` scans the directory **before** it reads any fixture and refuses it on a finding. `write` scans what it wrote and removes it on a finding. `load_all` scans the whole tree, then loads every scenario. |
| `scrub` | The capture-side `Scrubber`, one per scenario. Identifiers are replaced deterministically, so an id seen in a response and sent back in a later request gets the same placeholder in both. `reveal` maps a placeholder back to the real id, for the capture's next live request; the real values stay in memory only. Credentials and signatures become `scrubbed` and are never kept. Private addresses and CIDRs are kept. |
| `scan` | The `cloud-fixture-scan` (spec 22): each scrubbed class in its real form, plus non-UTF-8 files. A finding names the file, line, column and class, never the value. |
| `canon` | The replay comparison. Query strings and form bodies are compared as sorted, percent-decoded pairs, without signing parameters, timestamps or `ClientToken`. JSON bodies are compared as values with sorted keys. Anything else is compared trimmed. |
| `replay` | The in-order `Replayer`. Each request must match the next recorded interaction by method, canonical target and canonical body. A mismatch is reported beside the closest remaining recorded interaction. `finish(strict)` also fails on interactions never used. A request with nothing left to match fails; nothing falls back to a live endpoint. |
| `server` | `ReplayServer`: a loopback HTTP/1.1 server (keep-alive, `Content-Length` and chunked bodies, origin- or absolute-form targets) answering from a `Replayer`. Point a provider client's endpoint and IMDS at `url()` with a static test credential, so the client's own signing, retry, pagination and error mapping are tested. An unmatched request gets `500` with `x-flowsdn-replay: mismatch`. |

## Placeholders

Placeholders are chosen so that a scrubbed value never matches the scan, and
scrubbing scrubbed text changes nothing.

| Class | Replacement |
|---|---|
| AWS resource ids (`eni-`, `subnet-`, `vpc-`, `sg-`, `i-`, `ami-`, `eni-attach-`, …; 8 or 17 hex) | same length, `5c7b` + counter in hex |
| Alibaba ids (`eni-`, `vsw-`, `vpc-`, `sg-`, `i-`, `eip-`, `lb-`; 20+ characters) | same length, `5c7b` + counter in decimal |
| Account ids and UIDs (12 or 16 digits after `OwnerId`, `AccountId`, `RequesterId`, `Uid` …) | same length, zero-padded counter |
| GUIDs (subscription, tenant, object, request ids) | `00000000-0000-4000-8000-<12-digit counter>` |
| Resource group, VMSS names | `rg-<n>`, `vmss-<n>` (case-insensitive) |
| ARNs | `arn:scrubbed:<n>` |
| Instance DNS names (`*.compute.amazonaws.com`, `*.ec2.internal`, `*.cloudapp.azure.com`, …) | `host-<n>.scrubbed.invalid` |
| Public IPv4 | `203.0.113.x`, then `198.51.100.x`, then `192.0.2.x` (RFC 5737) |
| Public IPv6 (2000::/3) | low 96 bits kept, each /32 mapped to `2001:db8`, then `3fff:000n` (RFC 3849, RFC 9637), so prefixes and the addresses inside them stay related |
| `Authorization` and other credential headers, credential JSON/XML keys (`SecretAccessKey`, `Token`, `access_token`, …), signing parameters (`Signature`, `X-Amz-Signature`, `AccessKeyId`, …), bearer tokens, JWTs, AWS key ids, PEM private keys | `scrubbed` |

A counter runs per class within one scenario. A real id that happens to begin
with the placeholder marker (`5c7b`, or seven zeros for an account) is not
flagged by the scan.

## Running the scan

`cargo xtask cloud-scan` scans `tests/cloud/**` and loads every scenario. The
xtask's unit test does the same, so every `sc-build` (`cargo test`) gates the
committed fixtures.

## Not here yet (#391)

- **Capture** (`cargo xtask cloud-record`, ADR-0007 §1). It needs a cloud
  IPAM provider client that sends requests: `flowsdn-cloud-azure` only plans
  them, and there is no AWS ENI or Alibaba client (spec 07; milestone 3, #293).
  It also needs a throwaway account per provider.
- **The fourteen scenarios per provider** (ADR-0007 §4), which capture records.
- **The `--check` diff** that the weekly drift job (#260) runs against the live
  account.
- **AWS `aws-smithy-runtime` replay**, for whichever client fits it.
