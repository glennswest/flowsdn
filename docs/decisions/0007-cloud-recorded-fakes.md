# ADR-0007: Cloud CI runs against recorded-response fakes.

Date: 2026-09-07. Status: accepted (user decision).

## Context

Spec 07 covers AWS ENI, Azure, Alibaba and GKE IPAM normatively — roughly 23k
lines of Rust when written, and the area the user has called out as important.
Spec 19 records gap 9: no CI runs against a cloud provider, so those modes
would ship untested end to end. Live-cloud CI costs money, needs long-lived
credentials in CI, is rate-limited, and fails for reasons unrelated to the
change under test.

## Decision

Cloud IPAM is tested in CI against **recorded-response fakes**: real provider
API responses, captured once, scrubbed, committed, and replayed deterministically.

### 1. Capture

A `flowsdn-cloud-record` xtask drives the real provider API against a
throwaway account and writes every request/response pair to
`tests/cloud/<provider>/<scenario>/NNN-<operation>.json`, together with a
`scenario.toml` naming the scenario, provider, region, the flowsdn operations
performed, and the capture date. Capture is a **manual, occasional,
human-run** operation, never part of CI.

### 2. Scrub

Capture writes through a scrubber that MUST replace, deterministically and
reversibly within a scenario: account IDs, ARNs and resource IDs (ENI, subnet,
VPC, security group, instance, image), subscription and tenant IDs, resource
group and VMSS names, Alibaba UIDs and vSwitch/VPC IDs, public IP addresses,
DNS names, `Authorization` / `x-amz-security-token` / MSI token headers and
any bearer token, and request signatures. Private IPs and CIDRs inside the
test VPC are kept — they are the substance of the test. A committed fixture
MUST NOT contain a credential, a real account identifier, or a signature.
CI enforces this with a pattern scan over `tests/cloud/**` that fails the
build on a hit, and the scan runs before the fixtures are ever read.

### 3. Replay

Replay is at the **HTTP layer**, not by stubbing the SDK's Rust traits, so the
SDK's own signing, retry, pagination and error-mapping code is exercised:

- AWS: `aws-smithy-runtime`'s replay client where it fits, otherwise the
  shared local replay server with `--ec2-api-endpoint` pointed at it.
- Azure and Alibaba: the shared local replay server, with the SDK's endpoint
  and credential source overridden to a static test credential.
- IMDS and the Azure instance metadata endpoint are served by the same server.

Matching is by method, path, and a canonicalized body, in scenario order.
An unmatched request fails the test and prints the request next to the closest
recorded one. Strict mode (default in CI) also fails on recorded interactions
that were never used, so a fixture set cannot silently rot.

### 4. Scenarios each provider MUST carry

Happy path node bring-up; pre-allocation watermark growth; excess-IP release;
ENI creation, attach and tag; subnet selection with several candidates;
prefix delegation and the `InsufficientCidrBlocks` fallback (AWS); instance
type limits lookup; API throttling with backoff; ENI or IP limit reached;
subnet exhausted; IMDS unavailable at startup; credential expiry mid-run;
operator restart mid-allocation; node deleted during allocation.

### 5. Drift detection

Recorded fixtures go stale silently when a provider changes its API. A
**weekly** scheduled job re-runs the capture xtask against the live account
and diffs the normalized result against the committed fixtures, opening an
issue on a difference. It gates nothing. This is the only job that needs cloud
credentials, it runs on a schedule rather than on a pull request, and its
credentials are read-only where the provider supports that.

## Consequences

- Cloud IPAM becomes a pull-request gate rather than an untested surface, at
  the cost of one manual capture per provider per API change.
- The fixtures are the contract: a change to how flowsdn calls a cloud API
  requires a re-capture in the same commit, which is the behavior we want.
- Spec 07's test plan and spec 22's CI matrix MUST be amended to name this
  mechanism, and spec 19's gap 9 is closed by it.
- No CI job outside the weekly drift check may hold cloud credentials.
