# ADR-0014: CNI ownership and configuration boundaries

Date: 2026-09-21. Status: accepted; implementation validation recorded separately.

This batch resolves seven related issue contracts. Foundation implementation does
not establish milestone 1 networking acceptance.

| Issue | Decision and implementation boundary |
| --- | --- |
| #48 | `strict-config` defaults false. The effective layered value enables rejection of unknown normalized keys, including lower-priority typos. This is a configuration-library extension; CLI and chart lint integration remain future work. |
| #115 | `endpoint-id-max` defaults 4095, accepts 1–65535, and bounds new allocation inclusively. Restored IDs above a lowered ceiling remain reserved. No high-scale performance claim is made. |
| #120 | Spec 01 owns the versioned object identity hash and successful-load publication contract; endpoint configuration identity is separate. Persistent generation caching remains future loader work. |
| #121 | Incomplete module probes report Warning while aggregate HTTP readiness remains 500. |
| #127 | Duplicate ADD reuses only a healthy attachment matching the live namespace cookie, host and peer identity, and addresses. Creation-time gateways and route MTU are persisted and reused across configuration changes. Missing ownership metadata fails safely; foreign attachments are never deleted to make ADD succeed. |
| #130 | CNI omits a synthetic namespace mount path it never created. The namespace cookie establishes identity; an optional path is informational. |
| #131 | ADR-0003 and spec 10 agree that FORWARD ACCEPT cannot bypass other base chains. Detect incompatible policy and require an external allowlist; executable N31/N32 acceptance remains outstanding. |

Relevant contracts: specs 00, 01, 08, 09 and 10. Implementations are in the
configuration library, endpoint manager, standalone API, API client and CNI.
The privileged fixtures cover duplicate ADD, foreign namespaces, restart with
changed route MTU, bounded endpoint exhaustion, and released-ID reuse.

Remaining milestone obligations are tracked by #291. CHECK route/MTU depth
(#126), cross-endpoint rollback verification (#129), and connectivity-suite
specification (#261) are not resolved by this batch.
