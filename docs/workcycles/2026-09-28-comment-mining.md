# Issue-comment mining — 2026-09-28

Scope: all 32 open/closed flowsdn issues returned by updated:>=2026-09-27 (limit 200). Read every issue comments collection and reviewed all 25 comments created since the cutoff. The paginated issue-comments API confirmed 25 updated comments, with no older comments edited into this window. Snapshot preceded this audit follow-up comments.

Outcome: one new P1 issue, stormcos#183; one existing owner decision supplemented and labeled needs-owner, stormcentral#83. Linked both back to flowsdn#296. No implementation fixes, host changes, tests, golden or release.

The owner must designate/register a disposable flowsdn pair; the existing Decide issue is the canonical decision. The TLS-provider decision is already resolved.

| Source issue#comment | Finding | Issue / disposition |
|---|---|---|
| [3#5858327314](https://github.com/glennswest/flowsdn/issues/3#issuecomment-5858327314) | Pinned Aya kfunc relocation fails UnknownFunction | [flowsdn#3](https://github.com/glennswest/flowsdn/issues/3) — existing |
| [103#5858326476](https://github.com/glennswest/flowsdn/issues/103#issuecomment-5858326476) | Full Rule-to-LPM compiler and sustained independent oracle gate remain | [flowsdn#103](https://github.com/glennswest/flowsdn/issues/103) — existing |
| [165#5858325557](https://github.com/glennswest/flowsdn/issues/165#issuecomment-5858325557) | C21 HTTP negotiation and 5,000-pod list measurement unverified | [flowsdn#165](https://github.com/glennswest/flowsdn/issues/165) — existing |
| [266#5858324616](https://github.com/glennswest/flowsdn/issues/266#issuecomment-5858324616) | Dead-file encryption cases lack full packet/map ports and reference validation | [flowsdn#266](https://github.com/glennswest/flowsdn/issues/266) — existing |
| [281#5858324355](https://github.com/glennswest/flowsdn/issues/281#issuecomment-5858324355) | HTTPS matcher fixed locally; upstream report remains outstanding | [flowsdn#281](https://github.com/glennswest/flowsdn/issues/281) — existing |
| [291#5858324086](https://github.com/glennswest/flowsdn/issues/291#issuecomment-5858324086) | Watch/identity/ipcache/routes integration and two-node acceptance incomplete | [flowsdn#291](https://github.com/glennswest/flowsdn/issues/291) — existing |
| [291#5873814891](https://github.com/glennswest/flowsdn/issues/291#issuecomment-5873814891) | Build-volume/reaper infrastructure finding | [stormcentral#132](https://github.com/glennswest/stormcentral/issues/132) — existing |
| [291#5873814891](https://github.com/glennswest/flowsdn/issues/291#issuecomment-5873814891) | Unwritable cache prevents build-failure reporting | [stormcentral#138](https://github.com/glennswest/stormcentral/issues/138) — existing |
| [291#5874665803](https://github.com/glennswest/flowsdn/issues/291#issuecomment-5874665803) | GNU/Fedora OpenSSL agent runtime packaging required | [stormcos#171](https://github.com/glennswest/stormcos/issues/171) — existing |
| [291#5875080799](https://github.com/glennswest/flowsdn/issues/291#issuecomment-5875080799) | TLS policy failure and provider decision resolved by system OpenSSL | [flowsdn#306](https://github.com/glennswest/flowsdn/issues/306) — existing, resolved |
| [293#5858345511](https://github.com/glennswest/flowsdn/issues/293#issuecomment-5858345511) | Live WireGuard ACK, Observer, Azure transport/auth, BGP TCP, ClusterMesh Secret/TLS integration remain | [flowsdn#293](https://github.com/glennswest/flowsdn/issues/293) — existing |
| [294#5858345637](https://github.com/glennswest/flowsdn/issues/294#issuecomment-5858345637) | Expanded seccomp/runtime packaging and full kernel matrix gates remain | [flowsdn#294](https://github.com/glennswest/flowsdn/issues/294) — existing |
| [296#5858323432](https://github.com/glennswest/flowsdn/issues/296#issuecomment-5858323432) | Operator, observer/relay and multi-node integration missing | [flowsdn#296](https://github.com/glennswest/flowsdn/issues/296) — existing |
| [296#5858323432](https://github.com/glennswest/flowsdn/issues/296#issuecomment-5858323432) | Golden lacks required BPF object; host CNI exposure unverified | [stormcos#145](https://github.com/glennswest/stormcos/issues/145) — existing |
| [296#5875433822](https://github.com/glennswest/flowsdn/issues/296#issuecomment-5875433822) | Owner must designate/register disposable flowsdn pair | [stormcentral#83](https://github.com/glennswest/stormcentral/issues/83) — decision, existing; supplemented and needs-owner |
| [296#5875433822](https://github.com/glennswest/flowsdn/issues/296#issuecomment-5875433822) | Referenced root-SSH testbed path unusable under component-session rules | [stormcos#183](https://github.com/glennswest/stormcos/issues/183) — new, P1 |
| [298#5858323029](https://github.com/glennswest/flowsdn/issues/298#issuecomment-5858323029) | Generated CRD/event/sc net integration incomplete; API is Unix-only | [flowsdn#298](https://github.com/glennswest/flowsdn/issues/298) — existing |
| [299#5875226805](https://github.com/glennswest/flowsdn/issues/299#issuecomment-5875226805) | Special golden staging omits flowsdn; no golden produced | [stormcos#155](https://github.com/glennswest/stormcos/issues/155) — existing |
| [30#5858349478](https://github.com/glennswest/flowsdn/issues/30#issuecomment-5858349478) | CRD schema/CEL/defaulting/list-map enforcement gaps | [rustkube#121](https://github.com/glennswest/rustkube/issues/121) — existing |
| [30#5858349478](https://github.com/glennswest/flowsdn/issues/30#issuecomment-5858349478) | Compacted watches do not return Kubernetes 410 | [rustkube#127](https://github.com/glennswest/rustkube/issues/127) — existing |
| [30#5858349478](https://github.com/glennswest/flowsdn/issues/30#issuecomment-5858349478) | Main CR writes can overwrite controller-owned status | [rustkube#128](https://github.com/glennswest/rustkube/issues/128) — existing |
| [301#5858915445](https://github.com/glennswest/flowsdn/issues/301#issuecomment-5858915445) | SSH configuration ownership blocked remote validation | [stormcentral#102](https://github.com/glennswest/stormcentral/issues/102) — existing, resolved |
| [305#5873815491](https://github.com/glennswest/flowsdn/issues/305#issuecomment-5873815491) | cargo-deny absent from disposable environment; invocation corrected | [flowsdn#305](https://github.com/glennswest/flowsdn/issues/305) — existing, resolved |

Repeated evidence: #300 comment 5858320687 and #301 comment 5858320480 repeat stormcos#145; #304 comment 5873441635 repeats stormcos#155. #306 comments repeat the TLS and integration findings on #291. #299 comment 5875209330 reports verification before its later staging failure; it does not establish live admission/migration. #296 comment 5874876930 records a dependency on #299 subsequently resolved by closure. No separate defect was inferred from success/queue updates.

Deduplication used all-state keyword searches in each owning repository and body/comment inspection of candidate trackers. Flowsdn searches included kfunc, simulator, protobuf, encrypt_host_wireguard_tunnel, HTTPS redirect, Milestone, operator relay, printer, deny, WireGuard ACK, Observer, Azure, BGP, ClusterMesh, seccomp, kernel matrix, two-node and Decide. Rustkube searches included schema CEL, compacted watch, preserve status and protobuf. Infrastructure searches included flowsdn, make-testbed, root SSH, provisioning, test machines and each explicit cross-repository reference.

The provisioning issue distinguishes the script default from an absolute privilege requirement: PVE is configurable, but no supported delegated route is documented. It permits an infrastructure-owner handoff; no script was run. Its source link is pinned to stormcos 5f1504084647b4d5c209ec96212aaec960660c22.

Updates: [decision evidence](https://github.com/glennswest/stormcentral/issues/83#issuecomment-5878117370), [flowsdn handoff](https://github.com/glennswest/flowsdn/issues/296#issuecomment-5878122103).

Validation: read-only GitHub issue/source review, exact source-comment links, confirmed P1 response and needs-owner label; local whitespace and JSON checks only. No build/runtime acceptance claim.
