# Reference CRD schema corpus — not installation manifests

Copyright Authors of Cilium. Licensed under the Apache License 2.0; the exact
upstream license text is retained in `LICENSE-APACHE-2.0`.

These 22 YAML files are copied byte-for-byte from
[cilium/cilium](https://github.com/cilium/cilium/tree/7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc/pkg/k8s/apis/cilium.io/client/crds)
at commit `7d68cfb394f2960e10aa72e76d0d51e66c1b2ebc` (reference tag v1.20.1),
from `pkg/k8s/apis/cilium.io/client/crds/{v2,v2alpha1}/`, on 2026-09-27.
Every exact source path, license, reference commit and SHA-256 is recorded in
`manifest.json`; `SHA256SUMS` provides the conventional checksum listing.
The seven graduated CRDs embed both served v2 and deprecated v2alpha1 schemas
inside their v2 YAML files. No embedded versions or fields have been removed.

The original YAML is intentionally not modified to add attribution headers:
this adjacent notice, the machine-readable manifest and repository `NOTICE`
provide attribution while preserving exact upstream byte identity.

**Do not apply these YAML files to a cluster as flowsdn manifests.** They
retain upstream names solely as reference data. `schemas::registration_payloads`
verifies the complete corpus before projecting it into `flowsdn.io/v1alpha1`,
with owned kinds, names, category, and adapted schema identity constraints.
No Cilium-owned CRD is installed or adopted by this loader.

The manifest digest in `src/schemas.rs` binds this corpus to schema provenance
`1.33.11`. A schema update must review source revision, file hashes, manifest
digest, schema provenance version and the projection tests together. Checksums
establish corpus integrity; they do not establish Kubernetes admission or
stored-instance migration compatibility. The loader retains schema extensions,
including CEL rules, without interpreting or reimplementing admission.
