# flowsdn-policy

Policy-library building blocks from spec 06:

- atomic replacement of one resolved subject's resource rules, rejecting
  Pass/authentication combinations before changing contents or revision;
- CIDR base/exception prefix planning with allocation-before-publication and
  release-after-publication sets;
- selector-owned named-port contributions recomputed after changes;
- API port validation, masked-port expansion and BPF key conversion;
- exact policy-map pressure alarms and explicit overflow action planning;
- independent brute-force resolved L3/L4 oracle for tiers, priorities, Pass,
  deny precedence and redirect preference.

The oracle does not implement authentication inheritance or L7 content matching.
It refuses authentication inputs rather than reporting an unverified verdict.
CIDR planning currently requires a base prefix. Selectors containing only
exception requirements still require an importer planning path; the normative
contract includes allocating those prefixes before policy publication.
There is no Kubernetes importer, label-selector compiler, complete optimized
mapstate builder, BPF map writer, policy REST handler, or controller here. Kernel
publication and its atomicity remain the caller's responsibility. Full policy
scope and the required fuzz comparison against the eventual optimized builder
remain in spec 06; this crate is not a claim of network-policy enforcement.
