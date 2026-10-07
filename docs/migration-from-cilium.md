# Migrating a cluster from Cilium

flowsdn does not read Cilium's objects, configuration or state at run time
([ADR-0020](decisions/0020-no-reference-names-shipped.md)). Moving a cluster
is a one-time conversion, done before flowsdn starts:

1. **Drain Cilium.** Uninstall it (its DaemonSet, operator, CNI configuration
   in `/etc/cni/net.d` and binary in `/opt/cni/bin`), then reboot each node so
   its BPF programs, pinned maps and links are gone. flowsdn never adopts
   them.
2. **Install flowsdn**: on stormcos, the flowsdn edition; elsewhere the Helm
   chart ([helm.md](helm.md)), whose "Coming from another CNI's chart"
   section maps Cilium's Helm values to flowsdn's.
3. **Convert policies and pools.** Each `cilium.io` kind has a `flowsdn.io`
   kind with the same schema ([crds.md](crds.md) has the table). Change
   `apiVersion` to `flowsdn.io/v1alpha1` and `kind` to the flowsdn kind;
   selectors, label keys and rules stay as they are. Objects the Cilium agent
   wrote for itself (endpoints, identities, nodes, endpoint slices) are not
   converted: flowsdn writes its own.
4. **Delete the `cilium.io` CRDs** once nothing uses them. flowsdn does not
   delete them.
5. **Command line:** `sc net` (stormcos) and the agent API
   ([agent-api.md](agent-api.md)) replace the Cilium CLI; there is no
   compatibility layer.

Pod IPs come from flowsdn's pools, so pods restart onto flowsdn's network.
