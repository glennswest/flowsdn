# flowsdn-cli

Install an offline ClusterMesh peer bundle:

```text
flowsdn-cli clustermesh connect --bundle peer.json --config-dir /var/lib/cilium/clustermesh --dry-run
flowsdn-cli clustermesh connect --bundle peer.json --config-dir /var/lib/cilium/clustermesh
```

Create the configuration directory first, writable only by its owner. The JSON
bundle is an owner-only file (for example mode 0600) containing:

```json
{
  "cluster": "east",
  "endpoints": ["https://east.mesh.example:2379"],
  "ca_pem": "<provisioned CA certificate PEM>",
  "cert_pem": "<authorized client certificate PEM>",
  "key_pem": "<matching private key PEM>"
}
```

Use credentials issued for access to that peer and transfer the bundle securely.
Repeat separately for each direction. `--replace` explicitly replaces an existing
peer config. Credentials are written with mode 0400 into immutable generations;
one atomic rename publishes the completed YAML config. Old generations remain
so existing readers retain their referenced files. Mount this directory at the
same absolute path for agents, because the config contains absolute certificate
paths. A stale `.flowsdn-connect.lock` requires checking that the previous writer
has stopped before removing it.

This command does not access Kubernetes, issue certificates or test connectivity.
PEM checks are structural; the receiving TLS client must verify certificates and
key correspondence. The command never prints credential contents. It rejects
symlinks, parent traversal and writable-by-others configuration directories.
The current project still requires live ClusterMesh client/controller integration.
