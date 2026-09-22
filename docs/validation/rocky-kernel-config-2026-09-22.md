# Rocky 10 kernel configuration validation — 2026-09-22

Booted the official Rocky Linux 10.0 GenericCloud x86-64 image in a disposable
KVM virtual machine and read `/boot/config-$(uname -r)` from the running guest.
Kernel: `6.12.0-55.14.1.el10_0.x86_64`. All **73** configured symbols in the flowsdn §2.6
fragment are available (`y` or `m`). `VETH=m` differs from the fragment’s `y`;
its module must be included in the node image. Thirteen other symbols are built
in instead of modular, which satisfies availability. No feature is missing.

Source image: [Rocky 10.0 GenericCloud](https://dl.rockylinux.org/vault/rocky/10.0/images/x86_64/Rocky-10-GenericCloud-Base-10.0-20250609.1.x86_64.qcow2).
The published CHECKSUM was verified before boot:
`20e771c654724e002c32fb92a05fdfdd7ac878c192f50e2fc21f53e8f098b8f9`.
Guest configuration SHA-256: `0cfb32396ead10705ac2021a4ff1e143f9ff02d0940f7536deda66416481d500`.
Checklist: flowsdn commit `d5d026c`, `docs/kernel-requirements.md` §2.6.

This verifies configuration availability on this x86-64 kernel. It does not
validate physical NIC support, arm64, module packaging, or end-to-end networking.
It does not replace stormcos’s newer 6.12.0-211 release pin.

| Symbol | Fragment | Guest |
|---|---|---|
| `CONFIG_BPF` | `y` | `y` |
| `CONFIG_BPF_SYSCALL` | `y` | `y` |
| `CONFIG_BPF_JIT` | `y` | `y` |
| `CONFIG_HAVE_EBPF_JIT` | `y` | `y` |
| `CONFIG_BPF_JIT_ALWAYS_ON` | `y` | `y` |
| `CONFIG_BPF_JIT_DEFAULT_ON` | `y` | `y` |
| `CONFIG_DEBUG_INFO_BTF` | `y` | `y` |
| `CONFIG_DEBUG_INFO_BTF_MODULES` | `y` | `y` |
| `CONFIG_BPF_EVENTS` | `y` | `y` |
| `CONFIG_PERF_EVENTS` | `y` | `y` |
| `CONFIG_CGROUPS` | `y` | `y` |
| `CONFIG_CGROUP_BPF` | `y` | `y` |
| `CONFIG_CGROUP_NET_CLASSID` | `y` | `y` |
| `CONFIG_MEMCG` | `y` | `y` |
| `CONFIG_NAMESPACES` | `y` | `y` |
| `CONFIG_NET_NS` | `y` | `y` |
| `CONFIG_NET_SCHED` | `y` | `y` |
| `CONFIG_NET_CLS_ACT` | `y` | `y` |
| `CONFIG_NET_SCH_INGRESS` | `m` | `m` |
| `CONFIG_NET_CLS_BPF` | `m` | `m` |
| `CONFIG_VETH` | `y` | `m` |
| `CONFIG_NETKIT` | `y` | `y` |
| `CONFIG_VXLAN` | `m` | `m` |
| `CONFIG_GENEVE` | `m` | `m` |
| `CONFIG_NET_UDP_TUNNEL` | `m` | `m` |
| `CONFIG_NET_IPIP` | `m` | `m` |
| `CONFIG_IPV6_TUNNEL` | `m` | `m` |
| `CONFIG_INET` | `y` | `y` |
| `CONFIG_IPV6` | `y` | `y` |
| `CONFIG_IP_ADVANCED_ROUTER` | `y` | `y` |
| `CONFIG_IP_MULTIPLE_TABLES` | `y` | `y` |
| `CONFIG_IPV6_MULTIPLE_TABLES` | `y` | `y` |
| `CONFIG_FIB_RULES` | `y` | `y` |
| `CONFIG_INET_DIAG` | `m` | `y` |
| `CONFIG_INET_TCP_DIAG` | `m` | `y` |
| `CONFIG_INET_UDP_DIAG` | `m` | `y` |
| `CONFIG_INET_DIAG_DESTROY` | `y` | `y` |
| `CONFIG_NETFILTER` | `y` | `y` |
| `CONFIG_NF_TABLES` | `m` | `m` |
| `CONFIG_NF_TABLES_INET` | `y` | `y` |
| `CONFIG_NF_CONNTRACK` | `m` | `m` |
| `CONFIG_NFT_CT` | `m` | `m` |
| `CONFIG_NFT_TPROXY` | `m` | `m` |
| `CONFIG_NF_TPROXY_IPV4` | `m` | `m` |
| `CONFIG_NF_TPROXY_IPV6` | `m` | `m` |
| `CONFIG_NFT_SOCKET` | `m` | `m` |
| `CONFIG_NF_SOCKET_IPV4` | `m` | `m` |
| `CONFIG_NF_SOCKET_IPV6` | `m` | `m` |
| `CONFIG_NET_SCH_FQ` | `m` | `m` |
| `CONFIG_TCP_CONG_BBR` | `m` | `m` |
| `CONFIG_TCP_CONG_ADVANCED` | `y` | `y` |
| `CONFIG_WIREGUARD` | `m` | `m` |
| `CONFIG_XFRM` | `y` | `y` |
| `CONFIG_XFRM_USER` | `m` | `y` |
| `CONFIG_XFRM_ALGO` | `m` | `y` |
| `CONFIG_XFRM_STATISTICS` | `y` | `y` |
| `CONFIG_XFRM_OFFLOAD` | `y` | `y` |
| `CONFIG_INET_ESP` | `m` | `m` |
| `CONFIG_INET6_ESP` | `m` | `m` |
| `CONFIG_INET_IPCOMP` | `m` | `m` |
| `CONFIG_INET6_IPCOMP` | `m` | `m` |
| `CONFIG_INET_XFRM_TUNNEL` | `m` | `m` |
| `CONFIG_INET6_XFRM_TUNNEL` | `m` | `m` |
| `CONFIG_INET_TUNNEL` | `m` | `m` |
| `CONFIG_INET6_TUNNEL` | `m` | `m` |
| `CONFIG_CRYPTO_AEAD` | `m` | `y` |
| `CONFIG_CRYPTO_AEAD2` | `m` | `y` |
| `CONFIG_CRYPTO_GCM` | `m` | `y` |
| `CONFIG_CRYPTO_SEQIV` | `m` | `y` |
| `CONFIG_CRYPTO_CBC` | `m` | `y` |
| `CONFIG_CRYPTO_HMAC` | `m` | `y` |
| `CONFIG_CRYPTO_SHA256` | `m` | `y` |
| `CONFIG_CRYPTO_AES` | `m` | `y` |
