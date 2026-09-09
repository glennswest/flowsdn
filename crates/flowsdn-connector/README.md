# Native Linux connector

Rust netlink operations for veth creation, interface lookup/configuration,
namespace transfer, address and route installation, neighbor entries and
idempotent deletion. Requests use a namespace-bound socket and a five-second
deadline. Namespace work runs on a dedicated joined thread; normal and error
returns restore the original namespace. A kernel namespace cookie is available
for endpoint identity.

The live CNI fixtures use these operations for endpoint setup and rollback.
The initial configuration supports dual-stack Ethernet interfaces with MTU at
least 1280. Netkit, advanced GRO/GSO settings, delegated-IPAM rules and route
reconciliation remain outstanding. Call synchronous operations outside an
existing asynchronous runtime.
