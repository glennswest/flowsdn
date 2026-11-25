//! #523: `egress/policy-maps-dump` runs flowsdn's egress gateway planner over
//! the fake API, with flowsdn's own kinds.
#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Archive, RunOptions, State};
use std::time::Duration;

#[test]
fn policy_maps_dump_shows_the_planned_entries() {
    let archive = Archive::parse(
        "hive start\nk8s/add node.yaml pod.yaml policy.yaml\negress/policy-maps-dump actual\ncmp actual expected\n\
-- node.yaml --\napiVersion: v1\nkind: Node\nmetadata:\n  name: kind-worker\n  labels:\n    kubernetes.io/hostname: kind-worker\nspec:\n  podCIDRs: [10.244.3.0/24]\nstatus:\n  addresses:\n  - type: InternalIP\n    address: 172.18.0.3\n\
-- pod.yaml --\napiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  namespace: default\n  uid: 1b0c4f4e-0000-4000-8000-000000000001\n  labels:\n    foo: bar\nspec:\n  nodeName: kind-worker\nstatus:\n  podIP: 10.244.3.91\n\
-- policy.yaml --\napiVersion: flowsdn.io/v1alpha1\nkind: FlowsdnEgressGatewayPolicy\nmetadata:\n  name: policy1\nspec:\n  destinationCIDRs: [0.0.0.0/0]\n  egressGateway:\n    egressIP: 10.10.0.1\n    nodeSelector:\n      matchLabels:\n        kubernetes.io/hostname: kind-worker\n  selectors:\n  - podSelector:\n      matchLabels:\n        foo: bar\n\
-- expected --\nsource_ip=10.244.3.91 dest_cidr=0.0.0.0 egress_ip=0.0.0.0 egress_ifindex=0 gateway_ip=172.18.0.3\n",
    )
    .unwrap();
    let engine = flowsdn_scripttest_fixtures::areas::egress(&[]).unwrap();
    let mut state = State::with_workspace(&std::env::temp_dir(), &std::env::temp_dir()).unwrap();
    state.materialize(&archive).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let options = RunOptions::with_timeout(Duration::from_secs(10)).unwrap();
    runtime
        .block_on(engine.run_async(archive.script(), &mut state, &options))
        .unwrap_or_else(|e| panic!("{e:?}\n{}", engine.diagnostic_dump(&state)));
}
