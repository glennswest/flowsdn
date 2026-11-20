use super::*;
use serde_json::json;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("IP")
}
fn pool(name: &str, created: &str, spec: Value) -> Pool {
    Pool::parse(&json!({
        "metadata": {"name": name, "creationTimestamp": created, "generation": 1},
        "spec": spec,
    }))
}
fn lb(namespace: &str, name: &str, created: &str) -> ServiceInfo {
    ServiceInfo {
        namespace: namespace.into(),
        name: name.into(),
        service_type: "LoadBalancer".into(),
        created: created.into(),
        resource_version: "7".into(),
        ..ServiceInfo::default()
    }
}
fn ips(plan: &Plan, namespace: &str, name: &str) -> Vec<String> {
    plan.services[&(namespace.to_owned(), name.to_owned())]
        .ips
        .iter()
        .map(ToString::to_string)
        .collect()
}
const NOW: &str = "2026-11-19T00:00:00Z";

#[test]
fn edge_lb_gets_the_lowest_address_and_the_status_patch_names_it() {
    let pools = [pool(
        "lan",
        "2026-11-01T00:00:00Z",
        json!({"blocks": [{"start": "192.168.30.240", "stop": "192.168.30.250"}]}),
    )];
    let edge = ServiceInfo {
        external_local: true,
        ..lb("storefront", "edge-lb", "2026-11-19T00:00:00Z")
    };
    let plan = plan(&pools, std::slice::from_ref(&edge), NOW);
    assert_eq!(ips(&plan, "storefront", "edge-lb"), ["192.168.30.240"]);
    let patches = plan.patches(std::slice::from_ref(&edge));
    assert_eq!(patches.len(), 1);
    assert_eq!(
        patches[0].path(),
        "/api/v1/namespaces/storefront/services/edge-lb/status"
    );
    assert_eq!(
        patches[0].body(),
        json!({"metadata": {"resourceVersion": "7"},
               "status": {"loadBalancer": {"ingress": [{"ip": "192.168.30.240"}]}}})
    );
    // Once the status says so, nothing is patched.
    let written = ServiceInfo {
        load_balancer_ips: vec![ip("192.168.30.240")],
        ..edge
    };
    let again = super::plan(&pools, std::slice::from_ref(&written), NOW);
    assert!(again.patches(std::slice::from_ref(&written)).is_empty());
    assert_eq!(again.pools[0].used, 1);
    assert_eq!(again.pools[0].available, 10);
}

#[test]
fn addresses_are_kept_released_and_never_shared() {
    let pools = [pool(
        "p",
        "2026-11-01T00:00:00Z",
        json!({"blocks": [{"cidr": "10.0.0.0/30"}]}),
    )];
    // b already holds .0; a (older) gets the next free address, not .0.
    let a = lb("ns", "a", "2026-11-01T00:00:00Z");
    let b = ServiceInfo {
        load_balancer_ips: vec![ip("10.0.0.0")],
        ..lb("ns", "b", "2026-11-02T00:00:00Z")
    };
    let plan1 = plan(&pools, &[a.clone(), b.clone()], NOW);
    assert_eq!(ips(&plan1, "ns", "b"), ["10.0.0.0"]);
    assert_eq!(ips(&plan1, "ns", "a"), ["10.0.0.1"]);
    // Two Services claim one address: the older keeps it.
    let c = ServiceInfo {
        load_balancer_ips: vec![ip("10.0.0.0")],
        ..lb("ns", "c", "2026-11-03T00:00:00Z")
    };
    let plan2 = plan(&pools, &[b.clone(), c.clone()], NOW);
    assert_eq!(ips(&plan2, "ns", "b"), ["10.0.0.0"]);
    assert_eq!(ips(&plan2, "ns", "c"), ["10.0.0.1"]);
    // b is deleted: its address is free for the next Service.
    let plan3 = plan(&pools, &[lb("ns", "d", "2026-11-04T00:00:00Z")], NOW);
    assert_eq!(ips(&plan3, "ns", "d"), ["10.0.0.0"]);
    // A Service that stops being a LoadBalancer gives its address back.
    let cluster_ip = ServiceInfo {
        service_type: "ClusterIP".into(),
        ..b
    };
    let plan4 = plan(&pools, std::slice::from_ref(&cluster_ip), NOW);
    assert!(ips(&plan4, "ns", "b").is_empty());
    assert_eq!(plan4.patches(std::slice::from_ref(&cluster_ip)).len(), 1);
}

#[test]
fn exhausted_pool_and_requested_addresses() {
    let pools = [pool(
        "one",
        "2026-11-01T00:00:00Z",
        json!({"blocks": [{"start": "198.51.100.9"}]}),
    )];
    let first = lb("ns", "first", "2026-11-01T00:00:00Z");
    let second = lb("ns", "second", "2026-11-02T00:00:00Z");
    let full = plan(&pools, &[first, second.clone()], NOW);
    assert_eq!(ips(&full, "ns", "first"), ["198.51.100.9"]);
    let starved = &full.services[&("ns".to_owned(), "second".to_owned())];
    assert!(starved.ips.is_empty());
    assert_eq!(
        starved.problem.as_deref(),
        Some("no free IPv4 address in a matching pool")
    );
    assert_eq!(full.pools[0].available, 0);
    let conditions = full.pools[0].conditions.as_ref().expect("written");
    assert_eq!(conditions[1]["type"], CONDITION_AVAILABLE);
    assert_eq!(conditions[1]["status"], "False");
    // A requested address outside every pool is reported, not invented.
    let asks = ServiceInfo {
        requested_ips: vec![ip("203.0.113.1")],
        ..second
    };
    let refused = plan(&pools, &[asks], NOW);
    let desired = &refused.services[&("ns".to_owned(), "second".to_owned())];
    assert!(desired.ips.is_empty());
    assert_eq!(
        desired.problem.as_deref(),
        Some("203.0.113.1 is in no enabled pool that matches")
    );
}

#[test]
fn selectors_classes_families_and_disabled_pools() {
    let pools = [
        pool(
            "a-storefront",
            "2026-11-01T00:00:00Z",
            json!({"blocks": [{"cidr": "10.1.0.0/24"}, {"cidr": "fd00:1::/120"}],
                   "allowFirstLastIPs": "No",
                   "serviceSelector": {"matchLabels": {"io.kubernetes.service.namespace": "storefront"}}}),
        ),
        pool(
            "b-off",
            "2026-11-01T00:00:00Z",
            json!({"blocks": [{"cidr": "10.2.0.0/24"}], "disabled": true}),
        ),
    ];
    let dual = ServiceInfo {
        ip_families: vec!["IPv6".into(), "IPv4".into()],
        ..lb("storefront", "edge-lb", "2026-11-01T00:00:00Z")
    };
    let other = lb("default", "web", "2026-11-01T00:00:00Z");
    let classed = ServiceInfo {
        load_balancer_class: Some("example.com/other".into()),
        ..lb("storefront", "classed", "2026-11-01T00:00:00Z")
    };
    // A disabled pool keeps what it already gave.
    let old = ServiceInfo {
        load_balancer_ips: vec![ip("10.2.0.5")],
        ..lb("default", "old", "2026-10-01T00:00:00Z")
    };
    let out = plan(&pools, &[dual, other, classed, old], NOW);
    assert_eq!(ips(&out, "storefront", "edge-lb"), ["10.1.0.1", "fd00:1::1"]);
    assert!(ips(&out, "default", "web").is_empty());
    assert_eq!(
        out.services[&("default".to_owned(), "web".to_owned())]
            .problem
            .as_deref(),
        Some("no enabled pool matches for IPv4")
    );
    assert!(
        !out.services
            .contains_key(&("storefront".to_owned(), "classed".to_owned()))
    );
    assert_eq!(ips(&out, "default", "old"), ["10.2.0.5"]);
}

#[test]
fn overlapping_and_invalid_pools_are_not_used_and_say_why() {
    let pools = [
        pool(
            "newer",
            "2026-11-02T00:00:00Z",
            json!({"blocks": [{"cidr": "10.0.0.0/29"}]}),
        ),
        pool(
            "older",
            "2026-11-01T00:00:00Z",
            json!({"blocks": [{"start": "10.0.0.4", "stop": "10.0.0.5"}]}),
        ),
        pool(
            "broken",
            "2026-11-01T00:00:00Z",
            json!({"blocks": [{"cidr": "10.9.0.0/33"}]}),
        ),
    ];
    let out = plan(&pools, &[lb("ns", "s", "2026-11-03T00:00:00Z")], NOW);
    assert_eq!(ips(&out, "ns", "s"), ["10.0.0.4"]);
    let by_name: BTreeMap<_, _> = out.pools.iter().map(|p| (p.name.as_str(), p)).collect();
    assert_eq!(by_name["newer"].conflict.as_deref(), Some("older"));
    let newer = by_name["newer"].conditions.as_ref().expect("conditions");
    assert_eq!(newer[0]["type"], CONDITION_CONFLICT);
    assert_eq!(newer[0]["status"], "True");
    assert_eq!(newer[0]["lastTransitionTime"], NOW);
    let broken = by_name["broken"].conditions.as_ref().expect("conditions");
    assert_eq!(broken[1]["reason"], "InvalidPool");
    assert_eq!(by_name["broken"].available, 0);
    // Conditions already written (same status) are not written again and
    // keep their transition time.
    let written = Pool {
        conditions: by_name["older"].conditions.clone().expect("conditions"),
        ..pools[1].clone()
    };
    let later = plan(
        &[written],
        &[ServiceInfo {
            load_balancer_ips: vec![ip("10.0.0.4")],
            ..lb("ns", "s", "2026-11-03T00:00:00Z")
        }],
        "2026-11-20T00:00:00Z",
    );
    assert!(later.pools[0].conditions.is_none());
    assert_eq!(
        later.pools[0].path(),
        "/apis/flowsdn.io/v1alpha1/flowsdnloadbalancerippools/older/status"
    );
}

#[test]
fn the_status_json_lists_pools_and_services() {
    let pools = [pool(
        "p",
        "2026-11-01T00:00:00Z",
        json!({"blocks": [{"cidr": "10.0.0.0/31"}]}),
    )];
    let out = plan(&pools, &[lb("ns", "s", "x")], NOW);
    let status = status_json(&out, true, true);
    assert_eq!(status["leader"], true);
    assert_eq!(status["pools"][0]["available"], "1");
    assert_eq!(status["services"][0]["ips"][0], "10.0.0.0");
}
