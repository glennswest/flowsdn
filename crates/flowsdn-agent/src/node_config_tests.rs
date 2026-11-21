use super::*;

fn base() -> Value {
    json!({
        "socket-path": "/var/run/flowsdn/flowsdn.sock",
        "state-dir": "/var/lib/flowsdn",
        "ipv4-pool": "auto",
        "ipv6-pool": "auto",
        "device-mtu": 1500,
        "route-mtu": 1500,
        "egress": "stack",
        "kubernetes": {"node-name": "n1", "host-firewall": "audit"},
    })
}
fn config(name: &str, selector: Value, defaults: Value) -> Value {
    json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnNodeConfig",
        "metadata": {"name": name, "namespace": "kube-system"},
        "spec": {"nodeSelector": selector, "defaults": defaults}})
}
fn labels() -> BTreeMap<String, String> {
    [
        ("kubernetes.io/hostname".to_owned(), "n1".to_owned()),
        ("edge".to_owned(), "yes".to_owned()),
    ]
    .into()
}
/// The agent's own parse, as `run` passes it.
fn valid(candidate: &Value) -> Result<(), String> {
    crate::api::validate_config(candidate)
}

#[test]
fn selected_configs_override_agent_settings_in_name_order() {
    let configs = [
        config(
            "b-later",
            json!({"matchLabels": {"edge": "yes"}}),
            json!({"kubernetes.host-firewall": "enforce", "kubernetes.lb-sock-terminate-all-protos": "true"}),
        ),
        config(
            "a-first",
            json!({}),
            json!({"kubernetes.host-firewall": "off", "egress": "fib", "route-mtu": "1400"}),
        ),
        config(
            "other-nodes",
            json!({"matchLabels": {"edge": "no"}}),
            json!({"egress": "fib"}),
        ),
    ];
    let (merged, report) = apply(&base(), &configs, &labels(), &valid);
    assert_eq!(report.selected, ["a-first", "b-later"]);
    assert_eq!(
        merged.pointer("/kubernetes/host-firewall"),
        Some(&json!("enforce"))
    );
    assert_eq!(
        merged.pointer("/kubernetes/lb-sock-terminate-all-protos"),
        Some(&json!(true)),
        "JSON when it parses"
    );
    assert_eq!(merged.get("route-mtu"), Some(&json!(1400)));
    assert_eq!(merged.get("egress"), Some(&json!("fib")), "text otherwise");
    assert_eq!(
        report
            .applied
            .get("kubernetes.host-firewall")
            .map(String::as_str),
        Some("b-later")
    );
    assert_eq!(
        report.applied.get("egress").map(String::as_str),
        Some("a-first")
    );
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    // The merged document is a configuration the agent accepts.
    assert_eq!(valid(&merged), Ok(()));
}

#[test]
fn unknown_unsafe_and_invalid_keys_are_refused_and_the_rest_applies() {
    let configs = [config(
        "mixed",
        json!({"matchExpressions": [{"key": "edge", "operator": "Exists"}]}),
        json!({
            "kubernetes.node-name": "n2",
            "state-dir": "/tmp/elsewhere",
            "kubernetes.cluster-name": "other",
            "enable-bpf-masquerade": "true",
            "kubernetes.host-firewall": "bogus",
            "kubernetes.lb-mode": "dsr",
        }),
    )];
    let (merged, report) = apply(&base(), &configs, &labels(), &valid);
    assert_eq!(merged.pointer("/kubernetes/lb-mode"), Some(&json!("dsr")));
    assert_eq!(
        merged.pointer("/kubernetes/host-firewall"),
        Some(&json!("audit"))
    );
    assert_eq!(merged.pointer("/kubernetes/node-name"), Some(&json!("n1")));
    assert_eq!(merged.get("state-dir"), Some(&json!("/var/lib/flowsdn")));
    let mut refused: Vec<&str> = report.refused.iter().map(|r| r.key.as_str()).collect();
    refused.sort_unstable();
    assert_eq!(
        refused,
        [
            "enable-bpf-masquerade",
            "kubernetes.cluster-name",
            "kubernetes.host-firewall",
            "kubernetes.node-name",
            "state-dir",
        ]
    );
    let bogus = report
        .refused
        .iter()
        .find(|r| r.key == "kubernetes.host-firewall")
        .expect("refused");
    assert!(bogus.reason.contains("host-firewall"), "{}", bogus.reason);
    assert_eq!(report.applied.len(), 1);
    let health = report.json();
    assert_eq!(
        health.pointer("/applied/kubernetes.lb-mode"),
        Some(&json!("mixed"))
    );
    assert_eq!(health.pointer("/refused/0/config"), Some(&json!("mixed")));
    assert_eq!(health.pointer("/selected/0"), Some(&json!("mixed")));
}

#[test]
fn a_bad_selector_and_a_non_string_value_are_refused() {
    let configs = [
        config(
            "bad",
            json!({"matchExpressions": [{"key": "edge", "operator": "Bogus"}]}),
            json!({"egress": "fib"}),
        ),
        config("numbers", json!({}), json!({"device-mtu": 1400})),
    ];
    let (merged, report) = apply(&base(), &configs, &labels(), &valid);
    assert_eq!(merged, base());
    assert_eq!(report.selected, ["numbers"]);
    let keys: Vec<(&str, &str)> = report
        .refused
        .iter()
        .map(|r| (r.config.as_str(), r.key.as_str()))
        .collect();
    assert_eq!(keys, [("bad", "nodeSelector"), ("numbers", "device-mtu")]);
}

#[test]
fn every_allowed_key_is_one_the_agent_reads() {
    // Each allowed key, set to a value of its own kind, is accepted by the
    // agent's parse and changes the parsed configuration's document.
    let samples = [
        ("egress", "fib"),
        ("device-mtu", "9000"),
        ("route-mtu", "1400"),
        ("ipv4-pool", "auto"),
        ("ipv6-pool", "auto"),
        ("ipv4-gateway", "auto"),
        ("ipv6-gateway", "auto"),
        ("kubernetes.auto-direct-node-routes", "false"),
        ("kubernetes.direct-routing-skip-unreachable", "true"),
        ("kubernetes.service-lb", "false"),
        ("kubernetes.node-port", "false"),
        ("kubernetes.lb-algorithm", "maglev"),
        ("kubernetes.lb-mode", "hybrid"),
        ("kubernetes.nat46x64", "true"),
        ("kubernetes.lb-external-clusterip", "true"),
        ("kubernetes.policy-audit-mode", "true"),
        ("kubernetes.bpf-masquerade", "true"),
        ("kubernetes.nat46x64-gateway", "true"),
        ("kubernetes.lb-ipam", "false"),
        ("kubernetes.l2-announcements", "false"),
        ("kubernetes.identity-allocation", "false"),
        ("kubernetes.network-policy", "false"),
        ("kubernetes.flowsdn-policy", "true"),
        ("kubernetes.host-firewall", "enforce"),
        ("kubernetes.uplinks", "{\"mode\":\"single\"}"),
        ("kubernetes.endpoint-crd", "false"),
        ("kubernetes.node-crd", "false"),
        ("kubernetes.crd-wait-timeout", "60"),
        ("kubernetes.lb-sock-terminate-all-protos", "true"),
    ];
    assert_eq!(samples.len(), ALLOWED.len());
    for (key, value) in samples {
        assert!(ALLOWED.contains(&key), "{key}");
        let configs = [config("one", json!({}), json!({ key: value }))];
        let (_, report) = apply(&base(), &configs, &labels(), &valid);
        assert!(report.refused.is_empty(), "{key}: {:?}", report.refused);
        assert_eq!(report.applied.len(), 1, "{key}");
    }
}

#[test]
fn a_pool_and_its_gateway_apply_together() {
    let configs = [config(
        "pool",
        json!({}),
        json!({"ipv4-pool": "10.9.0.0/16", "ipv4-gateway": "10.9.0.1"}),
    )];
    let (merged, report) = apply(&base(), &configs, &labels(), &valid);
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    assert_eq!(merged.get("ipv4-pool"), Some(&json!("10.9.0.0/16")));
    assert_eq!(merged.get("ipv4-gateway"), Some(&json!("10.9.0.1")));
    // Alone, the pool is not a valid configuration: refused, base kept.
    let alone = [config(
        "alone",
        json!({}),
        json!({"ipv4-pool": "10.9.0.0/16"}),
    )];
    let (merged, report) = apply(&base(), &alone, &labels(), &valid);
    assert_eq!(merged, base());
    assert_eq!(report.refused.len(), 1);
}
