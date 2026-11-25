use super::*;
use flowsdn_l7::dns::Policy as _;

fn answerer(rules: Rules) -> Arc<Answerer> {
    let a = Answerer::new(Box::new(|_, _, _| true));
    a.publish(&rules);
    a
}

#[test]
fn rules_match_identity_aggregate_port_and_name() {
    let mut rules = Rules::default();
    rules.endpoints.insert("10.1.0.5".parse().expect("ip"), (7, 300));
    rules.rules.insert(
        7,
        vec![
            DnsRule {
                identity: 301,
                protocol: 17,
                port: 53,
                prefix: 16,
                names: vec![r"^api\.example\.com\.$".into()],
                any_name: false,
            },
            DnsRule {
                identity: 13,
                protocol: 0,
                port: 0,
                prefix: 0,
                names: Vec::new(),
                any_name: true,
            },
        ],
    );
    let a = answerer(rules);
    assert_eq!(a.endpoint("10.1.0.5".parse().expect("ip")), Some((7, 300)));
    assert!(a.allowed(7, 301, 17, 53, "api.example.com."));
    assert!(!a.allowed(7, 301, 17, 53, "www.example.com."));
    assert!(!a.allowed(7, 301, 6, 53, "api.example.com."), "UDP only");
    assert!(!a.allowed(7, 302, 17, 53, "api.example.com."), "another server");
    // A local (CIDR/FQDN) identity aggregates to world (13): any name.
    assert!(a.allowed(7, (1 << 24) | 5, 6, 53, "anything."));
    assert!(!a.allowed(8, 301, 17, 53, "api.example.com."), "another endpoint");
}

#[test]
fn the_hold_waits_for_the_pass_and_gives_up_at_its_limit() {
    let wake = Arc::new(Wake::default());
    let learn = hold(|_, _, _| true, Arc::clone(&wake), Duration::from_millis(50));
    let started = Instant::now();
    assert!(!learn(&[], &[], 0), "nobody applies: timed out");
    assert!(started.elapsed() >= Duration::from_millis(50));
    let pass = Arc::clone(&wake);
    let thread = std::thread::spawn(move || {
        let requests = pass.wait(Duration::from_secs(5));
        pass.applied(requests);
    });
    let learn = hold(|_, _, _| true, Arc::clone(&wake), Duration::from_secs(5));
    assert!(learn(&[], &[], 0), "the pass applied it");
    thread.join().expect("pass");
    // Nothing changed: no wait at all.
    let learn = hold(|_, _, _| false, wake, Duration::from_secs(5));
    assert!(learn(&[], &[], 0));
}

#[test]
fn settings_parse_the_reference_keys() {
    let object = serde_json::json!({"tofqdns-proxy-port": 10053, "tofqdns-min-ttl": 30,
        "tofqdns-dns-reject-response-code": "nameError", "tofqdns-proxy-response-max-delay": 250});
    let settings = Settings::parse(object.as_object().expect("object")).expect("settings");
    assert_eq!(settings.port, 10053);
    assert_eq!(settings.limits.min_ttl, 30);
    assert_eq!(settings.config.reject, rcode::NXDOMAIN);
    assert_eq!(settings.max_delay, Duration::from_millis(250));
    let bad = serde_json::json!({"tofqdns-dns-reject-response-code": "drop"});
    assert!(Settings::parse(bad.as_object().expect("object")).is_err());
}
