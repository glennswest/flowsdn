use flowsdn_gateway::{config, conformance, matcher::*, status::*};
use serde_json::{Value, json};
use std::collections::BTreeSet;
fn resource(service: Value) -> Value { json!({"spec":{"service":service}}) }
#[test]
fn lb_only_fields_are_rejected_even_when_boolean_false_or_ranges_empty() {
    for (name, value) in [("loadBalancerClass",json!("example.com/lb")), ("loadBalancerSourceRanges",json!([])), ("allocateLoadBalancerNodePorts",json!(false))] {
        let mut service = json!({"type":"NodePort"});
        service.as_object_mut().expect("object").insert(name.into(),value.clone());
        let input = resource(service.clone());
        assert!(config::validate(&input).iter().any(|e| e.path == format!("spec.service.{name}")));
        service.as_object_mut().expect("object").remove("type");
        assert!(config::validate(&resource(service)).is_empty(),"{name}");
        assert_eq!(input.pointer("/spec/service/type"),Some(&json!("NodePort")));
    }
    assert!(config::validate(&resource(json!({"type":"NodePort","loadBalancerClass":null}))).is_empty());
}
#[test]
fn ip_family_policy_validates_combinations_not_only_enum_values() {
    for (policy, families, valid) in [
        ("SingleStack",json!(["IPv4"]),true), ("SingleStack",json!(["IPv6"]),true),
        ("SingleStack",json!(["IPv4","IPv6"]),false),
        ("PreferDualStack",json!(["IPv6"]),true), ("PreferDualStack",json!(["IPv6","IPv4"]),true),
        ("RequireDualStack",json!(["IPv4"]),true), ("RequireDualStack",json!(["IPv4","IPv6"]),true),
        ("RequireDualStack",json!([]),true), ("RequireDualStack",json!(["IPv4","IPv4"]),false),
        ("Unknown",json!(["IPv4"]),false), ("SingleStack",json!(["IPv5"]),false),
        ("PreferDualStack",json!(["IPv4","IPv6","IPv4"]),false),
    ] {
        assert_eq!(config::validate(&resource(json!({"ipFamilyPolicy":policy,"ipFamilies":families}))).is_empty(), valid, "{policy} {families}");
    }
    assert!(!config::validate(&resource(json!({"ipFamilies":["IPv4","IPv6"]}))).is_empty());
    assert!(config::validate(&resource(json!({"ipFamilyPolicy":"RequireDualStack"}))).is_empty());
}
#[test]
fn access_log_format_requires_corresponding_populated_payload() {
    for (entry, valid) in [
        (json!({"format":"Text","text":"%REQ(:PATH)%"}),true),
        (json!({"format":"JSON","json":{"path":"%REQ(:PATH)%"}}),true),
        (json!({"format":"Text","json":{"path":"x"}}),false),
        (json!({"format":"JSON","text":"x"}),false),
        (json!({"format":"Text","text":""}),false),
        (json!({"format":"JSON","json":{}}),false),
        (json!({"format":"JSON","json":{"path":4}}),false),
        (json!({"format":"Text","text":"x","json":{"unused":"default"}}),true),
        (json!({"format":"Unknown","text":"x"}),false),
        (json!({"format":"Text","text":"a".repeat(4097)}),false),
    ] {
        let input=json!({"spec":{"telemetry":{"accessLogs":[entry]}}});
        assert_eq!(config::validate(&input).is_empty(),valid,"{input}");
    }
}
#[test]
fn malformed_shapes_and_ranges_cannot_be_accepted() {
    for input in [json!(null),json!({"spec":[]}),resource(json!(42)),resource(json!({"type":5})),
        resource(json!({"ipFamilies":"IPv4"})),resource(json!({"allocateLoadBalancerNodePorts":"false"})),
        resource(json!({"loadBalancerSourceRanges":["10.0.0.0/33","::/129"]})),
        json!({"spec":{"telemetry":{"accessLogs":{}}}}),json!({"spec":{"telemetry":{"accessLogs":[]}}}),
        json!({"spec":{"telemetry":{"accessLogs":[null]}}})] {
        assert!(!config::validate(&input).is_empty(),"{input}");
        assert_eq!(config::accepted_condition(&input,7).get("reason"),Some(&json!("InvalidParameters")));
    }
    assert!(config::validate(&resource(json!({"loadBalancerSourceRanges":["10.0.0.0/8","2001:db8::/32"]}))).is_empty());
}
#[test]
fn validation_condition_tracks_acceptance_and_generation_without_mutating_resource() {
    let input=json!({"spec":{"service":{"type":"NodePort","allocateLoadBalancerNodePorts":false}},"status":{"foreign":"keep"}});
    let before=input.clone();
    assert_eq!(config::accepted_condition(&input,9),json!({"type":"Accepted","status":"False","reason":"InvalidParameters","message":"Invalid GatewayClassConfig","observedGeneration":9}));
    assert_eq!(input,before);
    assert_eq!(config::accepted_condition(&json!({"spec":{}}),10),json!({"type":"Accepted","status":"True","reason":"Accepted","message":"Valid GatewayClassConfig","observedGeneration":10}));
}
#[test]
fn redirect_keeps_headers_and_queries_separate_including_equal_names() {
    let headers=vec![HeaderMatch{name:"token".into(),value:StringMatch::Exact("header-value".into())}];
    let query_parameters=vec![QueryMatch{name:"token".into(),value:StringMatch::Prefix("query-value".into())}];
    let route=force_https(RouteMatches { headers:headers.clone(),query_parameters:query_parameters.clone() });
    assert_eq!(route.matches.headers,headers);
    assert_eq!(route.matches.query_parameters,query_parameters);
    assert_eq!(route.status_code,301);
    let query_only=force_https(RouteMatches { headers:vec![],query_parameters });
    assert!(query_only.matches.headers.is_empty());
    assert_eq!(query_only.matches.query_parameters.len(),1);
    let header_only=force_https(RouteMatches { headers,..Default::default() });
    assert!(header_only.matches.query_parameters.is_empty());
}
#[test]
fn reason_strings_preserve_reference_quirks_but_not_config_validation_bug() {
    for (kind, expected) in [(RouteKind::Http,"InvalidHTTPRoute"),(RouteKind::Grpc,"InvalidGRPCRoute"),(RouteKind::Tls,"InvalidTLSRoute"),(RouteKind::Tcp,"InvalidTCPRoute"),(RouteKind::Udp,"InvalidUDPRoute")] {
        assert_eq!(kind.missing_parent_reason(),expected);
    }
    for (kind,reason) in [(GammaCondition::Attached,"Accepted"),(GammaCondition::Programmed,"Programmed")] {
        for success in [true,false] {
            let condition=kind.project(success);
            assert_eq!(condition.get("reason"),Some(&json!(reason)));
            assert_eq!(condition.get("status"),Some(&json!(if success {"True"}else{"False"})));
        }
    }
}
#[test]
fn conformance_plan_detects_drift_and_cannot_advertise_unimplemented_targets() {
    // Synthetic catalogue exercises the contract; this is not the upstream
    // AllFeatures corpus or evidence of a real conformance-suite run.
    let golden=BTreeSet::from(["Gateway".into(),"HTTPRoute".into()]);
    let all=golden.iter().cloned().chain(conformance::EXEMPT_FEATURES.iter().map(|s|(*s).to_owned())).collect::<BTreeSet<_>>();
    let target=conformance::checked_target(&all,&golden).expect("target");
    assert_eq!(conformance::supported_features(&target,&golden).expect("implemented"),vec!["Gateway","HTTPRoute"]);
    assert!(conformance::supported_features(&target,&BTreeSet::new()).is_err());
    assert!(!target.contains("ListenerSet"));
    let mut drift=all.clone(); drift.insert("NewFeature".into());
    assert_eq!(conformance::checked_target(&drift,&golden),Err(conformance::Error::GoldenMismatch));
    drift.remove("ListenerSet");
    assert!(matches!(conformance::checked_target(&drift,&golden),Err(conformance::Error::ExemptionNotInCatalogue(_))));
    for list in [conformance::EXEMPT_FEATURES,conformance::SKIPPED_TESTS,conformance::PROFILES] {
        assert_eq!(list.iter().copied().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>(),list);
    }
}
