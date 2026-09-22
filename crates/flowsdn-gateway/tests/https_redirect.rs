use flowsdn_gateway::matcher::*;
use serde_json::json;
#[test]
fn corrected_projection_matches_annotated_golden() {
    let route = force_https(RouteMatches {
        headers: vec![HeaderMatch {
            name: "token".into(),
            value: StringMatch::Exact("header-value".into()),
        }],
        query_parameters: vec![QueryMatch {
            name: "token".into(),
            value: StringMatch::Prefix("query-value".into()),
        }],
    });
    let expected:serde_json::Value=serde_json::from_str(include_str!("../../../tests/golden/08-operator-model-translation-ingress/flowsdn-https-matchers/output-route.json")).expect("golden");
    assert_eq!(
        route
            .envoy_route(&StringMatch::Prefix("/secure/".into()))
            .expect("route"),
        expected
    );
}
#[test]
fn each_single_list_stays_in_its_own_envoy_field() {
    let header = force_https(RouteMatches {
        headers: vec![HeaderMatch {
            name: "x-header".into(),
            value: StringMatch::Any,
        }],
        query_parameters: vec![],
    })
    .envoy_route(&StringMatch::Any)
    .expect("header");
    assert_eq!(
        header.pointer("/match/headers/0"),
        Some(&json!({"name":"x-header","presentMatch":true}))
    );
    assert!(header.pointer("/match/queryParameters").is_none());
    let query = force_https(RouteMatches {
        headers: vec![],
        query_parameters: vec![QueryMatch {
            name: "q".into(),
            value: StringMatch::Regex("^yes$".into()),
        }],
    })
    .envoy_route(&StringMatch::Exact("/".into()))
    .expect("query");
    assert_eq!(
        query.pointer("/match/queryParameters/0"),
        Some(&json!({"name":"q","stringMatch":{"safeRegex":{"regex":"^yes$"}}}))
    );
    assert!(query.pointer("/match/headers").is_none());
    assert_eq!(query.pointer("/redirect/httpsRedirect"), Some(&json!(true)));
    assert!(query.pointer("/redirect/responseCode").is_none());
}
#[test]
fn empty_lists_match_existing_harvest_shape_and_bad_input_rejects() {
    assert_eq!(
        force_https(RouteMatches::default())
            .envoy_route(&StringMatch::Any)
            .expect("empty"),
        json!({"match":{"prefix":"/"},"redirect":{"httpsRedirect":true}})
    );
    let bad = force_https(RouteMatches {
        headers: vec![HeaderMatch {
            name: String::new(),
            value: StringMatch::Any,
        }],
        query_parameters: vec![],
    });
    assert!(bad.envoy_route(&StringMatch::Any).is_err());
}
