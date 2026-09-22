use flowsdn_cloud_azure::{Cloud, Monitor, Operation, Poller, Response, State, request};
use serde_json::{Value, json};
fn response(status: u16, headers: &[(&str, &str)], body: Value) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body,
    }
}
fn resource() -> String {
    request(Cloud::Public, "sub", "rg", Operation::PutNic("n"))
        .expect("request")
        .url
}
#[test]
fn all_thirteen_operations_have_independent_pinned_routes() {
    let cases: Value = serde_json::from_str(include_str!("fixtures/routes.json")).expect("fixture");
    let operations = [
        Operation::ListNics,
        Operation::GetNic("n"),
        Operation::PutNic("n"),
        Operation::ListScaleSets,
        Operation::ListScaleSetNics("s"),
        Operation::ListVmNics("s", "0"),
        Operation::GetVm("s", "0"),
        Operation::UpdateVm("s", "0"),
        Operation::GetStandaloneVm("v"),
        Operation::GetSubnet("v", "u"),
        Operation::ListPublicPrefixes,
        Operation::GetPublicIp("p"),
        Operation::ListVmPublicIps("s", "0", "n", "i"),
    ];
    assert_eq!(cases.as_array().expect("array").len(), operations.len());
    for (operation, expected) in operations.into_iter().zip(cases.as_array().expect("array")) {
        for cloud in [Cloud::Public, Cloud::Government, Cloud::China] {
            let actual = request(cloud, "sub", "rg", operation.clone()).expect("request");
            assert_eq!(Some(actual.method), expected.get(0).and_then(Value::as_str));
            assert_eq!(
                actual.url,
                format!(
                    "{}/subscriptions/sub/resourceGroups/rg/providers/{}",
                    cloud.endpoint(),
                    expected.get(1).and_then(Value::as_str).expect("url")
                )
            );
            assert_eq!(actual.long_running, actual.method == "PUT");
        }
    }
    for bad in ["..", "a/b", "a?b", "%2f", "a b", ""] {
        assert!(request(Cloud::Public, "sub", "rg", Operation::GetNic(bad)).is_err());
    }
}
#[test]
fn fixture_replay_initial_delay_throttling_final_get_and_restart() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/lro.json")).expect("fixture");
    let responses: Vec<Response> = fixture
        .as_array()
        .expect("array")
        .iter()
        .map(|v| Response {
            status: u16::try_from(v.get("status").and_then(Value::as_u64).expect("status"))
                .expect("u16"),
            headers: v
                .get("headers")
                .and_then(Value::as_array)
                .expect("headers")
                .iter()
                .map(|h| {
                    (
                        h.get(0).and_then(Value::as_str).expect("key").to_owned(),
                        h.get(1).and_then(Value::as_str).expect("value").to_owned(),
                    )
                })
                .collect(),
            body: v.get("body").expect("body").clone(),
        })
        .collect();
    let mut poller = Poller::begin(Cloud::Public, resource(), responses.first().expect("begin"))
        .expect("accepted");
    assert!(matches!(
        poller.state(),
        State::Waiting {
            monitor: Monitor::AsyncOperation,
            delay_seconds: 17,
            ..
        }
    ));
    for (reply, expected_delay) in responses.iter().skip(1).take(2).zip([3, 21]) {
        poller.observe(reply).expect("poll");
        assert!(
            matches!(poller.state(),State::Waiting { delay_seconds,.. } if *delay_seconds==expected_delay)
        );
        assert!(!poller.may_release_ownership());
        poller = Poller::restore(&poller.checkpoint()).expect("recover");
    }
    poller
        .observe(responses.get(3).expect("success"))
        .expect("poll");
    assert_eq!(poller.state(), &State::FetchResource);
    assert!(!poller.may_release_ownership());
    poller
        .observe(responses.get(4).expect("resource"))
        .expect("get");
    assert!(poller.may_release_ownership());
}
#[test]
fn location_fallback_resource_polling_and_terminal_failures() {
    let mut poller = Poller::begin(
        Cloud::Public,
        resource(),
        &response(
            202,
            &[("location", "https://management.azure.com/operations/one")],
            json!({}),
        ),
    )
    .expect("location");
    poller
        .observe(&response(202, &[], json!({})))
        .expect("pending");
    assert!(!poller.may_release_ownership());
    poller
        .observe(&response(204, &[], Value::Null))
        .expect("done");
    assert_eq!(poller.state(), &State::FetchResource);
    for status in ["Failed", "Canceled"] {
        let mut poller = Poller::begin(
            Cloud::Public,
            resource(),
            &response(
                201,
                &[],
                json!({"properties":{"provisioningState":"Updating"}}),
            ),
        )
        .expect("resource monitor");
        poller
            .observe(&response(
                200,
                &[],
                json!({"properties":{"provisioningState":status}}),
            ))
            .expect("terminal");
        assert!(poller.may_release_ownership());
        assert_ne!(poller.state(), &State::Succeeded);
    }
}
#[test]
fn errors_do_not_release_ownership_or_corrupt_checkpoint() {
    let mut p = Poller::begin(
        Cloud::Public,
        resource(),
        &response(
            202,
            &[(
                "Azure-AsyncOperation",
                "https://management.azure.com/operations/x",
            )],
            json!({}),
        ),
    )
    .expect("poller");
    for r in [
        response(200, &[], json!({})),
        response(403, &[], json!({})),
        response(429, &[("Retry-After", "tomorrow")], json!({})),
    ] {
        let before = p.checkpoint();
        assert!(p.observe(&r).is_err());
        assert_eq!(p.checkpoint(), before);
        assert!(!p.may_release_ownership());
    }
    for url in [
        "http://management.azure.com/x",
        "https://management.azure.com.evil/x",
        "https://management.azure.com@evil/x",
        "https://management.azure.com/../x",
        "https://management.azure.com/x#fragment",
    ] {
        assert!(
            Poller::begin(
                Cloud::Public,
                resource(),
                &response(202, &[("Location", url)], json!({}))
            )
            .is_err()
        );
    }
    assert!(Poller::begin(Cloud::Public, resource(), &response(202, &[], json!({}))).is_err());
    assert!(
        Poller::begin(
            Cloud::Public,
            resource(),
            &response(
                202,
                &[
                    ("Location", "https://management.azure.com/x"),
                    ("location", "https://management.azure.com/y")
                ],
                json!({})
            )
        )
        .is_err()
    );
    let mut checkpoint = p.checkpoint();
    checkpoint
        .as_object_mut()
        .expect("object")
        .insert("endpoint".to_owned(), json!("https://evil.test"));
    assert!(Poller::restore(&checkpoint).is_err());
    assert!(
        Cloud::Public
            .validate_url(&format!(
                "https://management.azure.com/operations/{}",
                "a".repeat(4096)
            ))
            .is_ok()
    );
}
#[test]
fn preserves_unknown_model_fields_and_guards_pagination_authority() {
    let model = json!({"name":"vm","futureField":{"a":1},"properties":{"storageProfile":{"imageReference":{"id":"image"},"dataDisks":[1]},"networkProfile":{"keep":true}}});
    let result = flowsdn_cloud_azure::prepare_vm_update(model.clone()).expect("model");
    assert!(
        result
            .pointer("/properties/storageProfile/imageReference")
            .is_none()
    );
    assert_eq!(result.get("futureField"), model.get("futureField"));
    assert_eq!(
        result.pointer("/properties/networkProfile"),
        model.pointer("/properties/networkProfile")
    );
    assert!(
        flowsdn_cloud_azure::next_page(
            Cloud::Public,
            &json!({"nextLink":"https://evil.test/page"})
        )
        .is_err()
    );
    assert_eq!(
        flowsdn_cloud_azure::next_page(Cloud::Public, &json!({})),
        Ok(None)
    );
    assert!(flowsdn_cloud_azure::next_page(Cloud::Public, &json!({"nextLink":false})).is_err());
}

#[test]
fn malformed_resource_shapes_never_authorize_completion() {
    let bad = [
        Value::Null,
        json!([]),
        json!("not a resource"),
        json!({"properties":null}),
        json!({"properties":[]}),
        json!({"properties":{"provisioningState":null}}),
        json!({"properties":{"provisioningState":17}}),
        json!({"properties":{"provisioningState":""}}),
    ];
    for body in bad {
        assert!(
            Poller::begin(Cloud::Public, resource(), &response(200, &[], body.clone())).is_err()
        );
        assert!(
            Poller::begin(Cloud::Public, resource(), &response(201, &[], body.clone())).is_err()
        );
        let mut polling = Poller::begin(
            Cloud::Public,
            resource(),
            &response(
                201,
                &[],
                json!({"properties":{"provisioningState":"Updating"}}),
            ),
        )
        .expect("resource poller");
        let before = polling.checkpoint();
        assert!(polling.observe(&response(200, &[], body.clone())).is_err());
        assert_eq!(polling.checkpoint(), before);
        assert!(!polling.may_release_ownership());
        let mut final_get = Poller::begin(
            Cloud::Public,
            resource(),
            &response(
                202,
                &[("Location", "https://management.azure.com/operations/check")],
                Value::Null,
            ),
        )
        .expect("location");
        final_get
            .observe(&response(204, &[], Value::Null))
            .expect("empty complete monitor");
        let before = final_get.checkpoint();
        assert!(final_get.observe(&response(200, &[], body)).is_err());
        assert_eq!(final_get.checkpoint(), before);
        assert!(!final_get.may_release_ownership());
    }
}
#[test]
fn valid_objects_without_provisioning_state_remain_supported() {
    for body in [
        json!({}),
        json!({"properties":{}}),
        json!({"name":"nic","future":true}),
    ] {
        let immediate = Poller::begin(Cloud::Public, resource(), &response(200, &[], body.clone()))
            .expect("object");
        assert_eq!(immediate.state(), &State::Succeeded);
        let mut poller = Poller::begin(
            Cloud::Public,
            resource(),
            &response(
                202,
                &[("Location", "https://management.azure.com/operations/check")],
                Value::Null,
            ),
        )
        .expect("location");
        poller
            .observe(&response(202, &[], Value::Null))
            .expect("pending empty");
        assert!(!poller.may_release_ownership());
        poller
            .observe(&response(204, &[], Value::Null))
            .expect("completed empty");
        poller
            .observe(&response(200, &[], body))
            .expect("valid final resource");
        assert!(poller.may_release_ownership());
    }
}
