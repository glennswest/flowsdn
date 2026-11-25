use super::*;
use crate::kubernetes::NodeInfo;

fn view() -> View {
    let mut view = View {
        local_node: "n1".into(),
        nodes: vec![NodeInfo {
            name: "n1".into(),
            internal_ips: vec!["192.0.2.1".parse().expect("IP")],
            ..NodeInfo::default()
        }],
        pods: vec![PodInfo {
            namespace: "shop".into(),
            name: "web".into(),
            node: "n1".into(),
            uid: "pod-1".into(),
            service_account: "web".into(),
            ips: vec!["10.1.0.5".parse().expect("IP")],
            named_ports: vec![(6, "http".into(), 8080), (1, "odd".into(), 1)],
            ..PodInfo::default()
        }],
        pods_synced: true,
        endpoints_published: true,
        identity: true,
        ..View::default()
    };
    view.endpoints = vec![LocalEndpoint {
        id: 7,
        namespace: "shop".into(),
        name: "web".into(),
        uid: "pod-1".into(),
        value: json!({"default": {
            "interface": "eth0", "sandbox": "abc123",
            "ip_addresses": ["10.1.0.5/32", "fd00::5/128"],
        }}),
        ..LocalEndpoint::default()
    }];
    view.pod_identities
        .insert(("shop".into(), "web".into()), 5000);
    view.identities.insert(5000, vec!["k8s:app=web".into()]);
    view.policy_status = json!({"endpoints": [
        {"id": 7, "ingress-enforced": true, "egress-enforced": false}
    ]});
    view
}

#[test]
fn the_object_carries_the_endpoint_and_is_owned_by_the_pod() {
    let view = view();
    let desired = desired(&view);
    let want = desired
        .get(&("shop".to_owned(), "web".to_owned()))
        .expect("desired");
    assert_eq!(want.pod_uid, "pod-1");
    let value = serde_json::to_value(&want.object).expect("JSON");
    assert_eq!(
        value,
        json!({
            "apiVersion": "flowsdn.io/v1alpha1",
            "kind": "FlowsdnEndpoint",
            "metadata": {"name": "web", "namespace": "shop", "ownerReferences": [{
                "apiVersion": "v1", "kind": "Pod", "name": "web", "uid": "pod-1",
                "controller": true, "blockOwnerDeletion": true,
            }]},
            "status": {
                "id": 7,
                "state": "ready",
                "service-account": "web",
                "identity": {"id": 5000, "labels": ["k8s:app=web"]},
                "networking": {"node": "192.0.2.1",
                    "addressing": [{"ipv4": "10.1.0.5", "ipv6": "fd00::5"}]},
                "named-ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
                "external-identifiers": {
                    "container-id": "abc123", "cni-attachment-id": "abc123:eth0",
                    "k8s-namespace": "shop", "k8s-pod-name": "web", "pod-name": "shop/web",
                },
                "policy": {
                    "ingress": {"enforcing": true, "state": "enforcing"},
                    "egress": {"enforcing": false, "state": "non-enforcing"},
                },
            },
        })
    );
    // What the agent writes is what the CRD admits.
    let crd = flowsdn_k8s::crd::owned_crds()
        .expect("CRDs")
        .into_iter()
        .find(|c| c.document.pointer("/spec/names/plural") == Some(&json!("flowsdnendpoints")))
        .expect("CRD");
    let schema = crd
        .document
        .pointer("/spec/versions/0/schema/openAPIV3Schema")
        .expect("schema");
    assert_eq!(
        flowsdn_k8s::schema::validate(schema, &value),
        Vec::<String>::new()
    );
}

#[test]
fn nothing_before_the_lists_and_no_host_network_pods() {
    let mut early = view();
    early.endpoints_published = false;
    assert!(desired(&early).is_empty());
    let mut host = view();
    if let Some(pod) = host.pods.first_mut() {
        pod.host_network = true;
    }
    assert!(desired(&host).is_empty());
    let mut waiting = view();
    waiting.pod_identities.clear();
    let state = desired(&waiting)
        .into_values()
        .next()
        .and_then(|d| d.object.status)
        .and_then(|s| s.state);
    assert_eq!(state.as_deref(), Some("waiting-for-identity"));
}

/// A recording API: answers by (method, path) from a script, default 200
/// echoing the body with `metadata.uid` "ep-1".
#[derive(Default)]
struct Api {
    calls: Vec<(String, String, Option<Value>)>,
    answers: Vec<(String, u16, Value)>,
}
impl Api {
    fn answer(&mut self, method: &str, status: u16, body: Value) {
        self.answers.push((method.into(), status, body));
    }
    fn send(&mut self, method: http::Method, path: &str, body: Option<&Value>) -> (u16, Value) {
        self.calls
            .push((method.to_string(), path.to_owned(), body.cloned()));
        if let Some(index) = self
            .answers
            .iter()
            .position(|(m, _, _)| *m == method.as_str())
        {
            let (_, status, body) = self.answers.remove(index);
            return (status, body);
        }
        let mut echo = body.cloned().unwrap_or(Value::Null);
        if let Some(meta) = echo.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("uid".into(), json!("ep-1"));
        }
        (200, echo)
    }
    fn methods(&self) -> Vec<&str> {
        self.calls.iter().map(|(m, _, _)| m.as_str()).collect()
    }
}
fn pass(writer: &mut Writer, want: &BTreeMap<Key, Desired>, api: &mut Api) -> Outcome {
    let mut send = |m: http::Method, p: &str, b: Option<&Value>| -> Result<(u16, Value), String> {
        Ok(api.send(m, p, b))
    };
    writer.sync(want, &mut send)
}

#[test]
fn create_then_patch_status_with_a_uid_test_then_delete() {
    let mut view = view();
    let mut writer = Writer::default();
    let mut api = Api::default();
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(outcome, Outcome::default());
    assert_eq!(api.methods(), ["POST"]);
    assert_eq!(
        api.calls.first().map(|c| c.1.as_str()),
        Some("/apis/flowsdn.io/v1alpha1/namespaces/shop/flowsdnendpoints")
    );
    assert_eq!(writer.held(), 1);
    // Unchanged: no request.
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.calls.len(), 1);
    // The policy changes: a JSON patch testing the object's UID first.
    view.policy_status = json!({"endpoints": [
        {"id": 7, "ingress-enforced": true, "egress-enforced": true}
    ]});
    pass(&mut writer, &desired(&view), &mut api);
    let (method, path, body) = api.calls.get(1).cloned().expect("patch");
    assert_eq!(method, "PATCH");
    assert_eq!(
        path,
        "/apis/flowsdn.io/v1alpha1/namespaces/shop/flowsdnendpoints/web"
    );
    let body = body.expect("body");
    assert_eq!(
        body.pointer("/0"),
        Some(&json!({"op": "test", "path": "/metadata/uid", "value": "ep-1"}))
    );
    assert_eq!(body.pointer("/1/op"), Some(&json!("replace")));
    assert_eq!(
        body.pointer("/1/value/policy/egress/enforcing"),
        Some(&json!(true))
    );
    // The endpoint goes: deleted with the UID as a precondition.
    view.endpoints.clear();
    pass(&mut writer, &desired(&view), &mut api);
    let (method, _, body) = api.calls.get(2).cloned().expect("delete");
    assert_eq!(method, "DELETE");
    assert_eq!(body, Some(json!({"preconditions": {"uid": "ep-1"}})));
    assert_eq!(writer.held(), 0);
}

#[test]
fn an_unserved_kind_waits_and_is_not_a_failure() {
    let view = view();
    let mut writer = Writer::default();
    let mut api = Api::default();
    api.answer("POST", 404, Value::Null);
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert!(outcome.unserved && outcome.failures.is_empty());
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.calls.len(), 1, "no retry within the minute");
}

#[test]
fn an_existing_object_is_adopted_or_replaced_by_owner() {
    let view = view();
    // Same Pod (an agent restart): adopted, its stale status patched.
    let mut writer = Writer::default();
    let mut api = Api::default();
    api.answer("POST", 409, Value::Null);
    api.answer(
        "GET",
        200,
        json!({"metadata": {"uid": "old-ep", "ownerReferences": [
            {"controller": true, "uid": "pod-1"}]}, "status": {"id": 1}}),
    );
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.methods(), ["POST", "GET", "PATCH"]);
    assert_eq!(
        api.calls
            .get(2)
            .and_then(|c| c.2.as_ref())
            .and_then(|b| b.pointer("/0/value")),
        Some(&json!("old-ep"))
    );
    assert_eq!(writer.held(), 1);

    // Another Pod of the same name: deleted, created again next pass.
    let mut writer = Writer::default();
    let mut api = Api::default();
    api.answer("POST", 409, Value::Null);
    api.answer(
        "GET",
        200,
        json!({"metadata": {"uid": "old-ep", "ownerReferences": [
            {"controller": true, "uid": "pod-0"}]}}),
    );
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.methods(), ["POST", "GET", "DELETE"]);
    assert_eq!(writer.held(), 0);
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.methods(), ["POST", "GET", "DELETE", "POST"]);
    assert_eq!(writer.held(), 1);
}

#[test]
fn a_failed_uid_test_starts_over_and_a_refusal_is_reported() {
    let mut view = view();
    let mut writer = Writer::default();
    let mut api = Api::default();
    pass(&mut writer, &desired(&view), &mut api);
    view.policy_status = json!({});
    api.answer("PATCH", 422, json!({"message": "test failed"}));
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert!(outcome.failures.is_empty());
    assert_eq!(
        writer.held(),
        0,
        "forgotten: the next pass creates or adopts"
    );

    api.answer("POST", 500, json!({"message": "boom"}));
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(
        outcome.failures,
        vec![(
            ("shop".to_owned(), "web".to_owned()),
            "HTTP 500 boom".to_owned()
        )]
    );
}

/// #551 (finding 86abd1e1de01): a DELETE that fails (a transient error or a
/// failed request) keeps the object in the writer's memory and is retried on
/// the next pass until it succeeds; a same-named new Pod's object is created
/// only once the old one is gone.
#[test]
fn a_failed_delete_is_retried_until_it_succeeds() {
    let mut view = view();
    let mut writer = Writer::default();
    let mut api = Api::default();
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(writer.held(), 1);
    let endpoints = view.endpoints.clone();
    view.endpoints.clear();
    api.answer("DELETE", 503, json!({"message": "unavailable"}));
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(
        outcome.failures,
        vec![(
            ("shop".to_owned(), "web".to_owned()),
            "HTTP 503 unavailable".to_owned()
        )]
    );
    assert_eq!(writer.held(), 1, "kept for the retry");
    // A request that fails outright is kept too.
    let outcome = {
        let mut send = |m: http::Method, p: &str, b: Option<&Value>| {
            api.send(m, p, b);
            Err::<(u16, Value), String>("connection reset".into())
        };
        writer.sync(&desired(&view), &mut send)
    };
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(writer.held(), 1);
    // The next pass deletes it, with the same precondition.
    let outcome = pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(outcome, Outcome::default());
    assert_eq!(api.methods(), ["POST", "DELETE", "DELETE", "DELETE"]);
    assert_eq!(
        api.calls.last().and_then(|c| c.2.clone()),
        Some(json!({"preconditions": {"uid": "ep-1"}}))
    );
    assert_eq!(writer.held(), 0);
    pass(&mut writer, &desired(&view), &mut api);
    assert_eq!(api.calls.len(), 4, "nothing left to delete");

    // A new Pod of the same name while the old object's DELETE fails: the
    // old object is not patched for it; it is created after the delete.
    view.endpoints = endpoints;
    let mut writer = Writer::default();
    let mut api = Api::default();
    pass(&mut writer, &desired(&view), &mut api);
    let mut renamed = desired(&view);
    for want in renamed.values_mut() {
        want.pod_uid = "pod-2".into();
    }
    api.answer("DELETE", 500, json!({"message": "boom"}));
    let outcome = pass(&mut writer, &renamed, &mut api);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(api.methods(), ["POST", "DELETE"]);
    pass(&mut writer, &renamed, &mut api);
    assert_eq!(api.methods(), ["POST", "DELETE", "DELETE", "POST"]);
    assert_eq!(writer.held(), 1);
}
