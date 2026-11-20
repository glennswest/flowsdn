use super::*;
use crate::kubernetes::{Derive, LocalEndpoint, NodeInfo};

fn view() -> View {
    View {
        local_node: "n1".into(),
        nodes: vec![
            NodeInfo {
                name: "n1".into(),
                uid: "node-uid".into(),
                internal_ips: vec!["192.0.2.1".parse().expect("IP")],
                pod_cidrs: vec![("10.1.0.0".parse().expect("IP"), 16)],
                labels: [("kubernetes.io/hostname".to_owned(), "n1".to_owned())].into(),
                ..NodeInfo::default()
            },
            NodeInfo {
                name: "n2".into(),
                uid: "other".into(),
                ..NodeInfo::default()
            },
        ],
        endpoints: vec![LocalEndpoint {
            id: 7,
            namespace: "shop".into(),
            name: "web".into(),
            value: json!({"default": {"ip_addresses": ["10.1.0.5/32"]}}),
            ..LocalEndpoint::default()
        }],
        derive: Derive {
            v4: true,
            v6: true,
        },
        ..View::default()
    }
}

#[test]
fn the_node_object_carries_addresses_pools_and_used_addresses() {
    let object = desired(&view(), "boot-1").expect("desired");
    let value = serde_json::to_value(&object).expect("JSON");
    // IPv6 has no Node CIDR, so the derived one (#296) is published too.
    let cidrs = value
        .pointer("/spec/ipam/podCIDRs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(cidrs.first(), Some(&json!("10.1.0.0/16")));
    assert_eq!(cidrs.len(), 2, "{cidrs:?}");
    let expected = json!({
        "apiVersion": "flowsdn.io/v1alpha1",
        "kind": "FlowsdnNode",
        "metadata": {"name": "n1",
            "labels": {"kubernetes.io/hostname": "n1"},
            "ownerReferences": [{"apiVersion": "v1", "kind": "Node", "name": "n1", "uid": "node-uid"}]},
        "spec": {
            "addresses": [{"type": "InternalIP", "ip": "192.0.2.1"}],
            "bootid": "boot-1",
            "ipam": {"podCIDRs": cidrs},
        },
        "status": {"ipam": {"used": {"10.1.0.5": {"owner": "shop/web"}}}},
    });
    assert_eq!(value, expected);
    let crd = flowsdn_k8s::crd::owned_crds()
        .expect("CRDs")
        .into_iter()
        .find(|c| c.document.pointer("/spec/names/plural") == Some(&json!("flowsdnnodes")))
        .expect("CRD");
    let schema = crd
        .document
        .pointer("/spec/versions/0/schema/openAPIV3Schema")
        .expect("schema");
    assert_eq!(
        flowsdn_k8s::schema::validate(schema, &value),
        Vec::<String>::new()
    );
    // No Node UID yet: nothing.
    let mut early = view();
    early.nodes.retain(|n| n.name != "n1");
    assert!(desired(&early, "boot-1").is_none());
}

#[derive(Default)]
struct Api {
    calls: Vec<(String, String, Option<Value>)>,
    answers: Vec<(String, u16, Value)>,
}
impl Api {
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
            meta.insert("resourceVersion".into(), json!("5"));
        }
        (200, echo)
    }
    fn methods(&self) -> Vec<String> {
        self.calls
            .iter()
            .map(|(m, p, _)| format!("{m} {p}"))
            .collect()
    }
}
fn pass(writer: &mut NodeWriter, want: Option<&FlowsdnNode>, api: &mut Api) -> Result {
    let mut send =
        |m: http::Method, p: &str, b: Option<&Value>| -> std::result::Result<(u16, Value), String> {
            Ok(api.send(m, p, b))
        };
    writer.sync(want, &mut send)
}

const PATH: &str = "/apis/flowsdn.io/v1alpha1/flowsdnnodes/n1";

#[test]
fn created_then_status_then_left_alone() {
    let object = desired(&view(), "boot-1").expect("desired");
    let mut writer = NodeWriter::default();
    let mut api = Api::default();
    api.answers.push(("GET".into(), 404, Value::Null));
    assert_eq!(pass(&mut writer, Some(&object), &mut api), Ok(true));
    assert_eq!(
        api.methods(),
        [
            format!("GET {PATH}"),
            "POST /apis/flowsdn.io/v1alpha1/flowsdnnodes".to_owned(),
            format!("PUT {PATH}/status"),
        ]
    );
    // The create carries no status; the status write carries it and the
    // created object's resourceVersion.
    let create = api.calls.get(1).and_then(|c| c.2.clone()).expect("create");
    assert!(create.get("status").is_none());
    let status = api.calls.get(2).and_then(|c| c.2.clone()).expect("status");
    assert_eq!(
        status.pointer("/metadata/resourceVersion"),
        Some(&json!("5"))
    );
    assert_eq!(
        status.pointer("/status/ipam/used/10.1.0.5/owner"),
        Some(&json!("shop/web"))
    );
    // Unchanged: no request.
    assert_eq!(pass(&mut writer, Some(&object), &mut api), Ok(true));
    assert_eq!(api.calls.len(), 3);
}

#[test]
fn a_changed_spec_is_replaced_with_the_read_version() {
    let object = desired(&view(), "boot-2").expect("desired");
    let mut stale = serde_json::to_value(&object).expect("JSON");
    if let Some(spec) = stale.get_mut("spec").and_then(Value::as_object_mut) {
        spec.insert("bootid".into(), json!("boot-1"));
    }
    if let Some(meta) = stale.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("resourceVersion".into(), json!("3"));
    }
    let mut writer = NodeWriter::default();
    let mut api = Api::default();
    api.answers.push(("GET".into(), 200, stale));
    assert_eq!(pass(&mut writer, Some(&object), &mut api), Ok(true));
    assert_eq!(
        api.methods(),
        [format!("GET {PATH}"), format!("PUT {PATH}")],
        "the status already matches"
    );
    let put = api.calls.get(1).and_then(|c| c.2.clone()).expect("put");
    assert_eq!(put.pointer("/metadata/resourceVersion"), Some(&json!("3")));
    assert_eq!(put.pointer("/spec/bootid"), Some(&json!("boot-2")));
}

#[test]
fn an_unserved_kind_waits() {
    let object = desired(&view(), "boot-1").expect("desired");
    let mut writer = NodeWriter::default();
    let mut api = Api::default();
    api.answers.push(("GET".into(), 404, Value::Null));
    api.answers.push(("POST".into(), 404, Value::Null));
    assert_eq!(pass(&mut writer, Some(&object), &mut api), Ok(false));
    assert_eq!(pass(&mut writer, Some(&object), &mut api), Ok(false));
    assert_eq!(api.calls.len(), 2, "no retry within the minute");
}

#[test]
fn a_refused_write_is_an_error() {
    let object = desired(&view(), "boot-1").expect("desired");
    let mut writer = NodeWriter::default();
    let mut api = Api::default();
    api.answers.push(("GET".into(), 500, json!({"message": "boom"})));
    assert_eq!(
        pass(&mut writer, Some(&object), &mut api),
        Err("HTTP 500 boom".to_owned())
    );
}
