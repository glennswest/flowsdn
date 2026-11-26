#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;

fn plugin(name: &str, uid: &str) -> Value {
    json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnDatapathPlugin",
           "metadata": {"name": name, "uid": uid},
           "spec": {"attachmentPolicy": "Always", "version": "1"}})
}

#[test]
fn each_plugin_gets_one_not_applied_event() {
    let now = "2026-11-26T15:00:00Z";
    let plugins = vec![plugin("tracer", "0123456789abcdef"), plugin("other", "fedcba9876543210")];
    let events = plan(&plugins, &BTreeSet::new(), now);
    assert_eq!(events.len(), 2);
    let (uid, event) = &events[0];
    assert_eq!(uid, "0123456789abcdef");
    assert_eq!(event["metadata"]["name"], "tracer.01234567");
    assert_eq!(event["involvedObject"]["kind"], "FlowsdnDatapathPlugin");
    assert_eq!(event["involvedObject"]["uid"], "0123456789abcdef");
    assert_eq!((event["type"].as_str(), event["reason"].as_str()), (Some("Warning"), Some(REASON)));
    assert!(event["message"].as_str().unwrap().contains("not applied"));
    // An object already reported is not reported again.
    let seen = BTreeSet::from(["0123456789abcdef".to_owned()]);
    let again = plan(&plugins, &seen, now);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].0, "fedcba9876543210");
    // An object without a name or uid is skipped.
    assert!(plan(&[json!({"metadata": {"name": "x"}})], &BTreeSet::new(), now).is_empty());
}

type Reply = Result<(u16, Value), flowsdn_k8s::Error>;

#[test]
fn a_pass_posts_once_tolerates_409_and_forgets_deleted_objects() {
    let mut reported = BTreeSet::new();
    let mut posted: Vec<String> = Vec::new();
    let mut items = vec![plugin("tracer", "u1"), plugin("again", "u2")];
    {
        let mut send = |method: http::Method, path: &str, body: Option<&Value>| -> Reply {
            match method.as_str() {
                "GET" => Ok((200, json!({"items": items.clone()}))),
                "POST" => {
                    assert_eq!(path, "/api/v1/namespaces/default/events");
                    let name = body.unwrap()["involvedObject"]["name"].as_str().unwrap().to_owned();
                    posted.push(name.clone());
                    // The second was posted by an earlier term already.
                    Ok((if name == "again" { 409 } else { 201 }, json!({})))
                }
                _ => panic!("{method} {path}"),
            }
        };
        let names = report(&mut reported, "2026-11-26T15:00:00Z", &mut send).unwrap();
        assert_eq!(names, ["tracer", "again"]);
        assert!(report(&mut reported, "2026-11-26T15:01:00Z", &mut send).unwrap().is_empty());
    }
    assert_eq!(posted, ["tracer", "again"], "each posted once");
    // A deleted object is forgotten; a new one with the same name is reported.
    items = vec![plugin("tracer", "u3")];
    let mut send = |method: http::Method, _: &str, _: Option<&Value>| -> Reply {
        match method.as_str() {
            "GET" => Ok((200, json!({"items": items.clone()}))),
            _ => Ok((201, json!({}))),
        }
    };
    assert_eq!(report(&mut reported, "2026-11-26T15:02:00Z", &mut send).unwrap(), ["tracer"]);
    assert_eq!(reported, BTreeSet::from(["u3".to_owned()]));
    // No CRD yet: nothing, no error. Another failure is an error.
    let mut absent = |_: http::Method, _: &str, _: Option<&Value>| -> Reply { Ok((404, json!({}))) };
    assert!(report(&mut reported, "x", &mut absent).unwrap().is_empty());
    let mut denied = |_: http::Method, _: &str, _: Option<&Value>| -> Reply {
        Ok((403, json!({"message": "forbidden"})))
    };
    assert!(report(&mut reported, "x", &mut denied).unwrap_err().contains("403 forbidden"));
}
