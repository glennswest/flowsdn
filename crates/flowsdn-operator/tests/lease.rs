use flowsdn_operator::lease::{Action, Election, Method, Request, State, Timing};
use serde_json::{Value, json};
use std::time::Duration;
fn t(secs: u64) -> Duration { Duration::from_secs(secs) }
const WALL: &str = "2026-09-27T01:00:00Z";
fn election(holder: &str) -> Election { Election::new("default", "flowsdn-operator-resource-lock", holder, Timing::default()).expect("election") }
fn request(action: Action) -> Request {
    match action { Action::Request(request) | Action::CancelAndRelease(request) => request, other => panic!("expected request, got {other:?}") }
}
fn field(value: &mut Value, pointer: &str, key: &str, val: Value) {
    value.pointer_mut(pointer).and_then(Value::as_object_mut).expect("object").insert(key.into(), val);
}
#[derive(Default)]
struct Server { lease: Option<Value>, revision: u64 }
impl Server {
    fn execute(&mut self, request: &Request) -> (u16, Option<Value>) {
        assert!(request.path.starts_with("/apis/coordination.k8s.io/v1/namespaces/default/leases"));
        if request.method == Method::Get { return (if self.lease.is_some() { 200 } else { 404 }, self.lease.clone()); }
        let mut body = request.body.clone().expect("write body");
        if request.method == Method::Post && self.lease.is_some() { return (409, None); }
        if request.method == Method::Put {
            let Some(old) = self.lease.as_ref() else { return (404, None); };
            if old.pointer("/metadata/uid") != body.pointer("/metadata/uid") || old.pointer("/metadata/resourceVersion") != body.pointer("/metadata/resourceVersion") { return (409, None); }
        }
        self.revision = self.revision.checked_add(1).expect("revision");
        field(&mut body, "/metadata", "uid", json!("lease-uid"));
        field(&mut body, "/metadata", "resourceVersion", json!(self.revision.to_string()));
        self.lease = Some(body.clone());
        (if request.method == Method::Post { 201 } else { 200 }, Some(body))
    }
}
fn deliver(election: &mut Election, request: &Request, server: &mut Server, now: u64) -> Action {
    let (status, body) = server.execute(request);
    election.complete(request.id, Some(status), body.as_ref(), t(now), WALL).expect("completion")
}
fn acquire(election: &mut Election, server: &mut Server) {
    let get = request(election.poll(t(0)).expect("poll"));
    let create = request(deliver(election, &get, server, 0));
    assert_eq!(create.method, Method::Post);
    assert_eq!(election.state(), State::Follower);
    assert!(matches!(deliver(election, &create, server, 0), Action::Acquired));
}
#[test]
fn create_race_has_only_one_successful_leader() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    let mut second = election("second-0123456789");
    let a = request(first.poll(t(0)).expect("poll"));
    let b = request(second.poll(t(0)).expect("poll"));
    let a = request(deliver(&mut first, &a, &mut server, 0));
    let b = request(deliver(&mut second, &b, &mut server, 0));
    assert!(matches!(deliver(&mut first, &a, &mut server, 0), Action::Acquired));
    assert!(matches!(deliver(&mut second, &b, &mut server, 0), Action::WaitUntil(_)));
    assert_eq!(second.state(), State::Follower);
}
#[test]
fn takeover_waits_for_locally_observed_expiry_and_old_leader_loses() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    acquire(&mut first, &mut server);
    // Wall timestamps in the distant past never permit instant takeover.
    let lease = server.lease.as_mut().expect("lease");
    field(lease, "/spec", "renewTime", json!("1900-01-01T00:00:00Z"));
    let mut second = election("second-0123456789");
    let get = request(second.poll(t(100)).expect("poll"));
    assert!(matches!(deliver(&mut second, &get, &mut server, 100), Action::WaitUntil(_)));
    let get = request(second.poll(t(115)).expect("poll"));
    assert!(matches!(deliver(&mut second, &get, &mut server, 115), Action::WaitUntil(_)));
    let get = request(second.poll(t(117)).expect("poll"));
    let put = request(deliver(&mut second, &get, &mut server, 117));
    assert_eq!(put.method, Method::Put);
    assert!(matches!(deliver(&mut second, &put, &mut server, 117), Action::Acquired));
    assert!(matches!(first.poll(t(10)).expect("loss"), Action::CancelAndExit));
    assert_eq!(first.state(), State::Terminal);
    assert_eq!(server.lease.as_ref().and_then(|v| v.pointer("/spec/leaseTransitions")), Some(&json!(1)));
}
#[test]
fn changed_record_resets_expiry_but_metadata_revision_does_not() {
    let mut server = Server::default();
    acquire(&mut election("first-0123456789"), &mut server);
    let mut second = election("second-0123456789");
    let get = request(second.poll(t(0)).expect("poll"));
    assert!(matches!(deliver(&mut second, &get, &mut server, 0), Action::WaitUntil(_)));
    field(server.lease.as_mut().expect("lease"), "/spec", "renewTime", json!("2099-01-01T00:00:00Z"));
    let get = request(second.poll(t(14)).expect("poll"));
    assert!(matches!(deliver(&mut second, &get, &mut server, 14), Action::WaitUntil(_)));
    field(server.lease.as_mut().expect("lease"), "/metadata", "resourceVersion", json!("unrelated"));
    let get = request(second.poll(t(30)).expect("poll"));
    assert!(matches!(deliver(&mut second, &get, &mut server, 30), Action::Request(_)));
}
#[test]
fn late_success_and_stale_request_ids_cannot_acquire_or_revive() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    let get = request(first.poll(t(0)).expect("poll"));
    let create = request(deliver(&mut first, &get, &mut server, 0));
    let (status, body) = server.execute(&create);
    assert!(matches!(first.complete(create.id, Some(status), body.as_ref(), t(5), WALL).expect("late"), Action::WaitUntil(_)));
    assert_eq!(first.state(), State::Follower);
    assert!(matches!(first.complete(create.id, Some(status), body.as_ref(), t(6), WALL).expect("stale"), Action::Ignored));
    let get = request(first.poll(t(7)).expect("poll"));
    let put = request(deliver(&mut first, &get, &mut server, 7));
    assert!(matches!(deliver(&mut first, &put, &mut server, 7), Action::Acquired));
    assert!(matches!(first.poll(t(17)).expect("loss"), Action::CancelAndExit));
    assert!(matches!(first.complete(put.id, Some(200), server.lease.as_ref(), t(17), WALL).expect("stale"), Action::Ignored));
}
#[test]
fn successful_renewal_preserves_acquire_time_and_clips_request_deadline() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    acquire(&mut first, &mut server);
    field(server.lease.as_mut().expect("lease"), "/metadata", "labels", json!({"custom-label":"preserve"}));
    field(server.lease.as_mut().expect("lease"), "/metadata", "annotations", json!({"custom-annotation":"preserve"}));
    let get = request(first.poll(t(8)).expect("poll"));
    assert_eq!(get.deadline, t(10));
    let put = request(deliver(&mut first, &get, &mut server, 8));
    assert_eq!(put.body.as_ref().and_then(|v| v.pointer("/spec/acquireTime")), Some(&json!("2026-09-27T01:00:00.000000Z")));
    assert_eq!(put.body.as_ref().and_then(|v| v.pointer("/metadata/labels/custom-label")), Some(&json!("preserve")));
    assert_eq!(put.body.as_ref().and_then(|v| v.pointer("/metadata/annotations/custom-annotation")), Some(&json!("preserve")));
    assert!(matches!(deliver(&mut first, &put, &mut server, 8), Action::Renewed));
    assert_eq!(first.state(), State::Leader);
}
#[test]
fn release_is_uid_rv_guarded_and_conflict_is_terminal() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    acquire(&mut first, &mut server);
    let release = first.release(t(1), WALL).expect("release");
    assert!(matches!(release, Action::CancelAndRelease(_)));
    let release = request(release);
    assert_eq!(release.body.as_ref().and_then(|v| v.pointer("/spec/holderIdentity")), Some(&json!("")));
    field(server.lease.as_mut().expect("lease"), "/metadata", "uid", json!("replacement-uid"));
    assert!(matches!(deliver(&mut first, &release, &mut server, 1), Action::CancelAndExit));
    assert_eq!(server.lease.as_ref().and_then(|v| v.pointer("/metadata/uid")), Some(&json!("replacement-uid")));
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    acquire(&mut first, &mut server);
    let release = request(first.release(t(1), WALL).expect("release"));
    assert!(matches!(deliver(&mut first, &release, &mut server, 1), Action::Released));
    assert_eq!(first.state(), State::Terminal);
}
#[test]
fn configuration_and_clock_validation() {
    assert!(Timing { request: t(9), ..Timing::default() }.validate().is_err());
    assert!(Timing { retry: Duration::ZERO, ..Timing::default() }.validate().is_err());
    assert!(Election::new("bad/path", "lease", "first-0123456789", Timing::default()).is_err());
    assert!(Election::new("default", "lease", "not-unique", Timing::default()).is_err());
    let mut first = election("first-0123456789");
    first.poll(t(2)).expect("clock");
    assert!(first.poll(t(1)).is_err());
}
#[test]
fn replaced_lease_loses_immediately_and_retry_waits_cannot_outlive_renewal() {
    for (key, value) in [("uid", "replacement"), ("holderIdentity", "other-0123456789")] {
        let mut server = Server::default();
        let mut first = election("first-0123456789");
        acquire(&mut first, &mut server);
        let parent = if key == "uid" { "/metadata" } else { "/spec" };
        field(server.lease.as_mut().expect("lease"), parent, key, json!(value));
        let get = request(first.poll(t(2)).expect("poll"));
        assert!(matches!(deliver(&mut first, &get, &mut server, 2), Action::CancelAndExit));
    }
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    acquire(&mut first, &mut server);
    let get = request(first.poll(t(9)).expect("poll"));
    let action = first.complete(get.id, None, None, t(9), WALL).expect("transport failure");
    assert!(matches!(action, Action::WaitUntil(deadline) if deadline == t(10)));
    assert!(matches!(first.poll(t(10)).expect("renewal deadline"), Action::CancelAndExit));
}

#[test]
fn timestamps_normalize_to_microtime_and_missing_acquire_time_is_initialized() {
    let mut server = Server::default();
    let mut first = election("first-0123456789");
    let get = request(first.poll(t(0)).expect("poll"));
    let create = request(first.complete(get.id, Some(404), None, t(0), "2026-09-27T01:00:00.123456789+00:00").expect("create"));
    assert_eq!(create.body.as_ref().and_then(|v| v.pointer("/spec/renewTime")), Some(&json!("2026-09-27T01:00:00.123456Z")));
    let (status, mut response) = server.execute(&create);
    field(response.as_mut().expect("response"), "/spec", "renewTime", json!("2026-09-27T01:00:00.123456+00:00"));
    assert!(matches!(first.complete(create.id, Some(status), response.as_ref(), t(0), WALL).expect("confirmation"), Action::Acquired));
    field(server.lease.as_mut().expect("lease"), "/spec", "acquireTime", Value::Null);
    let get = request(first.poll(t(2)).expect("poll"));
    let put = request(deliver(&mut first, &get, &mut server, 2));
    assert_eq!(put.body.as_ref().and_then(|v| v.pointer("/spec/acquireTime")), Some(&json!("2026-09-27T01:00:00.000000Z")));
    for wall in ["invalid", "2026-02-30T01:00:00Z", "2026-09-27T25:00:00Z"] {
        let mut candidate = election("candidate-0123456789");
        let get = request(candidate.poll(t(0)).expect("poll"));
        assert!(candidate.complete(get.id, Some(404), None, t(0), wall).is_err());
    }
}
