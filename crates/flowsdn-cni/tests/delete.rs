use flowsdn_cni::{CniError, Result, delete::*};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

type Events = Rc<RefCell<Vec<&'static str>>>;
struct Queue { events: Events, fail: bool }
impl Drop for Queue {
    fn drop(&mut self) { self.events.borrow_mut().push("unlock"); }
}
impl DeleteQueueGuard for Queue {
    fn enqueue(&mut self, _: &DeleteRequest) -> Result<()> {
        self.events.borrow_mut().push("enqueue");
        if self.fail { Err(CniError::internal("queue full")) } else { Ok(()) }
    }
}
struct Backend {
    events: Events,
    attempts: VecDeque<DeleteAttempt>,
    fail: &'static str,
    namespace: bool,
}
impl Backend {
    fn new(attempts: impl IntoIterator<Item=DeleteAttempt>) -> Self {
        Self { events: Events::default(), attempts: attempts.into_iter().collect(), fail: "", namespace: true }
    }
    fn operation(&mut self, name: &'static str) -> Result<()> {
        self.events.borrow_mut().push(name);
        if self.fail == name { Err(CniError::internal(name)) } else { Ok(()) }
    }
}
impl DeleteBackend for Backend {
    type QueueGuard = Queue;
    fn try_delete(&mut self, _: &DeleteRequest) -> DeleteAttempt {
        self.events.borrow_mut().push("delete");
        self.attempts.pop_front().expect("unexpected deletion attempt")
    }
    fn lock_queue(&mut self) -> Result<Queue> {
        self.operation("lock")?;
        Ok(Queue { events: self.events.clone(), fail: self.fail == "enqueue" })
    }
    fn delegated_delete(&mut self, _: &DeleteRequest) -> Result<()> { self.operation("delegate") }
    fn enter_namespace(&mut self, _: Option<&str>) -> Result<bool> {
        self.operation("namespace")?;
        Ok(self.namespace)
    }
    fn delete_interface(&mut self, _: &str) -> Result<()> { self.operation("link") }
}
fn request() -> DeleteRequest {
    DeleteRequest { container_id: "container".into(), ifname: "eth0".into(), netns: None, delegated_ipam: true }
}

#[test]
fn offline_deletion_is_rechecked_under_lock_and_unlocks_before_namespace() {
    let mut backend = Backend::new([DeleteAttempt::Unavailable, DeleteAttempt::Unavailable]);
    backend.namespace = false;
    assert!(delete(&request(), &mut backend).expect("queued").queued);
    assert_eq!(*backend.events.borrow(), ["delete", "lock", "delete", "enqueue", "unlock", "delegate", "namespace"]);
    let mut recovered = Backend::new([DeleteAttempt::Unavailable, DeleteAttempt::Complete]);
    assert!(!delete(&request(), &mut recovered).expect("recovered").queued);
    assert_eq!(*recovered.events.borrow(), ["delete", "lock", "delete", "unlock", "delegate", "namespace", "link"]);
}

#[test]
fn queue_failure_is_retryable_and_releases_lock_without_losing_namespace() {
    for failure in ["lock", "enqueue"] {
        let mut backend = Backend::new([DeleteAttempt::Unavailable, DeleteAttempt::Unavailable]);
        backend.fail = failure;
        assert!(delete(&request(), &mut backend).is_err());
        let events = backend.events.borrow();
        assert!(!events.contains(&"namespace"));
        assert_eq!(events.contains(&"unlock"), failure == "enqueue");
    }
}

#[test]
fn missing_or_duplicate_endpoints_and_link_errors_are_nonfatal() {
    for namespace in [false, true] {
        let mut backend = Backend::new([DeleteAttempt::AgentWarning(CniError::internal("404")), DeleteAttempt::Complete]);
        backend.namespace = namespace;
        backend.fail = "link";
        let first = delete(&request(), &mut backend).expect("idempotent delete");
        assert_eq!(first.warnings.len(), if namespace { 2 } else { 1 });
        delete(&request(), &mut backend).expect("duplicate delete");
        assert!(backend.events.borrow().contains(&"delegate"));
    }
}

#[test]
fn delegated_and_namespace_failures_remain_retryable() {
    for failure in ["delegate", "namespace"] {
        let mut backend = Backend::new([DeleteAttempt::Complete]);
        backend.fail = failure;
        assert_eq!(delete(&request(), &mut backend).expect_err("retry").message, failure);
        assert!(!backend.events.borrow().contains(&"link"));
    }
}

#[test]
fn queue_encoding_preserves_single_and_batch_delete_contracts() {
    let mut request = request();
    assert_eq!(request.queue_contents().expect("single"), b"container:eth0");
    request.ifname.clear();
    assert_eq!(request.queue_contents().expect("batch"), br#"{"container-id":"container"}"#);
    request.container_id.clear();
    let mut backend = Backend::new([]);
    assert!(delete(&request, &mut backend).is_err());
    assert!(backend.events.borrow().is_empty());
}
