//! Primary CNI deletion sequencing from specification 09 §3.6 and §5.1.
//! Platform adapters own transport deadlines, durable queue writes and netns entry.
use crate::{CniError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteRequest {
    pub container_id: String,
    pub ifname: String,
    pub netns: Option<String>,
    pub delegated_ipam: bool,
}

impl DeleteRequest {
    /// Queue wire format; an empty interface selects container-wide deletion.
    pub fn queue_contents(&self) -> Result<Vec<u8>> {
        if self.container_id.is_empty() {
            return Err(CniError::internal("container ID is required"));
        }
        if self.ifname.is_empty() {
            serde_json::to_vec(&serde_json::json!({"container-id":self.container_id}))
                .map_err(|e| CniError::internal(e.to_string()))
        } else {
            Ok(format!("{}:{}", self.container_id, self.ifname).into_bytes())
        }
    }
}

/// Only connection failures and HTTP 503 require durable offline fallback.
#[derive(Clone, Debug)]
pub enum DeleteAttempt {
    Complete,
    AgentWarning(CniError),
    Unavailable,
}

/// Lock ownership is RAII: dropping this guard must release the shared flock.
/// Enqueue must persist the request or fail, respecting the 256-entry cap.
pub trait DeleteQueueGuard {
    fn enqueue(&mut self, request: &DeleteRequest) -> Result<()>;
}

pub trait DeleteBackend {
    type QueueGuard: DeleteQueueGuard;

    /// Apply the deletion-client budget and classify HTTP/transport outcomes.
    fn try_delete(&mut self, request: &DeleteRequest) -> DeleteAttempt;
    /// Return an owned guard so transport can be retried while holding it.
    fn lock_queue(&mut self) -> Result<Self::QueueGuard>;
    fn delegated_delete(&mut self, request: &DeleteRequest) -> Result<()>;
    /// Missing or empty namespace is Ok(false); other open/entry errors fail.
    fn enter_namespace(&mut self, path: Option<&str>) -> Result<bool>;
    fn delete_interface(&mut self, ifname: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct DeleteOutcome {
    pub queued: bool,
    pub warnings: Vec<CniError>,
}

/// Execute after configuration parsing/chainer resolution. Endpoint deletion
/// precedes delegated IPAM and namespace access, even if the namespace is gone.
pub fn delete(request: &DeleteRequest, backend: &mut impl DeleteBackend) -> Result<DeleteOutcome> {
    // Validate before a malformed request can mutate endpoint or queue state.
    request.queue_contents()?;
    let mut outcome = DeleteOutcome::default();
    match backend.try_delete(request) {
        DeleteAttempt::Complete => {}
        DeleteAttempt::AgentWarning(error) => outcome.warnings.push(error),
        DeleteAttempt::Unavailable => {
            let mut guard = backend.lock_queue()?;
            // Agent restore/replay can finish before the lock is acquired.
            match backend.try_delete(request) {
                DeleteAttempt::Complete => {}
                DeleteAttempt::AgentWarning(error) => outcome.warnings.push(error),
                DeleteAttempt::Unavailable => {
                    guard.enqueue(request)?;
                    outcome.queued = true;
                }
            }
        }
    }
    if request.delegated_ipam {
        backend.delegated_delete(request)?;
    }
    if backend.enter_namespace(request.netns.as_deref())?
        && let Err(error) = backend.delete_interface(&request.ifname)
    {
        outcome.warnings.push(error);
    }
    Ok(outcome)
}
