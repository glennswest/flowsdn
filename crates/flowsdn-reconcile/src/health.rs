use crate::{Keyed, Kind, Operation, ReconcileError, Reconciler, Target};
use flowsdn_health::Reporter;
use flowsdn_table::TableError;
use std::fmt::{self, Write};

const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const TRUNCATED: &str = "\n[diagnostics truncated]";
#[derive(Default)]
struct Diagnostics { text: String, truncated: bool }
impl Write for Diagnostics {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = MAX_DIAGNOSTIC_BYTES.saturating_sub(TRUNCATED.len()).saturating_sub(self.text.len());
        let mut end = available.min(value.len());
        while !value.is_char_boundary(end) { end = end.saturating_sub(1); }
        if let Some(prefix) = value.get(..end) { self.text.push_str(prefix); }
        self.truncated |= end < value.len();
        Ok(())
    }
}
impl Diagnostics {
    fn finish(mut self) -> String { if self.truncated { self.text.push_str(TRUNCATED); } self.text }
}
pub(crate) fn retain_error(error: &str) -> String {
    let mut output = Diagnostics::default();
    let _ = output.write_str(error);
    output.finish()
}

impl<T: Keyed, U: Target<T>> Reconciler<'_, T, U> {
    /// Attach a reporter for this reconciler. Use a distinct scope per owner.
    /// Reporting is optional and never writes into the desired table.
    pub fn with_reporter(mut self, reporter: Reporter) -> Self {
        self.health_failures = self.statuses.iter().filter(|(_, status)| status.kind == Kind::Error || status.retries > 0)
            .map(|(key, status)| (key.clone(), (status.id, retain_error(status.error.as_deref().unwrap_or("previous attempt failed"))))).collect();
        self.reporter = Some(reporter);
        self
    }

    pub(crate) fn forget_health_failure(&mut self, key: &[u8]) -> bool {
        let removed = self.health_failures.remove(key).is_some();
        self.health_dirty |= removed;
        removed
    }

    /// Last failed health-table publication, cleared by a successful round.
    pub fn last_health_error(&self) -> Option<&str> { self.health_error.as_deref() }

    fn health_result(&mut self, result: Result<(), TableError>) -> Result<(), ReconcileError> {
        match result {
            Ok(()) => Ok(())
            Err(error) => {
                self.health_error = Some(error.to_string());
                Err(ReconcileError::HealthPublicationFailed)
            }
        }
    }

    pub(crate) async fn begin_health_round(&mut self) -> Result<(), ReconcileError> {
        self.finish_health_round(None).await
    }

    pub(crate) async fn finish_health_round(&mut self, failure: Option<ReconcileError>) -> Result<(), ReconcileError> {
        let Some(reporter) = self.reporter.clone() else { return Ok(()); };
        let desired = self.table.snapshot();
        let mut errors = Diagnostics::default();
        let mut count = 0usize;
        for (key, (revision, error)) in &self.health_failures {
            let Some(status) = self.statuses.get(key).filter(|status| status.id == *revision && (status.kind == Kind::Error || status.retries > 0)) else { continue; };
            let current = desired.get("primary", key).expect("primary index exists");
            let relevant = match current {
                Some((_, desired_revision)) => status.operation == Operation::Update && *revision == desired_revision,
                None => status.operation == Operation::Delete,
            };
            if relevant {
                if count > 0 { let _ = errors.write_str("; "); }
                count = count.saturating_add(1);
                let _ = write!(errors, "{:?} revision {revision}: {error}", status.operation);
            }
        }
        if let Some(error) = self.prune.status.as_ref().and_then(|status| status.error.as_ref()) {
            if count > 0 { let _ = errors.write_str("; "); }
            count = count.saturating_add(1);
            let _ = write!(errors, "prune: {error}");
        }
        if self.resync_required {
            if count > 0 { let _ = errors.write_str("; "); }
            count = count.saturating_add(1);
            let _ = errors.write_str("deletion history requires prune recovery");
        }
        if let Some(error) = failure.or(self.health_round_error) {
            if count > 0 { let _ = errors.write_str("; "); }
            count = count.saturating_add(1);
            let _ = write!(errors, "{error}");
        }
        let result = if count == 0 {
            reporter.ok(format!("{} objects", desired.len())).await
        } else {
            reporter.degraded(format!("{count} errors"), errors.finish()).await
        };
        self.health_result(result)?;
        self.health_dirty = false;
        Ok(())
    }

    pub(crate) async fn publish_health_changes(&mut self) -> Result<(), ReconcileError> {
        if self.health_dirty { self.finish_health_round(None).await?; }
        Ok(())
    }

    pub(crate) async fn stop_health(&mut self, failure: Option<ReconcileError>) -> Result<(), ReconcileError> {
        let Some(reporter) = self.reporter.clone() else { return Ok(()); };
        let reason = failure.map_or_else(|| "reconciler loop stopped".to_owned(), |error| format!("reconciler loop stopped: {error}"));
        let result = reporter.stopped(reason).await;
        self.health_result(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Options;
    use flowsdn_health::{Level, Registry};
    use flowsdn_table::{Key, Snapshot, Table};
    use std::{sync::Arc, time::Instant};
    #[derive(Clone)]
    struct Item;
    impl Keyed for Item { fn primary_key(&self) -> Key { vec![1] } }
    struct TargetOk;
    impl Target<Item> for TargetOk {
        type Error = &'static str;
        async fn update(&mut self, _: Arc<Item>) -> Result<(), Self::Error> { Ok(()) }
        async fn delete(&mut self, _: Key) -> Result<(), Self::Error> { Ok(()) }
        async fn prune(&mut self, _: Snapshot<Item>) -> Result<(), Self::Error> { Ok(()) }
    }
    #[tokio::test]
    async fn publication_error_boundary_preserves_queued_work_and_can_recover() {
        let table = Table::new(vec![]).unwrap();
        table.insert(Item).await.unwrap();
        let registry = Registry::new();
        let mut reconciler = Reconciler::new(&table, TargetOk, Options::default()).unwrap().with_reporter(registry.reporter("test").unwrap());
        reconciler.load_changes();
        // Inject at the Reporter result boundary: exhausting a real health
        // table's u64 revision space is not feasible through its public API.
        assert_eq!(reconciler.health_result(Err(TableError::RevisionExhausted)), Err(ReconcileError::HealthPublicationFailed));
        assert!(reconciler.last_health_error().is_some());
        assert!(reconciler.has_pending_work());
        assert_eq!(reconciler.attempted_revision(), 0);
        assert_eq!(reconciler.run_round(Instant::now()).await.unwrap().updated, 1);
        assert!(reconciler.last_health_error().is_none());
        assert_eq!(registry.snapshot().get("primary", b"test").unwrap().unwrap().0.level, Level::Ok);
    }
}
