//! Module health and readiness evaluation from foundation spec §§3.4.2–3.4.3.
//! History files, metrics exporters, active probes and HTTP serving are separate.
use flowsdn_table::{Key, Keyed, Snapshot, Table, TableError};
use std::{collections::BTreeMap, fmt, sync::Arc, time::SystemTime};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Level {
    Ok,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthStatus {
    pub id: String,
    pub level: Level,
    pub message: String,
    pub error: String,
    pub last_ok: Option<SystemTime>,
    pub updated: SystemTime,
    pub stopped: Option<SystemTime>,
    pub final_message: String,
    /// Update count saturates at u64::MAX.
    pub count: u64,
}
impl Keyed for HealthStatus {
    fn primary_key(&self) -> Key {
        self.id.as_bytes().to_vec()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidScope(pub String);
impl fmt::Display for InvalidScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid health scope component: {}", self.0)
    }
}
impl std::error::Error for InvalidScope {}
fn component(name: &str) -> Result<(), InvalidScope> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        return Err(InvalidScope(name.to_owned()));
    }
    Ok(())
}

#[derive(Clone)]
pub struct Registry {
    table: Arc<Table<HealthStatus>>,
}
impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
impl Registry {
    pub const NAME: &'static str = "health";
    pub fn new() -> Self {
        let table = Table::new(vec![]).expect("health table has no secondary indexes");
        table.seal_initializers();
        Self {
            table: Arc::new(table),
        }
    }
    /// Construction does not insert a status: unknown remains absent until reported.
    pub fn reporter(&self, module: &str) -> Result<Reporter, InvalidScope> {
        component(module)?;
        Ok(Reporter {
            table: self.table.clone(),
            id: module.to_owned(),
        })
    }
    pub fn snapshot(&self) -> Snapshot<HealthStatus> {
        self.table.snapshot()
    }
    pub fn table(&self) -> &Table<HealthStatus> {
        &self.table
    }
}

#[derive(Clone)]
pub struct Reporter {
    table: Arc<Table<HealthStatus>>,
    id: String,
}
enum Update {
    Ok(String),
    Degraded(String, String),
    Stopped(String),
}
impl Reporter {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn new_scope(&self, name: &str) -> Result<Self, InvalidScope> {
        component(name)?;
        Ok(Self {
            table: self.table.clone(),
            id: format!("{}.{name}", self.id),
        })
    }
    pub async fn ok(&self, message: impl Into<String>) -> Result<(), TableError> {
        self.report(Update::Ok(message.into())).await
    }
    pub async fn degraded(
        &self,
        message: impl Into<String>,
        error: impl Into<String>,
    ) -> Result<(), TableError> {
        self.report(Update::Degraded(message.into(), error.into()))
            .await
    }
    /// Preserve the last level/message/error; mark stop separately. A first stop
    /// has Stopped level. A subsequent ok/degraded report resumes the scope.
    pub async fn stopped(&self, reason: impl Into<String>) -> Result<(), TableError> {
        self.report(Update::Stopped(reason.into())).await
    }
    /// Remove this scope only. Existing handles may report it again; dropping a
    /// handle has no effect because reporters may be cloned and outlive tasks.
    pub async fn close(&self) -> Result<(), TableError> {
        self.table.delete(self.id.as_bytes()).await.map(|_| ())
    }
    async fn report(&self, update: Update) -> Result<(), TableError> {
        self.table
            .modify(self.id.as_bytes(), |old| {
                let now = SystemTime::now();
                let mut row = old.cloned().unwrap_or_else(|| HealthStatus {
                    id: self.id.clone(),
                    level: Level::Stopped,
                    message: String::new(),
                    error: String::new(),
                    last_ok: None,
                    updated: now,
                    stopped: None,
                    final_message: String::new(),
                    count: 0,
                });
                row.count = row.count.saturating_add(1);
                row.updated = now;
                match update {
                    Update::Ok(message) => {
                        row.level = Level::Ok;
                        row.message = message;
                        row.error.clear();
                        row.last_ok = Some(now);
                        row.stopped = None;
                        row.final_message.clear();
                    }
                    Update::Degraded(message, error) => {
                        row.level = Level::Degraded;
                        row.message = message;
                        row.error = error;
                        row.stopped = None;
                        row.final_message.clear();
                    }
                    Update::Stopped(reason) => {
                        row.stopped = Some(now);
                        row.final_message = reason;
                    }
                }
                Some(row)
            })
            .await
            .map(|_| ())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    pub levels: BTreeMap<Level, u64>,
    pub degraded_modules: BTreeMap<String, u64>,
}
/// Snapshot values for cilium_hive_status and cilium_hive_degraded_status;
/// no metrics registry/exporter is installed by this crate.
pub fn metrics(snapshot: &Snapshot<HealthStatus>) -> Metrics {
    let mut metrics = Metrics::default();
    for level in [Level::Ok, Level::Degraded, Level::Stopped] {
        metrics.levels.insert(level, 0);
    }
    for (row, _) in snapshot.all() {
        let count = metrics.levels.entry(row.level).or_default();
        *count = count.saturating_add(1);
        if row.level == Level::Degraded {
            let count = metrics
                .degraded_modules
                .entry(row.id.split('.').next().unwrap_or(&row.id).to_owned())
                .or_default();
            *count = count.saturating_add(1);
        }
    }
    metrics
}

#[derive(Clone, Debug)]
pub struct Readiness {
    pub probes_complete: bool,
    pub pending_fence: Option<String>,
    pub kvstore_configured: bool,
    pub kvstore_failure: Option<String>,
    pub require_kubernetes: bool,
    pub kubernetes_failure: Option<String>,
    pub brief: bool,
}
impl Default for Readiness {
    fn default() -> Self {
        Self {
            probes_complete: false,
            pending_fence: None,
            kvstore_configured: false,
            kvstore_failure: None,
            require_kubernetes: true,
            kubernetes_failure: None,
            brief: false,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Ok,
    Warning,
    Failure,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verdict {
    pub http_status: u16,
    pub state: State,
    pub message: String,
}
/// Evaluate a coherent snapshot and caller-supplied probe/fence observations.
/// This does not schedule probes or detect stale probes/deadlocks itself.
pub fn readiness(snapshot: &Snapshot<HealthStatus>, input: &Readiness) -> Verdict {
    let verdict = |http_status, state, message| Verdict {
        http_status,
        state,
        message,
    };
    if !input.probes_complete {
        return verdict(
            500,
            State::Failure,
            "Not all probes executed at least once".to_owned(),
        );
    }
    if let Some(pending) = &input.pending_fence {
        return verdict(500, State::Warning, format!("Waiting for {pending}"));
    }
    if input.kvstore_configured
        && let Some(error) = &input.kvstore_failure
    {
        return verdict(500, State::Failure, format!("kvstore: {error}"));
    }
    if input.require_kubernetes
        && let Some(error) = &input.kubernetes_failure
    {
        return verdict(500, State::Failure, format!("kubernetes: {error}"));
    }
    let degraded: Vec<_> = snapshot
        .all()
        .filter(|(row, _)| row.level == Level::Degraded)
        .map(|(row, _)| format!("{}: {} ({})", row.id, row.message, row.error))
        .collect();
    if !degraded.is_empty() {
        return verdict(
            200,
            State::Warning,
            if input.brief {
                String::new()
            } else {
                degraded.join("; ")
            },
        );
    }
    verdict(200, State::Ok, String::new())
}
