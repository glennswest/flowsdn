//! Kubernetes Events for what the agent does to Pods and to its own Node
//! (#298), so `kubectl describe` (and `sc describe`) shows them.
//!
//! Recording never blocks the caller or fails it: events go into a bounded
//! queue (dropped when full) and a thread writes core/v1 Events. Repeats of
//! the same object, reason and message are aggregated the way the kubelet's
//! recorder does: one Event with a growing `count` and `lastTimestamp`,
//! rewritten at most once a minute, forgotten after an hour. `kubectl
//! describe` selects events by the object's UID, so a missing Pod or Node UID
//! is looked up once. Without the `kubernetes` feature, or before
//! [`start`], recording is a no-op.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Type {
    Normal,
    Warning,
}
impl Type {
    pub fn as_str(self) -> &'static str {
        match self {
            Type::Normal => "Normal",
            Type::Warning => "Warning",
        }
    }
}

/// One Event: the object it is about (a Pod, or the agent's Node when
/// `namespace` and `name` are empty), its type, reason and message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub kind: Type,
    pub reason: &'static str,
    pub message: String,
}

/// Messages longer than this are cut (the API server's Event note limit is 1 KiB).
pub const MESSAGE_MAX: usize = 1024;

/// Record an Event on a Pod. `uid` may be empty; it is then looked up.
pub fn pod(namespace: &str, name: &str, uid: &str, kind: Type, reason: &'static str, message: String) {
    if namespace.is_empty() || name.is_empty() {
        return;
    }
    record(Event {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        uid: uid.to_owned(),
        kind,
        reason,
        message,
    });
}

/// Record an Event on the agent's own Node.
pub fn node(kind: Type, reason: &'static str, message: String) {
    record(Event {
        namespace: String::new(),
        name: String::new(),
        uid: String::new(),
        kind,
        reason,
        message,
    });
}

#[cfg(not(feature = "kubernetes"))]
fn record(_event: Event) {}

#[cfg(feature = "kubernetes")]
pub use recorder::{event_body, rfc3339, start};
#[cfg(feature = "kubernetes")]
use recorder::record;

#[cfg(feature = "kubernetes")]
mod recorder {
    use super::{Event, MESSAGE_MAX, Type};
    use flowsdn_k8s::client::{JsonClient, TransportLimits};
    use serde_json::{Value, json};
    use std::{
        collections::HashMap,
        hash::{Hash, Hasher},
        path::PathBuf,
        sync::{OnceLock, mpsc},
        time::{Duration, Instant, SystemTime},
    };

    const QUEUE: usize = 256;
    const ENTRIES: usize = 1024;
    const REWRITE: Duration = Duration::from_secs(60);
    const FORGET: Duration = Duration::from_secs(3600);
    const COMPONENT: &str = "flowsdn-agent";

    static SENDER: OnceLock<mpsc::SyncSender<Event>> = OnceLock::new();

    pub(super) fn record(event: Event) {
        if let Some(sender) = SENDER.get() {
            // A full queue drops the event: recording must never stall the API.
            let _ = sender.try_send(event);
        }
    }

    /// Start the recorder thread for `node`, with its own client (same
    /// credentials as the controller). A second call is ignored.
    pub fn start(kubeconfig: Option<PathBuf>, node: String) -> std::io::Result<()> {
        if SENDER.get().is_some() {
            return Ok(());
        }
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        if SENDER.set(sender).is_err() {
            return Ok(());
        }
        std::thread::Builder::new()
            .name("flowsdn-events".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!("events: no runtime: {error}");
                        return;
                    }
                };
                let client = match runtime.block_on(JsonClient::load(
                    kubeconfig.as_deref(),
                    TransportLimits::default(),
                )) {
                    Ok(client) => client,
                    Err(error) => {
                        eprintln!("events: no Kubernetes client: {error}");
                        return;
                    }
                };
                let mut writer = Writer {
                    runtime,
                    client,
                    node,
                    node_uid: None,
                    pod_uids: HashMap::new(),
                    entries: HashMap::new(),
                };
                writer.run(&receiver);
            })?;
        Ok(())
    }

    type Key = (String, String, &'static str, String);

    struct Entry {
        name: String,
        namespace: String,
        involved: Value,
        event: Event,
        count: u64,
        first: SystemTime,
        last: SystemTime,
        written: Option<Instant>,
        dirty: bool,
        seen: Instant,
    }

    struct Writer {
        runtime: tokio::runtime::Runtime,
        client: JsonClient,
        node: String,
        node_uid: Option<String>,
        pod_uids: HashMap<(String, String), String>,
        entries: HashMap<Key, Entry>,
    }

    impl Writer {
        fn run(&mut self, receiver: &mpsc::Receiver<Event>) {
            loop {
                match receiver.recv_timeout(Duration::from_secs(10)) {
                    Ok(event) => self.add(event),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
                self.flush();
            }
        }

        fn add(&mut self, mut event: Event) {
            if event.message.len() > MESSAGE_MAX {
                let mut cut = MESSAGE_MAX;
                while !event.message.is_char_boundary(cut) {
                    cut = cut.saturating_sub(1);
                }
                event.message.truncate(cut);
            }
            let key: Key = (
                event.namespace.clone(),
                event.name.clone(),
                event.reason,
                event.message.clone(),
            );
            let now = SystemTime::now();
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.count = entry.count.saturating_add(1);
                entry.last = now;
                entry.dirty = true;
                entry.seen = Instant::now();
                return;
            }
            if self.entries.len() >= ENTRIES
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
            let Some(involved) = self.involved(&event) else {
                return;
            };
            let object = if event.name.is_empty() { self.node.clone() } else { event.name.clone() };
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .hash(&mut hasher);
            let entry = Entry {
                name: format!("{object}.{:016x}", hasher.finish()),
                namespace: if event.namespace.is_empty() { "default".into() } else { event.namespace.clone() },
                involved,
                event,
                count: 1,
                first: now,
                last: now,
                written: None,
                dirty: true,
                seen: Instant::now(),
            };
            self.entries.insert(key, entry);
        }

        /// The involvedObject reference, with the UID `kubectl describe` selects on.
        fn involved(&mut self, event: &Event) -> Option<Value> {
            if event.name.is_empty() {
                if self.node_uid.is_none() {
                    let path = format!("/api/v1/nodes/{}", self.node);
                    self.node_uid = self.uid(&path);
                }
                let uid = self.node_uid.clone()?;
                return Some(json!({"apiVersion":"v1","kind":"Node","name":self.node,"uid":uid}));
            }
            let uid = if event.uid.is_empty() {
                let key = (event.namespace.clone(), event.name.clone());
                match self.pod_uids.get(&key) {
                    Some(uid) => uid.clone(),
                    None => {
                        let path = format!("/api/v1/namespaces/{}/pods/{}", event.namespace, event.name);
                        let uid = self.uid(&path)?;
                        if self.pod_uids.len() >= ENTRIES {
                            self.pod_uids.clear();
                        }
                        self.pod_uids.insert(key, uid.clone());
                        uid
                    }
                }
            } else {
                event.uid.clone()
            };
            Some(json!({"apiVersion":"v1","kind":"Pod","namespace":event.namespace,"name":event.name,"uid":uid}))
        }

        fn uid(&self, path: &str) -> Option<String> {
            match self.runtime.block_on(self.client.send_json(http::Method::GET, path, None)) {
                Ok((200, object)) => object
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                Ok((status, _)) => {
                    eprintln!("events: GET {path}: HTTP {status}");
                    None
                }
                Err(error) => {
                    eprintln!("events: GET {path}: {error}");
                    None
                }
            }
        }

        fn flush(&mut self) {
            self.entries.retain(|_, entry| entry.seen.elapsed() < FORGET);
            let due: Vec<Key> = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.dirty && entry.written.is_none_or(|at| at.elapsed() >= REWRITE))
                .map(|(key, _)| key.clone())
                .collect();
            for key in due {
                let Some(entry) = self.entries.get(&key) else { continue };
                let body = event_body(
                    &entry.name,
                    &entry.namespace,
                    &entry.involved,
                    &entry.event,
                    entry.count,
                    entry.first,
                    entry.last,
                    &self.node,
                );
                let collection = format!("/api/v1/namespaces/{}/events", entry.namespace);
                let (method, path) = if entry.written.is_some() {
                    (http::Method::PUT, format!("{collection}/{}", entry.name))
                } else {
                    (http::Method::POST, collection)
                };
                let result = self.runtime.block_on(self.client.send_json(method, &path, Some(&body)));
                let ok = match result {
                    Ok((200..=299, _)) => true,
                    Ok((status, response)) => {
                        let message = response.get("message").and_then(Value::as_str).unwrap_or("");
                        eprintln!("events: {path}: HTTP {status} {message}");
                        false
                    }
                    Err(error) => {
                        eprintln!("events: {path}: {error}");
                        false
                    }
                };
                if let Some(entry) = self.entries.get_mut(&key) {
                    if ok {
                        entry.written = Some(Instant::now());
                        entry.dirty = false;
                    } else if entry.written.is_none() {
                        // Not created: give up on this one rather than retry forever.
                        self.entries.remove(&key);
                    }
                }
            }
        }
    }

    /// The core/v1 Event the recorder writes.
    #[allow(clippy::too_many_arguments)]
    pub fn event_body(
        name: &str,
        namespace: &str,
        involved: &Value,
        event: &Event,
        count: u64,
        first: SystemTime,
        last: SystemTime,
        node: &str,
    ) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {"name": name, "namespace": namespace},
            "involvedObject": involved,
            "reason": event.reason,
            "message": event.message,
            "type": event.kind.as_str(),
            "count": count,
            "firstTimestamp": rfc3339(first),
            "lastTimestamp": rfc3339(last),
            "source": {"component": COMPONENT, "host": node},
            "reportingComponent": COMPONENT,
            "reportingInstance": node,
        })
    }

    /// UTC `YYYY-MM-DDTHH:MM:SSZ` (Gregorian, through year 9999).
    #[allow(clippy::arithmetic_side_effects)] // Bounded below: every intermediate fits i64.
    pub fn rfc3339(time: SystemTime) -> String {
        let seconds = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .min(253_402_300_799);
        let seconds = i64::try_from(seconds).unwrap_or(0);
        let days = seconds / 86400 + 719_468;
        let era = days / 146_097;
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = month_index + if month_index < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            seconds / 3600 % 24,
            seconds / 60 % 60,
            seconds % 60
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn timestamps_are_rfc3339_utc() {
            let at = |s| SystemTime::UNIX_EPOCH + Duration::from_secs(s);
            assert_eq!(rfc3339(at(0)), "1970-01-01T00:00:00Z");
            assert_eq!(rfc3339(at(951_782_400)), "2000-02-29T00:00:00Z");
            assert_eq!(rfc3339(at(1_791_302_693)), "2026-10-06T16:04:53Z");
        }

        #[test]
        fn event_body_is_a_core_v1_event() {
            let event = Event {
                namespace: "prod".into(),
                name: "web-0".into(),
                uid: "u1".into(),
                kind: Type::Warning,
                reason: "IPAllocationFailed",
                message: "pool exhausted".into(),
            };
            let involved = json!({"apiVersion":"v1","kind":"Pod","namespace":"prod","name":"web-0","uid":"u1"});
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_302_693);
            let body = event_body("web-0.00ff", "prod", &involved, &event, 3, at, at, "node-a");
            assert_eq!(body.pointer("/involvedObject/uid"), Some(&json!("u1")));
            assert_eq!(body.get("type"), Some(&json!("Warning")));
            assert_eq!(body.get("count"), Some(&json!(3)));
            assert_eq!(body.pointer("/source/component"), Some(&json!("flowsdn-agent")));
            assert_eq!(body.pointer("/metadata/namespace"), Some(&json!("prod")));
            assert_eq!(body.get("lastTimestamp"), Some(&json!("2026-10-06T16:04:53Z")));
        }
    }
}
