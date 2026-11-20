//! The operator's garbage collectors (#479): FlowsdnIdentity GC (spec 03
//! §3.6) and FlowsdnNode GC (spec 12 §3.9). Each keeps its state for one
//! leader term and plans its writes from plain lists, so it is tested without
//! an API server; [`identity_gc`] and [`node_gc`] carry a run out through a
//! `send` function like [`crate::operator::register_all`].
use flowsdn_k8s::watch::HEARTBEAT_ANNOTATION;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub const IDENTITIES: &str = "/apis/flowsdn.io/v1alpha1/flowsdnidentities";
pub const ENDPOINTS: &str = "/apis/flowsdn.io/v1alpha1/flowsdnendpoints";
pub const ENDPOINT_SLICES: &str = "/apis/flowsdn.io/v1alpha1/flowsdnendpointslices";
pub const FLOWSDN_NODES: &str = "/apis/flowsdn.io/v1alpha1/flowsdnnodes";
pub const NODES: &str = "/api/v1/nodes";
/// A FlowsdnNode with this annotation set to `true` (any case) is never
/// collected (spec 12 §3.9).
pub const DO_NOT_GC: &str = "flowsdn.io/do-not-gc";

/// One API call: method, absolute path, body; the HTTP status and body back.
pub type Send<'a> =
    dyn FnMut(http::Method, &str, Option<&Value>) -> Result<(u16, Value), flowsdn_k8s::Error> + 'a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// 0: identity GC off.
    pub identity_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub rate_limit: u32,
    pub rate_interval: Duration,
    /// 0: FlowsdnNode GC off.
    pub nodes_interval: Duration,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            identity_interval: Duration::from_secs(900),
            heartbeat_timeout: Duration::from_secs(1800),
            rate_limit: 2500,
            rate_interval: Duration::from_secs(60),
            nodes_interval: Duration::from_secs(300),
        }
    }
}

fn items(list: &Value) -> &[Value] {
    list.get("items")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}
fn text<'a>(object: &'a Value, pointer: &str) -> &'a str {
    object
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// A FlowsdnIdentity write.
#[derive(Clone, Debug, PartialEq)]
pub enum IdentityAction {
    /// Pass 1: replace the object with the heartbeat annotation set.
    Mark { name: String, object: Value },
    /// Pass 2: delete it, if it is still the object that was seen.
    Delete {
        name: String,
        uid: String,
        resource_version: String,
    },
}

/// What one identity GC run found and did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentitySummary {
    pub alive: usize,
    pub marked: usize,
    pub deleted: usize,
    /// Deletes the API refused because the object changed or went (409/404).
    pub skipped: usize,
    /// Deletes left for the next run by the rate limit.
    pub deferred: usize,
}

/// Identity GC state for one leader term (spec 03 §3.6).
#[derive(Clone, Debug)]
pub struct IdentityGc {
    timeout: Duration,
    started: Instant,
    listed: bool,
    /// name -> (lifesign, resourceVersion last seen).
    seen: BTreeMap<String, (Instant, String)>,
    limiter: Limiter,
}
impl IdentityGc {
    pub fn new(settings: &Settings, started: Instant) -> Self {
        Self {
            timeout: settings.heartbeat_timeout,
            started,
            listed: false,
            seen: BTreeMap::new(),
            limiter: Limiter::new(settings.rate_limit, settings.rate_interval),
        }
    }

    /// Plan a run from the identity list and the ids endpoints use. An
    /// identity is alive when used; its lifesign is also renewed when its
    /// resourceVersion changed (an agent acquired it, or pass 1 wrote it).
    /// One first seen in the term's first list counts from operator start,
    /// so a new leader waits a whole timeout before marking anything.
    pub fn plan(
        &mut self,
        now: Instant,
        wall: &str,
        identities: &[Value],
        used: &BTreeSet<String>,
    ) -> (Vec<IdentityAction>, usize) {
        let first = !self.listed;
        self.listed = true;
        let mut actions = Vec::new();
        let mut alive = 0usize;
        let mut present = BTreeSet::new();
        for object in identities {
            let name = text(object, "/metadata/name");
            if name.is_empty() {
                continue;
            }
            present.insert(name.to_owned());
            let version = text(object, "/metadata/resourceVersion");
            let lifesign = match self.seen.get(name) {
                Some((at, seen)) if seen == version => *at,
                Some(_) => now,
                None if first => self.started,
                None => now,
            };
            let lifesign = if used.contains(name) {
                alive = alive.saturating_add(1);
                now
            } else {
                lifesign
            };
            self.seen
                .insert(name.to_owned(), (lifesign, version.to_owned()));
            if used.contains(name) || now.saturating_duration_since(lifesign) <= self.timeout {
                continue;
            }
            let marked = object
                .pointer("/metadata/annotations")
                .and_then(|a| a.get(HEARTBEAT_ANNOTATION))
                .is_some();
            if marked {
                actions.push(IdentityAction::Delete {
                    name: name.to_owned(),
                    uid: text(object, "/metadata/uid").to_owned(),
                    resource_version: version.to_owned(),
                });
            } else {
                let mut object = object.clone();
                if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
                    let annotations = meta.entry("annotations").or_insert_with(|| json!({}));
                    if !annotations.is_object() {
                        *annotations = json!({});
                    }
                    if let Some(map) = annotations.as_object_mut() {
                        map.insert(HEARTBEAT_ANNOTATION.to_owned(), json!(wall));
                    }
                }
                actions.push(IdentityAction::Mark {
                    name: name.to_owned(),
                    object,
                });
            }
        }
        // Gone from the list: nothing left to remember (the reference also
        // drops lifesigns older than ten timeouts; a listed object is never
        // that old here, since an expired one is marked, which renews it).
        self.seen.retain(|name, _| present.contains(name));
        (actions, alive)
    }
}

/// Deletes per window (`identity-gc-rate-limit` per
/// `identity-gc-rate-interval`). A delete it does not admit waits for the
/// next run rather than holding the operator's loop, which renews its Lease.
#[derive(Clone, Debug)]
pub struct Limiter {
    limit: u32,
    interval: Duration,
    window: Option<Instant>,
    used: u32,
}
impl Limiter {
    pub fn new(limit: u32, interval: Duration) -> Self {
        Self {
            limit,
            interval,
            window: None,
            used: 0,
        }
    }
    pub fn admit(&mut self, now: Instant) -> bool {
        let fresh = self
            .window
            .is_none_or(|start| now.saturating_duration_since(start) >= self.interval);
        if fresh {
            self.window = Some(now);
            self.used = 0;
        }
        if self.used < self.limit {
            self.used = self.used.saturating_add(1);
            true
        } else {
            false
        }
    }
}

/// The identity ids FlowsdnEndpoints (`status.identity.id`) and, when the
/// kind is served, FlowsdnEndpointSlices (`endpoints[].id`) name.
pub fn used_identities(endpoints: &Value, slices: Option<&Value>) -> BTreeSet<String> {
    let mut used: BTreeSet<String> = items(endpoints)
        .iter()
        .filter_map(|e| e.pointer("/status/identity/id").and_then(Value::as_i64))
        .map(|id| id.to_string())
        .collect();
    for slice in slices.map(items).unwrap_or(&[]) {
        for endpoint in slice
            .get("endpoints")
            .and_then(Value::as_array)
            .map_or(&[] as &[Value], Vec::as_slice)
        {
            if let Some(id) = endpoint.get("id").and_then(Value::as_i64) {
                used.insert(id.to_string());
            }
        }
    }
    used
}

fn list(send: &mut Send<'_>, path: &str) -> Result<Value, String> {
    match send(http::Method::GET, path, None).map_err(|e| format!("{path}: {e}"))? {
        (200, body) => Ok(body),
        (status, body) => Err(format!("{path}: HTTP {status} {}", text(&body, "/message"))),
    }
}

/// One identity GC run: list, plan, write. A list failure aborts the run
/// (nothing is written from a partial view).
pub fn identity_gc(
    gc: &mut IdentityGc,
    now: Instant,
    wall: &str,
    send: &mut Send<'_>,
) -> Result<IdentitySummary, String> {
    let identities = list(send, IDENTITIES)?;
    let endpoints = list(send, ENDPOINTS)?;
    let slices = match send(http::Method::GET, ENDPOINT_SLICES, None)
        .map_err(|e| format!("{ENDPOINT_SLICES}: {e}"))?
    {
        (200, body) => Some(body),
        (404, _) => None,
        (status, body) => {
            return Err(format!(
                "{ENDPOINT_SLICES}: HTTP {status} {}",
                text(&body, "/message")
            ));
        }
    };
    let used = used_identities(&endpoints, slices.as_ref());
    let (actions, alive) = gc.plan(now, wall, items(&identities), &used);
    let mut summary = IdentitySummary {
        alive,
        ..IdentitySummary::default()
    };
    for action in actions {
        match action {
            IdentityAction::Mark { name, object } => {
                let path = format!("{IDENTITIES}/{name}");
                match send(http::Method::PUT, &path, Some(&object))
                    .map_err(|e| format!("{path}: {e}"))?
                {
                    (200..=299, _) => summary.marked = summary.marked.saturating_add(1),
                    (404 | 409, _) => summary.skipped = summary.skipped.saturating_add(1),
                    (status, body) => {
                        return Err(format!("{path}: HTTP {status} {}", text(&body, "/message")));
                    }
                }
            }
            IdentityAction::Delete {
                name,
                uid,
                resource_version,
            } => {
                if !gc.limiter.admit(now) {
                    summary.deferred = summary.deferred.saturating_add(1);
                    continue;
                }
                let path = format!("{IDENTITIES}/{name}");
                let body =
                    json!({"preconditions": {"uid": uid, "resourceVersion": resource_version}});
                match send(http::Method::DELETE, &path, Some(&body))
                    .map_err(|e| format!("{path}: {e}"))?
                {
                    (200..=299, _) => summary.deleted = summary.deleted.saturating_add(1),
                    (404 | 409, _) => summary.skipped = summary.skipped.saturating_add(1),
                    (status, body) => {
                        return Err(format!("{path}: HTTP {status} {}", text(&body, "/message")));
                    }
                }
            }
        }
    }
    Ok(summary)
}

/// FlowsdnNode GC state for one leader term (spec 12 §3.9).
#[derive(Clone, Debug)]
pub struct NodeGc {
    interval: Duration,
    candidates: BTreeMap<String, Instant>,
}
impl NodeGc {
    pub fn new(settings: &Settings) -> Self {
        Self {
            interval: settings.nodes_interval,
            candidates: BTreeMap::new(),
        }
    }

    /// The FlowsdnNodes to delete now. One without a Node of its name, no
    /// owner and no `flowsdn.io/do-not-gc: true` becomes a candidate, and
    /// is deleted on a later run once it has been one for an interval; a
    /// Node that comes back ends the candidacy.
    pub fn plan(
        &mut self,
        now: Instant,
        flowsdn_nodes: &[Value],
        nodes: &BTreeSet<String>,
    ) -> Vec<String> {
        let mut delete = Vec::new();
        let mut orphans = BTreeSet::new();
        for object in flowsdn_nodes {
            let name = text(object, "/metadata/name");
            let owned = object
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .is_some_and(|owners| !owners.is_empty());
            let kept = object
                .pointer("/metadata/annotations")
                .and_then(|a| a.get(DO_NOT_GC))
                .and_then(Value::as_str)
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            if name.is_empty() || owned || kept || nodes.contains(name) {
                continue;
            }
            orphans.insert(name.to_owned());
            let since = *self.candidates.entry(name.to_owned()).or_insert(now);
            if now.saturating_duration_since(since) >= self.interval {
                delete.push(name.to_owned());
            }
        }
        self.candidates.retain(|name, _| orphans.contains(name));
        for name in &delete {
            self.candidates.remove(name);
        }
        delete
    }
}

/// One FlowsdnNode GC run; returns the names deleted (404 counts as done).
pub fn node_gc(gc: &mut NodeGc, now: Instant, send: &mut Send<'_>) -> Result<Vec<String>, String> {
    let flowsdn_nodes = list(send, FLOWSDN_NODES)?;
    let nodes: BTreeSet<String> = items(&list(send, NODES)?)
        .iter()
        .map(|n| text(n, "/metadata/name").to_owned())
        .collect();
    let mut deleted = Vec::new();
    for name in gc.plan(now, items(&flowsdn_nodes), &nodes) {
        let path = format!("{FLOWSDN_NODES}/{name}");
        match send(http::Method::DELETE, &path, None).map_err(|e| format!("{path}: {e}"))? {
            (200..=299 | 404, _) => deleted.push(name),
            (status, body) => {
                return Err(format!("{path}: HTTP {status} {}", text(&body, "/message")));
            }
        }
    }
    Ok(deleted)
}

#[cfg(test)]
#[path = "operator_gc_tests.rs"]
mod tests;
