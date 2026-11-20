//! A `coordination.k8s.io/v1` Lease held by one agent at a time (#475: the
//! LB-IPAM writer). Pure decisions; the caller does the HTTP.
//!
//! As in client-go's leader election, another holder's lease is taken over
//! only after its record (holder and `renewTime`) has not changed for
//! `leaseDurationSeconds` as this agent's own clock measures it, so clocks
//! that disagree between nodes do not matter. Writes carry the
//! resourceVersion they were based on, so of two agents taking over at once
//! one gets a 409 and stays a follower.
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// What to send next.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// POST this Lease (there is none).
    Create(Value),
    /// PUT this Lease (renew, or take over an expired one).
    Update(Value),
    /// Someone else holds it.
    Wait,
}

#[derive(Clone, Debug)]
pub struct Elector {
    pub namespace: String,
    pub name: String,
    pub identity: String,
    pub duration: Duration,
    /// The other holder's record and when this agent first saw it.
    observed: Option<((String, String), Instant)>,
    /// When this agent last wrote the Lease as its holder.
    renewed: Option<Instant>,
}

impl Elector {
    pub fn new(namespace: &str, name: &str, identity: &str, duration: Duration) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            identity: identity.into(),
            duration,
            observed: None,
            renewed: None,
        }
    }
    /// The collection path (POST) and the object path (GET, PUT).
    pub fn collection(&self) -> String {
        format!(
            "/apis/coordination.k8s.io/v1/namespaces/{}/leases",
            self.namespace
        )
    }
    pub fn path(&self) -> String {
        format!("{}/{}", self.collection(), self.name)
    }
    /// Whether this agent holds the Lease now: it wrote it as holder less
    /// than a lease duration ago (minus a margin for the write's own time).
    pub fn leading(&self, now: Instant) -> bool {
        let margin = self.duration.checked_div(5).unwrap_or_default();
        self.renewed.is_some_and(|at| {
            now.saturating_duration_since(at).saturating_add(margin) < self.duration
        })
    }
    /// The next step, given the Lease as read (`None`: it does not exist).
    /// `wall` is the current time as a MicroTime (`renewTime`).
    pub fn step(&mut self, now: Instant, wall: &str, current: Option<&Value>) -> Step {
        let seconds = self.duration.as_secs().max(1);
        let Some(current) = current else {
            return Step::Create(json!({
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "metadata": {"name": self.name, "namespace": self.namespace},
                "spec": {
                    "holderIdentity": self.identity,
                    "leaseDurationSeconds": seconds,
                    "acquireTime": wall,
                    "renewTime": wall,
                    "leaseTransitions": 0,
                },
            }));
        };
        let spec = current.get("spec").cloned().unwrap_or_else(|| json!({}));
        let holder = spec
            .get("holderIdentity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let renew = spec
            .get("renewTime")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut next = current.clone();
        if let Some(status) = next.as_object_mut() {
            status.remove("status");
        }
        if holder == self.identity {
            self.observed = None;
            if let Some(spec) = next.get_mut("spec").and_then(Value::as_object_mut) {
                spec.insert("renewTime".into(), json!(wall));
                spec.insert("leaseDurationSeconds".into(), json!(seconds));
            }
            return Step::Update(next);
        }
        // A different holder: hold off until its record stops changing.
        self.renewed = None;
        let record = (holder.clone(), renew);
        let since = match &self.observed {
            Some((seen, at)) if *seen == record => *at,
            _ => {
                self.observed = Some((record, now));
                now
            }
        };
        let their = spec
            .get("leaseDurationSeconds")
            .and_then(Value::as_u64)
            .map_or(self.duration, Duration::from_secs);
        if !holder.is_empty() && now.duration_since(since) < their {
            return Step::Wait;
        }
        let transitions = spec
            .get("leaseTransitions")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let spec = json!({
            "holderIdentity": self.identity,
            "leaseDurationSeconds": seconds,
            "acquireTime": wall,
            "renewTime": wall,
            "leaseTransitions": transitions.saturating_add(1),
        });
        if let Some(object) = next.as_object_mut() {
            object.insert("spec".into(), spec);
        }
        Step::Update(next)
    }
    /// The result of a Create or Update: `ok` when the API server took it.
    pub fn wrote(&mut self, now: Instant, ok: bool) {
        if ok {
            self.renewed = Some(now);
            self.observed = None;
        } else {
            self.renewed = None;
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS.000000Z` for a Lease's MicroTime fields.
pub fn micro_time(time: std::time::SystemTime) -> String {
    let since = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}.{:06}Z",
        crate::log::civil(since.as_secs()),
        since.subsec_micros()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(at: Instant, seconds: u64) -> Instant {
        at.checked_add(Duration::from_secs(seconds))
            .expect("instant")
    }
    fn lease(holder: &str, renew: &str) -> Value {
        json!({"metadata": {"name": "flowsdn-lb-ipam", "namespace": "kube-system",
                            "resourceVersion": "5"},
               "spec": {"holderIdentity": holder, "renewTime": renew,
                        "leaseDurationSeconds": 15, "leaseTransitions": 2}})
    }

    #[test]
    fn creates_renews_and_waits_out_another_holder() {
        let start = Instant::now();
        let mut me = Elector::new(
            "kube-system",
            "flowsdn-lb-ipam",
            "n1",
            Duration::from_secs(15),
        );
        assert_eq!(
            me.path(),
            "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/flowsdn-lb-ipam"
        );
        let Step::Create(body) = me.step(start, "t0", None) else {
            panic!("create");
        };
        assert_eq!(body.pointer("/spec/holderIdentity"), Some(&json!("n1")));
        assert!(!me.leading(start));
        me.wrote(start, true);
        assert!(me.leading(after(start, 5)));
        assert!(!me.leading(after(start, 13)));
        // Our own Lease: renew it, keeping the resourceVersion as a guard.
        let Step::Update(body) = me.step(start, "t1", Some(&lease("n1", "t0"))) else {
            panic!("renew");
        };
        assert_eq!(body.pointer("/spec/renewTime"), Some(&json!("t1")));
        assert_eq!(body.pointer("/metadata/resourceVersion"), Some(&json!("5")));
        // Someone else's live Lease: wait while its record keeps changing.
        let mut other = Elector::new(
            "kube-system",
            "flowsdn-lb-ipam",
            "n2",
            Duration::from_secs(15),
        );
        assert_eq!(other.step(start, "t", Some(&lease("n1", "a"))), Step::Wait);
        let later = after(start, 10);
        assert_eq!(other.step(later, "t", Some(&lease("n1", "b"))), Step::Wait);
        assert_eq!(
            other.step(after(later, 14), "t", Some(&lease("n1", "b"))),
            Step::Wait
        );
        // Unchanged for its duration: take it over.
        let Step::Update(body) = other.step(after(later, 15), "t9", Some(&lease("n1", "b"))) else {
            panic!("take over");
        };
        assert_eq!(body.pointer("/spec/holderIdentity"), Some(&json!("n2")));
        assert_eq!(body.pointer("/spec/leaseTransitions"), Some(&json!(3)));
        assert_eq!(body.pointer("/metadata/resourceVersion"), Some(&json!("5")));
        // Lost the race (409): not leading.
        other.wrote(later, false);
        assert!(!other.leading(later));
        // A released Lease (no holder) is taken at once.
        let mut third = Elector::new(
            "kube-system",
            "flowsdn-lb-ipam",
            "n3",
            Duration::from_secs(15),
        );
        assert!(matches!(
            third.step(start, "t", Some(&lease("", ""))),
            Step::Update(_)
        ));
    }

    #[test]
    fn micro_time_has_six_fraction_digits() {
        let time = std::time::SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_500_000))
            .expect("time");
        assert_eq!(micro_time(time), "1970-01-01T00:00:01.500000Z");
    }
}
