//! Optimistic Kubernetes Lease election. The caller executes requests, supplies
//! a monotonic elapsed clock, and cancels leader duties on terminal actions.
use serde_json::{Value, json};
use std::{fmt, time::Duration};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) } }
impl std::error::Error for Error {}
fn invalid(message: &str) -> Error { Error(message.into()) }

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub lease: Duration,
    pub renew: Duration,
    pub retry: Duration,
    pub request: Duration,
}
impl Default for Timing {
    fn default() -> Self { Self { lease: Duration::from_secs(15), renew: Duration::from_secs(10), retry: Duration::from_secs(2), request: Duration::from_secs(5) } }
}
impl Timing {
    pub fn validate(self) -> Result<Self, Error> {
        if self.retry.is_zero() || self.request.is_zero() || self.renew <= self.retry
            || self.request >= self.renew || self.lease <= self.renew
            || self.renew.checked_add(self.request).is_none_or(|sum| sum > self.lease)
            || self.lease.subsec_nanos() != 0 || self.lease.as_secs() > i32::MAX as u64
        { return Err(invalid("invalid Lease timing: require lease > renew > retry > 0 and 0 < request < renew, renew + request <= lease, integral lease seconds")); }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Follower, Leader, Terminal }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method { Get, Post, Put }
#[derive(Clone, Debug)]
pub struct Request {
    pub id: u64,
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    /// Absolute monotonic deadline. The driver must bound connect and body reads.
    pub deadline: Duration,
}
#[derive(Debug)]
pub enum Action {
    Request(Request),
    WaitUntil(Duration),
    /// Feed lifecycle::Event::LeaseAcquired, then start the leader scope.
    Acquired,
    Renewed,
    /// Cancel leader duties before executing this ownership-guarded PUT.
    CancelAndRelease(Request),
    Released,
    /// Terminal: abort outstanding requests/duties and exit without drain wait.
    CancelAndExit,
    /// A stale/cancelled operation response cannot change election state.
    Ignored,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    metadata: Value,
    uid: String,
    rv: String,
    holder: String,
    duration: u64,
    acquire: String,
    renew: String,
    transitions: u64,
}
impl Record {
    fn same_observation(&self, other: &Self) -> bool {
        self.uid == other.uid && self.holder == other.holder && self.duration == other.duration
            && self.acquire == other.acquire && self.renew == other.renew && self.transitions == other.transitions
    }
}
#[derive(Clone)]
enum Operation { Read, Write { expected: Record, release: bool } }
struct Pending { request: Request, operation: Operation }

pub struct Election {
    namespace: String,
    name: String,
    holder: String,
    timing: Timing,
    state: State,
    last_now: Duration,
    last_renew: Option<Duration>,
    observed: Option<(Record, Duration)>,
    pending: Option<Pending>,
    next_retry: Duration,
    sequence: u64,
}
impl Election {
    /// holder is generated once by the process: `<hostname>-<10 random chars>`.
    /// The driver must provide genuine per-process randomness; syntax alone
    /// cannot establish uniqueness. Name is explicit to avoid upstream lock adoption.
    pub fn new(namespace: &str, name: &str, holder: &str, timing: Timing) -> Result<Self, Error> {
        let dns = |s: &str| !s.is_empty() && s.len() <= 253 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'));
        if !dns(namespace) || !dns(name) { return Err(invalid("invalid Lease namespace or name")); }
        let (host, random) = holder.rsplit_once('-').ok_or_else(|| invalid("invalid Lease holder identity"))?;
        if !dns(host) || random.len() != 10 || !random.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return Err(invalid("invalid Lease holder identity"));
        }
        Ok(Self { namespace: namespace.into(), name: name.into(), holder: holder.into(), timing: timing.validate()?, state: State::Follower,
            last_now: Duration::ZERO, last_renew: None, observed: None, pending: None, next_retry: Duration::ZERO, sequence: 0 })
    }
    pub fn state(&self) -> State { self.state }
    fn clock(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.last_now { return Err(invalid("Lease clock moved backwards")); }
        self.last_now = now;
        Ok(())
    }
    fn expired(&self, now: Duration) -> bool {
        self.last_renew.is_some_and(|last| now.saturating_sub(last) >= self.timing.renew)
    }
    fn lost(&mut self) -> Action { self.state = State::Terminal; self.pending = None; Action::CancelAndExit }
    fn retry(&mut self, now: Duration) -> Result<Action, Error> {
        self.next_retry = now.checked_add(self.timing.retry).ok_or_else(|| invalid("Lease timer overflow"))?;
        if let Some(last) = self.last_renew {
            self.next_retry = self.next_retry.min(last.checked_add(self.timing.renew).ok_or_else(|| invalid("Lease timer overflow"))?);
        }
        Ok(Action::WaitUntil(self.next_retry))
    }
    fn collection(&self) -> String { format!("/apis/coordination.k8s.io/v1/namespaces/{}/leases", self.namespace) }
    fn issue(&mut self, method: Method, body: Option<Value>, operation: Operation, now: Duration) -> Result<Request, Error> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| invalid("Lease request ID exhausted"))?;
        let mut deadline = now.checked_add(self.timing.request).ok_or_else(|| invalid("Lease timer overflow"))?;
        if let Some(last) = self.last_renew {
            deadline = deadline.min(last.checked_add(self.timing.renew).ok_or_else(|| invalid("Lease timer overflow"))?);
        }
        let path = if method == Method::Post { self.collection() } else { format!("{}/{}", self.collection(), self.name) };
        let request = Request { id: self.sequence, method, path, body, deadline };
        self.pending = Some(Pending { request: request.clone(), operation });
        Ok(request)
    }
    /// Poll also while an HTTP request is in flight; never let transport stalls
    /// prevent the renew deadline from cancelling leader duties.
    pub fn poll(&mut self, now: Duration) -> Result<Action, Error> {
        self.clock(now)?;
        if self.state == State::Terminal { return Ok(Action::CancelAndExit); }
        if self.expired(now) { return Ok(self.lost()); }
        if let Some(pending) = &self.pending {
            if now < pending.request.deadline { return Ok(Action::WaitUntil(pending.request.deadline)); }
            let release = matches!(pending.operation, Operation::Write { release: true, .. });
            self.pending = None;
            if release { return Ok(self.lost()); }
            return self.retry(now);
        }
        if now < self.next_retry { return Ok(Action::WaitUntil(self.next_retry)); }
        Ok(Action::Request(self.issue(Method::Get, None, Operation::Read, now)?))
    }
    /// A transport failure is `status=None`. `wall_time` is a UTC RFC3339 timestamp
    /// supplied by the driver for serialization only, never for deciding expiry.
    /// All responses must be bounded/decoded by the authenticated HTTP driver.
    pub fn complete(&mut self, id: u64, status: Option<u16>, body: Option<&Value>, now: Duration, wall_time: &str) -> Result<Action, Error> {
        self.clock(now)?;
        if self.state == State::Terminal { return Ok(Action::Ignored); }
        if self.expired(now) { return Ok(self.lost()); }
        if self.pending.as_ref().is_none_or(|p| p.request.id != id) { return Ok(Action::Ignored); }
        let pending = self.pending.take().ok_or_else(|| invalid("missing Lease request"))?;
        if now >= pending.request.deadline {
            if matches!(pending.operation, Operation::Write { release: true, .. }) { return Ok(self.lost()); }
            return self.retry(now);
        }
        match pending.operation {
            Operation::Read => {
                if status == Some(404) {
                    if self.state == State::Leader { return Ok(self.lost()); }
                    return self.write(None, now, wall_time, false);
                }
                if status != Some(200) { return self.retry(now); }
                let record = match body.and_then(|body| self.parse(body).ok()) {
                    Some(record) => record,
                    None => return self.retry(now),
                };
                if self.state == State::Leader && (record.holder != self.holder || self.observed.as_ref().is_some_and(|(old, _)| old.uid != record.uid)) {
                    return Ok(self.lost());
                }
                let changed = self.observed.as_ref().is_none_or(|(old, _)| !old.same_observation(&record));
                let seen = if changed { now } else { self.observed.as_ref().map(|(_, seen)| *seen).unwrap_or(now) };
                self.observed = Some((record.clone(), seen));
                if record.holder == self.holder || record.holder.is_empty() || now.saturating_sub(seen) > Duration::from_secs(record.duration) {
                    return self.write(Some(record), now, wall_time, false);
                }
                self.retry(now)
            }
            Operation::Write { expected, release } => {
                if !matches!(status, Some(200 | 201)) {
                    if release { return Ok(self.lost()); }
                    return self.retry(now);
                }
                let record = body.and_then(|body| self.parse(body).ok());
                let confirmed = record.as_ref().is_some_and(|record| {
                    (expected.uid.is_empty() || record.uid == expected.uid)
                        && record.rv != expected.rv && record.holder == expected.holder
                        && record.duration == expected.duration && record.acquire == expected.acquire
                        && record.renew == expected.renew && record.transitions == expected.transitions
                });
                if !confirmed {
                    if release { return Ok(self.lost()); }
                    return self.retry(now);
                }
                if release { self.state = State::Terminal; return Ok(Action::Released); }
                let acquired = self.state == State::Follower;
                self.state = State::Leader;
                self.last_renew = Some(now);
                self.observed = record.map(|record| (record, now));
                self.retry(now)?;
                Ok(if acquired { Action::Acquired } else { Action::Renewed })
            }
        }
    }
    /// Cancel duties first; release only the last positively confirmed own Lease
    /// with UID and resourceVersion. Conflict/timeout is terminal, not a blind retry.
    pub fn release(&mut self, now: Duration, wall_time: &str) -> Result<Action, Error> {
        self.clock(now)?;
        if self.state != State::Leader || self.expired(now) { return Ok(self.lost()); }
        self.pending = None;
        let record = self.observed.as_ref().map(|(r, _)| r.clone()).ok_or_else(|| invalid("missing owned Lease"))?;
        if record.holder != self.holder { return Ok(self.lost()); }
        self.write(Some(record), now, wall_time, true)
    }
    fn write(&mut self, old: Option<Record>, now: Duration, wall_time: &str, release: bool) -> Result<Action, Error> {
        let wall_time = microtime(wall_time)?;
        let takeover = old.as_ref().is_some_and(|old| old.holder != self.holder);
        let transitions = old.as_ref().map_or(0, |old| old.transitions);
        let expected = Record {
            metadata: old.as_ref().map(|old| old.metadata.clone()).unwrap_or_else(|| json!({"name":self.name,"namespace":self.namespace})),
            uid: old.as_ref().map(|old| old.uid.clone()).unwrap_or_default(),
            rv: old.as_ref().map(|old| old.rv.clone()).unwrap_or_default(),
            holder: if release { String::new() } else { self.holder.clone() }, duration: self.timing.lease.as_secs(),
            acquire: old.as_ref().filter(|old| !takeover && !old.acquire.is_empty()).map(|old| old.acquire.clone()).unwrap_or_else(|| wall_time.clone()),
            renew: wall_time, transitions: if takeover { transitions.checked_add(1).filter(|v| *v <= i32::MAX as u64).ok_or_else(|| invalid("Lease transitions exhausted"))? } else { transitions },
        };
        let mut metadata = expected.metadata.clone();
        if old.is_some() {
            let fields = metadata.as_object_mut().ok_or_else(|| invalid("invalid Lease metadata"))?;
            fields.insert("uid".into(), json!(expected.uid));
            fields.insert("resourceVersion".into(), json!(expected.rv));
        }
        let body = json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":metadata,
            "spec":{"holderIdentity":expected.holder,"leaseDurationSeconds":expected.duration,"acquireTime":expected.acquire,"renewTime":expected.renew,"leaseTransitions":expected.transitions}});
        let method = if old.is_some() { Method::Put } else { Method::Post };
        let request = self.issue(method, Some(body), Operation::Write { expected, release }, now)?;
        Ok(if release { Action::CancelAndRelease(request) } else { Action::Request(request) })
    }
    fn parse(&self, value: &Value) -> Result<Record, Error> {
        let string = |pointer: &str| value.pointer(pointer).and_then(Value::as_str).ok_or_else(|| invalid("invalid Lease response"));
        if string("/apiVersion")? != "coordination.k8s.io/v1" || string("/kind")? != "Lease"
            || string("/metadata/name")? != self.name || string("/metadata/namespace")? != self.namespace { return Err(invalid("unexpected Lease identity")); }
        let uid = string("/metadata/uid")?;
        let rv = string("/metadata/resourceVersion")?;
        if uid.is_empty() || rv.is_empty() { return Err(invalid("missing Lease UID/resourceVersion")); }
        let duration = value.pointer("/spec/leaseDurationSeconds").and_then(Value::as_u64).filter(|v| *v > 0 && *v <= i32::MAX as u64).ok_or_else(|| invalid("invalid Lease duration"))?;
        let optional_string = |pointer: &str| match value.pointer(pointer) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(value) => value.as_str().map(str::to_owned).ok_or_else(|| invalid("invalid Lease string field")),
        };
        let transitions = match value.pointer("/spec/leaseTransitions") {
            None | Some(Value::Null) => 0,
            Some(value) => value.as_u64().filter(|v| *v <= i32::MAX as u64).ok_or_else(|| invalid("invalid Lease transitions"))?,
        };
        let timestamp = |pointer| -> Result<String, Error> {
            let value = optional_string(pointer)?;
            if value.is_empty() { Ok(value) } else { microtime(&value) }
        };
        Ok(Record { metadata: value.get("metadata").cloned().ok_or_else(|| invalid("missing Lease metadata"))?, uid: uid.into(), rv: rv.into(), holder: optional_string("/spec/holderIdentity")?,
            duration, acquire: timestamp("/spec/acquireTime")?,
            renew: timestamp("/spec/renewTime")?, transitions })
    }
}

// Kubernetes metav1::MicroTime serializes UTC with exactly six decimal places.
// Accept UTC RFC3339 spellings only; callers with local offsets normalize first.
fn microtime(value: &str) -> Result<String, Error> {
    let error = || invalid("Lease timestamp must be a valid UTC RFC3339 value");
    if !value.is_ascii() { return Err(error()); }
    let core = value.strip_suffix('Z').or_else(|| value.strip_suffix("+00:00")).ok_or_else(error)?;
    let (whole, fraction) = core.split_once('.').unwrap_or((core, ""));
    if whole.len() != 19 || fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit())
        || (core.contains('.') && fraction.is_empty()) { return Err(error()); }
    for (index, separator) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if whole.as_bytes().get(index) != Some(&separator) { return Err(error()); }
    }
    let number = |range: std::ops::Range<usize>| -> Result<u32, Error> {
        let digits = whole.get(range).ok_or_else(error)?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) { return Err(error()); }
        digits.parse().map_err(|_| error())
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month { 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, 4 | 6 | 9 | 11 => 30, 2 if leap => 29, 2 => 28, _ => return Err(error()) };
    if day == 0 || day > days || number(11..13)? > 23 || number(14..16)? > 59 || number(17..19)? > 59 { return Err(error()); }
    let mut micros: String = fraction.chars().take(6).collect();
    while micros.len() < 6 { micros.push('0'); }
    Ok(format!("{whole}.{micros}Z"))
}
