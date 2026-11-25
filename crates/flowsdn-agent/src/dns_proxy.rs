//! The agent's side of the DNS proxy (#536, spec 16 §3.6, ADR-0024 step 2):
//! its settings, the rules the policy thread publishes for it after each
//! pass ([`Rules`], from [`crate::policy::Desired`]), and the
//! [`flowsdn_l7::dns::Policy`] it asks ([`Answerer`]).
//!
//! An answer the proxy allows reaches the FQDN cache before the response is
//! released: the agent wakes the policy thread and waits (at most
//! `tofqdns-proxy-response-max-delay`) for the pass that programs the new
//! addresses (the response hold of §3.6.5), so the endpoint's first packet
//! to them is allowed.
use flowsdn_identity::cidr::CidrPrefix;
use flowsdn_l7::dns::{
    Config, Policy,
    cache::Limits,
    message::rcode,
};
use flowsdn_policy::ports::PortBlock;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Condvar, Mutex, RwLock},
    time::{Duration, Instant},
};

/// The world identity: an address the ipcache does not hold.
const WORLD: u32 = 2;

/// `kubernetes.l7-proxy` and the `tofqdns-*` keys (spec 16 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `tofqdns-proxy-port` (0: chosen at start).
    pub port: u16,
    pub limits: Limits,
    pub config: Config,
    /// `tofqdns-proxy-response-max-delay` (default 100 ms).
    pub max_delay: Duration,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 0,
            limits: Limits::default(),
            config: Config::default(),
            max_delay: Duration::from_millis(100),
        }
    }
}
impl Settings {
    /// From the `kubernetes` object's keys.
    pub fn parse(object: &Map<String, Value>) -> Result<Self, String> {
        let number = |key: &str, default: u64, max: u64| -> Result<u64, String> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(value) => value
                    .as_u64()
                    .filter(|n| *n <= max)
                    .ok_or_else(|| format!("kubernetes.{key} must be a number up to {max}")),
            }
        };
        let reject = match object.get("tofqdns-dns-reject-response-code") {
            None | Some(Value::Null) => rcode::REFUSED,
            Some(Value::String(s)) if s == "refused" => rcode::REFUSED,
            Some(Value::String(s)) if s == "nameError" => rcode::NXDOMAIN,
            Some(_) => {
                return Err(
                    "kubernetes.tofqdns-dns-reject-response-code must be refused or nameError"
                        .into(),
                );
            }
        };
        let port = u16::try_from(number("tofqdns-proxy-port", 0, 65535)?).unwrap_or(0);
        let min_ttl = u32::try_from(number("tofqdns-min-ttl", 0, 86_400 * 7)?).unwrap_or(0);
        let per_name = usize::try_from(number(
            "tofqdns-endpoint-max-ip-per-hostname",
            1000,
            100_000,
        )?)
        .unwrap_or(1000)
        .max(1);
        let delay = number("tofqdns-proxy-response-max-delay", 100, 10_000)?;
        let concurrency =
            usize::try_from(number("dnsproxy-concurrency-limit", 0, 100_000)?).unwrap_or(0);
        Ok(Self {
            port,
            limits: Limits {
                min_ttl,
                max_ips_per_name: per_name,
            },
            config: Config {
                reject,
                concurrency,
                ..Config::default()
            },
            max_delay: Duration::from_millis(delay),
        })
    }
}

/// One DNS rule of an endpoint: queries to a server of `identity` (0: any)
/// on `protocol` (0: any) and the port block `port/prefix`, for names one
/// of `names` matches (`any_name`: every name).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsRule {
    pub identity: u32,
    pub protocol: u8,
    pub port: u16,
    pub prefix: u8,
    pub names: Vec<String>,
    pub any_name: bool,
}

/// What the DNS proxy needs from a policy pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    /// Local endpoint addresses: (endpoint ID, identity).
    pub endpoints: BTreeMap<IpAddr, (u16, u32)>,
    /// Each endpoint's DNS rules.
    pub rules: BTreeMap<u16, Vec<DnsRule>>,
    /// Address identities: whole addresses, then prefixes (longest first).
    pub addresses: BTreeMap<IpAddr, u32>,
    pub prefixes: Vec<(CidrPrefix, u32)>,
    /// This cluster's ID, for the aggregate identities.
    pub cluster_id: u32,
}

impl Rules {
    /// An address's identity, as the ipcache gives it (world on a miss).
    pub fn identity(&self, address: IpAddr) -> u32 {
        if let Some(id) = self.addresses.get(&address) {
            return *id;
        }
        self.prefixes
            .iter()
            .filter(|(prefix, _)| prefix.contains_address(address))
            .max_by_key(|(prefix, _)| prefix.prefix_len())
            .map_or(WORLD, |(_, id)| *id)
    }
}

/// The datapath's `aggregate` (spec 03 `aggregate_for`): local scope is
/// world, scope 2 remote node, a global identity its cluster's.
pub fn aggregate(identity: u32, cluster_id: u32) -> u32 {
    match identity {
        0 | 11..=14 => identity,
        _ => match identity >> 24 {
            1 => 13,
            2 => 14,
            _ if identity < 100 => 0,
            _ if (identity >> 16) & 0xff == cluster_id => 11,
            _ => 12,
        },
    }
}

/// The policy thread's wake-up and what it has applied (§3.6.5): a learned
/// answer asks for a pass and waits for it.
#[derive(Debug, Default)]
pub struct Wake {
    /// (passes asked for, passes applied).
    state: Mutex<(u64, u64)>,
    changed: Condvar,
}
impl Wake {
    fn guard(&self) -> std::sync::MutexGuard<'_, (u64, u64)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Ask for a pass; the number to wait for.
    pub fn request(&self) -> u64 {
        let mut state = self.guard();
        state.0 = state.0.saturating_add(1);
        self.changed.notify_all();
        state.0
    }
    /// The policy thread: sleep until asked or `interval` passes. The
    /// requests the coming pass covers.
    pub fn wait(&self, interval: Duration) -> u64 {
        let state = self.guard();
        let applied = state.1;
        let (state, _) = self
            .changed
            .wait_timeout_while(state, interval, |s| s.0 <= applied)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0
    }
    /// The policy thread applied a pass that covered `requests`.
    pub fn applied(&self, requests: u64) {
        let mut state = self.guard();
        state.1 = state.1.max(requests);
        self.changed.notify_all();
    }
    /// Wait until pass `request` is applied or `limit` passes; whether it was.
    pub fn wait_applied(&self, request: u64, limit: Duration) -> bool {
        let state = self.guard();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, limit, |s| s.1 < request)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1 >= request
    }
}

/// What the proxy counted since start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub forwarded: u64,
    pub denied: u64,
    pub errors: u64,
    pub timeouts: u64,
    /// Answers released before their pass applied (the reference's
    /// `cilium_proxy_datapath_update_timeout_total`).
    pub hold_timeouts: u64,
}

/// Learn an answer: (names, addresses, TTL) -> whether the datapath has
/// them (false: the hold timed out).
pub type Learn = Box<dyn Fn(&[String], &[IpAddr], u32) -> bool + Send + Sync>;

/// The DNS proxy's [`Policy`]: the rules of the last policy pass and how to
/// learn an answer.
pub struct Answerer {
    rules: RwLock<(Rules, BTreeMap<String, Regex>)>,
    learn: Learn,
    counters: Mutex<Counters>,
}
impl std::fmt::Debug for Answerer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answerer").finish_non_exhaustive()
    }
}

impl Answerer {
    pub fn new(learn: Learn) -> Arc<Self> {
        Arc::new(Self {
            rules: RwLock::new((Rules::default(), BTreeMap::new())),
            learn,
            counters: Mutex::new(Counters::default()),
        })
    }
    /// A policy pass's rules (a no-op when unchanged).
    pub fn publish(&self, rules: &Rules) {
        let mut slot = self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.0 == *rules {
            return;
        }
        let mut compiled = BTreeMap::new();
        for rule in rules.rules.values().flatten() {
            for name in &rule.names {
                if !compiled.contains_key(name)
                    && let Ok(regex) = Regex::new(name)
                {
                    compiled.insert(name.clone(), regex);
                }
            }
        }
        *slot = (rules.clone(), compiled);
    }
    pub fn counters(&self) -> Counters {
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub fn status(&self, port: u16) -> Value {
        let c = self.counters();
        json!({"port": port, "forwarded": c.forwarded, "denied": c.denied,
            "errors": c.errors, "timeouts": c.timeouts, "hold-timeouts": c.hold_timeouts})
    }
    fn read(&self) -> std::sync::RwLockReadGuard<'_, (Rules, BTreeMap<String, Regex>)> {
        self.rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Policy for Answerer {
    fn endpoint(&self, source: IpAddr) -> Option<(u16, u32)> {
        self.read().0.endpoints.get(&source).copied()
    }
    fn identity(&self, address: IpAddr) -> u32 {
        self.read().0.identity(address)
    }
    fn allowed(&self, endpoint: u16, server: u32, protocol: u8, port: u16, name: &str) -> bool {
        let guard = self.read();
        let (rules, compiled) = &*guard;
        let group = aggregate(server, rules.cluster_id);
        rules.rules.get(&endpoint).into_iter().flatten().any(|rule| {
            (rule.identity == 0 || rule.identity == server || rule.identity == group)
                && (rule.protocol == 0 || rule.protocol == protocol)
                && PortBlock {
                    port: rule.port,
                    prefix: rule.prefix,
                }
                .matches(port)
                && (rule.any_name
                    || rule
                        .names
                        .iter()
                        .any(|n| compiled.get(n).is_some_and(|re| re.is_match(name))))
        })
    }
    fn learned(&self, _endpoint: u16, names: &[String], ips: &[IpAddr], ttl: u32) {
        if !(self.learn)(names, ips, ttl) {
            let mut c = self
                .counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            c.hold_timeouts = c.hold_timeouts.saturating_add(1);
        }
    }
    fn record(&self, record: flowsdn_l7::record::Record) {
        let mut c = self
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = match record.verdict.as_str() {
            "forwarded" => &mut c.forwarded,
            "denied" => &mut c.denied,
            "timeout" => &mut c.timeouts,
            _ => &mut c.errors,
        };
        *slot = slot.saturating_add(1);
    }
}

/// The hold (§3.6.5) as a [`Learn`] for the agent: `insert` puts the answer
/// in the FQDN cache and says whether that changed what policy allows;
/// then a pass is asked for and waited on, at most `limit`.
pub fn hold(
    insert: impl Fn(&[String], &[IpAddr], u32) -> bool + Send + Sync + 'static,
    wake: Arc<Wake>,
    limit: Duration,
) -> Learn {
    Box::new(move |names, ips, ttl| {
        if !insert(names, ips, ttl) {
            return true;
        }
        let started = Instant::now();
        let request = wake.request();
        wake.wait_applied(request, limit.saturating_sub(started.elapsed()))
    })
}

/// Seconds since the epoch: the FQDN cache's clock.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[path = "dns_proxy_tests.rs"]
mod tests;
