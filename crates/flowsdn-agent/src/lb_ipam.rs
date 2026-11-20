//! LB-IPAM (#475): addresses for `type: LoadBalancer` Services from
//! FlowsdnLoadBalancerIPPools, written to `status.loadBalancer.ingress`.
//!
//! Pure data; the Kubernetes controller's `flowsdn-lb-ipam` thread feeds it
//! the pools and Services and writes what it plans, while it holds the
//! LB-IPAM Lease (one writer in the cluster).
//!
//! - A pool's `blocks` are CIDRs or `start`..`stop` ranges (`stop` absent: one
//!   address). `allowFirstLastIPs: "No"` reserves a CIDR's first and last
//!   address (not for /31, /32, /127, /128). A pool with a block that does
//!   not parse is not used and says so in its `flowsdn.io/IPsAvailable`
//!   condition.
//! - A pool whose addresses overlap an older pool's (by creation time, then
//!   name) is conflicting (`flowsdn.io/PoolConflict` True) and not used.
//! - `serviceSelector` matches the Service's labels plus
//!   `io.kubernetes.service.namespace` and `io.kubernetes.service.name`;
//!   absent, the pool serves every Service.
//! - Services are handled oldest first. A Service is managed when it is
//!   `type: LoadBalancer` with no `loadBalancerClass` or
//!   [`LB_CLASS_L2`]. An ingress address it already has stays while a
//!   matching pool holds it (also a disabled one) and no older Service has
//!   it. A Service that asks for addresses (`lbipam.flowsdn.io/ips`,
//!   `spec.loadBalancerIP`) gets exactly those, when free in a matching
//!   enabled pool. Otherwise it gets one address per `spec.ipFamilies`
//!   family (default IPv4): the lowest free one of the first matching
//!   enabled pool, by name, that has one.
//! - A Service that is no longer managed (another type) loses the ingress
//!   addresses that are in a pool; a deleted Service's addresses are free
//!   once it is gone from the list.
use crate::services::ServiceInfo;
use flowsdn_policy::k8s::LabelSelector;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// The `loadBalancerClass` flowsdn's L2 announcer serves (with none).
pub const LB_CLASS_L2: &str = "io.flowsdn/l2-announcer";
pub const CONDITION_CONFLICT: &str = "flowsdn.io/PoolConflict";
pub const CONDITION_AVAILABLE: &str = "flowsdn.io/IPsAvailable";
/// The labels a `serviceSelector` can use to name a Service.
pub const SERVICE_NAMESPACE_LABEL: &str = "io.kubernetes.service.namespace";
pub const SERVICE_NAME_LABEL: &str = "io.kubernetes.service.name";

/// Addresses as numbers: IPv4 in the low 32 bits, the family kept apart.
type Number = (bool, u128);

fn number(ip: IpAddr) -> Number {
    match ip {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (true, u128::from(v6)),
    }
}
fn address((v6, value): Number) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(value))
    } else {
        IpAddr::V4(Ipv4Addr::from(u32::try_from(value).unwrap_or(u32::MAX)))
    }
}

/// An inclusive address range of one family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub v6: bool,
    pub first: u128,
    pub last: u128,
}
impl Range {
    fn contains(&self, (v6, value): Number) -> bool {
        self.v6 == v6 && self.first <= value && value <= self.last
    }
    fn overlaps(&self, other: &Range) -> bool {
        self.v6 == other.v6 && self.first <= other.last && other.first <= self.last
    }
    fn size(&self) -> u128 {
        self.last.saturating_sub(self.first).saturating_add(1)
    }
}

/// A FlowsdnLoadBalancerIPPool as LB-IPAM uses it.
#[derive(Clone, Debug, Default)]
pub struct Pool {
    pub name: String,
    pub created: String,
    pub generation: Option<u64>,
    pub disabled: bool,
    pub ranges: Vec<Range>,
    pub selector: LabelSelector,
    /// Why the pool cannot be used (a bad block or selector).
    pub invalid: Option<String>,
    /// `status.conditions` as they are (their transition times are kept).
    pub conditions: Vec<Value>,
}

fn parse_block(block: &Value, allow_first_last: bool) -> Result<Range, String> {
    if let Some(cidr) = block.get("cidr").and_then(Value::as_str) {
        let (ip, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| format!("{cidr}: not a CIDR"))?;
        let ip: IpAddr = ip.parse().map_err(|_| format!("{cidr}: not a CIDR"))?;
        let bits: u32 = if ip.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= bits)
            .ok_or_else(|| format!("{cidr}: invalid prefix"))?;
        let (v6, value) = number(ip);
        let host_bits = bits.saturating_sub(prefix);
        let mask = 1u128
            .checked_shl(host_bits)
            .map_or(u128::MAX, |bit| bit.wrapping_sub(1));
        let first = value & !mask;
        let last = first | mask;
        if !allow_first_last && host_bits >= 2 {
            return Ok(Range {
                v6,
                first: first.saturating_add(1),
                last: last.saturating_sub(1),
            });
        }
        return Ok(Range { v6, first, last });
    }
    let start = block
        .get("start")
        .and_then(Value::as_str)
        .ok_or("a block needs cidr or start")?;
    let first: IpAddr = start
        .parse()
        .map_err(|_| format!("{start}: not an address"))?;
    let last: IpAddr = match block.get("stop").and_then(Value::as_str) {
        Some(stop) => stop
            .parse()
            .map_err(|_| format!("{stop}: not an address"))?,
        None => first,
    };
    let (v6, first) = number(first);
    let (stop_v6, last) = number(last);
    if v6 != stop_v6 || last < first {
        return Err(format!(
            "{start}: stop must be of its family and not before it"
        ));
    }
    Ok(Range { v6, first, last })
}

impl Pool {
    /// A FlowsdnLoadBalancerIPPool object.
    pub fn parse(object: &Value) -> Pool {
        let meta = |key: &str| {
            object
                .pointer(&format!("/metadata/{key}"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let spec = object.get("spec").unwrap_or(&Value::Null);
        let mut pool = Pool {
            name: meta("name"),
            created: meta("creationTimestamp"),
            generation: object
                .pointer("/metadata/generation")
                .and_then(Value::as_u64),
            disabled: spec.get("disabled").and_then(Value::as_bool) == Some(true),
            conditions: object
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            ..Pool::default()
        };
        let allow_first_last = spec.get("allowFirstLastIPs").and_then(Value::as_str) != Some("No");
        let mut problems = Vec::new();
        for block in spec
            .get("blocks")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            match parse_block(block, allow_first_last) {
                Ok(range) => pool.ranges.push(range),
                Err(problem) => problems.push(problem),
            }
        }
        match LabelSelector::parse(spec.get("serviceSelector")) {
            Ok(selector) => pool.selector = selector,
            Err(error) => problems.push(format!("serviceSelector: {error}")),
        }
        if !problems.is_empty() {
            pool.invalid = Some(problems.join("; "));
        }
        pool
    }
    fn contains(&self, ip: Number) -> bool {
        self.ranges.iter().any(|r| r.contains(ip))
    }
    fn size(&self) -> u128 {
        self.ranges
            .iter()
            .fold(0u128, |sum, r| sum.saturating_add(r.size()))
    }
}

/// A Service's labels with the two naming labels added.
pub fn service_labels(service: &ServiceInfo) -> BTreeMap<String, String> {
    let mut labels = service.labels.clone();
    labels.insert(SERVICE_NAMESPACE_LABEL.into(), service.namespace.clone());
    labels.insert(SERVICE_NAME_LABEL.into(), service.name.clone());
    labels
}

/// Whether LB-IPAM gives `service` its addresses.
pub fn managed(service: &ServiceInfo) -> bool {
    service.service_type == "LoadBalancer"
        && service
            .load_balancer_class
            .as_deref()
            .is_none_or(|class| class == LB_CLASS_L2)
}

/// What one Service should carry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Desired {
    pub namespace: String,
    pub name: String,
    pub resource_version: String,
    /// The ingress addresses, in this order.
    pub ips: Vec<IpAddr>,
    /// Why it has fewer addresses than it asks for.
    pub problem: Option<String>,
}
impl Desired {
    /// Whether the Service's status already says this.
    pub fn current(&self, service: &ServiceInfo) -> bool {
        service.load_balancer_ips == self.ips
    }
    /// The `services/<name>/status` path.
    pub fn path(&self) -> String {
        format!(
            "/api/v1/namespaces/{}/services/{}/status",
            self.namespace, self.name
        )
    }
    /// The merge patch: the ingress list, guarded by the resourceVersion
    /// the plan was made from (a 409 means a newer Service: plan again).
    pub fn body(&self) -> Value {
        let ingress: Vec<Value> = self
            .ips
            .iter()
            .map(|ip| json!({"ip": ip.to_string()}))
            .collect();
        json!({
            "metadata": {"resourceVersion": self.resource_version},
            "status": {"loadBalancer": {"ingress": ingress}},
        })
    }
}

/// A pool's conditions LB-IPAM writes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PoolStatus {
    pub name: String,
    /// The `status.conditions` to write; `None` when they are current.
    pub conditions: Option<Vec<Value>>,
    pub used: u128,
    pub available: u128,
    pub conflict: Option<String>,
}
impl PoolStatus {
    pub fn path(&self) -> String {
        format!(
            "/apis/flowsdn.io/v1alpha1/flowsdnloadbalancerippools/{}/status",
            self.name
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Every Service whose ingress LB-IPAM decides, by (namespace, name).
    pub services: BTreeMap<(String, String), Desired>,
    pub pools: Vec<PoolStatus>,
}
impl Plan {
    /// The Services whose status differs from the plan.
    pub fn patches(&self, services: &[ServiceInfo]) -> Vec<&Desired> {
        services
            .iter()
            .filter_map(|s| {
                let desired = self.services.get(&(s.namespace.clone(), s.name.clone()))?;
                (!desired.current(s)).then_some(desired)
            })
            .collect()
    }
}

/// Mark the conflicting pools: their name -> the older pool they overlap.
fn conflicts(pools: &[Pool]) -> BTreeMap<String, String> {
    let mut ordered: Vec<&Pool> = pools.iter().filter(|p| p.invalid.is_none()).collect();
    ordered.sort_by(|a, b| (&a.created, &a.name).cmp(&(&b.created, &b.name)));
    let mut kept: Vec<&Pool> = Vec::new();
    let mut out = BTreeMap::new();
    for pool in ordered {
        if let Some(older) = kept.iter().find(|k| {
            k.ranges
                .iter()
                .any(|a| pool.ranges.iter().any(|b| a.overlaps(b)))
        }) {
            out.insert(pool.name.clone(), older.name.clone());
        } else {
            // Overlap inside one pool is the same pool's addresses: not a conflict.
            kept.push(pool);
        }
    }
    out
}

/// The lowest address of `pool` in `family` that is not in `used`.
fn lowest_free(pool: &Pool, v6: bool, used: &BTreeMap<Number, (String, String)>) -> Option<Number> {
    for range in pool.ranges.iter().filter(|r| r.v6 == v6) {
        let mut candidate = range.first;
        // Each step skips one used address, so this ends within used.len() + 1 steps.
        loop {
            if !used.contains_key(&(v6, candidate)) {
                return Some((v6, candidate));
            }
            if candidate == range.last {
                break;
            }
            candidate = candidate.saturating_add(1);
        }
    }
    None
}

fn condition(
    kind: &str,
    status: bool,
    reason: &str,
    message: String,
    existing: &[Value],
    generation: Option<u64>,
    now: &str,
) -> Value {
    let status = if status { "True" } else { "False" };
    let since = existing
        .iter()
        .find(|c| {
            c.get("type").and_then(Value::as_str) == Some(kind)
                && c.get("status").and_then(Value::as_str) == Some(status)
        })
        .and_then(|c| c.get("lastTransitionTime").and_then(Value::as_str))
        .unwrap_or(now);
    let mut value = json!({
        "type": kind,
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": since,
    });
    if let (Some(generation), Some(object)) = (generation, value.as_object_mut()) {
        object.insert("observedGeneration".into(), json!(generation));
    }
    value
}

/// Plan every managed Service's ingress addresses and every pool's
/// conditions. `now` is the RFC 3339 time a changed condition gets.
pub fn plan(pools: &[Pool], services: &[ServiceInfo], now: &str) -> Plan {
    let conflicting = conflicts(pools);
    let mut usable: Vec<&Pool> = pools
        .iter()
        .filter(|p| p.invalid.is_none() && !conflicting.contains_key(&p.name))
        .collect();
    usable.sort_by(|a, b| a.name.cmp(&b.name));
    let mut ordered: Vec<&ServiceInfo> = services.iter().collect();
    ordered.sort_by(|a, b| {
        (&a.created, &a.namespace, &a.name).cmp(&(&b.created, &b.namespace, &b.name))
    });
    let matching = |labels: &BTreeMap<String, String>, enabled: bool| -> Vec<&Pool> {
        usable
            .iter()
            .filter(|p| (!enabled || !p.disabled) && p.selector.matches(labels))
            .copied()
            .collect()
    };
    let mut used: BTreeMap<Number, (String, String)> = BTreeMap::new();
    let mut kept: BTreeMap<(String, String), Vec<IpAddr>> = BTreeMap::new();
    let mut plan = Plan::default();
    // Pass 1: every Service keeps the valid addresses it has, oldest first.
    for service in &ordered {
        let key = (service.namespace.clone(), service.name.clone());
        if !managed(service) {
            // No longer a LoadBalancer of ours: give back pool addresses.
            if service.load_balancer_ips.iter().any(|ip| {
                let n = number(*ip);
                usable.iter().any(|p| p.contains(n))
            }) && service.load_balancer_class.is_none()
            {
                let ips: Vec<IpAddr> = service
                    .load_balancer_ips
                    .iter()
                    .copied()
                    .filter(|ip| !usable.iter().any(|p| p.contains(number(*ip))))
                    .collect();
                plan.services.insert(
                    key,
                    Desired {
                        namespace: service.namespace.clone(),
                        name: service.name.clone(),
                        resource_version: service.resource_version.clone(),
                        ips,
                        problem: None,
                    },
                );
            }
            continue;
        }
        let families = families(service);
        let pools = matching(&service_labels(service), false);
        let mine = kept.entry(key.clone()).or_default();
        for ip in &service.load_balancer_ips {
            let n = number(*ip);
            let wanted = if service.requested_ips.is_empty() {
                families.contains(&ip.is_ipv6())
                    && !mine.iter().any(|k| k.is_ipv6() == ip.is_ipv6())
            } else {
                service.requested_ips.contains(ip)
            };
            if wanted && !used.contains_key(&n) && pools.iter().any(|p| p.contains(n)) {
                used.insert(n, key.clone());
                mine.push(*ip);
            }
        }
    }
    // Pass 2: what is still missing, oldest first.
    for service in &ordered {
        if !managed(service) {
            continue;
        }
        let key = (service.namespace.clone(), service.name.clone());
        let pools = matching(&service_labels(service), true);
        let mut ips = kept.get(&key).cloned().unwrap_or_default();
        let mut problems = Vec::new();
        if service.requested_ips.is_empty() {
            for v6 in families(service) {
                if ips.iter().any(|ip| ip.is_ipv6() == v6) {
                    continue;
                }
                let family = if v6 { "IPv6" } else { "IPv4" };
                match pools.iter().find_map(|p| lowest_free(p, v6, &used)) {
                    Some(n) => {
                        used.insert(n, key.clone());
                        ips.push(address(n));
                    }
                    None if pools.is_empty() => {
                        problems.push(format!("no enabled pool matches for {family}"));
                    }
                    None => problems.push(format!("no free {family} address in a matching pool")),
                }
            }
        } else {
            for ip in &service.requested_ips {
                if ips.contains(ip) {
                    continue;
                }
                let n = number(*ip);
                if let Some(holder) = used.get(&n) {
                    problems.push(format!("{ip} is held by {}/{}", holder.0, holder.1));
                } else if pools.iter().any(|p| p.contains(n)) {
                    used.insert(n, key.clone());
                    ips.push(*ip);
                } else {
                    problems.push(format!("{ip} is in no enabled pool that matches"));
                }
            }
        }
        ips.sort_by_key(IpAddr::is_ipv6);
        plan.services.insert(
            key,
            Desired {
                namespace: service.namespace.clone(),
                name: service.name.clone(),
                resource_version: service.resource_version.clone(),
                ips,
                problem: (!problems.is_empty()).then(|| problems.join("; ")),
            },
        );
    }
    for pool in pools {
        let conflict = conflicting.get(&pool.name).cloned();
        let in_use = used.keys().filter(|n| pool.contains(**n)).count();
        let used_count = u128::try_from(in_use).unwrap_or(u128::MAX);
        let available = if pool.invalid.is_some() || conflict.is_some() {
            0
        } else {
            pool.size().saturating_sub(used_count)
        };
        let conflict_condition = match &conflict {
            Some(older) => condition(
                CONDITION_CONFLICT,
                true,
                "Conflict",
                format!("addresses overlap pool {older}"),
                &pool.conditions,
                pool.generation,
                now,
            ),
            None => condition(
                CONDITION_CONFLICT,
                false,
                "NoConflict",
                "no overlap with another pool".into(),
                &pool.conditions,
                pool.generation,
                now,
            ),
        };
        let available_condition = match &pool.invalid {
            Some(problem) => condition(
                CONDITION_AVAILABLE,
                false,
                "InvalidPool",
                problem.clone(),
                &pool.conditions,
                pool.generation,
                now,
            ),
            None => condition(
                CONDITION_AVAILABLE,
                available > 0,
                if available > 0 {
                    "IPsAvailable"
                } else {
                    "NoIPsAvailable"
                },
                available.to_string(),
                &pool.conditions,
                pool.generation,
                now,
            ),
        };
        let desired = vec![conflict_condition, available_condition];
        let ours: BTreeSet<&str> = [CONDITION_CONFLICT, CONDITION_AVAILABLE].into();
        let mut existing: Vec<&Value> = pool
            .conditions
            .iter()
            .filter(|c| {
                c.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| ours.contains(t))
            })
            .collect();
        existing.sort_by_key(|c| c.get("type").and_then(Value::as_str).map(str::to_owned));
        let mut wanted: Vec<&Value> = desired.iter().collect();
        wanted.sort_by_key(|c| c.get("type").and_then(Value::as_str).map(str::to_owned));
        let current = existing == wanted;
        plan.pools.push(PoolStatus {
            name: pool.name.clone(),
            conditions: (!current).then_some(desired),
            used: used_count,
            available,
            conflict,
        });
    }
    plan
}

/// The families a Service asks for, IPv4 first: `spec.ipFamilies`, else IPv4.
fn families(service: &ServiceInfo) -> Vec<bool> {
    let mut out: Vec<bool> = service
        .ip_families
        .iter()
        .filter_map(|f| match f.as_str() {
            "IPv4" => Some(false),
            "IPv6" => Some(true),
            _ => None,
        })
        .collect();
    if out.is_empty() {
        out.push(false);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The pool status merge patch.
pub fn pool_body(conditions: &[Value]) -> Value {
    json!({"status": {"conditions": conditions}})
}

/// `GET /v1/lb-ipam`: whether this agent writes, the pools and the Services.
pub fn status_json(plan: &Plan, leading: bool, synced: bool) -> Value {
    json!({
        "leader": leading,
        "synced": synced,
        "pools": plan.pools.iter().map(|p| json!({
            "name": p.name,
            "used": p.used.to_string(),
            "available": p.available.to_string(),
            "conflict": p.conflict,
        })).collect::<Vec<_>>(),
        "services": plan.services.values().map(|d| json!({
            "namespace": d.namespace,
            "name": d.name,
            "ips": d.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "problem": d.problem,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[path = "lb_ipam_tests.rs"]
mod tests;
