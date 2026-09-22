//! Load-balancer input contracts from spec 05. No kernel or controller adapter yet.
use std::collections::BTreeMap;
use serde_json::Value;

/// Kubernetes creation timestamps normalized to UTC seconds/nanoseconds by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PoolOrder {
    pub created_seconds: i64,
    pub created_nanos: u32,
    pub name: String,
}

/// Missing creation timestamps sort as Kubernetes' zero time. Never reorder
/// allocations already assigned to a service; apply only to new allocations.
pub fn ordered_pools(mut pools: Vec<PoolOrder>) -> Result<Vec<PoolOrder>, &'static str> {
    if pools.iter().any(|p| p.name.is_empty() || p.created_nanos >= 1_000_000_000) {
        return Err("invalid pool metadata");
    }
    let mut names = std::collections::BTreeSet::new();
    if pools.iter().any(|p| !names.insert(p.name.clone())) { return Err("duplicate pool name"); }
    pools.sort();
    Ok(pools)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol { Tcp, Udp, Other }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Termination {
    pub kernel_supported: bool,
    pub terminate_pods: bool,
    pub hostns_only: bool,
    pub all_protocols: bool,
}
impl Termination {
    /// Cookie membership and backend liveness are supplied from the same
    /// reconciled snapshot. Ownership is mandatory even in the host namespace.
    pub fn eligible(self, host_netns: bool, protocol: Protocol, owned_cookie: bool, backend_alive: bool) -> bool {
        self.kernel_supported && owned_cookie && !backend_alive
            && (host_netns || (self.terminate_pods && !self.hostns_only))
            && (protocol == Protocol::Udp || (protocol == Protocol::Tcp && self.all_protocols))
    }
}

/// Raw Kubernetes objects retained losslessly until the shared conversion layer.
/// A snapshot only owns LocalAPI objects, never Kubernetes-controller objects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalSnapshot {
    pub services: BTreeMap<(String, String), Value>,
    pub endpoints: BTreeMap<(String, String), Value>,
}
fn yaml_value(v: &yaml_rust2::Yaml) -> Result<Value, String> {
    use yaml_rust2::Yaml;
    Ok(match v {
        Yaml::Null => Value::Null,
        Yaml::Boolean(v) => Value::Bool(*v),
        Yaml::Integer(v) => Value::from(*v),
        Yaml::Real(v) => serde_json::from_str(v).map_err(|e| format!("invalid YAML number: {e}"))?,
        Yaml::String(v) => Value::String(v.clone()),
        Yaml::Array(a) => Value::Array(a.iter().map(yaml_value).collect::<Result<_, _>>()?),
        Yaml::Hash(m) => {
            let mut out = serde_json::Map::new();
            for (k,v) in m { out.insert(k.as_str().ok_or("non-string YAML key")?.to_owned(), yaml_value(v)?); }
            Value::Object(out)
        },
        _ => return Err("unsupported YAML value".into()),
    })
}
fn objects(root: &Value, field: &str) -> Result<BTreeMap<(String, String), Value>, String> {
    let mut result = BTreeMap::new();
    let Some(array) = root.get(field).filter(|v| !v.is_null()) else { return Ok(result); };
    for object in array.as_array().ok_or("expected object array")? {
        let metadata = object.get("metadata").ok_or("missing metadata")?;
        let name = metadata.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()).ok_or("missing name")?;
        let namespace = match metadata.get("namespace") { None | Some(Value::Null) => "", Some(value) => value.as_str().ok_or("invalid namespace")? };
        if result.insert((namespace.to_owned(), name.to_owned()), object.clone()).is_some() { return Err("duplicate object".into()); }
    }
    Ok(result)
}
impl LocalSnapshot {
    /// Parse JSON or a single YAML document. Empty files intentionally clear the
    /// LocalAPI source, matching the reference fixture. Unknown fields survive
    /// inside objects; unknown top-level fields are ignored for compatibility.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.trim().is_empty() { return Ok(Self::default()); }
        let docs = yaml_rust2::YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
        if docs.len() != 1 { return Err("expected one state document".into()); }
        let root = yaml_value(docs.first().ok_or("missing document")?)?;
        if !root.is_object() { return Err("expected state object".into()); }
        Ok(Self { services: objects(&root, "services")?, endpoints: objects(&root, "endpoints")? })
    }
    pub fn to_json(&self) -> Value {
        serde_json::json!({"services": self.services.values().collect::<Vec<_>>(), "endpoints": self.endpoints.values().collect::<Vec<_>>()})
    }
    /// Parse/validate the entire next snapshot before atomically replacing the
    /// caller-owned LocalAPI input. Conversion/map application is a later layer.
    pub fn reload(&mut self, text: &str) -> Result<bool, String> {
        let next = Self::parse(text)?;
        let changed = *self != next;
        *self = next;
        Ok(changed)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pool_order_is_total_and_rejects_ambiguous_input() -> Result<(), &'static str> {
        let pool = |name: &str, created_seconds| PoolOrder { name:name.into(), created_seconds, created_nanos:0 };
        let expected = vec![pool("old",1),pool("a",2),pool("z",2)];
        assert_eq!(ordered_pools(vec![pool("z",2),pool("old",1),pool("a",2)])?,expected);
        assert!(ordered_pools(vec![pool("a",1),pool("a",2)]).is_err());
        Ok(())
    }
    #[test]
    fn termination_never_destroys_unowned_or_live_sockets() {
        let t = Termination { kernel_supported:true,terminate_pods:true,hostns_only:false,all_protocols:false };
        assert!(t.eligible(false,Protocol::Udp,true,false));
        for (owned,alive) in [(false,false),(false,true),(true,true)] { assert!(!t.eligible(true,Protocol::Udp,owned,alive)); }
        assert!(!t.eligible(true,Protocol::Tcp,true,false));
        assert!(!Termination { hostns_only:true,..t }.eligible(false,Protocol::Udp,true,false));
        assert!(Termination { all_protocols:true,..t }.eligible(true,Protocol::Tcp,true,false));
        assert!(!Termination { kernel_supported:false,..t }.eligible(true,Protocol::Udp,true,false));
    }
    #[test]
    fn reflector_replacement_is_atomic_and_roundtrips() -> Result<(), String> {
        let mut state = LocalSnapshot::parse("services:\n- metadata: {name: echo, namespace: test}\n  spec: {ports: [{port: 80}]}\nendpoints: []")?;
        let old = state.clone();
        assert!(!state.reload(&state.to_json().to_string())?);
        assert!(state.reload("services: [").is_err());
        assert_eq!(state,old);
        assert!(state.reload("")?);
        assert_eq!(state,LocalSnapshot::default());
        Ok(())
    }
    #[test]
    fn malformed_identity_and_duplicate_objects_rejected() {
        for s in ["services: [null]", "services: [{metadata: {name: a, namespace: true}}]", "services: [{metadata: {name: a}}, {metadata: {name: a}}]", "---\n{}\n---\n{}", "services: true"] {
            assert!(LocalSnapshot::parse(s).is_err(),"{s}");
        }
    }
}
