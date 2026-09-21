//! Primary CNI ADD transaction from spec 09 §3.4, with reverse-order rollback.
//! Transport, veth syscalls, chaining and non-ADD verbs are separate adapters.
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt, net::IpAddr};

pub mod delete;
pub mod queue;
pub mod runtime;

pub type Result<T> = std::result::Result<T, CniError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CniError {
    pub code: u32,
    pub message: String,
    pub details: String,
}
impl CniError {
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 999,
            message: message.into(),
            details: String::new(),
        }
    }
    pub fn json(&self, version: &str) -> Value {
        json!({"cniVersion":version,"code":self.code,"msg":self.message,"details":self.details})
    }
}
impl fmt::Display for CniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for CniError {}

#[derive(Clone, Debug)]
pub struct AddRequest {
    pub version: String,
    pub container_id: String,
    pub ifname: String,
    pub netns: String,
    pub cni_path: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub pod_uid: String,
}
impl AddRequest {
    /// Parse a primary CNI 1.x ADD; reject unsupported modes before mutation.
    pub fn parse(input: &[u8], env: &BTreeMap<String, String>) -> Result<Self> {
        let conf: Value = serde_json::from_slice(input).map_err(|e| CniError {
            code: 6,
            message: "invalid network configuration".into(),
            details: e.to_string(),
        })?;
        let version = conf.get("cniVersion").and_then(Value::as_str).unwrap_or("");
        if !matches!(version, "1.0.0" | "1.1.0") {
            return Err(CniError {
                code: 1,
                message: "primary ADD currently requires CNI 1.0.0 or 1.1.0".into(),
                details: String::new(),
            });
        }
        if conf.get("prevResult").is_some_and(|v| !v.is_null()) {
            return Err(CniError::internal(
                "chained ADD requires a chaining adapter",
            ));
        }
        if conf
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(CniError::internal("network name is required"));
        }
        let required = |name: &str| -> Result<String> {
            env.get(name)
                .filter(|s| !s.is_empty())
                .cloned()
                .ok_or_else(|| CniError {
                    code: 4,
                    message: format!("missing {name}"),
                    details: String::new(),
                })
        };
        let ifname = required("CNI_IFNAME")?;
        if ifname.len() >= 16 || ifname.contains(['\0', '/']) {
            return Err(CniError {
                code: 7,
                message: "invalid interface name".into(),
                details: String::new(),
            });
        }
        let mut pod = BTreeMap::new();
        if let Some(args) = env.get("CNI_ARGS").filter(|s| !s.is_empty()) {
            for pair in args.split(';') {
                let (key, value) = pair
                    .split_once('=')
                    .filter(|(key, _)| !key.is_empty())
                    .ok_or_else(|| CniError::internal("malformed CNI_ARGS pair"))?;
                pod.insert(key, value);
            }
        }
        Ok(Self {
            version: version.into(),
            container_id: required("CNI_CONTAINERID")?,
            ifname,
            netns: required("CNI_NETNS")?,
            cni_path: required("CNI_PATH")?,
            pod_name: pod.get("K8S_POD_NAME").unwrap_or(&"").to_string(),
            pod_namespace: pod.get("K8S_POD_NAMESPACE").unwrap_or(&"").to_string(),
            pod_uid: pod.get("K8S_POD_UID").unwrap_or(&"").to_string(),
        })
    }
    pub fn owner(&self) -> String {
        format!("{}/{}", self.pod_namespace, self.pod_name)
    }
    pub fn attachment_id(&self) -> String {
        format!("cni-attachment-id:{}:{}", self.container_id, self.ifname)
    }
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub address: IpAddr,
    pub gateway: IpAddr,
    pub pool: String,
    pub expiration_uuid: String,
}
#[derive(Clone, Debug)]
pub struct Link {
    pub host_name: String,
    pub host_index: u32,
    pub host_mac: String,
    pub peer_mac: String,
}
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub mac_override: Option<String>,
}

/// System/agent operations supplied by the platform adapter. `allocate` must
/// be atomic across families. `create_link` must clean up any partial creation
/// before returning an error. Creation must wait for agent regeneration.
pub trait AddBackend {
    fn allocate(&mut self, request: &AddRequest) -> Result<Vec<Lease>>;
    fn create_link(&mut self, request: &AddRequest) -> Result<Link>;
    fn configure(&mut self, request: &AddRequest, link: &Link, leases: &[Lease]) -> Result<()>;
    fn create_endpoint(
        &mut self,
        request: &AddRequest,
        link: &Link,
        leases: &[Lease],
    ) -> Result<Endpoint>;
    fn finalize(
        &mut self,
        request: &AddRequest,
        link: &mut Link,
        endpoint: &Endpoint,
    ) -> Result<()>;
    /// False when endpoint publication or deletion is unresolved. Preserve link
    /// and addresses until the adapter confirms they cannot belong to an endpoint.
    fn may_release_resources(&self) -> bool { true }
    fn delete_endpoint(&mut self, request: &AddRequest) -> Result<()>;
    fn delete_link(&mut self, link: &Link) -> Result<()>;
    fn release(&mut self, lease: &Lease) -> Result<()>;
}

#[derive(Debug)]
pub struct AddFailure {
    pub primary: CniError,
    pub rollback_errors: Vec<CniError>,
}

/// Execute only after the adapter has fetched and validated agent configuration.
/// Preserve the primary failure and attempt every registered cleanup action.
pub fn add(
    request: &AddRequest,
    route_mtu: u32,
    backend: &mut impl AddBackend,
) -> std::result::Result<Value, AddFailure> {
    let fail = |primary| AddFailure {
        primary,
        rollback_errors: Vec::new(),
    };
    if !matches!(request.version.as_str(), "1.0.0" | "1.1.0") || route_mtu == 0 {
        return Err(fail(CniError::internal(
            "unsupported version or zero route MTU",
        )));
    }
    let mut leases = backend.allocate(request).map_err(fail)?;
    leases.sort_by_key(|lease| lease.address.is_ipv4()); // IPv6 first.
    let mut link = None;
    let mut endpoint_created = false;
    let outcome = (|| -> Result<Value> {
        if leases.is_empty()
            || leases.len() > 2
            || leases
                .iter()
                .any(|l| l.address.is_ipv4() != l.gateway.is_ipv4())
            || (leases.len() == 2
                && leases.first().map(|l| l.address.is_ipv4())
                    == leases.last().map(|l| l.address.is_ipv4()))
        {
            return Err(CniError::internal("invalid IPAM addressing"));
        }
        link = Some(backend.create_link(request)?);
        let link = link.as_mut().expect("link was just created");
        backend.configure(request, link, &leases)?;
        let endpoint = backend.create_endpoint(request, link, &leases)?;
        endpoint_created = true;
        backend.finalize(request, link, &endpoint)?;
        Ok(result(request, link, &leases, route_mtu))
    })();
    match outcome {
        Ok(result) => Ok(result),
        Err(primary) => {
            let mut errors = Vec::new();
            if endpoint_created && let Err(e) = backend.delete_endpoint(request) {
                errors.push(e);
            }
            if !backend.may_release_resources() {
                errors.push(CniError::internal("endpoint ownership unresolved; retaining link and IP allocations for retry or DEL"));
                return Err(AddFailure { primary, rollback_errors: errors });
            }
            if let Some(link) = link
                && let Err(e) = backend.delete_link(&link)
            {
                errors.push(e);
            }
            for lease in leases.iter().rev() {
                if let Err(e) = backend.release(lease) {
                    errors.push(e);
                }
            }
            Err(AddFailure {
                primary,
                rollback_errors: errors,
            })
        }
    }
}

fn result(request: &AddRequest, link: &Link, leases: &[Lease], mtu: u32) -> Value {
    let ips: Vec<_> = leases.iter().map(|l| json!({"address":format!("{}/{}",l.address,if l.address.is_ipv4(){32}else{128}),"gateway":l.gateway.to_string(),"interface":1})).collect();
    let routes: Vec<_> = leases.iter().flat_map(|l| [json!({"dst":format!("{}/{}",l.gateway,if l.gateway.is_ipv4(){32}else{128})}),json!({"dst":if l.gateway.is_ipv4(){"0.0.0.0/0"}else{"::/0"},"gw":l.gateway.to_string(),"mtu":mtu})]).collect();
    json!({"cniVersion":request.version,"interfaces":[{"name":link.host_name,"mac":link.host_mac},{"name":request.ifname,"mac":link.peer_mac,"sandbox":request.netns}],"ips":ips,"routes":routes,"dns":{}})
}
