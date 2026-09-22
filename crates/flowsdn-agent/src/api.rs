//! Initial Unix API for primary host-scope CNI and persisted endpoint ownership.
//! This daemon has no Kubernetes discovery, policy or identity controller.
use crate::{endpoints::Manager, state::Result};
use flowsdn_cni::queue::{Queue, ReplayRequest};
use flowsdn_ipam::{HostScope, Ipam};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    net::IpAddr,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "health_api.rs"]
mod health_api;

const BODY_LIMIT: usize = 4_194_304;
const HEADER_LIMIT: usize = 16_384;
const REQUEST_BUDGET: Duration = Duration::from_secs(2);
const EXPIRATION: Duration = Duration::from_secs(600);

#[derive(Debug)]
struct Failure {
    status: u16,
    message: String,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Failure {}
fn fail<T>(status: u16, message: impl Into<String>) -> Result<T> {
    Err(Box::new(Failure {
        status,
        message: message.into(),
    }))
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(value) => Ok(value),
        None => fail(400, format!("missing or invalid {key}")),
    }
}
fn optional<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(value)) => Ok(value),
        _ => fail(400, format!("invalid {key}")),
    }
}

struct Config {
    socket: PathBuf,
    state: PathBuf,
    object: PathBuf,
    pin_root: Option<PathBuf>,
    queue: PathBuf,
    v4: Option<(IpAddr, u8)>,
    v6: Option<(IpAddr, u8)>,
    gateway4: Option<IpAddr>,
    gateway6: Option<IpAddr>,
    device_mtu: u32,
    route_mtu: u32,
    endpoint_id_max: u32,
}
impl Config {
    fn read(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return fail(400, "agent configuration exceeds 1 MiB");
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        let socket = PathBuf::from(string(&value, "socket-path")?);
        let state = PathBuf::from(string(&value, "state-dir")?);
        let object = PathBuf::from(string(&value, "bpf-object")?);
        let pin_root = match optional(&value, "bpf-pin-root")? {
            "" => None,
            path => Some(PathBuf::from(path)),
        };
        let queue = if optional(&value, "delete-queue")?.is_empty() {
            socket
                .parent()
                .ok_or("socket has no parent")?
                .join("deleteQueue")
        } else {
            PathBuf::from(string(&value, "delete-queue")?)
        };
        let pool = |key, v6| -> Result<Option<(IpAddr, u8)>> {
            let raw = optional(&value, key)?;
            if raw.is_empty() {
                return Ok(None);
            }
            let (ip, prefix) = raw.split_once('/').ok_or("pool must be CIDR")?;
            let ip: IpAddr = ip.parse()?;
            let prefix: u8 = prefix.parse()?;
            if ip.is_ipv6() != v6 {
                return fail(400, "pool address family mismatch");
            }
            HostScope::new(ip, prefix, Default::default())?;
            Ok(Some((ip, prefix)))
        };
        let v4 = pool("ipv4-pool", false)?;
        let v6 = pool("ipv6-pool", true)?;
        if v4.is_none() && v6.is_none() {
            return fail(400, "at least one IP pool is required");
        }
        let gateway = |key, v6, enabled: bool| -> Result<Option<IpAddr>> {
            let raw = optional(&value, key)?;
            if !enabled {
                if raw.is_empty() {
                    return Ok(None);
                }
                return fail(400, "gateway provided for disabled family");
            }
            let ip: IpAddr = raw.parse()?;
            if ip.is_ipv6() != v6
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_loopback()
                || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
            {
                return fail(400, "invalid gateway");
            }
            Ok(Some(ip))
        };
        let gateway4 = gateway("ipv4-gateway", false, v4.is_some())?;
        let gateway6 = gateway("ipv6-gateway", true, v6.is_some())?;
        let mtu = |key| -> Result<u32> {
            value
                .get(key)
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v >= 1280)
                .ok_or_else(|| format!("invalid {key}").into())
        };
        let endpoint_id_max = match value.get("endpoint-id-max") {
            None => u32::from(crate::state::DEFAULT_ENDPOINT_ID_MAX),
            Some(value) => value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| (1..=65535).contains(n))
                .ok_or("endpoint-id-max must be an integer in 1..=65535")?,
        };
        let device_mtu = mtu("device-mtu")?;
        let route_mtu = mtu("route-mtu")?;
        if route_mtu > device_mtu {
            return fail(400, "route MTU exceeds device MTU");
        }
        Ok(Self {
            socket,
            state,
            object,
            pin_root,
            queue,
            v4,
            v6,
            gateway4,
            gateway6,
            device_mtu,
            route_mtu,
            endpoint_id_max,
        })
    }
    fn ipam(&self) -> Result<Ipam> {
        let scope = |pool: Option<(IpAddr, u8)>| {
            pool.map(|(ip, prefix)| HostScope::new(ip, prefix, Default::default()))
                .transpose()
        };
        let mut ipam = Ipam::new(scope(self.v4)?, scope(self.v6)?)?;
        for gateway in [self.gateway4, self.gateway6].into_iter().flatten() {
            ipam.exclude_ip(gateway, "router")?;
        }
        Ok(ipam)
    }
    fn addressing(&self) -> Value {
        let family = |pool: Option<(IpAddr, u8)>, gateway: Option<IpAddr>| match (pool, gateway) {
            (Some((ip, prefix)), Some(gateway)) => {
                json!({"enabled":true,"ip":gateway.to_string(),"alloc-range":format!("{ip}/{prefix}")})
            }
            _ => json!({"enabled":false,"ip":"","alloc-range":""}),
        };
        json!({"ipv4":family(self.v4,self.gateway4),"ipv6":family(self.v6,self.gateway6)})
    }
}

struct Lease {
    owner: String,
    uuid: String,
    expires: Option<Instant>,
}
struct Api {
    config: Config,
    manager: Manager,
    leases: BTreeMap<IpAddr, Lease>,
}
impl Api {
    fn expire(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .leases
            .iter()
            .filter_map(|(ip, lease)| lease.expires.is_some_and(|time| time <= now).then_some(*ip))
            .collect();
        for ip in expired {
            match self.manager.ipam_mut().release(ip) {
                Ok(()) => {
                    self.leases.remove(&ip);
                }
                Err(error) => eprintln!("IPAM expiration failed: {error}"),
            }
        }
    }
    fn handle(&mut self, request: Request) -> Result<(u16, Value)> {
        self.expire();
        let (path, query) = request
            .target
            .split_once('?')
            .unwrap_or((&request.target, ""));
        let query = query_values(query)?;
        match (request.method.as_str(), path) {
            ("GET", "/v1/config") => {
                return Ok((
                    200,
                    json!({"status":{"datapath-mode":"veth","ipam-mode":"kubernetes",
                "device-mtu":self.config.device_mtu,"route-mtu":self.config.route_mtu,"host-addressing":self.config.addressing()}}),
                ));
            }
            ("GET", "/v1/healthz") => {
                return Ok((
                    200,
                    json!({"cilium":{"state":"Ok","msg":"initial endpoint API ready"}}),
                ));
            }
            ("POST", "/v1/ipam") => return self.allocate(&query, request.expiration),
            ("DELETE", "/v1/endpoint") => {
                let cid = string(&request.body, "container-id")?;
                let attachments: Vec<_> = self
                    .manager
                    .records()
                    .filter(|record| {
                        record.document.get("dockerID").and_then(Value::as_str) == Some(cid)
                    })
                    .map(|record| record.attachment.clone())
                    .collect();
                let mut failures = 0u32;
                for attachment in attachments {
                    if let Err(error) = self.manager.delete(&attachment) {
                        failures = failures.saturating_add(1);
                        eprintln!("endpoint deletion failed: {error}");
                    }
                }
                return Ok(if failures == 0 {
                    (200, json!(0))
                } else {
                    (206, json!(failures))
                });
            }
            _ => {}
        }
        if let Some(ip) = path.strip_prefix("/v1/ipam/") {
            if request.method != "DELETE" {
                return fail(405, "method not supported");
            }
            let ip: IpAddr = decode(ip)?.parse().map_err(|_| Failure {
                status: 400,
                message: "invalid IP address".into(),
            })?;
            check_pool(query.get("pool").map(String::as_str).unwrap_or(""), false)?;
            let used = self.manager.records().any(|record| {
                ["IPv4", "IPv6"].iter().any(|key| {
                    record
                        .document
                        .get(key)
                        .and_then(Value::as_str)
                        .and_then(|raw| raw.parse::<IpAddr>().ok())
                        == Some(ip)
                })
            });
            if used {
                return fail(409, "IP is in use by an endpoint");
            }
            self.manager.ipam_mut().release(ip).map_err(|e| Failure {
                status: 500,
                message: e.to_string(),
            })?;
            self.leases.remove(&ip);
            return Ok((200, json!({})));
        }
        if let Some(id) = path.strip_prefix("/v1/endpoint/") {
            if let Some(id) = id.strip_suffix("/healthz") {
                if request.method != "GET" {
                    return fail(405, "method not supported");
                }
                if self.manager.get(&decode(id)?).is_none() {
                    return fail(404, "endpoint not found");
                }
                let healthy = self.manager.healthy(&decode(id)?)?;
                let status = if healthy { "OK" } else { "Failure" };
                return Ok((
                    200,
                    json!({"overallHealth":status,"bpf":status,"policy":"Disabled","connected":healthy}),
                ));
            }
            let id = decode(id)?;
            return match request.method.as_str() {
                "PUT" => self.create(&id, &request.body),
                "DELETE" => {
                    if self.manager.delete(&id)? {
                        Ok((200, json!(0)))
                    } else {
                        fail(404, "endpoint not found")
                    }
                }
                "GET" => {
                    let record = self.manager.get(&id).ok_or_else(|| Failure {
                        status: 404,
                        message: "endpoint not found".into(),
                    })?;
                    Ok((200, endpoint_response(record.id, &record.document)))
                }
                _ => fail(405, "method not supported"),
            };
        }
        fail(404, "API route not implemented")
    }
    fn allocate(
        &mut self,
        query: &BTreeMap<String, String>,
        expiration: bool,
    ) -> Result<(u16, Value)> {
        let owner = query
            .get("owner")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Failure {
                status: 400,
                message: "owner is required".into(),
            })?;
        check_pool(query.get("pool").map(String::as_str).unwrap_or(""), true)?;
        let addresses = match query.get("family").map(String::as_str).unwrap_or("") {
            "" => {
                let pair = self
                    .manager
                    .ipam_mut()
                    .allocate_next(owner)
                    .map_err(|e| Failure {
                        status: 502,
                        message: e.to_string(),
                    })?;
                pair.ipv6
                    .map(IpAddr::V6)
                    .into_iter()
                    .chain(pair.ipv4.map(IpAddr::V4))
                    .collect::<Vec<_>>()
            }
            "ipv4" => vec![
                self.manager
                    .ipam_mut()
                    .allocate_next_family(false, owner)
                    .map_err(|e| Failure {
                        status: 502,
                        message: e.to_string(),
                    })?,
            ],
            "ipv6" => vec![
                self.manager
                    .ipam_mut()
                    .allocate_next_family(true, owner)
                    .map_err(|e| Failure {
                        status: 502,
                        message: e.to_string(),
                    })?,
            ],
            _ => return fail(400, "family must be ipv4 or ipv6"),
        };
        let mut pair = serde_json::Map::new();
        let mut result = serde_json::Map::new();
        for ip in addresses {
            let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
            let uuid = if expiration {
                uuid::Uuid::new_v4().to_string()
            } else {
                String::new()
            };
            let expires = if expiration {
                Some(
                    Instant::now()
                        .checked_add(EXPIRATION)
                        .ok_or("expiration overflow")?,
                )
            } else {
                None
            };
            self.leases.insert(
                ip,
                Lease {
                    owner: owner.clone(),
                    uuid: uuid.clone(),
                    expires,
                },
            );
            pair.insert(family.into(), json!(ip.to_string()));
            pair.insert(format!("{family}-pool-name"), json!("default"));
            pair.insert(format!("{family}-expiration-uuid"), json!(uuid));
            result.insert(family.into(),json!({"ip":ip.to_string(),"expiration-uuid":uuid,"gateway":"","cidrs":[],"master-mac":"","interface-number":"","skip-masquerade":false}));
        }
        result.insert("address".into(), Value::Object(pair));
        result.insert("host-addressing".into(), self.config.addressing());
        Ok((201, Value::Object(result)))
    }
    fn create(&mut self, id: &str, body: &Value) -> Result<(u16, Value)> {
        if self.manager.get(id).is_some() {
            if !self.manager.healthy(id)? {
                return fail(500, "endpoint recovery or teardown remains incomplete");
            }
            return fail(409, "endpoint already exists");
        }
        let cid = string(body, "container-id")?;
        let interface = string(body, "container-interface-name")?;
        if id != format!("cni-attachment-id:{cid}:{interface}") {
            return fail(400, "endpoint URL and attachment do not match");
        }
        if body.get("sync-build-endpoint") != Some(&Value::Bool(true))
            || optional(body, "state")? != "waiting-for-identity"
        {
            return fail(400, "synchronous initial endpoint creation is required");
        }
        if body
            .get("labels")
            .is_some_and(|labels| labels.as_array().is_none_or(|labels| !labels.is_empty()))
        {
            return fail(501, "identity and policy labels are not implemented");
        }
        if body
            .get("datapath-configuration")
            .is_some_and(|v| v.as_object().is_none_or(|v| !v.is_empty()))
        {
            return fail(501, "custom datapath modes are not implemented");
        }
        if body
            .get("properties")
            .is_some_and(|v| v.as_object().is_none_or(|v| !v.is_empty()))
        {
            return fail(501, "endpoint properties are not implemented");
        }
        check_cni_route_mtu(body, self.config.route_mtu)?;
        let namespace = string(body, "k8s-namespace")?;
        let pod = string(body, "k8s-pod-name")?;
        let owner = format!("{namespace}/{pod}");
        let addressing = body.get("addressing").ok_or_else(|| Failure {
            status: 400,
            message: "addressing is required".into(),
        })?;
        let mut ips = Vec::new();
        for family in ["ipv6", "ipv4"] {
            let raw = optional(addressing, family)?;
            if raw.is_empty() {
                continue;
            }
            let ip: IpAddr = raw.parse().map_err(|_| Failure {
                status: 400,
                message: "invalid endpoint IP".into(),
            })?;
            if ip.is_ipv6() != (family == "ipv6") {
                return fail(400, "endpoint address family mismatch");
            }
            check_pool(optional(addressing, &format!("{family}-pool-name"))?, false)?;
            let lease = self.leases.get(&ip).ok_or_else(|| Failure {
                status: 409,
                message: "IP allocation is not pending".into(),
            })?;
            if lease.owner != owner
                || lease.uuid != optional(addressing, &format!("{family}-expiration-uuid"))?
            {
                return fail(409, "IP owner or expiration UUID does not match");
            }
            ips.push(ip);
        }
        if ips.is_empty() {
            return fail(400, "endpoint has no allocated addresses");
        }
        let index = body
            .get("interface-index")
            .and_then(Value::as_u64)
            .and_then(|v| i32::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| Failure {
                status: 400,
                message: "invalid host interface index".into(),
            })?;
        let cookie = optional(body, "netns-cookie")?
            .parse::<u64>()
            .map_err(|_| Failure {
                status: 400,
                message: "invalid namespace cookie".into(),
            })?;
        let document = json!({"dockerID":cid,"ContainerNetnsPath":optional(body,"container-netns-path")?,"IfName":string(body,"interface-name")?,"IfIndex":index,
            "DatapathMode":"veth","ParentIfIndex":0,"ContainerIfName":interface,"IsSecondaryInterface":false,
            "OpLabels":{"Custom":{},"OrchestrationIdentity":{},"Disabled":{},"OrchestrationInfo":{}},
            "LXCMAC":string(body,"mac")?,"NodeMAC":string(body,"host-mac")?,
            "IPv4":optional(addressing,"ipv4")?,"IPv4IPAMPool":optional(addressing,"ipv4-pool-name")?,
            "IPv6":optional(addressing,"ipv6")?,"IPv6IPAMPool":optional(addressing,"ipv6-pool-name")?,
            "SecLabel":null,"Options":{},"DNSHistory":null,"DNSZombies":null,
            "K8sPodName":pod,"K8sNamespace":namespace,"K8sUID":optional(body,"k8s-uid")?,
            "DatapathConfiguration":{"require-arp-passthrough":false,"require-egress-prog":false,"external-ipam":false,"require-routing":null,"install-endpoint-route":false,"disable-sip-verification":false},
            "CiliumEndpointUID":"","Properties":{},"NetnsCookie":cookie,"RTInfo":0,"CNIHostAddressing":self.config.addressing(),"CNIRouteMTU":self.config.route_mtu});
        let id = self.manager.create(document.clone())?;
        for ip in ips {
            self.leases.remove(&ip);
        }
        Ok((201, endpoint_response(id, &document)))
    }
}

fn endpoint_response(id: u16, document: &Value) -> Value {
    json!({"id":id,"status":{"state":"ready","networking":{"mac":document.get("LXCMAC"),"host-mac":document.get("NodeMAC"),
        "interface-name":document.get("IfName"),"interface-index":document.get("IfIndex"),"container-interface-name":document.get("ContainerIfName"),"netns-cookie":document.get("NetnsCookie").and_then(Value::as_u64).unwrap_or(0).to_string(),"host-addressing":document.get("CNIHostAddressing"),"route-mtu":document.get("CNIRouteMTU"),
        "addressing":[{"ipv4":document.get("IPv4"),"ipv6":document.get("IPv6"),"ipv4-pool-name":document.get("IPv4IPAMPool"),"ipv6-pool-name":document.get("IPv6IPAMPool")} ]}}})
}
fn check_pool(pool: &str, empty_allowed: bool) -> Result<()> {
    if pool == "default" || (pool.is_empty() && empty_allowed) {
        Ok(())
    } else {
        fail(400, "host-scope IPAM requires pool default")
    }
}
fn decode(text: &str) -> Result<String> {
    let mut input = text.bytes();
    let mut bytes = Vec::new();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let a = input
                .next()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or_else(|| Failure {
                    status: 400,
                    message: "invalid percent escape".into(),
                })?;
            let b = input
                .next()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or_else(|| Failure {
                    status: 400,
                    message: "invalid percent escape".into(),
                })?;
            bytes.push(u8::try_from((a << 4) | b)?);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        Box::new(Failure {
            status: 400,
            message: "URL is not UTF-8".into(),
        }) as _
    })
}
fn query_values(query: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or_else(|| Failure {
            status: 400,
            message: "invalid query parameter".into(),
        })?;
        let key = decode(key)?;
        let value = decode(value)?;
        if values.insert(key, value).is_some() {
            return fail(400, "duplicate query parameter");
        }
    }
    Ok(values)
}

struct Request {
    method: String,
    target: String,
    body: Value,
    expiration: bool,
}
fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let start = Instant::now();
    let mut bytes = Vec::new();
    loop {
        let remaining = REQUEST_BUDGET.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return fail(408, "request deadline exceeded");
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut part = [0u8; 4096];
        let count = match stream.read(&mut part) {
            Ok(0) => return fail(400, "truncated request"),
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return fail(408, "request deadline exceeded");
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        bytes.extend_from_slice(part.get(..count).ok_or("invalid read count")?);
        if bytes.len() > HEADER_LIMIT.saturating_add(BODY_LIMIT) {
            return fail(413, "request body exceeds 4 MiB");
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        let parsed = request.parse(&bytes).map_err(|e| Failure {
            status: 400,
            message: e.to_string(),
        })?;
        if let httparse::Status::Complete(header_len) = parsed {
            if header_len > HEADER_LIMIT {
                return fail(431, "request headers exceed 16 KiB");
            }
            if request.version != Some(1) {
                return fail(505, "HTTP/1.1 is required");
            }
            let mut length = None;
            let mut expiration = None;
            for header in request.headers.iter() {
                if header.name.eq_ignore_ascii_case("transfer-encoding") {
                    return fail(501, "chunked requests are not supported");
                }
                if header.name.eq_ignore_ascii_case("expect") {
                    return fail(417, "Expect is not supported");
                }
                if header.name.eq_ignore_ascii_case("content-length") {
                    if length.is_some() {
                        return fail(400, "duplicate Content-Length");
                    }
                    let text = std::str::from_utf8(header.value)?.trim();
                    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                        return fail(400, "invalid Content-Length");
                    }
                    length = Some(text.parse::<usize>().map_err(|_| Failure {
                        status: 413,
                        message: "Content-Length overflow".into(),
                    })?);
                }
                if header.name.eq_ignore_ascii_case("expiration") {
                    if expiration.is_some() {
                        return fail(400, "duplicate expiration header");
                    }
                    expiration = Some(match header.value {
                        b"true" => true,
                        b"false" => false,
                        _ => return fail(400, "expiration must be true or false"),
                    });
                }
            }
            let method = request.method.ok_or("missing method")?;
            let target = request.path.ok_or("missing target")?;
            if !target.starts_with('/') || target.contains('#') {
                return fail(400, "absolute request path required");
            }
            if length.is_none()
                && (method == "PUT" || (method == "DELETE" && target == "/v1/endpoint"))
            {
                return fail(411, "Content-Length is required");
            }
            let length = length.unwrap_or(0);
            if length > BODY_LIMIT {
                return fail(413, "request body exceeds 4 MiB");
            }
            let total = header_len.checked_add(length).ok_or("request overflow")?;
            if bytes.len() < total {
                continue;
            }
            if bytes.len() != total {
                return fail(400, "extra bytes after request body");
            }
            let body = bytes.get(header_len..total).ok_or("invalid body bounds")?;
            let body = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(body).map_err(|e| Failure {
                    status: 400,
                    message: format!("invalid JSON: {e}"),
                })?
            };
            if start.elapsed() >= REQUEST_BUDGET {
                return fail(408, "request deadline exceeded");
            }
            return Ok(Request {
                method: method.into(),
                target: target.into(),
                body,
                expiration: expiration.unwrap_or(false),
            });
        }
        if bytes.len() > HEADER_LIMIT {
            return fail(431, "request headers exceed 16 KiB");
        }
    }
}

fn write_response(stream: &mut UnixStream, status: u16, body: Vec<u8>) -> Result<()> {
    let mut response=format!("HTTP/1.1 {status} Agent\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    response.extend_from_slice(&body);
    let start = Instant::now();
    let mut bytes = response.as_slice();
    while !bytes.is_empty() {
        let remaining = REQUEST_BUDGET.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err("response deadline exceeded".into());
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err("response write returned zero".into()),
            Ok(count) => bytes = bytes.get(count..).ok_or("invalid write count")?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && meta.dev() == self.device
            && meta.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn bind(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err("refusing to replace a non-socket API path".into());
            }
            let fd = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                None,
            )?;
            match connect(fd.as_raw_fd(), &UnixAddr::new(path)?) {
                Err(nix::errno::Errno::ECONNREFUSED) => {
                    let current = fs::symlink_metadata(path)?;
                    if current.dev() != meta.dev()
                        || current.ino() != meta.ino()
                        || !current.file_type().is_socket()
                    {
                        return Err("API socket changed during stale check".into());
                    }
                    fs::remove_file(path)?;
                }
                _ => return Err("API socket is live or cannot be proven stale".into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    let meta = fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        device: meta.dev(),
        inode: meta.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
}

fn replay_pending(
    guard: &mut flowsdn_cni::queue::ExclusiveGuard,
    mut delete: impl FnMut(&ReplayRequest) -> Result<()>,
) -> Result<()> {
    for entry in guard.entries()? {
        match &entry.request {
            Ok(request) => delete(request)?,
            Err(error) => eprintln!("discarding malformed deletion entry: {error}"),
        }
        guard.remove(&entry)?;
    }
    Ok(())
}

/// Restore state and replay offline deletions before exposing the local API.
/// The listener is root-only and intentionally supports one bounded request
/// per connection. It does not provide authentication, watches or Kubernetes.
pub fn run(config_path: &Path) -> Result<()> {
    let config = Config::read(config_path)?;
    // The manager's exclusive state lock is acquired before inspecting or
    // removing a stale socket, preventing a second owner of this state tree.
    let manager = Manager::restore_with_pins(
        &config.state,
        &config.object,
        config.ipam()?,
        config.endpoint_id_max,
        config.pin_root.as_deref(),
    )?;
    let mut api = Api {
        config,
        manager,
        leases: BTreeMap::new(),
    };
    // Without endpoint GC, never advertise readiness after skipping a deletion.
    // Preserve failed entries and fail startup so a supervisor can retry safely.
    let mut replay = Queue::open(&api.config.queue)?.lock_exclusive(Duration::from_millis(1500))?;
    replay_pending(&mut replay, |request| {
        match request {
            ReplayRequest::Attachment {
                container_id,
                ifname,
            } => {
                api.manager
                    .delete(&format!("cni-attachment-id:{container_id}:{ifname}"))?;
            }
            ReplayRequest::Container { container_id } => {
                let ids: Vec<_> = api
                    .manager
                    .records()
                    .filter(|record| {
                        record.document.get("dockerID").and_then(Value::as_str)
                            == Some(container_id)
                    })
                    .map(|record| record.attachment.clone())
                    .collect();
                for id in ids {
                    api.manager.delete(&id)?;
                }
            }
        }
        Ok(())
    })?;
    let (listener, _socket) = bind(&api.config.socket)?;
    // Writers that waited for replay recheck a now-listening API under their
    // shared lock, so they cannot enqueue a deletion missed by this replay.
    drop(replay);
    let health = health_api::ModuleHealth::new()?;
    eprintln!("initial endpoint API listening; Kubernetes and policy controllers are not enabled");
    loop {
        api.expire();
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let result = read_request(&mut stream).and_then(|request| {
            match (request.method.as_str(), request.target.as_str()) {
                ("GET" | "POST", "/statedb/query" | "/v1/statedb/query") => {
                    health.query(&request.body).map(|body| (200, body))
                }
                ("GET", "/health/modules" | "/v1/health/modules") => {
                    Ok((200, serde_json::to_vec(&health.modules()?)?))
                }
                _ => api
                    .handle(request)
                    .and_then(|(status, body)| Ok((status, serde_json::to_vec(&body)?))),
            }
        });
        let (status, body) = match result {
            Ok(reply) => reply,
            Err(error) => {
                let status = error
                    .downcast_ref::<Failure>()
                    .map(|e| e.status)
                    .unwrap_or(500);
                (
                    status,
                    serde_json::to_vec(&json!({"code":status,"message":error.to_string()}))?,
                )
            }
        };
        if let Err(error) = write_response(&mut stream, status, body) {
            eprintln!("API response failed: {error}");
        }
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;

// Reject configuration changes between CNI GET config and endpoint PUT before
// consuming the pending lease or publishing endpoint state.
fn check_cni_route_mtu(body: &Value, expected: u32) -> Result<()> {
    let actual = body
        .get("cni-route-mtu")
        .and_then(Value::as_u64)
        .ok_or_else(|| Failure {
            status: 400,
            message: "cni-route-mtu is required".into(),
        })?;
    if actual != u64::from(expected) {
        return fail(
            409,
            "CNI route MTU changed; retry ADD with current configuration",
        );
    }
    Ok(())
}
