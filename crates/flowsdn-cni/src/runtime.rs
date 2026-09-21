//! Initial primary veth CNI adapter. Unsupported modes fail before allocation.
use crate::{
    delete::{DeleteAttempt, DeleteBackend, DeleteRequest},
    queue::{Queue, SharedGuard},
    *,
};
use flowsdn_api_client::{Client, Method, Response};
use flowsdn_connector::{Connector, in_namespace};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn error(e: impl std::fmt::Display) -> CniError {
    CniError::internal(e.to_string())
}
fn system<T>(result: flowsdn_connector::Result<T>) -> Result<T> {
    result.map_err(error)
}
fn response(response: std::result::Result<Response, flowsdn_api_client::Error>) -> Result<Value> {
    let response = response.map_err(error)?;
    if !(200..300).contains(&response.status) {
        return Err(error(format!(
            "agent HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )));
    }
    Ok(response.json.unwrap_or(Value::Null))
}
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn mac(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 6 {
        return Err(error("expected Ethernet MAC"));
    }
    Ok(bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}
fn mac_bytes(value: &str) -> Result<[u8; 6]> {
    let bytes: Vec<u8> = value
        .split(':')
        .map(|v| u8::from_str_radix(v, 16).map_err(error))
        .collect::<Result<_>>()?;
    bytes.try_into().map_err(|_| error("invalid Ethernet MAC"))
}
fn connect(path: &Path) -> Result<(Client, Value)> {
    let start = Instant::now();
    let budget = Duration::from_secs(30);
    loop {
        let remaining = budget.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(error("Is the agent running? connection budget expired"));
        }
        let client = Client::new(path, remaining.min(Duration::from_secs(5)));
        if let Ok(config) = response(client.config()) {
            return Ok((Client::new(path, Duration::from_secs(30)), config));
        }
        std::thread::sleep(
            budget
                .saturating_sub(start.elapsed())
                .min(Duration::from_millis(500)),
        );
    }
}

struct Platform {
    client: Client,
    namespace: File,
    config: Value,
    device_mtu: u32,
    route_mtu: u32,
    cookie: u64,
    endpoint_may_exist: bool,
    gateways: Vec<IpAddr>,
}
/// Only a confirmed 404 permits a new allocation. All malformed, forbidden or
/// unavailable lookups fail closed before touching either sandbox or IPAM.
fn existing_endpoint(client: &Client, request: &AddRequest) -> Result<Option<Value>> {
    let reply = client
        .get_endpoint(&request.attachment_id())
        .map_err(error)?;
    match reply.status {
        404 => Ok(None),
        200 => reply
            .json
            .filter(Value::is_object)
            .map(Some)
            .ok_or_else(|| error("endpoint lookup returned invalid JSON object")),
        _ => Err(error(format!(
            "endpoint lookup returned HTTP {}",
            reply.status
        ))),
    }
}

struct ExistingAttachment {
    cookie: u64,
    route_mtu: u32,
    link: Link,
    leases: Vec<Lease>,
}
impl ExistingAttachment {
    fn parse(request: &AddRequest, endpoint: &Value) -> Result<Self> {
        let status = field(endpoint, "status");
        if text(status, "state") != "ready" {
            return Err(error("existing endpoint is not ready"));
        }
        let network = field(status, "networking");
        if text(network, "container-interface-name") != request.ifname {
            return Err(error("existing endpoint has a different sandbox interface"));
        }
        let cookie = text(network, "netns-cookie")
            .parse::<u64>()
            .map_err(error)?;
        if cookie == 0 {
            return Err(error("existing endpoint has no usable namespace cookie"));
        }
        let index = field(network, "interface-index")
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v != 0)
            .ok_or_else(|| error("existing endpoint has no host interface index"))?;
        let link = Link {
            host_name: text(network, "interface-name").into(),
            host_index: index,
            host_mac: text(network, "host-mac").into(),
            peer_mac: text(network, "mac").into(),
        };
        mac_bytes(&link.host_mac)?;
        mac_bytes(&link.peer_mac)?;
        let rows = field(network, "addressing")
            .as_array()
            .filter(|rows| rows.len() == 1)
            .ok_or_else(|| error("existing endpoint has invalid addressing"))?;
        let address = rows
            .first()
            .ok_or_else(|| error("existing endpoint has no addressing"))?;
        let route_mtu = field(network, "route-mtu")
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v >= 1280)
            .ok_or_else(|| error("existing endpoint has no creation-time route MTU"))?;
        let mut leases = Vec::new();
        for family in ["ipv6", "ipv4"] {
            let raw = text(address, family);
            if raw.is_empty() {
                continue;
            }
            let ip: IpAddr = raw.parse().map_err(error)?;
            let host = field(field(network, "host-addressing"), family);
            if ip.is_ipv6() != (family == "ipv6") || field(host, "enabled") != &Value::Bool(true) {
                return Err(error(
                    "existing endpoint has disabled or invalid address family",
                ));
            }
            let gateway: IpAddr = text(host, "ip").parse().map_err(error)?;
            if gateway.is_ipv6() != ip.is_ipv6() {
                return Err(error("existing endpoint gateway has wrong family"));
            }
            leases.push(Lease {
                address: ip,
                gateway,
                pool: text(address, &format!("{family}-pool-name")).into(),
                expiration_uuid: String::new(),
            });
        }
        if leases.is_empty() {
            return Err(error("existing endpoint has no addresses"));
        }
        Ok(Self {
            cookie,
            route_mtu,
            link,
            leases,
        })
    }
    fn result(&self, request: &AddRequest) -> Value {
        result(request, &self.link, &self.leases, self.route_mtu)
    }
    fn validate_sandbox(&self, cookie: u64, peer_mac: &[u8], addresses: &[IpAddr]) -> Result<()> {
        if cookie == 0 || cookie != self.cookie {
            return Err(error("attachment belongs to a different sandbox namespace"));
        }
        if peer_mac != mac_bytes(&self.link.peer_mac)? {
            return Err(error("existing endpoint sandbox MAC does not match"));
        }
        if self
            .leases
            .iter()
            .any(|lease| !addresses.contains(&lease.address))
        {
            return Err(error("existing endpoint sandbox address does not match"));
        }
        Ok(())
    }
}
impl Platform {
    fn reuse_endpoint(&self, request: &AddRequest, endpoint: &Value) -> Result<Value> {
        let existing = ExistingAttachment::parse(request, endpoint)?;
        let health = response(self.client.endpoint_health(&request.attachment_id()))?;
        if text(&health, "overallHealth") != "OK" {
            return Err(error("existing endpoint is not healthy"));
        }
        let host =
            system(Connector::open().and_then(|c| c.require_link(&existing.link.host_name)))?;
        if host.index != existing.link.host_index || host.mac != mac_bytes(&existing.link.host_mac)?
        {
            return Err(error("existing endpoint host interface does not match"));
        }
        let namespace = self.namespace.try_clone().map_err(error)?;
        let name = request.ifname.clone();
        let (cookie, peer, addresses) = system(in_namespace(namespace, move || {
            let connector = Connector::open()?;
            let peer = connector.require_link(&name)?;
            let addresses = connector.addresses(peer.index)?;
            Ok((flowsdn_connector::namespace_cookie()?, peer, addresses))
        }))?;
        existing.validate_sandbox(cookie, &peer.mac, &addresses)?;
        Ok(existing.result(request))
    }
}

impl AddBackend for Platform {
    fn allocate(&mut self, request: &AddRequest) -> Result<Vec<Lease>> {
        let value = response(self.client.allocate(&request.owner(), "", "", true))?;
        let mut leases = Vec::new();
        let outcome = (|| {
            let mut first_error = None;
            for family in ["ipv6", "ipv4"] {
                let raw = text(field(&value, "address"), family);
                if raw.is_empty() {
                    continue;
                }
                let address = match raw.split('/').next().unwrap_or(raw).parse::<IpAddr>() {
                    Ok(address) => address,
                    Err(cause) => {
                        first_error.get_or_insert_with(|| error(cause));
                        continue;
                    }
                };
                if address.is_ipv6() != (family == "ipv6") {
                    first_error.get_or_insert_with(|| {
                        error("IPAM address family does not match its field")
                    });
                }
                // Register a releasable address before validating its gateway.
                leases.push(Lease {
                    address,
                    gateway: address,
                    pool: text(field(&value, "address"), &format!("{family}-pool-name")).into(),
                    expiration_uuid: text(
                        field(&value, "address"),
                        &format!("{family}-expiration-uuid"),
                    )
                    .into(),
                });
            }
            // A malformed first family must not hide a releasable allocation
            // in the second family of the same successful IPAM response.
            if let Some(error) = first_error {
                return Err(error);
            }
            for lease in &mut leases {
                let family = if lease.address.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                };
                if field(field(field(&value, "host-addressing"), family), "enabled")
                    != &Value::Bool(true)
                {
                    return Err(error("allocated address family is disabled"));
                }
                lease.gateway = text(field(field(&value, "host-addressing"), family), "ip")
                    .parse()
                    .map_err(error)?;
                if lease.expiration_uuid.is_empty() {
                    lease.expiration_uuid = text(field(&value, family), "expiration-uuid").into();
                }
            }
            if leases.is_empty() {
                return Err(error("invalid IPAM response, missing addressing"));
            }
            Ok(())
        })();
        if let Err(primary) = outcome {
            for lease in leases.iter().rev() {
                let _ = self.release(lease);
            }
            return Err(primary);
        }
        Ok(leases)
    }
    fn create_link(&mut self, request: &AddRequest) -> Result<Link> {
        let digest = format!(
            "{:x}",
            Sha256::digest(format!("{}:{}", request.container_id, request.ifname).as_bytes())
        );
        let host = format!("lxc{}", digest.get(..12).expect("SHA256 hex"));
        let peer = format!("tmp{}", digest.get(..5).expect("SHA256 hex"));
        let connector = system(Connector::open())?;
        let host_link = system(connector.create_veth(&host, &peer, self.device_mtu))?;
        let outcome = (|| {
            let peer_link = system(connector.require_link(&peer))?;
            let host_mac = mac(&host_link.mac)?;
            let peer_mac = mac(&peer_link.mac)?;
            system(connector.configure(
                host_link.index,
                &host,
                mac_bytes(&host_mac)?,
                self.device_mtu,
            ))?;
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{host}/rp_filter"), "0\n")
                .map_err(error)?;
            system(connector.move_to_namespace(peer_link.index, &self.namespace))?;
            let namespace = self.namespace.try_clone().map_err(error)?;
            let name = request.ifname.clone();
            let mtu = self.device_mtu;
            let peer_mac_bytes = mac_bytes(&peer_mac)?;
            system(in_namespace(namespace, move || {
                let connector = Connector::open()?;
                let link = connector.require_link(&peer)?;
                connector.configure(link.index, &name, peer_mac_bytes, mtu)
            }))?;
            Ok(Link {
                host_name: host.clone(),
                host_index: host_link.index,
                host_mac,
                peer_mac,
            })
        })();
        if outcome.is_err() {
            let _ = connector.delete(&host);
        }
        outcome
    }
    fn configure(&mut self, request: &AddRequest, link: &Link, leases: &[Lease]) -> Result<()> {
        let namespace = self.namespace.try_clone().map_err(error)?;
        let name = request.ifname.clone();
        let leases = leases.to_vec();
        self.gateways = leases.iter().map(|lease| lease.gateway).collect();
        let mtu = self.route_mtu;
        let host_mac = mac_bytes(&link.host_mac)?;
        self.cookie = system(in_namespace(namespace, move || {
            let connector = Connector::open()?;
            let link = connector.require_link(&name)?;
            if leases.iter().any(|l| l.address.is_ipv6()) {
                let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n");
            }
            for lease in leases {
                let prefix = if lease.address.is_ipv4() { 32 } else { 128 };
                connector.add_address(link.index, lease.address, prefix)?;
                connector.add_route(link.index, lease.gateway, prefix, None, None)?;
                connector.add_route(
                    link.index,
                    if lease.address.is_ipv4() {
                        "0.0.0.0"
                    } else {
                        "::"
                    }
                    .parse()?,
                    0,
                    Some(lease.gateway),
                    Some(mtu),
                )?;
                connector.neighbour(link.index, lease.gateway, host_mac)?;
            }
            flowsdn_connector::namespace_cookie()
        }))?;
        Ok(())
    }
    fn create_endpoint(
        &mut self,
        request: &AddRequest,
        link: &Link,
        leases: &[Lease],
    ) -> Result<Endpoint> {
        let mut addressing = serde_json::Map::new();
        for lease in leases {
            let family = if lease.address.is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            };
            addressing.insert(family.into(), json!(lease.address.to_string()));
            addressing.insert(format!("{family}-pool-name"), json!(lease.pool));
            addressing.insert(
                format!("{family}-expiration-uuid"),
                json!(lease.expiration_uuid),
            );
        }
        let body = json!({"container-id":request.container_id,"container-interface-name":request.ifname,
            "interface-name":link.host_name,"interface-index":link.host_index,"mac":link.peer_mac,"host-mac":link.host_mac,
            "k8s-pod-name":request.pod_name,"k8s-namespace":request.pod_namespace,"k8s-uid":request.pod_uid,
            "state":"waiting-for-identity","labels":[],"addressing":addressing,"datapath-configuration":{},"properties":{},
            "netns-cookie":self.cookie.to_string(),"cni-route-mtu":self.route_mtu,"sync-build-endpoint":true});
        // A transport error can occur after the server committed. Do not free
        // backing resources until deletion is confirmed; a duplicate ADD can
        // reconcile a complete committed attachment, otherwise DEL can recover.
        self.endpoint_may_exist = true;
        let reply = self
            .client
            .put_endpoint_unbounded_response(&request.attachment_id(), &body)
            .map_err(error)?;
        if !(200..300).contains(&reply.status) {
            // Client errors mean this request was rejected before publication.
            // Server failures are ambiguous and preserve ownership for recovery.
            if (400..500).contains(&reply.status) {
                self.endpoint_may_exist = false;
            }
            return response(Ok(reply)).map(|_| Endpoint { mac_override: None });
        }
        let endpoint = match endpoint_response(reply) {
            Ok(endpoint) => endpoint,
            Err(primary) => {
                // The server reported creation success, so an invalid response
                // does not imply no endpoint exists. Clean it before the ADD
                // coordinator releases this attachment's link and allocations.
                if let Err(cleanup) = self.delete_endpoint(request) {
                    eprintln!("CNI rollback: {cleanup}");
                }
                return Err(primary);
            }
        };
        let mac = text(field(field(&endpoint, "status"), "networking"), "mac");
        Ok(Endpoint {
            mac_override: if mac.is_empty() {
                None
            } else {
                Some(mac.into())
            },
        })
    }
    fn finalize(
        &mut self,
        request: &AddRequest,
        link: &mut Link,
        endpoint: &Endpoint,
    ) -> Result<()> {
        let namespace = self.namespace.try_clone().map_err(error)?;
        let name = request.ifname.clone();
        let new_mac = endpoint
            .mac_override
            .as_ref()
            .map(|v| mac_bytes(v))
            .transpose()?;
        let current_mac = mac_bytes(&link.peer_mac)?;
        let new_mac = new_mac.filter(|mac| *mac != current_mac);
        let gateways = self.gateways.clone();
        let host_mac = mac_bytes(&link.host_mac)?;
        let mtu = self.device_mtu;
        let cubic = field(&self.config, "enable-bbr-host-namespace-only") == &Value::Bool(true);
        system(in_namespace(namespace, move || {
            if let Some(mac) = new_mac {
                let connector = Connector::open()?;
                let index = connector.require_link(&name)?.index;
                connector.configure(index, &name, mac, mtu)?;
                // Changing the L2 address flushes neighbour state. Restore
                // the gateways established before the endpoint was created.
                for gateway in gateways {
                    connector.neighbour(index, gateway, host_mac)?;
                }
            }
            if cubic {
                std::fs::write("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")?;
            }
            Ok(())
        }))?;
        if let Some(mac) = &endpoint.mac_override {
            link.peer_mac = mac.clone();
        }
        Ok(())
    }
    fn may_release_resources(&self) -> bool {
        !self.endpoint_may_exist
    }
    fn delete_endpoint(&mut self, request: &AddRequest) -> Result<()> {
        let reply = self
            .client
            .delete_endpoint(&request.attachment_id())
            .map_err(error)?;
        if !matches!(reply.status, 200 | 404) {
            return Err(error(format!(
                "endpoint deletion not confirmed: HTTP {}",
                reply.status
            )));
        }
        self.endpoint_may_exist = false;
        Ok(())
    }
    fn delete_link(&mut self, link: &Link) -> Result<()> {
        system(Connector::open().and_then(|c| c.delete(&link.host_name)))
    }
    fn release(&mut self, lease: &Lease) -> Result<()> {
        response(self.client.release(lease.address, &lease.pool)).map(|_| ())
    }
}

struct Deleter {
    client: Client,
    queue: PathBuf,
    namespace: Option<File>,
}
impl DeleteBackend for Deleter {
    type QueueGuard = SharedGuard;
    fn try_delete(&mut self, request: &DeleteRequest) -> DeleteAttempt {
        let result = if request.ifname.is_empty() {
            self.client.delete_container(&request.container_id)
        } else {
            self.client.delete_endpoint(&format!(
                "cni-attachment-id:{}:{}",
                request.container_id, request.ifname
            ))
        };
        match result {
            Ok(reply) if reply.status == 503 => DeleteAttempt::Unavailable,
            Ok(reply) if (200..300).contains(&reply.status) && reply.status != 206 => {
                DeleteAttempt::Complete
            }
            Ok(reply) => {
                DeleteAttempt::AgentWarning(error(format!("agent deletion HTTP {}", reply.status)))
            }
            Err(error) if error.is_transport() => DeleteAttempt::Unavailable,
            Err(err) => DeleteAttempt::AgentWarning(error(err)),
        }
    }
    fn lock_queue(&mut self) -> Result<SharedGuard> {
        Queue::open(&self.queue)?.lock_shared(Duration::from_millis(1500))
    }
    fn delegated_delete(&mut self, _: &DeleteRequest) -> Result<()> {
        Err(error("delegated IPAM is not implemented"))
    }
    fn enter_namespace(&mut self, path: Option<&str>) -> Result<bool> {
        let Some(path) = path.filter(|p| !p.is_empty()) else {
            return Ok(false);
        };
        match File::open(path) {
            Ok(file) => {
                system(in_namespace(file.try_clone().map_err(error)?, || Ok(())))?;
                self.namespace = Some(file);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(error(e)),
        }
    }
    fn delete_interface(&mut self, ifname: &str) -> Result<()> {
        let namespace = self
            .namespace
            .take()
            .ok_or_else(|| error("namespace not open"))?;
        let name = ifname.to_owned();
        system(in_namespace(namespace, move || {
            Connector::open()?.delete(&name)
        }))
    }
}

pub fn run(command: &str, input: &[u8], env: &BTreeMap<String, String>) -> Result<Option<Value>> {
    if command == "VERSION" {
        return Ok(Some(
            json!({"cniVersion":"1.1.0","supportedVersions":["1.0.0","1.1.0"]}),
        ));
    }
    let conf: Value = serde_json::from_slice(input).map_err(error)?;
    if !matches!(text(&conf, "cniVersion"), "1.0.0" | "1.1.0") {
        return Err(CniError {
            code: 1,
            message: "unsupported CNI version".into(),
            details: String::new(),
        });
    }
    if !text(&conf, "chaining-mode").is_empty() || !text(field(&conf, "ipam"), "type").is_empty() {
        return Err(error("chaining and delegated IPAM are not implemented"));
    }
    let socket = PathBuf::from(
        env.get("CILIUM_SOCK")
            .map(String::as_str)
            .unwrap_or("/var/run/cilium/cilium.sock"),
    );
    match command {
        "ADD" => {
            let request = AddRequest::parse(input, env)?;
            let (client, conf) = connect(&socket)?;
            let config = field(&conf, "status").clone();
            if text(&config, "datapath-mode") != "veth"
                || !matches!(text(&config, "ipam-mode"), "kubernetes" | "cluster-pool")
            {
                return Err(error("initial CNI requires veth and host-scope IPAM"));
            }
            let mtu = |key| {
                field(&config, key)
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v >= 1280)
                    .ok_or_else(|| error(format!("invalid {key}")))
            };
            let mut platform = Platform {
                client,
                namespace: File::open(&request.netns).map_err(error)?,
                device_mtu: mtu("device-mtu")?,
                route_mtu: mtu("route-mtu")?,
                config,
                cookie: 0,
                endpoint_may_exist: false,
                gateways: Vec::new(),
            };
            if let Some(existing) = existing_endpoint(&platform.client, &request)? {
                return platform.reuse_endpoint(&request, &existing).map(Some);
            }
            // No successful lookup means no ownership of a pre-existing link.
            // Refuse it rather than deleting a different attachment's device.
            let namespace = platform.namespace.try_clone().map_err(error)?;
            let name = request.ifname.clone();
            system(in_namespace(namespace, move || {
                if Connector::open()?.link(&name)?.is_some() {
                    return Err("sandbox interface exists without a matching endpoint".into());
                }
                Ok(())
            }))?;
            match add(&request, platform.route_mtu, &mut platform) {
                Ok(value) => Ok(Some(value)),
                Err(failure) => {
                    for e in failure.rollback_errors {
                        eprintln!("CNI rollback: {e}");
                    }
                    Err(failure.primary)
                }
            }
        }
        "DEL" => {
            let request = DeleteRequest {
                container_id: env.get("CNI_CONTAINERID").cloned().unwrap_or_default(),
                ifname: env.get("CNI_IFNAME").cloned().unwrap_or_default(),
                netns: env.get("CNI_NETNS").cloned(),
                delegated_ipam: false,
            };
            let queue = env
                .get("FLOWSDN_DELETE_QUEUE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/run/cilium/deleteQueue"));
            let mut backend = Deleter {
                client: Client::new(socket, Duration::from_millis(1500)),
                queue,
                namespace: None,
            };
            let outcome = delete::delete(&request, &mut backend)?;
            for warning in outcome.warnings {
                eprintln!("CNI deletion: {warning}");
            }
            Ok(None)
        }
        "STATUS" => {
            let (client, _) = connect(&socket).map_err(|mut e| {
                e.code = 50;
                e
            })?;
            response(client.request(Method::Get, "/v1/healthz", None)).map_err(|mut e| {
                e.code = 50;
                e
            })?;
            Ok(None)
        }
        "CHECK" => {
            let request = AddRequest::parse(input, env).or_else(|_| {
                // CHECK carries prevResult; primary ADD deliberately rejects it.
                let mut primary = conf.clone();
                primary
                    .as_object_mut()
                    .ok_or_else(|| error("invalid configuration"))?
                    .remove("prevResult");
                AddRequest::parse(&serde_json::to_vec(&primary).map_err(error)?, env)
            })?;
            let (client, configuration) = connect(&socket).map_err(|mut e| {
                e.code = 11;
                e
            })?;
            let health =
                response(client.endpoint_health(&request.attachment_id())).map_err(|mut e| {
                    e.code = 100;
                    e
                })?;
            validate_health(&health)?;
            let interfaces = field(field(&conf, "prevResult"), "interfaces")
                .as_array()
                .ok_or_else(|| error("CHECK requires previous interfaces"))?;
            let selected: Vec<_> = interfaces
                .iter()
                .enumerate()
                .filter_map(|(i, value)| {
                    (text(value, "name") == request.ifname && !text(value, "sandbox").is_empty())
                        .then_some(i)
                })
                .collect();
            if selected.is_empty() {
                return Err(error("previous result has no sandbox interface"));
            }
            let mut expected = Vec::new();
            for ip in field(field(&conf, "prevResult"), "ips")
                .as_array()
                .ok_or_else(|| error("CHECK requires previous addresses"))?
            {
                if field(ip, "interface")
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .is_some_and(|i| selected.contains(&i))
                {
                    let raw = text(ip, "address");
                    expected.push(
                        raw.split('/')
                            .next()
                            .unwrap_or(raw)
                            .parse::<IpAddr>()
                            .map_err(error)?,
                    );
                }
            }
            let expected_mtu = field(field(&configuration, "status"), "device-mtu").as_u64();
            let previous_routes = field(field(&conf, "prevResult"), "routes").clone();
            let namespace = File::open(&request.netns).map_err(error)?;
            let name = request.ifname;
            system(in_namespace(namespace, move || {
                let connector = Connector::open()?;
                let link = connector.require_link(&name)?;
                let addresses = connector.addresses(link.index)?;
                for ip in expected {
                    if !addresses.contains(&ip) {
                        return Err(format!("expected ip {ip} on interface {name}").into());
                    }
                }
                if expected_mtu.is_some_and(|expected| expected != u64::from(link.mtu)) {
                    eprintln!(
                        "CNI CHECK diagnostic: interface MTU differs from current agent configuration"
                    );
                }
                match connector.routes(link.index) {
                    Ok(routes) => {
                        for warning in route_diagnostics(&previous_routes, &routes) {
                            eprintln!("CNI CHECK diagnostic: {warning}");
                        }
                    }
                    Err(error) => {
                        eprintln!("CNI CHECK diagnostic: route inspection failed: {error}")
                    }
                }
                Ok(())
            }))?;
            Ok(None)
        }
        "GC" => Err(CniError {
            code: 1,
            message: "plugin version does not allow GC".into(),
            details: String::new(),
        }),
        _ => Err(error(format!("CNI command {command} is not implemented"))),
    }
}

fn endpoint_response(reply: Response) -> Result<Value> {
    if reply.status != 201 {
        return Err(error("endpoint creation did not return HTTP 201"));
    }
    let endpoint = reply
        .json
        .filter(Value::is_object)
        .ok_or_else(|| error("endpoint creation returned invalid JSON object"))?;
    if let Some(status) = endpoint.get("status") {
        if !status.is_object() {
            return Err(error("invalid endpoint status"));
        }
        if let Some(networking) = status.get("networking")
            && (!networking.is_object()
                || networking.get("mac").is_some_and(|mac| !mac.is_string()))
        {
            return Err(error("invalid endpoint networking"));
        }
    }
    Ok(endpoint)
}

fn validate_health(health: &Value) -> Result<()> {
    match health.get("overallHealth").and_then(Value::as_str) {
        Some("OK" | "Bootstrap" | "Pending" | "Warning" | "Disabled") => Ok(()),
        Some("Failure") => Err(CniError {
            code: 101,
            message: "container is unhealthy in agent".into(),
            details: String::new(),
        }),
        _ => Err(CniError {
            code: 100,
            message: "failed to retrieve container health: invalid overallHealth".into(),
            details: String::new(),
        }),
    }
}

// Supplemental CHECK diagnostics never change the historical success verdict.
fn route_diagnostics(previous: &Value, actual: &[flowsdn_connector::Route]) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(routes) = previous.as_array() else {
        return vec!["previous routes unavailable".into()];
    };
    for expected in routes {
        let raw = text(expected, "dst");
        let Some((address, prefix)) = raw.split_once('/') else {
            warnings.push("previous route destination is invalid".into());
            continue;
        };
        let (Ok(destination), Ok(prefix)) = (address.parse::<IpAddr>(), prefix.parse::<u8>())
        else {
            warnings.push("previous route destination is invalid".into());
            continue;
        };
        let gateway = match expected.get("gw") {
            None => None,
            Some(value) => match value.as_str().and_then(|v| v.parse::<IpAddr>().ok()) {
                Some(ip) => Some(ip),
                None => {
                    warnings.push("previous route gateway is invalid".into());
                    continue;
                }
            },
        };
        let mtu = expected.get("mtu").and_then(Value::as_u64);
        if !actual.iter().any(|route| {
            route.destination == destination
                && route.prefix == prefix
                && route.gateway == gateway
                && mtu.is_none_or(|n| route.mtu.map(u64::from) == Some(n))
        }) {
            warnings.push(format!(
                "route {raw} gateway or MTU differs from previous result"
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
        thread::{self, JoinHandle},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Agent {
        path: PathBuf,
        thread: Option<JoinHandle<Vec<String>>>,
    }
    impl Agent {
        fn new(replies: Vec<(u16, Value)>) -> Self {
            let path = std::env::temp_dir().join(format!(
                "flowsdn-rollback-{}-{}.sock",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let listener = UnixListener::bind(&path).expect("fake agent");
            listener.set_nonblocking(true).expect("nonblocking");
            let thread = thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, body) in replies {
                    let start = Instant::now();
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    && start.elapsed() < Duration::from_secs(2) =>
                            {
                                thread::sleep(Duration::from_millis(2))
                            }
                            Err(e) => panic!("expected rollback request: {e}"),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .expect("read timeout");
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).expect("header");
                        bytes.extend_from_slice(&byte);
                        assert!(bytes.len() < 16_384);
                    }
                    let header = std::str::from_utf8(&bytes).expect("header text");
                    let request_line = header
                        .split("\r\n")
                        .next()
                        .expect("request line")
                        .to_owned();
                    let length: usize = header
                        .split("\r\n")
                        .find_map(|h| h.strip_prefix("Content-Length: "))
                        .expect("length")
                        .parse()
                        .expect("number");
                    assert!(length < 65_536);
                    let mut request_body = vec![0; length];
                    stream.read_exact(&mut request_body).expect("body");
                    requests.push(if request_body.is_empty() {
                        request_line
                    } else {
                        format!(
                            "{request_line}\n{}",
                            String::from_utf8(request_body).expect("JSON body")
                        )
                    });
                    // Zero simulates a server that consumed PUT then disconnected.
                    if status == 0 {
                        continue;
                    }
                    let body = body.to_string();
                    write!(
                        stream,
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .expect("response");
                }
                requests
            });
            Self {
                path,
                thread: Some(thread),
            }
        }
        fn platform(&self) -> Platform {
            Platform {
                client: Client::new(&self.path, Duration::from_secs(1)),
                namespace: File::open("/dev/null").expect("unused namespace fd"),
                config: json!({}),
                device_mtu: 1500,
                route_mtu: 1450,
                cookie: 0,
                endpoint_may_exist: false,
                gateways: Vec::new(),
            }
        }
        fn requests(&mut self) -> Vec<String> {
            self.thread
                .take()
                .expect("thread")
                .join()
                .expect("fake agent requests")
        }
    }
    impl Drop for Agent {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }
    fn request() -> AddRequest {
        AddRequest {
            version: "1.1.0".into(),
            container_id: "cid".into(),
            ifname: "eth0".into(),
            netns: "/fixture/netns".into(),
            cni_path: "/fixture".into(),
            pod_name: "pod".into(),
            pod_namespace: "ns".into(),
            pod_uid: "uid".into(),
        }
    }
    fn allocation(v6: &str, v4: &str, gateway6: &str) -> Value {
        json!({"address":{"ipv6":v6,"ipv4":v4,"ipv6-pool-name":"default","ipv4-pool-name":"default"},
            "host-addressing":{"ipv6":{"enabled":true,"ip":gateway6},"ipv4":{"enabled":true,"ip":"198.18.0.254"}}})
    }
    fn check_releases(response: Value, addresses: &[&str]) {
        let mut replies = vec![(201, response)];
        replies.extend(addresses.iter().map(|_| (200, json!({}))));
        let mut agent = Agent::new(replies);
        assert!(agent.platform().allocate(&request()).is_err());
        let requests = agent.requests();
        assert!(
            requests
                .first()
                .is_some_and(|r| r.starts_with("POST /v1/ipam?owner=ns%2Fpod"))
        );
        let mut actual: Vec<_> = requests.into_iter().skip(1).collect();
        actual.sort();
        let mut expected: Vec<_> = addresses
            .iter()
            .map(|ip| {
                format!(
                    "DELETE /v1/ipam/{}?pool=default HTTP/1.1",
                    flowsdn_api_client::encode_component(ip)
                )
            })
            .collect();
        expected.sort();
        assert_eq!(actual, expected);
    }

    fn existing_fixture() -> Value {
        json!({"status":{"state":"ready","networking":{
            "netns-cookie":"9007199254740993","container-interface-name":"eth0",
            "interface-name":"lxcfixture","interface-index":7,
            "mac":"02:00:00:00:00:02","host-mac":"02:00:00:00:00:01",
            "addressing":[{"ipv4":"198.18.0.1","ipv6":"2001:db8::1"}],
            "route-mtu":1450,
            "host-addressing":{
                "ipv4":{"enabled":true,"ip":"198.18.0.254"},
                "ipv6":{"enabled":true,"ip":"2001:db8::ffff"}}
        }}})
    }
    #[test]
    fn ambiguous_put_and_failed_cleanup_preserve_backing_ownership() {
        let link = Link {
            host_name: "lxcfixture".into(),
            host_index: 7,
            host_mac: "02:00:00:00:00:01".into(),
            peer_mac: "02:00:00:00:00:02".into(),
        };
        for (replies, releasable) in [
            (vec![(0, json!({}))], false),
            (vec![(503, json!({}))], false),
            (vec![(400, json!({}))], true),
            (vec![(201, json!({"status":null})), (503, json!({}))], false),
            (vec![(201, json!({"status":null})), (206, json!({}))], false),
            (vec![(201, json!({"status":null})), (200, json!({}))], true),
            (vec![(201, json!({"status":null})), (404, json!({}))], true),
        ] {
            let expected = replies.len();
            let mut agent = Agent::new(replies);
            let mut platform = agent.platform();
            assert!(platform.create_endpoint(&request(), &link, &[]).is_err());
            assert_eq!(platform.may_release_resources(), releasable);
            assert_eq!(agent.requests().len(), expected);
        }
    }
    #[test]
    fn route_check_reports_drift_without_changing_the_check_verdict() {
        let previous =
            json!([{"dst":"198.18.0.254/32"},{"dst":"0.0.0.0/0","gw":"198.18.0.254","mtu":1450}]);
        let mut routes = vec![
            flowsdn_connector::Route {
                destination: "198.18.0.254".parse().expect("IP"),
                prefix: 32,
                gateway: None,
                mtu: None,
            },
            flowsdn_connector::Route {
                destination: "0.0.0.0".parse().expect("IP"),
                prefix: 0,
                gateway: Some("198.18.0.254".parse().expect("IP")),
                mtu: Some(1450),
            },
        ];
        assert!(route_diagnostics(&previous, &routes).is_empty());
        routes.last_mut().expect("default").mtu = Some(1400);
        assert_eq!(route_diagnostics(&previous, &routes).len(), 1);
        routes.clear();
        assert_eq!(route_diagnostics(&previous, &routes).len(), 2);
        assert_eq!(route_diagnostics(&json!([{"dst":"bad"}]), &routes).len(), 1);
    }
    #[test]
    fn gc_is_explicitly_incompatible_without_mutation() {
        let input = br#"{"cniVersion":"1.1.0","name":"test","type":"flowsdn-cni"}"#;
        let error = run("GC", input, &BTreeMap::new()).expect_err("unsupported GC");
        assert_eq!(error.code, 1);
        assert!(error.message.contains("GC"));
    }
    #[test]
    fn attachment_lookup_only_treats_404_as_absent() {
        for (status, body, absent) in [
            (404, json!({}), true),
            (503, json!({}), false),
            (403, json!({}), false),
            (201, json!({}), false),
            (200, Value::Null, false),
        ] {
            let mut agent = Agent::new(vec![(status, body)]);
            let outcome = existing_endpoint(&agent.platform().client, &request());
            if absent {
                assert!(outcome.expect("404 absent").is_none());
            } else {
                assert!(outcome.is_err());
            }
            assert_eq!(
                agent.requests(),
                ["GET /v1/endpoint/cni-attachment-id%3Acid%3Aeth0 HTTP/1.1"]
            );
        }
        let endpoint = existing_fixture();
        let mut agent = Agent::new(vec![(200, endpoint.clone())]);
        assert_eq!(
            existing_endpoint(&agent.platform().client, &request()).expect("found"),
            Some(endpoint)
        );
        assert_eq!(agent.requests().len(), 1);
    }
    #[test]
    fn duplicate_attachment_requires_cookie_mac_and_each_address() {
        let endpoint = existing_fixture();
        let attachment = ExistingAttachment::parse(&request(), &endpoint).expect("parse");
        let cookie = 9_007_199_254_740_993;
        let peer = [2, 0, 0, 0, 0, 2];
        let ips = [
            "198.18.0.1".parse().expect("v4"),
            "2001:db8::1".parse().expect("v6"),
        ];
        attachment
            .validate_sandbox(cookie, &peer, &ips)
            .expect("same live sandbox");
        for wrong in [0, cookie - 1, cookie + 1] {
            assert!(attachment.validate_sandbox(wrong, &peer, &ips).is_err());
        }
        assert!(
            attachment
                .validate_sandbox(cookie, &[2, 0, 0, 0, 0, 3], &ips)
                .is_err()
        );
        assert!(
            attachment
                .validate_sandbox(cookie, &peer, ips.get(..1).expect("first address"))
                .is_err()
        );
        let result = attachment.result(&request());
        assert_eq!(
            result.pointer("/ips/0/address").expect("fixture field"),
            "2001:db8::1/128"
        );
        assert_eq!(
            result.pointer("/ips/1/address").expect("fixture field"),
            "198.18.0.1/32"
        );
        assert_eq!(
            result
                .pointer("/interfaces/1/sandbox")
                .expect("fixture field"),
            "/fixture/netns"
        );
        assert_eq!(
            result.pointer("/routes/1/mtu").expect("fixture field"),
            1450
        );
    }
    #[test]
    fn incomplete_or_unready_attachment_is_not_reused() {
        let endpoint = existing_fixture();
        for (pointer, invalid) in [
            ("/status/state", json!("waiting-for-identity")),
            ("/status/networking/netns-cookie", json!("0")),
            (
                "/status/networking/netns-cookie",
                json!(9007199254740993u64),
            ),
            ("/status/networking/container-interface-name", json!("eth1")),
            ("/status/networking/interface-index", json!(0)),
            ("/status/networking/route-mtu", Value::Null),
            ("/status/networking/route-mtu", json!(1279)),
            ("/status/networking/host-addressing", Value::Null),
            ("/status/networking/addressing", json!([])),
            ("/status/networking/addressing", json!([{}])),
            ("/status/networking/addressing/0/ipv4", json!("2001:db8::2")),
        ] {
            let mut invalid_endpoint = endpoint.clone();
            *invalid_endpoint.pointer_mut(pointer).expect("field") = invalid;
            assert!(
                ExistingAttachment::parse(&request(), &invalid_endpoint).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn duplicate_result_uses_creation_time_routes_after_config_change() {
        let endpoint = existing_fixture();
        let expected = ExistingAttachment::parse(&request(), &endpoint)
            .expect("original")
            .result(&request());
        let changed_config = json!({"route-mtu":1350,"host-addressing":{
            "ipv4":{"enabled":true,"ip":"198.18.0.253"},
            "ipv6":{"enabled":true,"ip":"2001:db8::fffe"}}});
        // Current configuration is deliberately not an input to parsing or
        // rendering an existing attachment: it describes a future ADD.
        let restored = ExistingAttachment::parse(&request(), &endpoint)
            .expect("restored")
            .result(&request());
        assert_eq!(restored, expected);
        assert_eq!(
            restored.pointer("/routes/1/mtu").expect("fixture field"),
            1450
        );
        assert_eq!(
            restored.pointer("/ips/0/gateway").expect("fixture field"),
            "2001:db8::ffff"
        );
        assert_eq!(
            restored.pointer("/ips/1/gateway").expect("fixture field"),
            "198.18.0.254"
        );
        assert_ne!(
            restored.pointer("/routes/1/mtu").expect("fixture field"),
            changed_config.pointer("/route-mtu").expect("fixture field")
        );
        assert_ne!(
            restored.pointer("/ips/1/gateway").expect("fixture field"),
            changed_config
                .pointer("/host-addressing/ipv4/ip")
                .expect("fixture field")
        );
        for field in ["route-mtu", "host-addressing"] {
            let mut older = endpoint.clone();
            older
                .pointer_mut("/status/networking")
                .expect("fixture field")
                .as_object_mut()
                .expect("networking")
                .remove(field);
            assert!(ExistingAttachment::parse(&request(), &older).is_err());
        }
    }
    #[test]
    fn endpoint_put_omits_uncreated_namespace_mount() {
        let mut agent = Agent::new(vec![(201, json!({}))]);
        let link = Link {
            host_name: "lxcfixture".into(),
            host_index: 7,
            host_mac: "02:00:00:00:00:01".into(),
            peer_mac: "02:00:00:00:00:02".into(),
        };
        let mut platform = agent.platform();
        platform.cookie = 9_007_199_254_740_993;
        platform
            .create_endpoint(&request(), &link, &[])
            .expect("created");
        let requests = agent.requests();
        let (_, body) = requests
            .first()
            .expect("request")
            .split_once('\n')
            .expect("body");
        let body: Value = serde_json::from_str(body).expect("JSON");
        assert!(body.get("container-netns-path").is_none());
        assert_eq!(
            body.pointer("/netns-cookie").expect("fixture field"),
            "9007199254740993"
        );
        assert_eq!(body.pointer("/cni-route-mtu").expect("fixture field"), 1450);
    }

    #[test]
    fn malformed_ipv6_does_not_hide_releasable_ipv4() {
        check_releases(
            allocation("bad", "198.18.0.1", "2001:db8::ffff"),
            &["198.18.0.1"],
        );
    }
    #[test]
    fn malformed_ipv4_releases_previously_parsed_ipv6() {
        check_releases(
            allocation("2001:db8::1", "bad", "2001:db8::ffff"),
            &["2001:db8::1"],
        );
    }
    #[test]
    fn incorrect_family_label_releases_every_parseable_address() {
        check_releases(
            allocation("198.18.0.2", "198.18.0.1", "2001:db8::ffff"),
            &["198.18.0.1", "198.18.0.2"],
        );
    }
    #[test]
    fn invalid_gateway_releases_both_families() {
        check_releases(
            allocation("2001:db8::1", "198.18.0.1", "bad"),
            &["198.18.0.1", "2001:db8::1"],
        );
    }
    #[test]
    fn malformed_successful_endpoint_response_deletes_created_endpoint() {
        let mut agent = Agent::new(vec![(201, Value::Null), (200, json!({}))]);
        let link = Link {
            host_name: "lxcfixture".into(),
            host_index: 1,
            host_mac: "02:00:00:00:00:01".into(),
            peer_mac: "02:00:00:00:00:02".into(),
        };
        assert!(
            agent
                .platform()
                .create_endpoint(&request(), &link, &[])
                .is_err()
        );
        let requests = agent.requests();
        assert!(
            requests
                .first()
                .is_some_and(|r| r.starts_with("PUT /v1/endpoint/"))
        );
        assert_eq!(
            requests.last().map(String::as_str),
            Some("DELETE /v1/endpoint/cni-attachment-id%3Acid%3Aeth0 HTTP/1.1")
        );
    }
    #[test]
    fn check_validates_real_health_wire_enum_and_rejects_missing_health() {
        for status in ["OK", "Bootstrap", "Pending", "Warning", "Disabled"] {
            assert!(validate_health(&json!({"overallHealth":status})).is_ok());
        }
        assert_eq!(
            validate_health(&json!({"overallHealth":"Failure"}))
                .expect_err("unhealthy")
                .code,
            101
        );
        for invalid in [
            Value::Null,
            json!({}),
            json!({"overall-health":"ok"}),
            json!({"overallHealth":"unknown"}),
        ] {
            assert_eq!(
                validate_health(&invalid).expect_err("invalid health").code,
                100
            );
        }
    }
    #[test]
    fn del_namespace_entry_failure_is_retryable() {
        let mut backend = Deleter {
            client: Client::new("/unused", Duration::from_secs(1)),
            queue: PathBuf::from("/unused"),
            namespace: None,
        };
        assert!(backend.enter_namespace(Some("/dev/null")).is_err());
        assert!(backend.namespace.is_none());
        assert!(!backend.enter_namespace(None).expect("missing namespace"));
    }
}
