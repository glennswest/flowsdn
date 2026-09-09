//! Initial primary veth CNI adapter. Unsupported modes fail before allocation.
use crate::{*, delete::{DeleteAttempt, DeleteBackend, DeleteRequest}, queue::{Queue, SharedGuard}};
use flowsdn_api_client::{Client, Method, Response};
use flowsdn_connector::{Connector, in_namespace};
use sha2::{Digest, Sha256};
use std::{fs::File, path::{Path, PathBuf}, time::{Duration, Instant}};

fn error(e: impl std::fmt::Display) -> CniError { CniError::internal(e.to_string()) }
fn system<T>(result: flowsdn_connector::Result<T>) -> Result<T> { result.map_err(error) }
fn response(response: std::result::Result<Response, flowsdn_api_client::Error>) -> Result<Value> {
    let response = response.map_err(error)?;
    if !(200..300).contains(&response.status) {
        return Err(error(format!("agent HTTP {}: {}", response.status, String::from_utf8_lossy(&response.body))));
    }
    Ok(response.json.unwrap_or(Value::Null))
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str { value.get(key).and_then(Value::as_str).unwrap_or("") }
fn mac(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 6 { return Err(error("expected Ethernet MAC")); }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}
fn mac_bytes(value: &str) -> Result<[u8; 6]> {
    let bytes: Vec<u8> = value.split(':').map(|v| u8::from_str_radix(v, 16).map_err(error)).collect::<Result<_>>()?;
    bytes.try_into().map_err(|_| error("invalid Ethernet MAC"))
}
fn connect(path: &Path) -> Result<(Client, Value)> {
    let start = Instant::now();
    let budget = Duration::from_secs(30);
    loop {
        let remaining = budget.saturating_sub(start.elapsed());
        if remaining.is_zero() { return Err(error("Is the agent running? connection budget expired")); }
        let client = Client::new(path, remaining.min(Duration::from_secs(5)));
        if let Ok(config) = response(client.config()) { return Ok((Client::new(path, Duration::from_secs(30)), config)); }
        std::thread::sleep(budget.saturating_sub(start.elapsed()).min(Duration::from_millis(500)));
    }
}

struct Platform {
    client: Client,
    namespace: File,
    config: Value,
    device_mtu: u32,
    route_mtu: u32,
    cookie: u64,
}
impl AddBackend for Platform {
    fn allocate(&mut self, request: &AddRequest) -> Result<Vec<Lease>> {
        let value = response(self.client.allocate(&request.owner(), "", "", true))?;
        let mut leases = Vec::new();
        let outcome = (|| {
            for family in ["ipv6", "ipv4"] {
                let raw = text(&value["address"], family);
                if raw.is_empty() { continue; }
                let address = raw.split('/').next().unwrap_or(raw).parse::<IpAddr>().map_err(error)?;
                // Register a releasable address before validating its gateway.
                leases.push(Lease { address, gateway: address,
                    pool: text(&value["address"], &format!("{family}-pool-name")).into(),
                    expiration_uuid: text(&value["address"], &format!("{family}-expiration-uuid")).into() });
            }
            for lease in &mut leases {
                let family = if lease.address.is_ipv4() { "ipv4" } else { "ipv6" };
                if value["host-addressing"][family]["enabled"] != true { return Err(error("allocated address family is disabled")); }
                lease.gateway = text(&value["host-addressing"][family], "ip").parse().map_err(error)?;
                if lease.expiration_uuid.is_empty() { lease.expiration_uuid = text(&value[family], "expiration-uuid").into(); }
            }
            if leases.is_empty() { return Err(error("invalid IPAM response, missing addressing")); }
            Ok(())
        })();
        if let Err(primary) = outcome {
            for lease in leases.iter().rev() { let _ = self.release(lease); }
            return Err(primary);
        }
        Ok(leases)
    }
    fn create_link(&mut self, request: &AddRequest) -> Result<Link> {
        let digest = format!("{:x}", Sha256::digest(format!("{}:{}", request.container_id, request.ifname).as_bytes()));
        let host = format!("lxc{}", digest.get(..12).expect("SHA256 hex"));
        let peer = format!("tmp{}", digest.get(..5).expect("SHA256 hex"));
        let connector = system(Connector::open())?;
        let host_link = system(connector.create_veth(&host, &peer, self.device_mtu))?;
        let outcome = (|| {
            let peer_link = system(connector.require_link(&peer))?;
            let host_mac = mac(&host_link.mac)?;
            let peer_mac = mac(&peer_link.mac)?;
            system(connector.configure(host_link.index, &host, mac_bytes(&host_mac)?, self.device_mtu))?;
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{host}/rp_filter"), "0\n").map_err(error)?;
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
            Ok(Link { host_name: host.clone(), host_index: host_link.index, host_mac, peer_mac })
        })();
        if outcome.is_err() { let _ = connector.delete(&host); }
        outcome
    }
    fn configure(&mut self, request: &AddRequest, link: &Link, leases: &[Lease]) -> Result<()> {
        let namespace = self.namespace.try_clone().map_err(error)?;
        let name = request.ifname.clone();
        let leases = leases.to_vec();
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
                connector.add_route(link.index, if lease.address.is_ipv4() { "0.0.0.0" } else { "::" }.parse()?, 0, Some(lease.gateway), Some(mtu))?;
                connector.neighbour(link.index, lease.gateway, host_mac)?;
            }
            flowsdn_connector::namespace_cookie()
        }))?;
        Ok(())
    }
    fn create_endpoint(&mut self, request: &AddRequest, link: &Link, leases: &[Lease]) -> Result<Endpoint> {
        let mut addressing = serde_json::Map::new();
        for lease in leases {
            let family = if lease.address.is_ipv4() { "ipv4" } else { "ipv6" };
            addressing.insert(family.into(), json!(lease.address.to_string()));
            addressing.insert(format!("{family}-pool-name"), json!(lease.pool));
            addressing.insert(format!("{family}-expiration-uuid"), json!(lease.expiration_uuid));
        }
        let basename = Path::new(&request.netns).file_name().and_then(|v| v.to_str()).ok_or_else(|| error("invalid namespace path"))?;
        let body = json!({"container-id":request.container_id,"container-interface-name":request.ifname,
            "container-netns-path":format!("/var/run/cilium/netns/{basename}"),
            "interface-name":link.host_name,"interface-index":link.host_index,"mac":link.peer_mac,"host-mac":link.host_mac,
            "k8s-pod-name":request.pod_name,"k8s-namespace":request.pod_namespace,"k8s-uid":request.pod_uid,
            "state":"waiting-for-identity","labels":[],"addressing":addressing,"datapath-configuration":{},"properties":{},
            "netns-cookie":self.cookie.to_string(),"sync-build-endpoint":true});
        let endpoint = response(self.client.put_endpoint_unbounded_response(&request.attachment_id(), &body))?;
        let mac = text(&endpoint["status"]["networking"], "mac");
        Ok(Endpoint { mac_override: if mac.is_empty() { None } else { Some(mac.into()) } })
    }
    fn finalize(&mut self, request: &AddRequest, link: &mut Link, endpoint: &Endpoint) -> Result<()> {
        let namespace = self.namespace.try_clone().map_err(error)?;
        let name = request.ifname.clone();
        let new_mac = endpoint.mac_override.as_ref().map(|v| mac_bytes(v)).transpose()?;
        let mtu = self.device_mtu;
        let cubic = self.config["enable-bbr-host-namespace-only"] == true;
        system(in_namespace(namespace, move || {
            if let Some(mac) = new_mac {
                let connector = Connector::open()?;
                connector.configure(connector.require_link(&name)?.index, &name, mac, mtu)?;
            }
            if cubic { std::fs::write("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")?; }
            Ok(())
        }))?;
        if let Some(mac) = &endpoint.mac_override { link.peer_mac = mac.clone(); }
        Ok(())
    }
    fn delete_endpoint(&mut self, request: &AddRequest) -> Result<()> { response(self.client.delete_endpoint(&request.attachment_id())).map(|_| ()) }
    fn delete_link(&mut self, link: &Link) -> Result<()> { system(Connector::open().and_then(|c| c.delete(&link.host_name))) }
    fn release(&mut self, lease: &Lease) -> Result<()> { response(self.client.release(lease.address, &lease.pool)).map(|_| ()) }
}

struct Deleter { client: Client, queue: PathBuf, namespace: Option<File> }
impl DeleteBackend for Deleter {
    type QueueGuard = SharedGuard;
    fn try_delete(&mut self, request: &DeleteRequest) -> DeleteAttempt {
        let result = if request.ifname.is_empty() { self.client.delete_container(&request.container_id) }
            else { self.client.delete_endpoint(&format!("cni-attachment-id:{}:{}", request.container_id, request.ifname)) };
        match result {
            Ok(reply) if reply.status == 503 => DeleteAttempt::Unavailable,
            Ok(reply) if (200..300).contains(&reply.status) && reply.status != 206 => DeleteAttempt::Complete,
            Ok(reply) => DeleteAttempt::AgentWarning(error(format!("agent deletion HTTP {}", reply.status))),
            Err(error) if error.is_transport() => DeleteAttempt::Unavailable,
            Err(err) => DeleteAttempt::AgentWarning(error(err)),
        }
    }
    fn lock_queue(&mut self) -> Result<SharedGuard> { Queue::open(&self.queue)?.lock_shared(Duration::from_millis(1500)) }
    fn delegated_delete(&mut self, _: &DeleteRequest) -> Result<()> { Err(error("delegated IPAM is not implemented")) }
    fn enter_namespace(&mut self, path: Option<&str>) -> Result<bool> {
        let Some(path) = path.filter(|p| !p.is_empty()) else { return Ok(false); };
        match File::open(path) {
            Ok(file) => { self.namespace = Some(file); Ok(true) }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(error(e)),
        }
    }
    fn delete_interface(&mut self, ifname: &str) -> Result<()> {
        let namespace = self.namespace.take().ok_or_else(|| error("namespace not open"))?;
        let name = ifname.to_owned();
        system(in_namespace(namespace, move || Connector::open()?.delete(&name)))
    }
}

pub fn run(command: &str, input: &[u8], env: &BTreeMap<String, String>) -> Result<Option<Value>> {
    if command == "VERSION" { return Ok(Some(json!({"cniVersion":"1.1.0","supportedVersions":["1.0.0","1.1.0"]}))); }
    let conf: Value = serde_json::from_slice(input).map_err(error)?;
    if !matches!(text(&conf, "cniVersion"), "1.0.0" | "1.1.0") { return Err(CniError { code:1,message:"unsupported CNI version".into(),details:String::new() }); }
    if !text(&conf, "chaining-mode").is_empty() || !text(&conf["ipam"], "type").is_empty() {
        return Err(error("chaining and delegated IPAM are not implemented"));
    }
    let socket = PathBuf::from(env.get("CILIUM_SOCK").map(String::as_str).unwrap_or("/var/run/cilium/cilium.sock"));
    match command {
        "ADD" => {
            let request = AddRequest::parse(input, env)?;
            let (client, conf) = connect(&socket)?;
            let config = conf["status"].clone();
            if text(&config, "datapath-mode") != "veth" || !matches!(text(&config, "ipam-mode"), "kubernetes" | "cluster-pool") {
                return Err(error("initial CNI requires veth and host-scope IPAM"));
            }
            let mtu = |key| config[key].as_u64().and_then(|v| u32::try_from(v).ok()).filter(|v| *v >= 1280).ok_or_else(|| error(format!("invalid {key}")));
            let mut platform = Platform { client, namespace: File::open(&request.netns).map_err(error)?, device_mtu:mtu("device-mtu")?,route_mtu:mtu("route-mtu")?, config,cookie:0 };
            let namespace = platform.namespace.try_clone().map_err(error)?;
            let name = request.ifname.clone();
            system(in_namespace(namespace, move || Connector::open()?.delete(&name)))?;
            match add(&request, platform.route_mtu, &mut platform) {
                Ok(value) => Ok(Some(value)),
                Err(failure) => { for e in failure.rollback_errors { eprintln!("CNI rollback: {e}"); } Err(failure.primary) }
            }
        }
        "DEL" => {
            let request = DeleteRequest { container_id: env.get("CNI_CONTAINERID").cloned().unwrap_or_default(),
                ifname:env.get("CNI_IFNAME").cloned().unwrap_or_default(),netns:env.get("CNI_NETNS").cloned(),delegated_ipam:false };
            let queue = env.get("FLOWSDN_DELETE_QUEUE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/var/run/cilium/deleteQueue"));
            let mut backend = Deleter { client: Client::new(socket, Duration::from_millis(1500)), queue, namespace:None };
            let outcome = delete::delete(&request, &mut backend)?;
            for warning in outcome.warnings { eprintln!("CNI deletion: {warning}"); }
            Ok(None)
        }
        "STATUS" => {
            let (client, _) = connect(&socket).map_err(|mut e| { e.code = 50; e })?;
            response(client.request(Method::Get, "/v1/healthz", None)).map_err(|mut e| { e.code = 50; e })?;
            Ok(None)
        }
        "CHECK" => {
            let request = AddRequest::parse(input, env).or_else(|_| {
                // CHECK carries prevResult; primary ADD deliberately rejects it.
                let mut primary = conf.clone();
                primary.as_object_mut().ok_or_else(|| error("invalid configuration"))?.remove("prevResult");
                AddRequest::parse(&serde_json::to_vec(&primary).map_err(error)?, env)
            })?;
            let (client, _) = connect(&socket).map_err(|mut e| { e.code = 11; e })?;
            let health = response(client.endpoint_health(&request.attachment_id())).map_err(|mut e| { e.code = 100; e })?;
            if health["overall-health"] == "failure" { return Err(CniError {code:101,message:"container is unhealthy in agent".into(),details:String::new()}); }
            let interfaces = conf["prevResult"]["interfaces"].as_array().ok_or_else(|| error("CHECK requires previous interfaces"))?;
            let selected: Vec<_> = interfaces.iter().enumerate().filter_map(|(i, value)|
                (text(value,"name") == request.ifname && !text(value,"sandbox").is_empty()).then_some(i)).collect();
            if selected.is_empty() { return Err(error("previous result has no sandbox interface")); }
            let mut expected = Vec::new();
            for ip in conf["prevResult"]["ips"].as_array().ok_or_else(|| error("CHECK requires previous addresses"))? {
                if ip["interface"].as_u64().and_then(|v| usize::try_from(v).ok()).is_some_and(|i| selected.contains(&i)) {
                    let raw = text(ip, "address");
                    expected.push(raw.split('/').next().unwrap_or(raw).parse::<IpAddr>().map_err(error)?);
                }
            }
            let namespace = File::open(&request.netns).map_err(error)?;
            let name = request.ifname;
            system(in_namespace(namespace, move || {
                let connector = Connector::open()?;
                let addresses = connector.addresses(connector.require_link(&name)?.index)?;
                for ip in expected {
                    if !addresses.contains(&ip) { return Err(format!("expected ip {ip} on interface {name}").into()); }
                }
                Ok(())
            }))?;
            Ok(None)
        }
        "GC" => Err(CniError { code:1,message:"plugin version does not allow GC".into(),details:String::new() }),
        _ => Err(error(format!("CNI command {command} is not implemented"))),
    }
}
