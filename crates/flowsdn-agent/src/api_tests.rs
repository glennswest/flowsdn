use super::*;
use flowsdn_cni::delete::DeleteRequest;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "flowsdn-api-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn parse(bytes: &[u8]) -> Result<Request> {
    let (mut client, mut server) = UnixStream::pair()?;
    client.write_all(bytes)?;
    client.shutdown(std::net::Shutdown::Write)?;
    read_request(&mut server)
}
fn status(bytes: &[u8]) -> u16 {
    match parse(bytes) {
        Ok(_) => panic!("request unexpectedly accepted"),
        Err(error) => {
            error
                .downcast_ref::<Failure>()
                .expect("HTTP failure")
                .status
        }
    }
}
#[test]
fn framing_rejects_ambiguous_truncated_and_oversized_requests() {
    assert_eq!(
        status(b"PUT /v1/endpoint/x HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"),
        400
    );
    assert_eq!(
        status(b"PUT /v1/endpoint/x HTTP/1.1\r\nContent-Length: 4\r\n\r\n{}"),
        400
    );
    assert_eq!(
        status(b"PUT /v1/endpoint/x HTTP/1.1\r\nContent-Length: 4194305\r\n\r\n"),
        413
    );
    assert_eq!(status(b"PUT /v1/endpoint/x HTTP/1.1\r\n\r\n"), 411);
    assert_eq!(
        status(b"GET /v1/config HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
        501
    );
    assert_eq!(status(b"GET /v1/config HTTP/1.1\r\n\r\nextra"), 400);
    assert_eq!(status(b"GET /v1/config HTTP/1.0\r\n\r\n"), 505);
    let request = parse(
        b"POST /v1/ipam?owner=a%2Fb HTTP/1.1\r\nExpiration: true\r\nContent-Length: 0\r\n\r\n",
    )
    .expect("valid request");
    assert!(request.expiration);
    assert_eq!(
        query_values("owner=a%2Fb")
            .expect("query")
            .get("owner")
            .map(String::as_str),
        Some("a/b")
    );
    assert!(query_values("owner=a&owner=b").is_err());
    assert!(query_values("owner=%ff").is_err());
}
#[test]
fn stalled_request_has_a_total_deadline() {
    let (_client, mut server) = UnixStream::pair().expect("pair");
    let start = Instant::now();
    let error = read_request(&mut server).err().expect("timeout");
    assert_eq!(
        error
            .downcast_ref::<Failure>()
            .expect("HTTP failure")
            .status,
        408
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}
#[test]
fn socket_binding_preserves_live_and_non_socket_paths_and_recovers_stale_socket() {
    let temp = Temp::new();
    let path = temp.0.join("agent.sock");
    fs::write(&path, b"preserve").expect("file");
    assert!(bind(&path).is_err());
    assert_eq!(fs::read(&path).expect("file"), b"preserve");
    fs::remove_file(&path).expect("remove test file");
    let (listener, guard) = bind(&path).expect("bind");
    assert!(bind(&path).is_err());
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    drop(listener);
    drop(guard);
    let stale = UnixListener::bind(&path).expect("stale bind");
    drop(stale);
    let (listener, guard) = bind(&path).expect("recover stale");
    drop(listener);
    drop(guard);
    assert!(!path.exists());
}
#[test]
fn failed_replay_preserves_durable_entry_for_next_startup() {
    let temp = Temp::new();
    let queue = Queue::open(temp.0.join("queue")).expect("queue");
    {
        let mut shared = queue
            .lock_shared(Duration::from_millis(100))
            .expect("shared");
        shared
            .enqueue(&DeleteRequest {
                container_id: "sandbox".into(),
                ifname: "eth0".into(),
                netns: None,
                delegated_ipam: false,
            })
            .expect("enqueue");
        assert!(queue.lock_exclusive(Duration::from_millis(20)).is_err());
    }
    let mut exclusive = queue
        .lock_exclusive(Duration::from_millis(100))
        .expect("exclusive");
    assert!(replay_pending(&mut exclusive, |_| Err("injected teardown failure".into())).is_err());
    assert_eq!(exclusive.entries().expect("entries").len(), 1);
    let mut called = false;
    replay_pending(&mut exclusive, |request| {assert!(matches!(request,ReplayRequest::Attachment {container_id,ifname} if container_id=="sandbox" && ifname=="eth0"));called=true;Ok(())}).expect("retry");
    assert!(called);
    assert!(exclusive.entries().expect("entries").is_empty());
}
#[test]
fn configuration_excludes_gateways_and_validates_families_and_mtu() {
    let temp = Temp::new();
    let path = temp.0.join("config.json");
    let mut config = json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"bpf-object":"object","ipv4-pool":"198.18.0.0/29","ipv4-gateway":"198.18.0.1","device-mtu":1500,"route-mtu":1450});
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    let mut ipam = Config::read(&path).expect("config").ipam().expect("IPAM");
    assert!(
        ipam.allocate("198.18.0.1".parse().expect("IP"), "pod")
            .is_err()
    );
    *config.get_mut("route-mtu").expect("route MTU") = json!(1600);
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    assert!(Config::read(&path).is_err());
    *config.get_mut("route-mtu").expect("route MTU") = json!(1450);
    *config.get_mut("ipv4-pool").expect("IPv4 pool") = json!("2001:db8::/64");
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    assert!(Config::read(&path).is_err());
}

#[test]
fn endpoint_id_limit_is_bounded_and_cookie_keeps_full_u64_precision() {
    let temp = Temp::new();
    let path = temp.0.join("config.json");
    let mut config = json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"bpf-object":"object","ipv4-pool":"198.18.0.0/29","ipv4-gateway":"198.18.0.1","device-mtu":1500,"route-mtu":1450});
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    assert_eq!(
        Config::read(&path).expect("default config").endpoint_id_max,
        4095
    );
    for (value, valid) in [
        (json!(1), true),
        (json!(65535), true),
        (json!(0), false),
        (json!(65536), false),
        (json!(-1), false),
        (json!(1.5), false),
        (json!("4095"), false),
        (Value::Null, false),
    ] {
        config
            .as_object_mut()
            .expect("config object")
            .insert("endpoint-id-max".into(), value);
        fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
        assert_eq!(Config::read(&path).is_ok(), valid);
    }
    let response = endpoint_response(1, &json!({"NetnsCookie":u64::MAX}), None);
    assert_eq!(
        response
            .pointer("/status/networking/netns-cookie")
            .and_then(Value::as_str),
        Some("18446744073709551615")
    );
}

#[test]
fn stale_cni_route_configuration_is_rejected_before_creation() {
    check_cni_route_mtu(&json!({"cni-route-mtu":1450}), 1450).expect("same configuration");
    for value in [
        json!({}),
        json!({"cni-route-mtu":"1450"}),
        json!({"cni-route-mtu":null}),
    ] {
        let error = check_cni_route_mtu(&value, 1450).expect_err("missing or malformed");
        assert_eq!(error.downcast_ref::<Failure>().expect("HTTP").status, 400);
    }
    let error =
        check_cni_route_mtu(&json!({"cni-route-mtu":1450}), 1400).expect_err("stale config");
    assert_eq!(error.downcast_ref::<Failure>().expect("HTTP").status, 409);
}

#[test]
fn endpoint_inventory_is_sorted_bounded_and_preserves_pod_identifiers() {
    let records = [
        crate::state::Record {
            id: 42,
            attachment: "cni-attachment-id:c:eth0".into(),
            document: json!({"K8sNamespace":"ns","K8sPodName":"pod","K8sUID":"uid","dockerID":"c","IPv4":"10.0.0.2"}),
        },
        crate::state::Record {
            id: 2,
            attachment: "cni-attachment-id:b:eth0".into(),
            document: json!({}),
        },
    ];
    let list = endpoint_list(records.iter(), None).expect("list");
    assert_eq!(list.get(0).and_then(|v| v.get("id")), Some(&json!(2)));
    assert_eq!(
        list.get(1)
            .and_then(|v| v.pointer("/status/external-identifiers/k8s-namespace")),
        Some(&json!("ns"))
    );
    assert_eq!(
        list.get(1)
            .and_then(|v| v.pointer("/status/external-identifiers/k8s-pod-name")),
        Some(&json!("pod"))
    );
    // #328: the Pod and container the endpoint is, and its annotation value.
    let tagged = list.get(1).expect("tagged");
    assert_eq!(
        tagged.pointer("/status/external-identifiers/pod-name"),
        Some(&json!("ns/pod"))
    );
    assert_eq!(
        tagged.pointer("/status/external-identifiers/cni-attachment-id"),
        Some(&json!("c:"))
    );
    assert_eq!(
        tagged.pointer("/status/pod"),
        Some(&json!({"ID":42,"namespace":"ns","pod_name":"pod","pod_uid":"uid","container_id":"c"}))
    );
    assert_eq!(
        tagged.pointer("/status/pod-networks/default/ip_addresses"),
        Some(&json!(["10.0.0.2/32"]))
    );
    assert_eq!(
        tagged.pointer("/status/pod-networks/default/sandbox"),
        Some(&json!("c"))
    );
    assert_eq!(
        read_endpoint(records.iter(), "42").map(|r| r.attachment.as_str()),
        Some("cni-attachment-id:c:eth0")
    );
    assert_eq!(
        read_endpoint(records.iter(), "cni-attachment-id:b:eth0").map(|r| r.id),
        Some(2)
    );
    for invalid in ["0", "65536", "999999999999999999999", "not-found"] {
        assert!(read_endpoint(records.iter(), invalid).is_none());
    }
    assert_eq!(endpoint_list(std::iter::empty(), None).expect("empty"), json!([]));
    let large = crate::state::Record {
        id: 1,
        attachment: "x".into(),
        document: json!({"K8sPodName":"x".repeat(BODY_LIMIT)}),
    };
    let error = endpoint_list(std::iter::once(&large), None).expect_err("bounded response");
    assert_eq!(
        error.downcast_ref::<Failure>().expect("HTTP error").status,
        413
    );
}
#[test]
fn ipam_inventory_counts_are_lossless_decimal_strings_and_disabled_families_absent() {
    let mut v6 = HostScope::new("::".parse().expect("IP"), 0, Default::default()).expect("pool");
    v6.exclude_ip("::1".parse().expect("IP"), "gateway");
    let ipam = Ipam::new(None, Some(v6)).expect("IPAM");
    let response = ipam_summary(&ipam);
    let pools = response
        .get("pools")
        .and_then(Value::as_array)
        .expect("pools");
    assert_eq!(pools.len(), 1);
    let pool = pools.first().expect("IPv6");
    assert_eq!(pool.get("family"), Some(&json!("ipv6")));
    assert_eq!(
        pool.get("capacity"),
        Some(&json!(u128::MAX.saturating_sub(1).to_string()))
    );
    assert_eq!(
        pool.get("available"),
        Some(&json!(u128::MAX.saturating_sub(2).to_string()))
    );
    assert_eq!(pool.get("excluded"), Some(&json!("1")));
    assert_eq!(
        ipam_summary(&Ipam::new(None, None).expect("empty")),
        json!({"pools":[]})
    );
}

/// The `sha256` bpf-objects.lock records for `name` (#245).
fn locked_sha256(name: &str) -> Option<String> {
    let mut current = None;
    for line in include_str!("../../../bpf-objects.lock").lines() {
        if let Some(value) = line.strip_prefix("name = ") {
            current = Some(value.trim_matches('"'));
        } else if let Some(value) = line.strip_prefix("sha256 = ")
            && current == Some(name)
        {
            return Some(value.trim_matches('"').to_owned());
        }
    }
    None
}

#[test]
fn embedded_objects_match_bpf_objects_lock() {
    use sha2::{Digest, Sha256};
    for (name, bytes) in [
        ("local-delivery", EMBEDDED_OBJECT),
        ("socket-lb", include_bytes!("../bpf/socket-lb").as_slice()),
    ] {
        assert_eq!(
            Some(format!("{:x}", Sha256::digest(bytes))),
            locked_sha256(name),
            "crates/flowsdn-agent/bpf/{name} differs from bpf-objects.lock; \
             run tools/bpf-objects-lock.sh write and commit the lock"
        );
    }
}

#[test]
fn egress_mode_and_embedded_object_default() {
    let temp = Temp::new();
    let path = temp.0.join("config.json");
    let mut config = json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"ipv4-pool":"198.18.0.0/29","ipv4-gateway":"198.18.0.1","device-mtu":1500,"route-mtu":1450});
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    let read = Config::read(&path).expect("config without bpf-object");
    assert!(
        read.object.is_none(),
        "absent bpf-object selects the embedded object"
    );
    assert_eq!(read.egress, Egress::Fib);
    for (value, expected) in [
        (json!("fib"), Some(Egress::Fib)),
        (json!("stack"), Some(Egress::Stack)),
        (json!("tunnel"), None),
        (json!(1), None),
    ] {
        config
            .as_object_mut()
            .expect("config object")
            .insert("egress".into(), value);
        fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
        assert_eq!(Config::read(&path).ok().map(|c| c.egress), expected);
    }
    // The embedded object is an ELF built for BPF (EM_BPF = 247).
    assert_eq!(EMBEDDED_OBJECT.get(..4), Some(&b"\x7fELF"[..]));
    assert_eq!(EMBEDDED_OBJECT.get(18..20), Some(&247u16.to_le_bytes()[..]));
}

#[test]
fn auto_pools_need_kubernetes_and_resolve_from_the_node() {
    let temp = Temp::new();
    let path = temp.0.join("config.json");
    let mut config = json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"ipv4-pool":"auto","device-mtu":1500,"route-mtu":1450});
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    assert!(Config::read(&path).is_err(), "auto without kubernetes");
    config
        .as_object_mut()
        .expect("config object")
        .insert("kubernetes".into(), json!({"node-name":"pvetest1"}));
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    let mut read = Config::read(&path).expect("auto pool");
    assert!(read.auto4 && !read.auto6 && read.v4.is_none());
    let settings = read.kubernetes.clone().expect("settings");
    assert_eq!(settings.node_name, "pvetest1");
    assert!(settings.auto_direct_node_routes && !settings.skip_unreachable);
    read.resolve_auto(Some(("10.172.0.0".parse().expect("IP"), 16)), None)
        .expect("resolve");
    assert_eq!(read.gateway4, Some("10.172.0.1".parse().expect("IP")));
    let mut ipam = read.ipam().expect("IPAM");
    assert!(
        ipam.allocate("10.172.0.1".parse().expect("IP"), "pod")
            .is_err()
    );
    assert_eq!(
        read.addressing().pointer("/ipv4/alloc-range"),
        Some(&json!("10.172.0.0/16"))
    );
    // An explicit gateway contradicts an auto pool; a bad kubernetes section fails.
    for (key, value) in [
        ("ipv4-gateway", json!("10.172.0.1")),
        ("kubernetes", json!({"node-name":"a/b"})),
        (
            "kubernetes",
            json!({"node-name":"n","auto-direct-node-routes":"yes"}),
        ),
        ("kubernetes", json!("n")),
    ] {
        let mut bad = config.clone();
        bad.as_object_mut()
            .expect("config object")
            .insert(key.into(), value);
        fs::write(&path, serde_json::to_vec(&bad).expect("JSON")).expect("config");
        assert!(Config::read(&path).is_err(), "{key}");
    }
    #[cfg(not(feature = "kubernetes"))]
    {
        fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
        let mut read = Config::read(&path).expect("auto pool");
        assert!(connect_kubernetes(&mut read).is_err());
    }
}

#[test]
fn http_listen_is_loopback_only() {
    let temp = Temp::new();
    let path = temp.0.join("config.json");
    let mut config = json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"ipv4-pool":"198.18.0.0/29","ipv4-gateway":"198.18.0.1","device-mtu":1500,"route-mtu":1450});
    fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
    assert_eq!(Config::read(&path).expect("config").http, None);
    for (value, valid) in [
        ("127.0.0.1:9878", true),
        ("[::1]:9878", true),
        ("0.0.0.0:9878", false),
        ("192.168.8.1:9878", false),
        ("127.0.0.1:0", false),
        ("127.0.0.1", false),
        ("localhost:9878", false),
    ] {
        config
            .as_object_mut()
            .expect("object")
            .insert("http-listen".into(), json!(value));
        fs::write(&path, serde_json::to_vec(&config).expect("JSON")).expect("config");
        assert_eq!(Config::read(&path).is_ok(), valid, "{value}");
    }
}

#[test]
fn read_only_listener_serves_reads_and_the_statedb_query_only() {
    for (method, target) in [
        ("GET", "/v1/endpoint"),
        ("GET", "/v1/endpoint/42"),
        ("GET", "/v1/ipam"),
        ("GET", "/v1/config"),
        ("GET", "/v1/health/modules"),
        ("POST", "/v1/statedb/query"),
        ("POST", "/statedb/query?x=1"),
    ] {
        assert!(read_only(method, target), "{method} {target}");
    }
    for (method, target) in [
        ("POST", "/v1/ipam?owner=x"),
        ("PUT", "/v1/endpoint/x"),
        ("DELETE", "/v1/endpoint"),
        ("DELETE", "/v1/ipam/10.0.0.2"),
        ("PATCH", "/v1/config"),
    ] {
        assert!(!read_only(method, target), "{method} {target}");
    }
}

#[test]
fn requests_are_read_and_answered_over_loopback_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream
            .write_all(b"GET /v1/ipam HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).expect("read");
        reply
    });
    let (mut server, _) = listener.accept().expect("accept");
    let request = read_request(&mut server).expect("request");
    assert_eq!(
        (request.method.as_str(), request.target.as_str()),
        ("GET", "/v1/ipam")
    );
    write_response(&mut server, 200, b"{}".to_vec()).expect("response");
    drop(server);
    let reply = client.join().expect("client");
    assert!(reply.starts_with("HTTP/1.1 200 "), "{reply}");
    assert!(reply.ends_with("\r\n\r\n{}"), "{reply}");
}

#[test]
fn documented_routes_are_the_served_routes() {
    let doc = include_str!("../../../docs/agent-api.md");
    let table = doc
        .split("## Supported methods")
        .nth(1)
        .expect("Supported methods section");
    let documented: Vec<&str> = table
        .lines()
        .skip_while(|line| !line.starts_with("|---"))
        .skip(1)
        .take_while(|line| line.starts_with('|'))
        .filter_map(|line| line.split('|').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(
        documented,
        ROUTES.to_vec(),
        "docs/agent-api.md and api::ROUTES differ"
    );
}
