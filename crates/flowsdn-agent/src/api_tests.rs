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
    let response = endpoint_response(1, &json!({"NetnsCookie":u64::MAX}));
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
    let list = endpoint_list(records.iter()).expect("list");
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
    assert_eq!(endpoint_list(std::iter::empty()).expect("empty"), json!([]));
    let large = crate::state::Record {
        id: 1,
        attachment: "x".into(),
        document: json!({"K8sPodName":"x".repeat(BODY_LIMIT)}),
    };
    let error = endpoint_list(std::iter::once(&large)).expect_err("bounded response");
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
