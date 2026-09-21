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
