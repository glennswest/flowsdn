use flowsdn_agent::probe;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct SocketPath(PathBuf);
impl SocketPath {
    fn new() -> Self {
        let root = std::env::var_os("TMPDIR").map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp"));
        fs::create_dir_all(&root).expect("scratch root");
        Self(root.join(format!("probe-{}-{}.sock", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for SocketPath {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}
struct Server { path: SocketPath, task: Option<JoinHandle<()>> }
impl Server {
    fn run(send: impl FnOnce(&mut UnixStream) + Send + 'static) -> Self {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).expect("listen");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let task = thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && start.elapsed() < Duration::from_secs(5) => thread::sleep(Duration::from_millis(1)),
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
            stream.set_write_timeout(Some(Duration::from_secs(3))).expect("timeout");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).expect("request");
                request.extend_from_slice(&byte);
                assert!(request.len() < 4096);
            }
            assert!(request.starts_with(b"GET /v1/healthz HTTP/1.1\r\n"));
            send(&mut stream);
        });
        Self { path, task: Some(task) }
    }
    fn response(response: Vec<u8>) -> Self {
        Self::run(move |stream| { let _ = stream.write_all(&response); })
    }
}
impl Drop for Server {
    fn drop(&mut self) { self.task.take().expect("task").join().expect("server"); }
}
fn response(status: u16, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} Response\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}
#[test]
fn health_cli_succeeds_without_daemon_initialization() {
    let server = Server::response(response(200, r#"{"cilium":{"state":"Ok","msg":"initial endpoint API ready"}}"#));
    let output = Command::new(env!("CARGO_BIN_EXE_flowsdn-agent"))
        .args(["health", "--socket"]).arg(&server.path.0).output().expect("health CLI");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
#[test]
fn degraded_state_http_failure_and_invalid_json_fail() {
    for (status, body) in [(503, r#"{"cilium":{"state":"Ok"}}"#), (200, r#"{"cilium":{"state":"Warning"}}"#), (200, "{}"), (200, "{")] {
        let server = Server::response(response(status, body));
        assert!(probe::health(&server.path.0).is_err());
    }
}
#[test]
fn malformed_truncated_and_oversize_responses_fail() {
    for bytes in [
        b"not HTTP\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n".to_vec(),
        format!("HTTP/1.1 200 OK\r\nX-Padding: {}\r\n\r\n", "a".repeat(4096)).into_bytes(),
    ] {
        let server = Server::response(bytes);
        assert!(probe::health(&server.path.0).is_err());
    }
}
#[test]
fn stalled_response_obeys_total_deadline() {
    let server = Server::run(|stream| {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
        thread::sleep(Duration::from_millis(2200));
    });
    let start = Instant::now();
    let error = probe::health(&server.path.0).expect_err("timeout");
    assert!(error.to_string().contains("deadline"));
    assert!(start.elapsed() < Duration::from_secs(3), "deadline plus scheduler tolerance");
}
#[test]
fn saturated_backlog_obeys_connect_deadline() {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket, listen, Backlog};
    use std::os::fd::AsRawFd;
    let path = SocketPath::new();
    let listener = UnixListener::bind(&path.0).expect("listen");
    listen(&listener, Backlog::new(1).expect("backlog")).expect("small backlog");
    let address = UnixAddr::new(&path.0).expect("address");
    let mut connections = Vec::new();
    let mut saturated = false;
    for _ in 0..16 {
        let fd = socket(AddressFamily::Unix, SockType::Stream, SockFlag::SOCK_NONBLOCK, None).expect("socket");
        match connect(fd.as_raw_fd(), &address) {
            Ok(()) => connections.push(fd),
            Err(nix::errno::Errno::EAGAIN) => { saturated = true; break; }
            Err(error) => panic!("saturate: {error}"),
        }
    }
    assert!(saturated);
    let start = Instant::now();
    let error = probe::health(&path.0).expect_err("connect timeout");
    assert!(error.to_string().contains("deadline"));
    assert!(start.elapsed() < Duration::from_secs(3), "connect deadline plus scheduler tolerance");
}
#[test]
fn health_cli_missing_socket_exits_unsuccessfully() {
    let path = SocketPath::new();
    let output = Command::new(env!("CARGO_BIN_EXE_flowsdn-agent"))
        .args(["health", "--socket"]).arg(&path.0).output().expect("health CLI");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
