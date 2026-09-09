use flowsdn_api_client::{
    Client, Error, Limits, Method, Response, encode_component, endpoint_path,
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Server {
    path: PathBuf,
    thread: Option<JoinHandle<Vec<u8>>>,
}
impl Server {
    fn new(response: Vec<u8>) -> Self {
        Self::run(move |stream| {
            let _ = stream.write_all(&response);
        })
    }
    fn run(send: impl FnOnce(&mut UnixStream) + Send + 'static) -> Self {
        let path = std::env::temp_dir().join(format!(
            "flowsdn-api-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).expect("bind fake agent");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let thread = thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && start.elapsed() < Duration::from_secs(3) =>
                    {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("fake agent accept: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("read timeout");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).expect("request header");
                request.extend_from_slice(&byte);
                assert!(request.len() < 32_768);
            }
            let head = std::str::from_utf8(&request).expect("HTTP header");
            let length: usize = head
                .split("\r\n")
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .expect("content length")
                .parse()
                .expect("length");
            let mut body = vec![0; length];
            stream.read_exact(&mut body).expect("request body");
            request.extend_from_slice(&body);
            send(&mut stream);
            request
        });
        Self {
            path,
            thread: Some(thread),
        }
    }
    fn client(&self) -> Client {
        Client::new(&self.path, Duration::from_secs(2))
    }
    fn request(&mut self) -> Vec<u8> {
        self.thread
            .take()
            .expect("server thread")
            .join()
            .expect("server success")
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn capture(call: impl FnOnce(&Client) -> flowsdn_api_client::Result<Response>) -> String {
    let mut server = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec());
    call(&server.client()).expect("API call");
    String::from_utf8(server.request()).expect("UTF8 request")
}

#[test]
fn helpers_emit_exact_paths_headers_and_bodies() {
    assert_eq!(
        capture(Client::config),
        "GET /v1/config HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let request = capture(|client| client.allocate("ns/pod +", "ipv6", "blue&green", true));
    assert!(request.starts_with(
        "POST /v1/ipam?owner=ns%2Fpod%20%2B&family=ipv6&pool=blue%26green HTTP/1.1\r\n"
    ));
    assert!(request.contains("\r\nexpiration: true\r\n"));
    assert!(!request.contains("expiration=true"));
    let request = capture(|client| client.allocate("ns/pod", "", "", true));
    assert_eq!(
        request,
        "POST /v1/ipam?owner=ns%2Fpod HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: 0\r\nexpiration: true\r\n\r\n"
    );
    let request = capture(|client| client.release("2001:db8::1".parse().expect("IP"), "pool/a"));
    assert!(request.starts_with("DELETE /v1/ipam/2001%3Adb8%3A%3A1?pool=pool%2Fa HTTP/1.1\r\n"));
    let body = json!({"state":"ready"});
    let request = capture(|client| client.put_endpoint("cni-attachment-id:cid:eth0", &body));
    assert!(request.starts_with("PUT /v1/endpoint/cni-attachment-id%3Acid%3Aeth0 HTTP/1.1\r\n"));
    assert!(request.contains("Content-Type: application/json\r\n"));
    assert!(request.ends_with("\r\n\r\n{\"state\":\"ready\"}"));
    assert!(
        capture(|client| client.delete_endpoint("id/a"))
            .starts_with("DELETE /v1/endpoint/id%2Fa HTTP/1.1\r\n")
    );
    let request = capture(|client| client.delete_container("cid"));
    assert!(request.starts_with("DELETE /v1/endpoint HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\n{\"container-id\":\"cid\"}"));
    assert!(
        capture(|client| client.endpoint_health("id?a"))
            .starts_with("GET /v1/endpoint/id%3Fa/healthz HTTP/1.1\r\n")
    );
    assert_eq!(encode_component("é:/? +%"), "%C3%A9%3A%2F%3F%20%2B%25");
    assert_eq!(endpoint_path("../a"), "/v1/endpoint/..%2Fa");
}

#[test]
fn http_failure_statuses_are_not_transport_errors_and_raw_body_survives() {
    for status in [404, 503] {
        let server = Server::new(
            format!("HTTP/1.1 {status} Error\r\nContent-Length: 2\r\n\r\n{{}}").into_bytes(),
        );
        let response = server
            .client()
            .config()
            .expect("HTTP failure is a response");
        assert_eq!(response.status, status);
        assert_eq!(response.json, Some(json!({})));
        assert_eq!(response.body, b"{}");
    }
    let server = Server::new(b"HTTP/1.0 500 Error\r\n\r\nnot json".to_vec());
    let response = server.client().config().expect("close-delimited response");
    assert_eq!(response.status, 500);
    assert_eq!(response.json, None);
    assert_eq!(response.body, b"not json");
}

#[test]
fn chunked_extensions_trailers_and_informational_headers_are_supported() {
    let server = Server::new(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;key=value\r\n{\"x\r\n4\r\n\":1}\r\n0\r\nX-Trace: done\r\n\r\n".to_vec());
    let response = server.client().config().expect("chunked response");
    assert_eq!(response.body, br#"{"x":1}"#);
    assert_eq!(response.json, Some(json!({"x":1})));
    let server = Server::new(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec());
    assert!(server.client().config().expect("204").body.is_empty());
}

#[test]
fn malformed_ambiguous_and_truncated_http_is_rejected() {
    for response in [
        b"not HTTP\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\n\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n"
            .as_slice(),
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n".as_slice(),
    ] {
        let server = Server::new(response.to_vec());
        assert!(
            matches!(server.client().config(), Err(Error::Protocol(_))),
            "accepted {:?}",
            String::from_utf8_lossy(response)
        );
    }
}

#[test]
fn response_header_body_and_wire_limits_are_independent() {
    let server = Server::new(
        format!("HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n", "x".repeat(300)).into_bytes(),
    );
    assert!(matches!(
        server
            .client()
            .with_limits(Limits {
                header_bytes: 256,
                ..Limits::default()
            })
            .config(),
        Err(Error::Limit("header bytes"))
    ));
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\n\r\nabcd".as_slice(),
    ] {
        let server = Server::new(response.to_vec());
        assert!(matches!(
            server
                .client()
                .with_limits(Limits {
                    body_bytes: 3,
                    ..Limits::default()
                })
                .config(),
            Err(Error::Limit("body bytes"))
        ));
    }
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    let server = Server::new(response.to_vec());
    assert!(matches!(
        server
            .client()
            .with_limits(Limits {
                wire_bytes: 16,
                ..Limits::default()
            })
            .config(),
        Err(Error::Limit("wire bytes"))
    ));
    let response = b"HTTP/1.0 200 OK\r\n\r\nabc";
    let server = Server::new(response.to_vec());
    assert_eq!(
        server
            .client()
            .with_limits(Limits {
                wire_bytes: response.len(),
                body_bytes: 3,
                ..Limits::default()
            })
            .config()
            .expect("exact limit EOF")
            .body,
        b"abc"
    );
}

#[test]
fn total_deadline_stops_slow_drip_even_when_individual_reads_succeed() {
    let server = Server::run(|stream| {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n");
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(10));
            if stream.write_all(b"a").is_err() {
                break;
            }
        }
    });
    let client = Client::new(&server.path, Duration::from_millis(60));
    let start = Instant::now();
    assert!(matches!(client.config(), Err(Error::Timeout)));
    assert!(start.elapsed() < Duration::from_millis(500));
}

#[test]
fn endpoint_regeneration_can_omit_the_response_deadline() {
    let server = Server::run(|stream| {
        thread::sleep(Duration::from_millis(180));
        let _ = stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}");
    });
    let client = Client::new(&server.path, Duration::from_millis(80));
    let response = client
        .put_endpoint_unbounded_response("1", &json!({}))
        .expect("agent owns regeneration timeout");
    assert_eq!(response.status, 201);
}

#[test]
fn invalid_request_and_missing_socket_have_distinct_errors() {
    let path = std::env::temp_dir().join(format!(
        "flowsdn-missing-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let client = Client::new(path, Duration::from_secs(1));
    assert!(matches!(
        client.request(Method::Get, "/v1/config\r\nInjected: true", None),
        Err(Error::InvalidRequest(_))
    ));
    assert!(client.config().expect_err("missing agent").is_transport());
}

#[test]
fn full_unix_listener_backlog_cannot_block_connect_past_deadline() {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
    use std::os::fd::AsRawFd;
    let path = std::env::temp_dir().join(format!(
        "flowsdn-backlog-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = UnixListener::bind(&path).expect("listener");
    let address = UnixAddr::new(&path).expect("address");
    let mut connections = Vec::new();
    let mut full = false;
    for _ in 0..512 {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )
        .expect("socket");
        match connect(fd.as_raw_fd(), &address) {
            Ok(()) => connections.push(fd),
            Err(nix::errno::Errno::EAGAIN) => {
                full = true;
                break;
            }
            Err(error) => panic!("fill backlog: {error}"),
        }
    }
    assert!(full, "fixture failed to saturate backlog");
    let start = Instant::now();
    let result = Client::new(&path, Duration::from_millis(40)).config();
    drop(connections);
    drop(listener);
    fs::remove_file(path).expect("remove socket");
    assert!(matches!(result, Err(Error::Timeout)));
    assert!(start.elapsed() < Duration::from_millis(500));
}
