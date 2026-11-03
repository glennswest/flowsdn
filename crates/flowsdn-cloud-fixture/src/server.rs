//! The shared local replay server (spec 07 §9.1): a loopback HTTP/1.1 server
//! that answers each request from a [`Replayer`], so a provider client's own
//! signing, retry, pagination and error mapping stay in the tested path. Point
//! the client's endpoint (and IMDS) at [`ReplayServer::url`] with a static test
//! credential. It never forwards a request anywhere: an unmatched one gets
//! `500` with `x-flowsdn-replay: mismatch`, and [`ReplayServer::finish`] fails.
use crate::fixture::{Request, Response};
use crate::replay::Replayer;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_HEAD: usize = 65_536;
const MAX_BODY: usize = 16_777_216;
const IDLE: Duration = Duration::from_secs(30);

pub struct ReplayServer {
    addr: SocketAddr,
    state: Arc<Mutex<Replayer>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn read_line(r: &mut impl BufRead, budget: &mut usize) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let n = r.by_ref().take(u64::try_from(*budget).unwrap_or(u64::MAX)).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    *budget = budget.checked_sub(n).ok_or_else(|| invalid("request head too large"))?;
    if line.last() != Some(&b'\n') {
        return Err(invalid("request head too large or truncated"));
    }
    let text = String::from_utf8(line).map_err(|_| invalid("request head is not UTF-8"))?;
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
}

fn read_exact_body(r: &mut impl Read, len: usize, body: &mut Vec<u8>) -> io::Result<()> {
    let total = body.len().checked_add(len).filter(|t| *t <= MAX_BODY);
    if total.is_none() {
        return Err(invalid("request body too large"));
    }
    let mut chunk = vec![0; len];
    r.read_exact(&mut chunk)?;
    body.extend_from_slice(&chunk);
    Ok(())
}

/// One request, or `None` at a clean end of the connection.
fn read_request(r: &mut impl BufRead) -> io::Result<Option<(Request, bool)>> {
    let mut budget = MAX_HEAD;
    let Some(start) = read_line(r, &mut budget)? else {
        return Ok(None);
    };
    let mut parts = start.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("malformed request line"));
    };
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let line = read_line(r, &mut budget)?.ok_or_else(|| invalid("truncated headers"))?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| invalid("malformed header"))?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        headers
            .entry(name)
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&value);
            })
            .or_insert_with(|| value.clone());
    }
    let mut body = Vec::new();
    let chunked = headers
        .get("transfer-encoding")
        .is_some_and(|t| t.to_ascii_lowercase().contains("chunked"));
    if chunked {
        loop {
            let mut budget = MAX_HEAD;
            let line = read_line(r, &mut budget)?.ok_or_else(|| invalid("truncated chunk"))?;
            let size = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size, 16).map_err(|_| invalid("bad chunk size"))?;
            if size == 0 {
                // Trailers, up to the blank line.
                while read_line(r, &mut budget)?.is_some_and(|l| !l.is_empty()) {}
                break;
            }
            read_exact_body(r, size, &mut body)?;
            let mut crlf = [0; 2];
            r.read_exact(&mut crlf)?;
        }
        headers.remove("transfer-encoding");
    } else if let Some(len) = headers.get("content-length") {
        let len: usize = len.parse().map_err(|_| invalid("bad content-length"))?;
        read_exact_body(r, len, &mut body)?;
    }
    let close = version.eq_ignore_ascii_case("HTTP/1.0")
        || headers
            .get("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
    let body = String::from_utf8(body).map_err(|_| invalid("request body is not UTF-8"))?;
    Ok(Some((
        Request {
            method: method.to_string(),
            path: target.to_string(),
            headers,
            body,
        },
        close,
    )))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Replayed",
    }
}

fn write_response(w: &mut impl Write, resp: &Response, close: bool) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    for (k, v) in &resp.headers {
        if !matches!(k.as_str(), "content-length" | "transfer-encoding" | "connection") {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    head.push_str(&format!(
        "content-length: {}\r\nconnection: {}\r\n\r\n",
        resp.body.len(),
        if close { "close" } else { "keep-alive" }
    ));
    w.write_all(head.as_bytes())?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}

fn mismatch(report: String) -> Response {
    let mut headers = BTreeMap::new();
    headers.insert("x-flowsdn-replay".to_string(), "mismatch".to_string());
    headers.insert("content-type".to_string(), "text/plain".to_string());
    Response {
        status: 500,
        headers,
        body: format!("flowsdn-cloud-fixture: {report}\n"),
    }
}

fn record(state: &Mutex<Replayer>, request: &Request) -> Response {
    match state.lock() {
        Ok(mut replayer) => replayer.respond(request).unwrap_or_else(mismatch),
        Err(_) => mismatch("replay state poisoned".to_string()),
    }
}

fn serve(stream: TcpStream, state: &Mutex<Replayer>) {
    if stream.set_read_timeout(Some(IDLE)).is_err() {
        return;
    }
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    loop {
        match read_request(&mut reader) {
            Ok(Some((request, close))) => {
                let response = record(state, &request);
                if write_response(&mut writer, &response, close).is_err() || close {
                    return;
                }
            }
            Ok(None) => return,
            // An idle keep-alive connection timing out is not a failure.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return;
            }
            Err(e) => {
                let report = format!("unreadable request: {e}");
                if let Ok(mut replayer) = state.lock() {
                    replayer.note_failure(report.clone());
                }
                let _ = write_response(&mut writer, &mismatch(report), true);
                return;
            }
        }
    }
}

impl ReplayServer {
    /// Listens on 127.0.0.1 on a free port.
    pub fn start(replayer: Replayer) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(replayer));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (state.clone(), stop.clone());
        let accept = thread::Builder::new()
            .name("cloud-replay".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if st.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let s = s.clone();
                    // Connections are detached: finish() reads the shared state.
                    let _ = thread::Builder::new()
                        .name("cloud-replay-conn".into())
                        .spawn(move || serve(stream, &s));
                }
            })?;
        Ok(Self {
            addr,
            state,
            stop,
            accept: Some(accept),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`: the endpoint to give the provider client.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }

    /// Stops listening and reports, as [`Replayer::finish`] does.
    pub fn finish(mut self, strict: bool) -> Result<(), String> {
        self.shutdown();
        match self.state.lock() {
            Ok(replayer) => replayer.finish(strict),
            Err(_) => Err("replay state poisoned".to_string()),
        }
    }
}

impl Drop for ReplayServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::tests::scenario;

    fn exchange(stream: &mut TcpStream, raw: &str) -> String {
        stream.write_all(raw.as_bytes()).expect("send");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut head = String::new();
        let mut len = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("line");
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().expect("length");
            }
            head.push_str(&line);
        }
        let mut body = vec![0; len];
        reader.read_exact(&mut body).expect("body");
        format!("{head}\r\n{}", String::from_utf8(body).expect("utf8"))
    }

    #[test]
    fn keep_alive_chunked_and_strict_finish() {
        let server = ServerUnderTest::new();
        let mut c = TcpStream::connect(server.0.addr()).expect("connect");
        let form = "content-type: application/x-www-form-urlencoded";
        let body = "Action=DescribeInstances&Version=2016-11-15";
        let first = exchange(
            &mut c,
            &format!(
                "POST / HTTP/1.1\r\nhost: x\r\n{form}\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
        assert!(first.contains("i-5c7b0000000000001"), "{first}");
        let chunks = "Action=CreateNetworkInterface&SubnetId=subnet-5c7b0002";
        let (a, b) = chunks.split_at(10);
        let second = exchange(
            &mut c,
            &format!(
                "POST http://127.0.0.1/ HTTP/1.1\r\n{form}\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                a.len(),
                b.len()
            ),
        );
        assert!(second.contains("eni-5c7b0000000000003"), "{second}");
        drop(c);
        assert_eq!(server.finish(true), Ok(()));
    }

    #[test]
    fn mismatch_is_answered_and_reported() {
        let server = ServerUnderTest::new();
        let mut c = TcpStream::connect(server.0.addr()).expect("connect");
        let reply = exchange(&mut c, "GET /latest/meta-data/ HTTP/1.1\r\nhost: x\r\n\r\n");
        assert!(reply.starts_with("HTTP/1.1 500"), "{reply}");
        assert!(reply.contains("x-flowsdn-replay: mismatch"), "{reply}");
        drop(c);
        let err = server.finish(false).expect_err("mismatch recorded");
        assert!(err.contains("GET /latest/meta-data/"), "{err}");
    }

    /// Starts a server on the sample scenario.
    struct ServerUnderTest(ReplayServer);

    impl ServerUnderTest {
        fn new() -> Self {
            Self(ReplayServer::start(Replayer::new(scenario().interactions)).expect("start"))
        }

        fn finish(self, strict: bool) -> Result<(), String> {
            self.0.finish(strict)
        }
    }
}
