//! Synchronous Unix-socket agent API client from specifications 08 and 09.
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt,
    },
};
use serde_json::Value;
use std::{
    fmt,
    io::{self, Write},
    net::IpAddr,
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

mod wire;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Transport(io::Error),
    Timeout,
    Protocol(String),
    Limit(&'static str),
    InvalidRequest(String),
}
impl Error {
    /// HTTP failures are returned as Response, never as transport errors.
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Timeout)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "agent transport: {e}"),
            Self::Timeout => f.write_str("agent request deadline exceeded"),
            Self::Protocol(e) => write!(f, "invalid HTTP response: {e}"),
            Self::Limit(which) => write!(f, "agent response exceeds {which} limit"),
            Self::InvalidRequest(e) => write!(f, "invalid agent request: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::Timeout
        } else {
            Self::Transport(e)
        }
    }
}
fn errno(e: Errno) -> Error {
    io::Error::from_raw_os_error(e as i32).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}
impl Method {
    fn text(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub header_bytes: usize,
    pub body_bytes: usize,
    pub wire_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            header_bytes: 16_384,
            body_bytes: 4_194_304,
            wire_bytes: 8_388_608,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// Empty and non-JSON bodies remain available in `body`, with `json=None`.
    pub json: Option<Value>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
    limits: Limits,
}
impl Client {
    pub fn new(path: impl AsRef<Path>, timeout: Duration) -> Self {
        Self {
            socket: path.as_ref().to_owned(),
            timeout,
            limits: Limits::default(),
        }
    }
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Response> {
        self.request_inner(method, path, body, None, false)
    }

    fn request_inner(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        expiration: Option<bool>,
        unbounded_response: bool,
    ) -> Result<Response> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| Error::InvalidRequest("timeout is too large".into()))?;
        if !path.starts_with('/')
            || !path.is_ascii()
            || path.bytes().any(|b| b <= b' ' || b == 127 || b == b'#')
        {
            return Err(Error::InvalidRequest(
                "expected an escaped absolute HTTP path".into(),
            ));
        }
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| Error::InvalidRequest(e.to_string()))?
            .unwrap_or_default();
        if body.len() > self.limits.body_bytes {
            return Err(Error::Limit("request body"));
        }
        let mut head = format!(
            "{} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
            method.text(),
            body.len()
        );
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        if let Some(expiration) = expiration {
            head.push_str(if expiration {
                "expiration: true\r\n"
            } else {
                "expiration: false\r\n"
            });
        }
        head.push_str("\r\n");
        if head.len() > self.limits.header_bytes {
            return Err(Error::Limit("request header"));
        }
        let mut stream = connect_deadline(&self.socket, deadline)?;
        write_deadline(&mut stream, head.as_bytes(), deadline)?;
        write_deadline(&mut stream, &body, deadline)?;
        wire::response(
            stream,
            if unbounded_response {
                None
            } else {
                Some(deadline)
            },
            self.limits,
        )
    }

    pub fn config(&self) -> Result<Response> {
        self.request(Method::Get, "/v1/config", None)
    }
    pub fn allocate(
        &self,
        owner: &str,
        family: &str,
        pool: &str,
        expiration: bool,
    ) -> Result<Response> {
        let mut path = format!("/v1/ipam?owner={}", encode_component(owner));
        if !family.is_empty() {
            path.push_str(&format!("&family={}", encode_component(family)));
        }
        if !pool.is_empty() {
            path.push_str(&format!("&pool={}", encode_component(pool)));
        }
        self.request_inner(Method::Post, &path, None, Some(expiration), false)
    }
    pub fn release(&self, ip: IpAddr, pool: &str) -> Result<Response> {
        self.request(
            Method::Delete,
            &format!(
                "/v1/ipam/{}?pool={}",
                encode_component(&ip.to_string()),
                encode_component(pool)
            ),
            None,
        )
    }
    pub fn put_endpoint(&self, id: &str, body: &Value) -> Result<Response> {
        self.request(Method::Put, &endpoint_path(id), Some(body))
    }
    /// CNI ADD regeneration is bounded by the agent (spec09 §3.4 step12).
    /// Connect/write retain this client's deadline; response byte limits remain
    /// enforced, but this method adds no response-time deadline of its own.
    pub fn put_endpoint_unbounded_response(&self, id: &str, body: &Value) -> Result<Response> {
        self.request_inner(Method::Put, &endpoint_path(id), Some(body), None, true)
    }
    pub fn delete_endpoint(&self, id: &str) -> Result<Response> {
        self.request(Method::Delete, &endpoint_path(id), None)
    }
    pub fn delete_container(&self, container_id: &str) -> Result<Response> {
        self.request(
            Method::Delete,
            "/v1/endpoint",
            Some(&serde_json::json!({"container-id": container_id})),
        )
    }
    pub fn endpoint_health(&self, id: &str) -> Result<Response> {
        self.request(Method::Get, &format!("{}/healthz", endpoint_path(id)), None)
    }
}

pub fn endpoint_path(id: &str) -> String {
    format!("/v1/endpoint/{}", encode_component(id))
}

/// RFC3986 unreserved bytes survive; every other UTF-8 byte is percent escaped.
pub fn encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

pub(crate) fn remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(remaining)
    }
}

fn connect_deadline(path: &Path, deadline: Instant) -> Result<UnixStream> {
    let address = UnixAddr::new(path).map_err(errno)?;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(errno)?;
    loop {
        let left = remaining(deadline)?;
        match connect(fd.as_raw_fd(), &address) {
            Ok(()) | Err(Errno::EISCONN) => break,
            // Linux AF_UNIX reports EAGAIN when the listener backlog is full;
            // no connection is pending, so retry connect rather than treating
            // a writable, unconnected socket as a successful connection.
            Err(Errno::EAGAIN) => std::thread::sleep(left.min(Duration::from_millis(5))),
            Err(Errno::EINTR) => continue,
            Err(Errno::EINPROGRESS | Errno::EALREADY) => {
                let millis = left.as_millis().saturating_add(1);
                let timeout = PollTimeout::try_from(millis).unwrap_or(PollTimeout::MAX);
                let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
                match poll(&mut fds, timeout) {
                    Ok(0) => {
                        remaining(deadline)?;
                        continue;
                    }
                    Ok(_) => {
                        let code = getsockopt(&fd, sockopt::SocketError).map_err(errno)?;
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(code).into());
                        }
                        break;
                    }
                    Err(Errno::EINTR) => continue,
                    Err(e) => return Err(errno(e)),
                }
            }
            Err(e) => return Err(errno(e)),
        }
    }
    remaining(deadline)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn write_deadline(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(count) => {
                bytes = bytes
                    .get(count..)
                    .ok_or_else(|| Error::Protocol("invalid write count".into()))?
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
