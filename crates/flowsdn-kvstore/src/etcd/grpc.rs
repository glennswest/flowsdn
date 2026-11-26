//! gRPC over `h2` for the etcd backend (spec 20 §2.6, §3.2.2-3.2.3,
//! ADR-0016): one HTTP/2 connection per dial over TCP or Fedora OpenSSL TLS,
//! length-prefixed messages, `grpc-status` trailers, unary calls and
//! bidirectional streams.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, Method, Request, StatusCode};
use openssl::ssl::{Ssl, SslConnector, SslFiletype, SslMethod};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use tokio::net::TcpStream;

use crate::{Error, Result};

/// The largest decoded message (§2.7 F24).
pub(crate) const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// The gRPC message prefix: compressed flag and big-endian length.
const PREFIX: usize = 5;
/// The default etcd client port.
const DEFAULT_PORT: u16 = 2379;

/// One endpoint URL of the client YAML (§2.3), `http://` or `https://`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Endpoint {
    /// The URL as configured, for status lines.
    pub(crate) url: String,
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Endpoint {
    /// Parse `scheme://host[:port][/]`; no scheme means `http`.
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let url = url.trim();
        let bad = || Error::Backend(format!("etcd: invalid endpoint {url:?}"));
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else if url.contains("://") {
            return Err(bad());
        } else {
            (false, url)
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let (host, tail) = after.split_once(']').ok_or_else(bad)?;
            let port = if tail.is_empty() {
                DEFAULT_PORT
            } else {
                let port = tail.strip_prefix(':').ok_or_else(bad)?;
                port.parse().map_err(|_| bad())?
            };
            (host.to_owned(), port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            (host.to_owned(), port.parse().map_err(|_| bad())?)
        } else {
            (authority.to_owned(), DEFAULT_PORT)
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_owned(),
            tls,
            host,
            port,
        })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }
}

/// The TLS files of the client YAML (§3.2.2), read again on every dial.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TlsFiles {
    pub(crate) ca: Option<PathBuf>,
    pub(crate) cert: Option<PathBuf>,
    pub(crate) key: Option<PathBuf>,
}

fn tls_error(what: &str, error: impl std::fmt::Display) -> Error {
    Error::Backend(format!("etcd tls: {what}: {error}"))
}

/// A fresh `Ssl` for one handshake: the CA file (else the system roots), the
/// client certificate and key when both are set, hostname verification
/// against `host`, ALPN `h2`.
fn ssl_for(host: &str, files: &TlsFiles) -> Result<Ssl> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|e| tls_error("context", e))?;
    match &files.ca {
        Some(ca) => {
            let pem = std::fs::read(ca).map_err(|e| tls_error(&ca.display().to_string(), e))?;
            let certs =
                X509::stack_from_pem(&pem).map_err(|e| tls_error(&ca.display().to_string(), e))?;
            let mut store = X509StoreBuilder::new().map_err(|e| tls_error("store", e))?;
            for cert in certs {
                store.add_cert(cert).map_err(|e| tls_error("store", e))?;
            }
            builder.set_cert_store(store.build());
        }
        None => builder
            .set_default_verify_paths()
            .map_err(|e| tls_error("system roots", e))?,
    }
    if let (Some(cert), Some(key)) = (&files.cert, &files.key) {
        builder
            .set_certificate_chain_file(cert)
            .map_err(|e| tls_error(&cert.display().to_string(), e))?;
        builder
            .set_private_key_file(key, SslFiletype::PEM)
            .map_err(|e| tls_error(&key.display().to_string(), e))?;
        builder.check_private_key().map_err(|e| tls_error("client key", e))?;
    }
    builder.set_alpn_protos(b"\x02h2").map_err(|e| tls_error("alpn", e))?;
    let connector = builder.build();
    connector
        .configure()
        .map_err(|e| tls_error("configure", e))?
        .into_ssl(host)
        .map_err(|e| tls_error("ssl", e))
}

/// Dial `endpoint`: TCP, TLS when `https`, then the HTTP/2 handshake. The
/// connection runs on its own task; [`Channel::is_alive`] turns false when it
/// ends.
pub(crate) async fn dial(endpoint: &Endpoint, files: &TlsFiles) -> Result<Channel> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(|e| Error::Backend(format!("etcd: connect {}: {e}", endpoint.url)))?;
    // Best effort: small request/response messages.
    let _ = tcp.set_nodelay(true);
    let alive = Arc::new(AtomicBool::new(true));
    let send = if endpoint.tls {
        let ssl = ssl_for(&endpoint.host, files)?;
        let mut stream =
            tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| tls_error("stream", e))?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| tls_error(&format!("handshake with {}", endpoint.url), e))?;
        handshake(stream, Arc::clone(&alive)).await?
    } else {
        handshake(tcp, Arc::clone(&alive)).await?
    };
    Ok(Channel {
        send,
        base: format!("{}://{}", endpoint.scheme(), endpoint.authority()),
        alive,
    })
}

async fn handshake<T>(io: T, alive: Arc<AtomicBool>) -> Result<SendRequest<Bytes>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send, connection) = h2::client::Builder::new()
        .initial_window_size(1_048_576)
        .initial_connection_window_size(16_777_216)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|e| Error::Backend(format!("etcd: http/2 handshake: {e}")))?;
    tokio::spawn(async move {
        // The error, if any, surfaces on the next request.
        let _ = connection.await;
        alive.store(false, Ordering::SeqCst);
    });
    Ok(send)
}

/// One HTTP/2 connection to an endpoint.
#[derive(Clone)]
pub(crate) struct Channel {
    send: SendRequest<Bytes>,
    /// `scheme://authority`.
    base: String,
    alive: Arc<AtomicBool>,
}

impl Channel {
    /// False once the connection has ended or failed.
    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn fail(&self, path: &str, error: &h2::Error) -> Error {
        if !error.is_reset() {
            self.alive.store(false, Ordering::SeqCst);
        }
        Error::Backend(format!("etcd {path}: {error}"))
    }

    /// Open a stream on `path` with extra `metadata`, send the framed
    /// `first` message (ending the request when `end`), and wait for the
    /// response headers.
    pub(crate) async fn open(
        &self,
        path: &str,
        metadata: &[(&'static str, &'static str)],
        first: Bytes,
        end: bool,
    ) -> Result<(StreamTx, StreamRx)> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{path}", self.base))
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        for (name, value) in metadata {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(())
            .map_err(|e| Error::Backend(format!("etcd {path}: request: {e}")))?;
        let mut send = self
            .send
            .clone()
            .ready()
            .await
            .map_err(|e| self.fail(path, &e))?;
        let (response, stream) = send
            .send_request(request, false)
            .map_err(|e| self.fail(path, &e))?;
        let mut tx = StreamTx { stream };
        tx.send(first, end).await?;
        let response = response.await.map_err(|e| self.fail(path, &e))?;
        let (parts, body) = response.into_parts();
        if parts.status != StatusCode::OK {
            return Err(Error::Backend(format!(
                "etcd {path}: HTTP status {}",
                parts.status
            )));
        }
        // A trailers-only response carries `grpc-status` in the headers.
        let done = check_status(&parts.headers)?;
        Ok((
            tx,
            StreamRx {
                body,
                decoder: Decoder::default(),
                done,
            },
        ))
    }

    /// One unary call.
    pub(crate) async fn unary<Q, R>(&self, path: &str, request: &Q) -> Result<R>
    where
        Q: prost::Message,
        R: prost::Message + Default,
    {
        let (_tx, mut rx) = self.open(path, &[], frame(request), true).await?;
        let response = rx
            .recv::<R>()
            .await?
            .ok_or_else(|| Error::Backend(format!("etcd {path}: no response message")))?;
        // Consume the trailers so the stream closes cleanly.
        let _ = rx.recv::<R>().await;
        Ok(response)
    }
}

/// The request half of a stream.
pub(crate) struct StreamTx {
    stream: SendStream<Bytes>,
}

impl StreamTx {
    /// Send framed bytes, waiting for flow-control capacity.
    pub(crate) async fn send(&mut self, mut data: Bytes, end: bool) -> Result<()> {
        let error = |e: h2::Error| Error::Backend(format!("etcd stream send: {e}"));
        if data.is_empty() {
            return self.stream.send_data(data, end).map_err(error);
        }
        while !data.is_empty() {
            self.stream.reserve_capacity(data.len());
            let capacity = match std::future::poll_fn(|cx| self.stream.poll_capacity(cx)).await {
                Some(Ok(capacity)) => capacity,
                Some(Err(e)) => return Err(error(e)),
                None => return Err(Error::Backend("etcd stream send: stream closed".into())),
            };
            if capacity == 0 {
                continue;
            }
            let chunk = data.split_to(capacity.min(data.len()));
            self.stream
                .send_data(chunk, end && data.is_empty())
                .map_err(error)?;
        }
        Ok(())
    }
}

/// The response half of a stream.
pub(crate) struct StreamRx {
    body: RecvStream,
    decoder: Decoder,
    done: bool,
}

impl StreamRx {
    /// The next message; `None` when the stream ended with status OK.
    /// Cancel-safe: the only await is on the next DATA frame.
    pub(crate) async fn recv<R: prost::Message + Default>(&mut self) -> Result<Option<R>> {
        loop {
            if let Some(message) = self.decoder.next_message()? {
                return R::decode(message)
                    .map(Some)
                    .map_err(|e| Error::Backend(format!("etcd: decode: {e}")));
            }
            if self.done {
                if !self.decoder.is_empty() {
                    return Err(Error::Backend("etcd: truncated gRPC message".into()));
                }
                return Ok(None);
            }
            match self.body.data().await {
                Some(Ok(chunk)) => {
                    let _ = self.body.flow_control().release_capacity(chunk.len());
                    self.decoder.push(&chunk);
                }
                Some(Err(e)) => return Err(Error::Backend(format!("etcd stream: {e}"))),
                None => {
                    let trailers = self
                        .body
                        .trailers()
                        .await
                        .map_err(|e| Error::Backend(format!("etcd stream trailers: {e}")))?;
                    self.done = true;
                    if let Some(trailers) = trailers {
                        check_status(&trailers)?;
                    }
                }
            }
        }
    }
}

/// Frame one message: flag 0, big-endian length, the encoded message.
pub(crate) fn frame(message: &impl prost::Message) -> Bytes {
    let body = message.encode_to_vec();
    let mut buf = BytesMut::with_capacity(body.len().saturating_add(PREFIX));
    buf.put_u8(0);
    buf.put_u32(u32::try_from(body.len()).unwrap_or(u32::MAX));
    buf.put_slice(&body);
    buf.freeze()
}

/// Reassembles length-prefixed messages across DATA frames.
#[derive(Default)]
pub(crate) struct Decoder {
    buf: BytesMut,
}

impl Decoder {
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next complete message, if buffered.
    pub(crate) fn next_message(&mut self) -> Result<Option<Bytes>> {
        let Some(prefix) = self.buf.get(..PREFIX) else {
            return Ok(None);
        };
        let compressed = prefix.first().copied().unwrap_or(0);
        let length: [u8; 4] = prefix
            .get(1..PREFIX)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| Error::Backend("etcd: bad gRPC prefix".into()))?;
        if compressed != 0 {
            return Err(Error::Backend("etcd: compressed gRPC message".into()));
        }
        let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
        if length > MAX_MESSAGE {
            return Err(Error::Backend(format!(
                "etcd: gRPC message of {length} bytes, over {MAX_MESSAGE}"
            )));
        }
        let total = length.saturating_add(PREFIX);
        if self.buf.len() < total {
            return Ok(None);
        }
        self.buf.advance(PREFIX);
        Ok(Some(self.buf.split_to(length).freeze()))
    }
}

/// `Ok(true)` when `grpc-status` is present and 0, `Ok(false)` when absent,
/// the mapped error otherwise.
fn check_status(headers: &HeaderMap) -> Result<bool> {
    let Some(code) = headers.get("grpc-status") else {
        return Ok(false);
    };
    let code: u32 = code
        .to_str()
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(2);
    if code == 0 {
        return Ok(true);
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .map(percent_decode)
        .unwrap_or_default();
    Err(status_error(code, &message))
}

/// A non-zero `grpc-status`. A missing lease (`etcdserver: requested lease
/// not found`, NOT_FOUND) is [`Error::LeaseNotFound`] with id 0; the caller
/// names the lease.
pub(crate) fn status_error(code: u32, message: &str) -> Error {
    if message.contains("lease not found") {
        Error::LeaseNotFound(0)
    } else {
        Error::Backend(format!("etcd: grpc status {code}: {message}"))
    }
}

/// Decode `grpc-message`'s percent-encoding.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        let escaped = if byte == b'%' {
            bytes
                .get(index.saturating_add(1)..index.saturating_add(3))
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        match escaped {
            Some(decoded) => {
                out.push(decoded);
                index = index.saturating_add(3);
            }
            None => {
                out.push(byte);
                index = index.saturating_add(1);
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::etcd::proto::{PutRequest, RangeResponse};
    use prost::Message;

    #[test]
    fn frames_decode_across_split_frames() {
        let first = PutRequest {
            key: b"flowsdn/a".to_vec(),
            value: vec![7; 300],
            ..Default::default()
        };
        let second = RangeResponse {
            more: true,
            count: 3,
            ..Default::default()
        };
        let mut wire = frame(&first).to_vec();
        wire.extend_from_slice(&frame(&second));
        assert_eq!(wire[0], 0);
        assert_eq!(
            u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize,
            first.encoded_len()
        );
        // Feed byte by byte, then in odd chunks: the same two messages.
        for chunk in [1usize, 3, 7, 64, wire.len()] {
            let mut decoder = Decoder::default();
            let mut out = Vec::new();
            for piece in wire.chunks(chunk) {
                decoder.push(piece);
                while let Some(message) = decoder.next_message().unwrap() {
                    out.push(message);
                }
            }
            assert!(decoder.is_empty());
            assert_eq!(out.len(), 2, "chunk {chunk}");
            assert_eq!(PutRequest::decode(out[0].clone()).unwrap(), first);
            assert_eq!(RangeResponse::decode(out[1].clone()).unwrap(), second);
        }
    }

    #[test]
    fn frames_refuse_oversize_and_compressed() {
        let mut decoder = Decoder::default();
        let too_big = u32::try_from(MAX_MESSAGE + 1).unwrap().to_be_bytes();
        decoder.push(&[0, too_big[0], too_big[1], too_big[2], too_big[3]]);
        assert!(decoder.next_message().is_err());
        let mut decoder = Decoder::default();
        decoder.push(&[1, 0, 0, 0, 0]);
        assert!(decoder.next_message().is_err());
        let mut decoder = Decoder::default();
        decoder.push(&[0, 0, 0]);
        assert_eq!(decoder.next_message().unwrap(), None);
    }

    #[test]
    fn statuses_map() {
        let mut headers = HeaderMap::new();
        assert_eq!(check_status(&headers), Ok(false));
        headers.insert("grpc-status", "0".parse().unwrap());
        assert_eq!(check_status(&headers), Ok(true));
        headers.insert("grpc-status", "5".parse().unwrap());
        headers.insert(
            "grpc-message",
            "etcdserver: requested lease not found".parse().unwrap(),
        );
        assert_eq!(check_status(&headers), Err(Error::LeaseNotFound(0)));
        headers.insert("grpc-status", "11".parse().unwrap());
        headers.insert(
            "grpc-message",
            "etcdserver: mvcc: required revision has been compacted%21"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            check_status(&headers),
            Err(Error::Backend(
                "etcd: grpc status 11: etcdserver: mvcc: required revision has been compacted!"
                    .into()
            ))
        );
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("100%25"), "100%");
    }

    #[test]
    fn endpoints_parse() {
        let endpoint = Endpoint::parse("https://cluster2.mesh.cilium.io:2379").unwrap();
        assert!(endpoint.tls);
        assert_eq!(endpoint.host, "cluster2.mesh.cilium.io");
        assert_eq!(endpoint.port, 2379);
        assert_eq!(endpoint.authority(), "cluster2.mesh.cilium.io:2379");
        let endpoint = Endpoint::parse("http://127.0.0.1:12379/").unwrap();
        assert!(!endpoint.tls);
        assert_eq!(endpoint.url, "http://127.0.0.1:12379");
        assert_eq!(endpoint.scheme(), "http");
        let endpoint = Endpoint::parse("https://[::1]:4000").unwrap();
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.authority(), "[::1]:4000");
        assert_eq!(Endpoint::parse("etcd.kube-system").unwrap().port, 2379);
        assert!(Endpoint::parse("unix:///run/etcd.sock").is_err());
        assert!(Endpoint::parse("http://host:notaport").is_err());
        assert!(Endpoint::parse("http://").is_err());
    }
}
