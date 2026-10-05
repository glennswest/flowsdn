//! Bounded JSON Node/Pod transport. Callers own relist, backoff and publication.
//! TLS/authentication use kube; no informer or runtime controller is implied.
use crate::{Error, watch::Scope};
use futures::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, TryStreamExt};
use http::{
    Request,
    header::{ACCEPT, AUTHORIZATION, HeaderValue},
};
use http_body_util::BodyExt;
use kube::{
    Client, Config,
    client::Body,
    config::{KubeConfigOptions, Kubeconfig},
};
use serde_json::Value;
use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

type Reader = Pin<Box<dyn AsyncBufRead + Send>>;

/// The error text of a watch the server closed normally (its timeoutSeconds):
/// the caller may resume from its last resourceVersion instead of relisting.
pub const WATCH_ENDED: &str = "watch ended; relist required";

#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    pub list_bytes: usize,
    pub frame_bytes: usize,
    /// Bounds the whole list operation or time to the next complete watch frame.
    pub timeout: Duration,
}
impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            list_bytes: 67_108_864,
            frame_bytes: 4_194_304,
            timeout: Duration::from_secs(90),
        }
    }
}

#[derive(Default, Debug)]
pub struct Query<'a> {
    pub limit: Option<u32>,
    pub continue_token: Option<&'a str>,
    pub resource_version: Option<&'a str>,
    pub label_selector: Option<&'a str>,
    pub watch: bool,
}

/// Percent-encode opaque values, including opaque resource versions and tokens.
/// Pod selection is always constrained to the requested node.
pub fn request_uri(scope: &Scope, query: &Query<'_>) -> Result<String, Error> {
    if let Scope::LocalPods { node_name } = scope
        && (node_name.is_empty()
            || node_name
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.'))
    {
        return Err(Error("invalid local node name".into()));
    }
    if query.watch && (query.limit.is_some() || query.continue_token.is_some()) {
        return Err(Error("watch cannot use list pagination".into()));
    }
    if query.limit == Some(0) {
        return Err(Error("list limit must be positive".into()));
    }
    let path = match scope {
        Scope::Nodes => "/api/v1/nodes",
        Scope::LocalPods { .. } | Scope::Pods => "/api/v1/pods",
    };
    let mut params = Vec::new();
    if let Some(selector) = scope.field_selector() {
        params.push(("fieldSelector", selector));
    }
    if let Some(selector) = query.label_selector {
        params.push(("labelSelector", selector.into()));
    }
    if let Some(limit) = query.limit {
        params.push(("limit", limit.to_string()));
    }
    if let Some(token) = query.continue_token {
        params.push(("continue", token.into()));
    }
    if let Some(rv) = query.resource_version {
        params.push(("resourceVersion", rv.into()));
    }
    if query.watch {
        params.push(("watch", "true".into()));
        params.push(("allowWatchBookmarks", "true".into()));
        params.push(("timeoutSeconds", "60".into()));
    }
    let encoded: Vec<_> = params
        .into_iter()
        .map(|(key, val)| format!("{key}={}", encode(&val)))
        .collect();
    Ok(if encoded.is_empty() {
        path.into()
    } else {
        format!("{path}?{}", encoded.join("&"))
    })
}
fn encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub struct JsonClient {
    client: Client,
    token_file: Option<PathBuf>,
    limits: TransportLimits,
}
impl JsonClient {
    /// Explicit kubeconfig takes precedence. Otherwise use in-cluster auth only;
    /// do not accidentally consult a developer's default kubeconfig.
    pub async fn load(kubeconfig: Option<&Path>, limits: TransportLimits) -> Result<Self, Error> {
        let config = match kubeconfig {
            Some(path) => Config::from_custom_kubeconfig(
                Kubeconfig::read_from(path)
                    .map_err(|_| Error("cannot read Kubernetes configuration".into()))?,
                &KubeConfigOptions::default(),
            )
            .await
            .map_err(|_| Error("cannot load Kubernetes configuration".into()))?,
            None => Config::incluster()
                .map_err(|_| Error("cannot load in-cluster configuration".into()))?,
        };
        Self::from_config(config, limits)
    }
    pub fn from_config(mut config: Config, limits: TransportLimits) -> Result<Self, Error> {
        if config.cluster_url.scheme_str() != Some("https") || config.accept_invalid_certs {
            return Err(Error("Kubernetes transport requires verified HTTPS".into()));
        }
        if limits.list_bytes == 0 || limits.frame_bytes == 0 || limits.timeout.is_zero() {
            return Err(Error("transport limits must be positive".into()));
        }
        let token_file = config.auth_info.token_file.take().map(PathBuf::from);
        if token_file.is_some() {
            // Bypass kube's token-file cache; a request must see the current file.
            config.auth_info.token = None;
            if config.auth_info.username.is_some()
                || config.auth_info.exec.is_some()
                || config.auth_info.auth_provider.is_some()
            {
                return Err(Error(
                    "token-file authentication cannot be combined with another credential provider"
                        .into(),
                ));
            }
        }
        // Caller retries with a freshly read token, never an internally cached request.
        config.default_retry = false;
        let client = Client::try_from(config)
            .map_err(|_| Error("cannot initialize Kubernetes TLS client".into()))?;
        Ok(Self {
            client,
            token_file,
            limits,
        })
    }
    /// Construct a fresh authenticated request. Never include credentials in errors.
    pub async fn request(&self, scope: &Scope, query: &Query<'_>) -> Result<Request<Body>, Error> {
        let mut request = Request::get(request_uri(scope, query)?)
            .header(ACCEPT, crate::JSON_CONTENT_TYPE)
            .body(Body::empty())
            .map_err(|_| Error("invalid Kubernetes request".into()))?;
        if let Some(path) = &self.token_file {
            // Follow projected-secret symlinks, but never block on a FIFO or
            // read from another special file. Async file work stays off the executor.
            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
                .await
                .map_err(|_| Error("cannot read Kubernetes token file".into()))?;
            if !file
                .metadata()
                .await
                .map_err(|_| Error("cannot inspect Kubernetes token file".into()))?
                .is_file()
            {
                return Err(Error("Kubernetes token must be a regular file".into()));
            }
            let mut token = String::new();
            let mut bounded = tokio::io::AsyncReadExt::take(file, 16_385);
            tokio::io::AsyncReadExt::read_to_string(&mut bounded, &mut token)
                .await
                .map_err(|_| Error("cannot read Kubernetes token file".into()))?;
            if token.len() > 16_384 {
                return Err(Error("invalid Kubernetes token file size".into()));
            }
            let token = token.trim();
            if token.is_empty() || token.len() > 16_384 {
                return Err(Error("invalid Kubernetes token file size".into()));
            }
            let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error("invalid Kubernetes bearer token".into()))?;
            header.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, header);
        }
        Ok(request)
    }
    async fn open(&self, scope: &Scope, query: &Query<'_>) -> Result<Reader, Error> {
        let response = self
            .client
            .send(self.request(scope, query).await?)
            .await
            .map_err(|_| Error("Kubernetes request failed; relist required".into()))?;
        // request_stream collects an error body before returning. Use send to
        // prevent an untrusted HTTP error body bypassing our byte bounds.
        if !response.status().is_success() {
            return Err(Error(format!(
                "Kubernetes HTTP {}; relist required",
                response.status().as_u16()
            )));
        }
        let stream = response
            .into_body()
            .into_data_stream()
            .map_err(io::Error::other)
            .into_async_read();
        Ok(Box::pin(stream))
    }
    pub async fn list(&self, scope: &Scope, query: &Query<'_>) -> Result<Value, Error> {
        if query.watch {
            return Err(Error("list request cannot enable watch".into()));
        }
        tokio::time::timeout(self.limits.timeout, async {
            read_list(self.open(scope, query).await?, self.limits.list_bytes).await
        })
        .await
        .map_err(|_| Error("Kubernetes list timeout; relist required".into()))?
    }
    pub async fn watch(
        &self,
        scope: &Scope,
        query: &Query<'_>,
    ) -> Result<JsonFrames<Reader>, Error> {
        if !query.watch {
            return Err(Error("watch request must enable watch".into()));
        }
        let reader = tokio::time::timeout(self.limits.timeout, self.open(scope, query))
            .await
            .map_err(|_| Error("Kubernetes watch connection timeout; relist required".into()))??;
        JsonFrames::new(reader, self.limits.frame_bytes, self.limits.timeout)
    }
}

/// Bound raw bytes before JSON decoding, including whitespace.
pub async fn read_list(reader: impl AsyncRead + Unpin, limit: usize) -> Result<Value, Error> {
    let take = limit
        .checked_add(1)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| Error("invalid list byte limit".into()))?;
    let mut bytes = Vec::new();
    reader
        .take(take)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Error("Kubernetes list read failed".into()))?;
    if bytes.len() > limit {
        return Err(Error("Kubernetes list exceeds raw byte limit".into()));
    }
    serde_json::from_slice(&bytes).map_err(|_| Error("invalid Kubernetes list JSON".into()))
}

pub struct JsonFrames<R> {
    reader: R,
    limit: usize,
    timeout: Duration,
    failed: bool,
    // State belongs to the reader, not the next() future: dropping a pending
    // call must preserve consumed bytes, byte accounting and its deadline.
    bytes: Vec<u8>,
    deadline: Option<tokio::time::Instant>,
}
impl<R: AsyncBufRead + Unpin> JsonFrames<R> {
    pub fn new(reader: R, limit: usize, timeout: Duration) -> Result<Self, Error> {
        if limit == 0 || timeout.is_zero() {
            return Err(Error("frame limits must be positive".into()));
        }
        Ok(Self {
            reader,
            limit,
            timeout,
            failed: false,
            bytes: Vec::new(),
            deadline: None,
        })
    }
    /// EOF, timeout, malformed input and ERROR events are terminal; relist.
    /// Cancelling a pending call preserves the incomplete frame and deadline.
    pub async fn next(&mut self) -> Result<Value, Error> {
        if self.failed {
            return Err(Error("watch failed; relist required".into()));
        }
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.timeout)
                    .ok_or_else(|| Error("watch timeout exceeds clock range".into()))?;
                self.deadline = Some(deadline);
                deadline
            }
        };
        let result = tokio::time::timeout_at(deadline, self.read_frame())
            .await
            .map_err(|_| Error("watch frame timeout; relist required".into()))
            .and_then(|result| result);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn read_frame(&mut self) -> Result<Value, Error> {
        loop {
            let chunk = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| Error("watch read failed; relist required".into()))?;
            if chunk.is_empty() {
                return Err(Error(WATCH_ENDED.into()));
            }
            let newline = chunk.iter().position(|b| *b == b'\n');
            let length = newline.map_or(chunk.len(), |n| n.saturating_add(1));
            if self
                .bytes
                .len()
                .checked_add(length)
                .is_none_or(|n| n > self.limit)
            {
                return Err(Error(
                    "watch exceeds raw frame limit; relist required".into(),
                ));
            }
            self.bytes.extend_from_slice(
                chunk
                    .get(..length)
                    .ok_or_else(|| Error("invalid watch frame".into()))?,
            );
            self.reader.consume_unpin(length);
            if newline.is_some() {
                let value: Value = serde_json::from_slice(&self.bytes)
                    .map_err(|_| Error("invalid watch JSON; relist required".into()))?;
                if value.get("type").and_then(Value::as_str) == Some("ERROR") {
                    return Err(Error(
                        "Kubernetes watch ERROR event; relist required".into(),
                    ));
                }
                self.bytes.clear();
                self.deadline = None;
                return Ok(value);
            }
        }
    }
}
