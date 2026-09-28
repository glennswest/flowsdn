use flowsdn_k8s::{client::{JsonClient, JsonFrames, Query, TransportLimits, read_list, request_uri}, watch::Scope};
use futures::io::{BufReader, Cursor};
use std::time::Duration;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
}
#[test]
fn request_paths_and_opaque_values_are_encoded() {
    assert_eq!(request_uri(&Scope::Nodes, &Query::default()).expect("URI"), "/api/v1/nodes");
    let query = Query { limit: Some(200), continue_token: Some("next+/=&"), resource_version: Some("rv?&"), label_selector: Some("app in (web,api)"), watch: false };
    assert_eq!(request_uri(&Scope::LocalPods { node_name: "worker-1.example".into() }, &query).expect("URI"),
        "/api/v1/pods?fieldSelector=spec.nodeName%3Dworker-1.example&labelSelector=app%20in%20%28web%2Capi%29&limit=200&continue=next%2B%2F%3D%26&resourceVersion=rv%3F%26");
    let query = Query { watch: true, resource_version: Some("opaque"), ..Query::default() };
    let uri = request_uri(&Scope::Nodes, &query).expect("URI");
    assert!(uri.contains("watch=true&allowWatchBookmarks=true&timeoutSeconds=60"));
    assert!(request_uri(&Scope::LocalPods { node_name: "node,other=value".into() }, &query).is_err());
    assert!(request_uri(&Scope::Nodes, &Query { watch: true, limit: Some(1), ..Query::default() }).is_err());
}
#[test]
fn list_bound_applies_before_decoding_whitespace() {
    runtime().block_on(async {
        assert_eq!(read_list(Cursor::new(b"{}"), 2).await.expect("JSON"), serde_json::json!({}));
        assert!(read_list(Cursor::new(b"{} "), 2).await.expect_err("bound").0.contains("raw byte limit"));
        assert!(read_list(Cursor::new(b"{"), 10).await.is_err());
    });
}
#[test]
fn split_frames_bound_newline_and_are_terminal_on_errors() {
    runtime().block_on(async {
        let reader = BufReader::with_capacity(2, Cursor::new(b"{}\n{}\n"));
        let mut frames = JsonFrames::new(reader, 3, Duration::from_secs(1)).expect("frames");
        assert_eq!(frames.next().await.expect("first"), serde_json::json!({}));
        assert_eq!(frames.next().await.expect("second"), serde_json::json!({}));
        assert!(frames.next().await.expect_err("EOF").0.contains("ended"));
        assert!(frames.next().await.expect_err("terminal").0.contains("failed"));
        let mut frames = JsonFrames::new(Cursor::new(b"{} \n{}\n"), 3, Duration::from_secs(1)).expect("frames");
        assert!(frames.next().await.expect_err("bound").0.contains("raw frame limit"));
        assert!(frames.next().await.expect_err("terminal").0.contains("failed"));
        for bytes in [b"{".as_slice(), b"{\n", b"{\"type\":\"ERROR\",\"object\":{\"code\":410}}\n"] {
            let mut frames = JsonFrames::new(Cursor::new(bytes), 100, Duration::from_secs(1)).expect("frames");
            assert!(frames.next().await.is_err());
        }
    });
}
#[test]
fn stalled_frame_times_out() {
    runtime().block_on(async {
        let reader = futures::stream::pending::<Result<Vec<u8>, std::io::Error>>();
        use futures::TryStreamExt;
        let mut frames = JsonFrames::new(reader.into_async_read(), 100, Duration::from_millis(1)).expect("frames");
        assert!(frames.next().await.expect_err("timeout").0.contains("timeout"));
    });
}
#[test]
fn rejects_insecure_configuration_before_client_creation() {
    for (url, invalid) in [("http://api.invalid", false), ("https://api.invalid", true)] {
        let mut config = kube::Config::new(url.parse().expect("URI"));
        config.accept_invalid_certs = invalid;
        assert!(JsonClient::from_config(config, TransportLimits::default()).is_err());
    }
}
#[test]
fn token_file_is_reread_for_each_request() {
    runtime().block_on(async {
        let root = std::env::var_os("TMPDIR").map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp"));
        std::fs::create_dir_all(&root).expect("scratch root");
        let path = root.join(format!("k8s-token-test-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).expect("unique token file");
        use std::io::Write;
        file.write_all(b"first-token\n").expect("fixture token");
        let mut config = kube::Config::new("https://api.invalid".parse().expect("URI"));
        let link = path.with_extension("projected");
        std::os::unix::fs::symlink(&path, &link).expect("projected token symlink");
        config.auth_info.token_file = Some(link.to_string_lossy().into_owned());
        let client = JsonClient::from_config(config, TransportLimits::default()).expect("client");
        let request = client.request(&Scope::Nodes, &Query::default()).await.expect("request");
        assert_eq!(request.headers().get("accept").expect("accept"), "application/json");
        assert_eq!(request.headers().get("authorization").expect("auth"), "Bearer first-token");
        assert!(request.headers().get("authorization").expect("auth").is_sensitive());
        std::fs::write(&path, b"second-token").expect("rotate");
        assert_eq!(client.request(&Scope::Nodes, &Query::default()).await.expect("request").headers().get("authorization").expect("auth"), "Bearer second-token");
        std::fs::remove_file(&path).expect("remove fixture");
        std::fs::create_dir(&path).expect("nonregular token fixture");
        let error = client.request(&Scope::Nodes, &Query::default()).await.expect_err("reject directory");
        assert_eq!(error.0, "Kubernetes token must be a regular file");
        std::fs::remove_dir(&path).expect("remove directory");
        std::fs::remove_file(link).expect("remove symlink");
        assert!(client.request(&Scope::Nodes, &Query::default()).await.is_err());
    });
}

#[test]
fn cancelled_next_preserves_frame_bytes_and_limit() {
    use futures::{FutureExt, TryStreamExt};
    use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, task::Poll};
    runtime().block_on(async {
        for limit in [100, 8] {
            let released = Arc::new(AtomicBool::new(false));
            let gate = released.clone();
            let mut first = true;
            let mut last = false;
            let stream = futures::stream::poll_fn(move |_| {
                if first {
                    first = false;
                    return Poll::Ready(Some(Ok::<_, std::io::Error>(b"{\"ok\":".to_vec())));
                }
                if !gate.load(Ordering::Relaxed) { return Poll::Pending; }
                if last { return Poll::Ready(None); }
                last = true;
                Poll::Ready(Some(Ok(b"true}\n".to_vec())))
            });
            let mut frames = JsonFrames::new(stream.into_async_read(), limit, Duration::from_secs(1)).expect("frames");
            // Poll consumes the first fragment, then drops the pending future.
            assert!(frames.next().now_or_never().is_none());
            released.store(true, Ordering::Relaxed);
            if limit == 100 {
                assert_eq!(frames.next().await.expect("resumed frame"), serde_json::json!({"ok": true}));
            } else {
                assert!(frames.next().await.expect_err("combined frame limit").0.contains("raw frame limit"));
            }
        }
    });
}
