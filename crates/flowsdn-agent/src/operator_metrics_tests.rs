#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;

fn sample<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find(|l| l.split([' ', '{']).next() == Some(name))
        .and_then(|l| l.rsplit(' ').next())
}

#[test]
fn every_series_is_named_typed_and_from_the_stats() {
    let stats = Stats {
        leading: true,
        crds_established: Some(22),
        identity_gc_runs: 3,
        identities_alive: Some(40),
        identities_deleted: 2,
        nodes_deleted: 1,
        bgp_enabled: true,
        bgp_errors: 1,
        bgp_created: 4,
        ..Stats::default()
    };
    let text = render(&stats);
    assert_eq!(sample(&text, "flowsdn_operator_leader"), Some("1"));
    assert_eq!(
        sample(&text, "flowsdn_operator_crds_established"),
        Some("22")
    );
    assert_eq!(
        sample(&text, "flowsdn_operator_identities_alive"),
        Some("40")
    );
    assert_eq!(
        sample(&text, "flowsdn_operator_identities_deleted_total"),
        Some("2")
    );
    assert_eq!(
        sample(&text, "flowsdn_operator_nodes_deleted_total"),
        Some("1")
    );
    assert_eq!(sample(&text, "flowsdn_operator_bgp_errors"), Some("1"));
    assert_eq!(
        sample(&text, "flowsdn_operator_bgp_node_configs_created_total"),
        Some("4")
    );
    assert!(text.contains("flowsdn_operator_build_info{version=\""));
    // Every sample has its HELP and TYPE, and every name is flowsdn_operator_.
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let name = line.split([' ', '{']).next().unwrap();
        assert!(name.starts_with("flowsdn_operator_"), "{name}");
        assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
        assert!(text.contains(&format!("# HELP {name} ")), "{name}");
    }
    // Counters are counters, and a gauge not yet observed is left out.
    assert!(text.contains("# TYPE flowsdn_operator_identities_deleted_total counter"));
    let fresh = render(&Stats::default());
    assert_eq!(sample(&fresh, "flowsdn_operator_leader"), Some("0"));
    assert!(sample(&fresh, "flowsdn_operator_crds_established").is_none());
    assert!(
        sample(&fresh, "flowsdn_operator_bgp_errors").is_none(),
        "BGP off: no BGP gauge"
    );
}

#[test]
fn only_get_metrics_is_answered() {
    let stats = Stats::default();
    let status = |request: &str| -> String {
        let reply = String::from_utf8(answer(request.as_bytes(), &stats)).unwrap();
        reply.lines().next().unwrap().to_owned()
    };
    assert_eq!(status("GET /metrics HTTP/1.1\r\n\r\n"), "HTTP/1.1 200 OK");
    assert_eq!(status("GET /metrics HTTP/1.0\r\n\r\n"), "HTTP/1.1 200 OK");
    assert_eq!(status("GET / HTTP/1.1\r\n\r\n"), "HTTP/1.1 404 Not Found");
    assert_eq!(
        status("POST /metrics HTTP/1.1\r\n\r\n"),
        "HTTP/1.1 405 Method Not Allowed"
    );
    assert_eq!(
        status("GET /metrics HTTP/2.0\r\n\r\n"),
        "HTTP/1.1 400 Bad Request"
    );
    assert_eq!(status(""), "HTTP/1.1 400 Bad Request");
    let reply = String::from_utf8(answer(b"GET /metrics HTTP/1.1\r\n\r\n", &stats)).unwrap();
    assert!(reply.contains("Content-Type: text/plain; version=0.0.4"));
    let (head, body) = reply.split_once("\r\n\r\n").unwrap();
    assert!(head.contains(&format!("Content-Length: {}", body.len())));
}

#[test]
fn the_listen_address_is_loopback_with_a_port() {
    assert_eq!(
        parse_listen("127.0.0.1:9967"),
        Ok("127.0.0.1:9967".parse().unwrap())
    );
    assert!(parse_listen("[::1]:9967").is_ok());
    assert!(parse_listen("192.168.1.2:9967").is_err());
    assert!(parse_listen("127.0.0.1:0").is_err());
    assert!(parse_listen("localhost:9967").is_err());
}

#[test]
fn a_scrape_reads_the_live_stats() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let shared = Shared::default();
    spawn(address, shared.clone()).unwrap();
    shared.lock().nodes_deleted = 7;
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(
        sample(&reply, "flowsdn_operator_nodes_deleted_total"),
        Some("7")
    );
}
