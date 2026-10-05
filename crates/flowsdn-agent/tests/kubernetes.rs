//! The controller against a loopback HTTPS API server: kubeconfig credentials,
//! Node/Pod lists, a watch event, a watch the server ends, and the pool the
//! agent derives. No routes are installed (that needs CAP_NET_ADMIN); this is
//! not cluster acceptance.
#![cfg(feature = "kubernetes")]
use flowsdn_agent::kubernetes::{Settings, controller::Controller, lock};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn certificate() -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA key")).expect("private key");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", "localhost").expect("CN");
    let name = name.build();
    let mut cert = X509::builder().expect("builder");
    cert.set_version(2).expect("v3");
    let serial = BigNum::from_u32(1)
        .expect("serial")
        .to_asn1_integer()
        .expect("serial");
    cert.set_serial_number(&serial).expect("serial");
    cert.set_subject_name(&name).expect("subject");
    cert.set_issuer_name(&name).expect("issuer");
    cert.set_pubkey(&key).expect("public key");
    cert.set_not_before(&Asn1Time::days_from_now(0).expect("start"))
        .expect("start");
    cert.set_not_after(&Asn1Time::days_from_now(1).expect("end"))
        .expect("end");
    cert.append_extension(BasicConstraints::new().critical().ca().build().expect("CA"))
        .expect("CA");
    cert.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()
            .expect("usage"),
    )
    .expect("usage");
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build().expect("EKU"))
        .expect("EKU");
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(None, None))
        .expect("SAN");
    cert.append_extension(san).expect("SAN");
    cert.sign(&key, MessageDigest::sha256()).expect("sign");
    (key, cert.build())
}

fn node(name: &str, rv: &str, cidrs: &[&str], ips: &[&str]) -> serde_json::Value {
    let addresses: Vec<_> = ips
        .iter()
        .map(|ip| json!({"type":"InternalIP","address":ip}))
        .collect();
    json!({"metadata":{"name":name,"uid":format!("uid-{name}"),"resourceVersion":rv},
        "spec":{"podCIDRs":cidrs},"status":{"addresses":addresses}})
}

/// Each connection is answered on its own thread: lists, one node watch event
/// then the end of that watch, and later watches held open.
fn server(key: PKey<Private>, cert: X509, watches: Arc<AtomicUsize>) -> u16 {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("acceptor");
    acceptor.set_private_key(&key).expect("key");
    acceptor.set_certificate(&cert).expect("certificate");
    let acceptor = Arc::new(acceptor.build());
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = listener.local_addr().expect("address").port();
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { continue };
            let acceptor = Arc::clone(&acceptor);
            let watches = Arc::clone(&watches);
            thread::spawn(move || {
                let Ok(mut stream) = acceptor.accept(socket) else {
                    return;
                };
                let mut request = Vec::new();
                while !request.windows(4).any(|b| b == b"\r\n\r\n") {
                    let mut buffer = [0_u8; 1024];
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(buffer.get(..n).unwrap_or_default()),
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                assert!(
                    String::from_utf8_lossy(&request).contains("Bearer test-token"),
                    "credentials from the kubeconfig"
                );
                let nodes = line.starts_with("GET /api/v1/nodes");
                if line.contains("watch=true") {
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(head.as_bytes());
                    if nodes && watches.fetch_add(1, Ordering::SeqCst) == 0 {
                        let peer = node(
                            "peer",
                            "11",
                            &["10.173.0.0/16"],
                            &["192.0.2.173", "2001:db8::173"],
                        );
                        let event = json!({"type":"MODIFIED","object":peer});
                        let _ = stream.write_all(format!("{event}\n").as_bytes());
                        let _ = stream.flush();
                        // The server ends this watch; the agent resumes from rv 11.
                        let _ = stream.shutdown();
                        return;
                    }
                    let _ = stream.flush();
                    thread::sleep(Duration::from_secs(30));
                    return;
                }
                let body = if nodes {
                    json!({"metadata":{"resourceVersion":"10"},"items":[
                        node("local", "8", &[], &["192.0.2.172"]),
                        node("peer", "9", &[], &["192.0.2.173"]),
                    ]})
                } else {
                    json!({"metadata":{"resourceVersion":"20"},"items":[
                        {"metadata":{"name":"web","namespace":"ns","uid":"p1","resourceVersion":"19",
                            "labels":{"app":"web"}},
                         "spec":{"nodeName":"peer"},"status":{"podIPs":[{"ip":"10.173.0.5"}]}}
                    ]})
                }
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown();
            });
        }
    });
    port
}

#[test]
fn controller_lists_watches_and_derives_the_pool() {
    let dir = std::env::temp_dir().join(format!("flowsdn-k8s-agent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let (key, cert) = certificate();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, cert.to_pem().expect("PEM")).expect("CA file");
    let watches = Arc::new(AtomicUsize::new(0));
    let port = server(key, cert, Arc::clone(&watches));
    let kubeconfig = dir.join("kubeconfig");
    std::fs::write(
        &kubeconfig,
        format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://localhost:{port}\n    certificate-authority: {}\nusers:\n- name: u\n  user:\n    token: test-token\ncontexts:\n- name: x\n  context:\n    cluster: c\n    user: u\ncurrent-context: x\n",
            ca.display()
        ),
    )
    .expect("kubeconfig");
    let settings = Settings {
        node_name: "local".into(),
        kubeconfig: Some(PathBuf::from(&kubeconfig)),
        auto_direct_node_routes: false,
        skip_unreachable: false,
    };
    let controller = Controller::connect(settings, &dir).expect("connect");
    let (pool4, pool6) = controller.wait_for_pools(true, true).expect("pools");
    assert_eq!(pool4, Some(("10.172.0.0".parse().expect("IP"), 16)));
    // No node IPv6, so IPv6 derives from the IPv4 alloc CIDR.
    assert_eq!(pool6, Some(("f00d::aac:0:0:0".parse().expect("IP"), 96)));
    let view = controller.spawn().expect("spawn");
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(20))
        .expect("deadline");
    loop {
        {
            let view = lock(&view);
            let peer_v6 = view
                .nodes
                .iter()
                .any(|n| n.name == "peer" && n.internal_ips.len() == 2);
            if view.nodes_synced && view.pods_synced && peer_v6 && watches.load(Ordering::SeqCst) >= 2 {
                assert_eq!(view.health().get("state"), Some(&json!("Ok")));
                let ips = view.ip_list();
                let rows = ips.as_array().expect("rows");
                let pod = rows
                    .iter()
                    .find(|r| r.get("cidr") == Some(&json!("10.173.0.5/32")))
                    .expect("pod row");
                assert_eq!(pod.get("hostIP"), Some(&json!("192.0.2.173")));
                assert_eq!(
                    rows.iter()
                        .filter(|r| r.get("identity") == Some(&json!(6)))
                        .count(),
                    2,
                    "the peer's two InternalIPs are remote-node"
                );
                assert!(view.routes.is_empty(), "auto-direct-node-routes is off");
                break;
            }
        }
        assert!(Instant::now() < deadline, "controller did not converge");
        thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
