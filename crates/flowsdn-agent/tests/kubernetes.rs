//! The controller against a loopback HTTPS API server: kubeconfig credentials,
//! Node/Pod lists, a watch event, a watch the server ends, the pool the
//! agent derives, and a FlowsdnIdentity created for the local Pod while the
//! remote Pod resolves to an existing one. No routes are installed (that
//! needs CAP_NET_ADMIN); this is not cluster acceptance.
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
        Arc, Mutex,
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
fn server(
    key: PKey<Private>,
    cert: X509,
    watches: Arc<AtomicUsize>,
    created: Arc<Mutex<Vec<serde_json::Value>>>,
) -> u16 {
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
            let created = Arc::clone(&created);
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
                if line.starts_with("POST /apis/flowsdn.io/v1alpha1/flowsdnidentities ") {
                    let text = String::from_utf8_lossy(&request).into_owned();
                    let length: usize = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_owned())
                        })
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let start = request
                        .windows(4)
                        .position(|b| b == b"\r\n\r\n")
                        .map_or(request.len(), |p| p.saturating_add(4));
                    let mut body = request.get(start..).unwrap_or_default().to_vec();
                    while body.len() < length {
                        let mut buffer = [0_u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => body.extend_from_slice(buffer.get(..n).unwrap_or_default()),
                        }
                    }
                    let value: serde_json::Value =
                        serde_json::from_slice(&body).expect("identity JSON");
                    created.lock().expect("created").push(value.clone());
                    let body = value.to_string();
                    let response = format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.shutdown();
                    return;
                }
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
                let body = if line.starts_with("GET /api/v1/services") {
                    json!({"metadata":{"resourceVersion":"30"},"items":[
                        {"metadata":{"name":"kube-dns","namespace":"kube-system","uid":"s1","resourceVersion":"29"},
                         "spec":{"clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10"],
                            "ports":[{"name":"dns","protocol":"UDP","port":53},
                                     {"name":"dns-tcp","protocol":"TCP","port":53}]}}
                    ]})
                } else if line.starts_with("GET /apis/discovery.k8s.io/v1/endpointslices") {
                    json!({"metadata":{"resourceVersion":"40"},"items":[
                        {"metadata":{"name":"kube-dns-1","namespace":"kube-system","uid":"e1","resourceVersion":"39",
                            "labels":{"kubernetes.io/service-name":"kube-dns"}},
                         "addressType":"IPv4",
                         "endpoints":[{"addresses":["10.173.0.53"],"conditions":{"ready":true}}],
                         "ports":[{"name":"dns","protocol":"UDP","port":53},
                                  {"name":"dns-tcp","protocol":"TCP","port":53}]}
                    ]})
                } else if line.starts_with("GET /api/v1/namespaces") {
                    json!({"metadata":{"resourceVersion":"50"},"items":[
                        {"metadata":{"name":"ns","uid":"n1","resourceVersion":"49",
                            "labels":{"kubernetes.io/metadata.name":"ns"}}}
                    ]})
                } else if line.starts_with("GET /apis/flowsdn.io/v1alpha1/flowsdnidentities") {
                    json!({"metadata":{"resourceVersion":"60"},"items":[
                        {"apiVersion":"flowsdn.io/v1alpha1","kind":"FlowsdnIdentity",
                         "metadata":{"name":"5000","uid":"i1","resourceVersion":"59",
                            "creationTimestamp":"2026-10-09T10:00:00Z"},
                         "security-labels":{"k8s:app":"web",
                            "k8s:io.flowsdn.k8s.namespace.labels.kubernetes.io/metadata.name":"ns",
                            "k8s:io.flowsdn.k8s.policy.cluster":"default",
                            "k8s:io.kubernetes.pod.namespace":"ns"}}
                    ]})
                } else if nodes {
                    json!({"metadata":{"resourceVersion":"10"},"items":[
                        node("local", "8", &[], &["192.0.2.172"]),
                        node("peer", "9", &[], &["192.0.2.173"]),
                    ]})
                } else {
                    json!({"metadata":{"resourceVersion":"20"},"items":[
                        {"metadata":{"name":"web","namespace":"ns","uid":"p1","resourceVersion":"19",
                            "labels":{"app":"web"}},
                         "spec":{"nodeName":"peer"},"status":{"podIPs":[{"ip":"10.173.0.5"}]}},
                        {"metadata":{"name":"api","namespace":"ns","uid":"p2","resourceVersion":"18",
                            "labels":{"app":"api"}},
                         "spec":{"nodeName":"local","serviceAccountName":"api"},
                         "status":{"podIPs":[{"ip":"10.172.0.7"}]}}
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
    let created = Arc::new(Mutex::new(Vec::new()));
    let port = server(key, cert, Arc::clone(&watches), Arc::clone(&created));
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
        service_lb: true,
        cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        node_port: false,
        identity_allocation: true,
        cluster_name: "default".into(),
    };
    let controller = Controller::connect(settings, &dir).expect("connect");
    let (pool4, pool6) = controller.wait_for_pools(true, true).expect("pools");
    assert_eq!(pool4, Some(("10.172.0.0".parse().expect("IP"), 16)));
    // No node IPv6, so IPv6 derives from the IPv4 alloc CIDR.
    assert_eq!(pool6, Some(("f00d::aac:0:0:0".parse().expect("IP"), 96)));
    // No socket-lb object: Services and EndpointSlices are watched, nothing
    // is attached (that needs CAP_BPF and a cgroup).
    let view = controller.spawn(false, None, None).expect("spawn");
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
            if view.nodes_synced
                && view.pods_synced
                && view.services_synced
                && view.slices_synced
                && peer_v6
                && watches.load(Ordering::SeqCst) >= 2
                && view.identities_synced
                && view.pod_identities.len() == 2
            {
                // Unprivileged test runs cannot write /proc/sys; nothing else failed.
                assert!(
                    view.errors.keys().all(|part| part == "sysctl"),
                    "{:?}",
                    view.errors
                );
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
                let dns: Vec<_> = view
                    .frontends
                    .iter()
                    .map(|f| {
                        let backends: Vec<_> =
                            f.service.backends.iter().map(ToString::to_string).collect();
                        format!("{} -> {}", f.service.frontend, backends.join(","))
                    })
                    .collect();
                assert_eq!(
                    dns,
                    vec![
                        "10.96.0.10:53/TCP -> 10.173.0.53:53/TCP",
                        "10.96.0.10:53/UDP -> 10.173.0.53:53/UDP"
                    ]
                );
                assert!(view.service_ids.is_empty(), "nothing is programmed");
                // The remote Pod has the existing object; the local one a new number.
                assert_eq!(pod.get("identity"), Some(&json!(5000)));
                let local = view.pod_identity("ns", "api").expect("local identity");
                assert!((256..=65_535).contains(&local) && local != 5000);
                let created = created.lock().expect("created").clone();
                assert_eq!(
                    created.len(),
                    1,
                    "one create, no recreate before it is listed"
                );
                let body = created.first().expect("create body");
                assert_eq!(
                    body.pointer("/metadata/name"),
                    Some(&json!(local.to_string()))
                );
                assert_eq!(
                    body.get("security-labels"),
                    Some(&json!({"k8s:app":"api",
                        "k8s:io.flowsdn.k8s.namespace.labels.kubernetes.io/metadata.name":"ns",
                        "k8s:io.flowsdn.k8s.policy.cluster":"default",
                        "k8s:io.flowsdn.k8s.policy.serviceaccount":"api",
                        "k8s:io.kubernetes.pod.namespace":"ns"}))
                );
                let identities = view.identity_list();
                assert_eq!(identities.as_array().map(Vec::len), Some(2));
                break;
            }
        }
        assert!(Instant::now() < deadline, "controller did not converge");
        thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
