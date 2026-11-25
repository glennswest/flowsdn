//! The controller against a loopback HTTPS API server: kubeconfig credentials,
//! Node/Pod lists, a watch event, a watch the server ends, the pool the
//! agent derives, and a FlowsdnIdentity created for the local Pod while the
//! remote Pod resolves to an existing one. LB-IPAM takes the Lease and
//! writes a LoadBalancer Service's ingress address from a pool (#475). The
//! flowsdn.io watchers wait for their CRDs (#337: a metadata-only list that
//! lacks FlowsdnIdentity's CRD at first). No
//! routes are installed (that needs CAP_NET_ADMIN); this is not cluster
//! acceptance.
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

/// The request body, `Content-Length` bytes after the head.
fn read_body(stream: &mut impl Read, request: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(request).into_owned();
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
            Ok(0) | Err(_) => return None,
            Ok(n) => body.extend_from_slice(buffer.get(..n).unwrap_or_default()),
        }
    }
    Some(body)
}

/// Writes other than FlowsdnIdentity creates: (method, path, body).
type Writes = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;
const LEASE: &str = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases";

/// Each connection is answered on its own thread: lists, one node watch event
/// then the end of that watch, and later watches held open.
fn server(
    key: PKey<Private>,
    cert: X509,
    watches: Arc<AtomicUsize>,
    created: Arc<Mutex<Vec<serde_json::Value>>>,
    writes: Writes,
    crd_served_at: Instant,
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
            let writes = Arc::clone(&writes);
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
                // The agent's CRD gate (#337): a metadata-only list, without
                // FlowsdnIdentity's CRD until it is served.
                if line.starts_with("GET /apis/apiextensions.k8s.io/v1/customresourcedefinitions") {
                    assert!(
                        String::from_utf8_lossy(&request).contains("as=PartialObjectMetadataList"),
                        "the CRD list asks for metadata only"
                    );
                    let mut names = vec![
                        "flowsdnloadbalancerippools.flowsdn.io",
                        "flowsdnendpoints.flowsdn.io",
                        "flowsdnnodes.flowsdn.io",
                    ];
                    if Instant::now() >= crd_served_at {
                        names.push("flowsdnidentities.flowsdn.io");
                    }
                    let items: Vec<_> = names
                        .iter()
                        .map(|n| json!({"metadata": {"name": n}}))
                        .collect();
                    let body = json!({"kind": "PartialObjectMetadataList",
                        "metadata": {"resourceVersion": "5"}, "items": items})
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }
                // The FlowsdnNodeConfig source (#480): this Node's labels and
                // the configs of kube-system.
                if line.starts_with("GET /api/v1/nodes/local ")
                    || line.starts_with(
                        "GET /apis/flowsdn.io/v1alpha1/namespaces/kube-system/flowsdnnodeconfigs ",
                    )
                {
                    let body = if line.contains("/nodes/local") {
                        json!({"metadata": {"name": "local", "labels": {"edge": "yes"}}})
                    } else {
                        json!({"items": [{"metadata": {"name": "edge"}, "spec": {
                            "nodeSelector": {"matchLabels": {"edge": "yes"}},
                            "defaults": {"kubernetes.lb-mode": "dsr"}}}]})
                    }
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }
                // At the start of a boot the kind is not served yet (#397).
                if line.starts_with("GET /apis/flowsdn.io/v1alpha1/flowsdnidentities")
                    && Instant::now() < crd_served_at
                {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    return;
                }
                if line.starts_with("POST /apis/flowsdn.io/v1alpha1/flowsdnidentities ") {
                    let Some(body) = read_body(&mut stream, &request) else {
                        return;
                    };
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
                let mut words = line.split(' ');
                let (method, path) = (
                    words.next().unwrap_or_default().to_owned(),
                    words.next().unwrap_or_default().to_owned(),
                );
                // The LB-IPAM Lease: 404 until created, then the last write.
                if method == "GET" && path.starts_with(LEASE) {
                    let lease = writes
                        .lock()
                        .expect("writes")
                        .iter()
                        .rev()
                        .find(|(_, p, _)| p.starts_with(LEASE))
                        .map(|(_, _, body)| body.clone());
                    let response = match lease {
                        Some(mut lease) => {
                            if let Some(metadata) =
                                lease.get_mut("metadata").and_then(|m| m.as_object_mut())
                            {
                                metadata.insert("resourceVersion".into(), json!("70"));
                            }
                            let body = lease.to_string();
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                        }
                        None => {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_owned()
                        }
                    };
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }
                if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
                    let Some(body) = read_body(&mut stream, &request) else {
                        return;
                    };
                    let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
                    writes
                        .lock()
                        .expect("writes")
                        .push((method, path, value.clone()));
                    let body = value.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
                                     {"name":"dns-tcp","protocol":"TCP","port":53}]}},
                        {"metadata":{"name":"edge-lb","namespace":"storefront","uid":"s2","resourceVersion":"31",
                            "creationTimestamp":"2026-11-19T10:00:00Z"},
                         "spec":{"type":"LoadBalancer","clusterIP":"10.96.0.80","clusterIPs":["10.96.0.80"],
                            "externalTrafficPolicy":"Local",
                            "ports":[{"name":"http","protocol":"TCP","port":80,"nodePort":30080}]}}
                    ]})
                } else if line.starts_with("GET /apis/flowsdn.io/v1alpha1/flowsdnloadbalancerippools") {
                    json!({"metadata":{"resourceVersion":"80"},"items":[
                        {"apiVersion":"flowsdn.io/v1alpha1","kind":"FlowsdnLoadBalancerIPPool",
                         "metadata":{"name":"lan","uid":"lp1","resourceVersion":"79",
                            "creationTimestamp":"2026-11-01T00:00:00Z"},
                         "spec":{"blocks":[{"start":"192.0.2.240","stop":"192.0.2.250"}]}}
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

/// What [`controller_body`] is doing, for the watchdog's message (#555).
const PHASES: [&str; 6] = [
    "starting the mock API server",
    "reading the FlowsdnNodeConfig source",
    "connecting (the CRD gate)",
    "waiting for the Node's pool (wait_for_pools)",
    "converging after spawn",
    "done",
];

/// #555: the body once ran for 30+ minutes in sc-build without failing, and
/// passed on the next run. It now runs on its own thread under a watchdog: a
/// recurrence fails within [`WATCHDOG`], naming the phase it was in, instead
/// of holding the build.
const WATCHDOG: Duration = Duration::from_secs(240);

#[test]
fn controller_lists_watches_and_derives_the_pool() {
    let phase = Arc::new(AtomicUsize::new(0));
    let (done, finished) = std::sync::mpsc::channel();
    let body_phase = Arc::clone(&phase);
    let body = thread::spawn(move || {
        controller_body(&body_phase);
        let _ = done.send(());
    });
    match finished.recv_timeout(WATCHDOG) {
        Ok(()) => {}
        // The body panicked: its own message, from the join below.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let at = PHASES
                .get(phase.load(Ordering::SeqCst))
                .copied()
                .unwrap_or("unknown");
            panic!("the controller test hung for {WATCHDOG:?} while {at} (#555)");
        }
    }
    if let Err(panic) = body.join() {
        std::panic::resume_unwind(panic);
    }
}

fn controller_body(phase: &AtomicUsize) {
    let dir = std::env::temp_dir().join(format!("flowsdn-k8s-agent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let (key, cert) = certificate();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, cert.to_pem().expect("PEM")).expect("CA file");
    let watches = Arc::new(AtomicUsize::new(0));
    let created = Arc::new(Mutex::new(Vec::new()));
    let writes: Writes = Arc::new(Mutex::new(Vec::new()));
    // Late enough that doubling from 1 s (retries at 0, 1, 3, 7, 15 s) would be 7 s
    // late; #397's target is within 2 s.
    let crd_served_at = Instant::now()
        .checked_add(Duration::from_secs(8))
        .expect("CRD time");
    let port = server(
        key,
        cert,
        Arc::clone(&watches),
        Arc::clone(&created),
        Arc::clone(&writes),
        crd_served_at,
    );
    phase.store(1, Ordering::SeqCst);
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
        lb_mode: Default::default(),
        lb_dsr_dispatch: Default::default(),
        nat46x64: false,
        external_clusterip: false,
        node_name: "local".into(),
        kubeconfig: Some(PathBuf::from(&kubeconfig)),
        auto_direct_node_routes: false,
        skip_unreachable: false,
        service_lb: true,
        cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        node_port: false,
        l2_neigh_discovery: false,
        xdp_prefilter: false,
        maglev: false,
        host_firewall: flowsdn_agent::kubernetes::HostFirewall::Off,
        identity_allocation: true,
        network_policy: false,
        flowsdn_policy: false,
        policy_audit: false,
        cluster_name: "default".into(),
        // The uplink monitor runs here too; `single` keeps it from touching
        // the build host's rules on a machine with several ports.
        uplinks: flowsdn_agent::uplinks::Settings {
            mode: flowsdn_agent::uplinks::Mode::Single,
            ..Default::default()
        },
        lb_ipam: true,
        // Needs node-port; answering ARP needs CAP_NET_RAW.
        l2_announcements: false,
        // No endpoint is published here (no API thread), so nothing is written.
        endpoint_crd: true,
        node_crd: true,
        crd_wait_timeout: Duration::from_secs(60),
        drop_events: None,
        terminate_tcp: false,
        bpf_masquerade: false,
        non_masquerade: Vec::new(),
        gateway64: None,
        node_config: serde_json::Value::Null,
    };
    // FlowsdnNodeConfig (#480): the agent reads its Node's labels and the
    // configs of its namespace at start; the edge config selects it.
    let (labels, configs) =
        flowsdn_agent::node_config::fetch(&settings, "kube-system").expect("node configuration");
    assert_eq!(labels.get("edge").map(String::as_str), Some("yes"));
    let (merged, report) =
        flowsdn_agent::node_config::apply(&json!({"kubernetes": {}}), &configs, &labels, &|_| {
            Ok(())
        });
    assert_eq!(report.selected, ["edge"]);
    assert_eq!(merged.pointer("/kubernetes/lb-mode"), Some(&json!("dsr")));
    phase.store(2, Ordering::SeqCst);
    let controller = Controller::connect(settings, &dir).expect("connect");
    phase.store(3, Ordering::SeqCst);
    let (pool4, pool6) = controller.wait_for_pools(true, true).expect("pools");
    assert_eq!(pool4, Some(("10.172.0.0".parse().expect("IP"), 16)));
    // No node IPv6, so IPv6 derives from the IPv4 alloc CIDR.
    assert_eq!(pool6, Some(("f00d::aac:0:0:0".parse().expect("IP"), 96)));
    // No socket-lb object: Services and EndpointSlices are watched, nothing
    // is attached (that needs CAP_BPF and a cgroup).
    let view = controller.spawn(false, None, None, None).expect("spawn");
    phase.store(4, Ordering::SeqCst);
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("deadline");
    let mut identities_at = None;
    loop {
        {
            let view = lock(&view);
            if view.identities_synced && identities_at.is_none() {
                let late = Instant::now().saturating_duration_since(crd_served_at);
                // The gate polls every second (#337), then the list runs.
                assert!(
                    late < Duration::from_secs(3),
                    "identities listed {late:?} after the CRD was served"
                );
                identities_at = Some(late);
            }
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
                && view.lb_ipam_json().get("leader") == Some(&json!(true))
                && writes
                    .lock()
                    .expect("writes")
                    .iter()
                    .any(|(_, path, _)| path.ends_with("/services/edge-lb/status"))
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
                    .filter(|f| f.name == "kube-dns")
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
                // LB-IPAM: the Lease was created as this node, then edge-lb's
                // status patched with the pool's first address, guarded by
                // the Service's resourceVersion, and the pool's conditions.
                let writes = writes.lock().expect("writes").clone();
                let (method, _, lease) = writes
                    .iter()
                    .find(|(_, p, _)| p.starts_with(LEASE))
                    .expect("lease write");
                assert_eq!(method, "POST");
                assert_eq!(lease.pointer("/spec/holderIdentity"), Some(&json!("local")));
                let (method, _, patch) = writes
                    .iter()
                    .find(|(_, p, _)| p == "/api/v1/namespaces/storefront/services/edge-lb/status")
                    .expect("status patch");
                assert_eq!(method, "PATCH");
                assert_eq!(
                    patch,
                    &json!({"metadata":{"resourceVersion":"31"},
                        "status":{"loadBalancer":{"ingress":[{"ip":"192.0.2.240"}]}}})
                );
                assert!(
                    !writes
                        .iter()
                        .any(|(_, p, _)| p.contains("/services/kube-dns")),
                    "a ClusterIP Service is not touched"
                );
                assert!(writes.iter().any(|(m, p, body)| m == "PATCH"
                    && p == "/apis/flowsdn.io/v1alpha1/flowsdnloadbalancerippools/lan/status"
                    && body.pointer("/status/conditions/1/message") == Some(&json!("10"))));
                let status = view.lb_ipam_json();
                assert_eq!(status.pointer("/services/0/name"), Some(&json!("edge-lb")));
                assert_eq!(
                    status.pointer("/services/0/ips/0"),
                    Some(&json!("192.0.2.240"))
                );
                break;
            }
        }
        assert!(Instant::now() < deadline, "controller did not converge");
        thread::sleep(Duration::from_millis(50));
    }
    phase.store(5, Ordering::SeqCst);
    let _ = std::fs::remove_dir_all(&dir);
}
