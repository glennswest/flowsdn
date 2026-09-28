//! Loopback-only transport checks; these do not establish cluster acceptance.
use flowsdn_k8s::{
    client::{JsonClient, Query, TransportLimits},
    watch::Scope,
};
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
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(10);

fn certificate() -> (PKey<Private>, X509) {
    let key =
        PKey::from_rsa(Rsa::generate(2048).expect("fixture RSA key")).expect("fixture private key");
    let mut name = X509NameBuilder::new().expect("certificate name");
    name.append_entry_by_text("CN", "localhost")
        .expect("common name");
    let name = name.build();
    let mut cert = X509::builder().expect("certificate builder");
    cert.set_version(2).expect("X509v3");
    let serial = BigNum::from_u32(1)
        .expect("serial")
        .to_asn1_integer()
        .expect("ASN1 serial");
    cert.set_serial_number(&serial).expect("set serial");
    cert.set_subject_name(&name).expect("subject");
    cert.set_issuer_name(&name).expect("issuer");
    cert.set_pubkey(&key).expect("public key");
    cert.set_not_before(&Asn1Time::days_from_now(0).expect("validity start"))
        .expect("set validity start");
    cert.set_not_after(&Asn1Time::days_from_now(1).expect("validity end"))
        .expect("set validity end");
    cert.append_extension(BasicConstraints::new().critical().ca().build().expect("CA"))
        .expect("CA extension");
    cert.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()
            .expect("key usage"),
    )
    .expect("key usage extension");
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build().expect("EKU"))
        .expect("server authentication extension");
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(None, None))
        .expect("localhost SAN");
    cert.append_extension(san).expect("SAN extension");
    cert.sign(&key, MessageDigest::sha256())
        .expect("certificate signature");
    (key, cert.build())
}

/// Serve at most one request. Both accept and blocking I/O have finite bounds.
fn server(key: &PKey<Private>, cert: &X509) -> (u16, thread::JoinHandle<bool>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("TLS acceptor");
    acceptor.set_private_key(key).expect("server key");
    acceptor.set_certificate(cert).expect("server certificate");
    acceptor.check_private_key().expect("matching key");
    let acceptor = acceptor.build();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let port = listener.local_addr().expect("listener address").port();
    listener.set_nonblocking(true).expect("bounded accept");
    let task = thread::spawn(move || {
        let deadline = Instant::now().checked_add(DEADLINE).expect("deadline");
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "TLS client did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(DEADLINE)).expect("read bound");
        socket
            .set_write_timeout(Some(DEADLINE))
            .expect("write bound");
        let Ok(mut stream) = acceptor.accept(socket) else {
            return false;
        };
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            assert!(Instant::now() < deadline, "HTTP request deadline");
            assert!(request.len() < 16_384, "HTTP request bound");
            let mut buffer = [0_u8; 1024];
            let length = stream.read(&mut buffer).expect("HTTP request");
            assert_ne!(length, 0, "request ended before headers");
            request.extend_from_slice(buffer.get(..length).expect("received bytes"));
        }
        assert!(request.starts_with(b"GET /api/v1/nodes HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"items\":[]}")
            .expect("HTTP response");
        true
    });
    (port, task)
}

fn list(host: &str, port: u16, root: &X509) -> Result<serde_json::Value, flowsdn_k8s::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut config = kube::Config::new(format!("https://{host}:{port}").parse().expect("URI"));
        config.root_cert = Some(vec![root.to_der().expect("trust root")]);
        let client = JsonClient::from_config(
            config,
            TransportLimits {
                timeout: DEADLINE,
                ..TransportLimits::default()
            },
        )?;
        client.list(&Scope::Nodes, &Query::default()).await
    })
}

#[test]
fn trusted_local_https_returns_node_list() {
    let (key, cert) = certificate();
    let (port, task) = server(&key, &cert);
    let result = list("localhost", port, &cert);
    assert!(task.join().expect("server thread"));
    assert_eq!(
        result.expect("verified HTTPS"),
        serde_json::json!({"items": []})
    );
}

#[test]
fn untrusted_ca_is_rejected() {
    let (key, cert) = certificate();
    let (_, other_root) = certificate();
    let (port, task) = server(&key, &cert);
    let result = list("localhost", port, &other_root);
    assert!(!task.join().expect("server thread"));
    assert_eq!(
        result.expect_err("untrusted CA").0,
        "Kubernetes request failed; relist required"
    );
}

#[test]
fn trusted_certificate_with_wrong_hostname_is_rejected() {
    let (key, cert) = certificate();
    let (port, task) = server(&key, &cert);
    // Certificate has only a DNS localhost SAN, never an IP SAN.
    let result = list("127.0.0.1", port, &cert);
    assert!(!task.join().expect("server thread"));
    assert_eq!(
        result.expect_err("hostname mismatch").0,
        "Kubernetes request failed; relist required"
    );
}
