//! The etcd backend against a live fastetcd (spec 20 §3.1-3.3, §5.3-5.5).
//! Runs only when `FASTETCD_BIN` names a fastetcd binary; otherwise each
//! test prints `skipped: FASTETCD_BIN unset` and passes.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use flowsdn_kvstore::etcd::{EtcdBackend, EtcdConfig};
use flowsdn_kvstore::{Compare, Error, Event, EventKind, Kvstore, Lease, MAX_VALUE, State, TxnPut};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(15);

fn fastetcd() -> Option<String> {
    match std::env::var("FASTETCD_BIN") {
        Ok(bin) if !bin.is_empty() => Some(bin),
        _ => {
            println!("skipped: FASTETCD_BIN unset");
            None
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fastetcd-{name}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Server TLS files and the client CA (§3.8.6 layout, test-generated).
struct ServerTls {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

struct Server {
    _child: tokio::process::Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    async fn start(bin: &str, name: &str, dir: PathBuf, tls: Option<&ServerTls>) -> Self {
        let port = free_port();
        let peer = free_port();
        let metrics = free_port();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let mut command = tokio::process::Command::new(bin);
        command
            .arg("--name")
            .arg(name)
            .arg("--data-dir")
            .arg(dir.join("data"))
            .arg("--listen-client-urls")
            .arg(format!("{scheme}://127.0.0.1:{port}"))
            .arg("--listen-peer-urls")
            .arg(format!("http://127.0.0.1:{peer}"))
            .arg("--listen-metrics-url")
            .arg(format!("127.0.0.1:{metrics}"));
        if let Some(tls) = tls {
            command
                .arg("--cert-file")
                .arg(&tls.cert)
                .arg("--key-file")
                .arg(&tls.key)
                .arg("--trusted-ca-file")
                .arg(&tls.ca)
                .arg("--client-cert-auth");
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "fastetcd did not listen on {port} within 30 s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Self {
            _child: child,
            port,
            dir,
        }
    }

    fn config(&self) -> EtcdConfig {
        EtcdConfig {
            endpoints: vec![format!("http://127.0.0.1:{}", self.port)],
            ..EtcdConfig::default()
        }
    }
}

/// Connect, retrying while the server finishes starting.
async fn connect(config: EtcdConfig) -> EtcdBackend {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match EtcdBackend::connect(config.clone()).await {
            Ok(backend) => return backend,
            Err(e) => {
                assert!(tokio::time::Instant::now() < deadline, "connect: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn next(rx: &mut mpsc::Receiver<Event>) -> Event {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("watch event within 15 s")
        .expect("watch open")
}

#[tokio::test]
async fn kv_operations() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let server = Server::start(&bin, "kv", temp_dir("kv"), None).await;
    let client = connect(EtcdConfig {
        list_limit: 2,
        ..server.config()
    })
    .await;

    client
        .put("t/a", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let a = client.get("t/a", None).await.unwrap().unwrap();
    assert_eq!(a.data, b"1");
    assert_eq!(a.lease_id, 0);
    assert!(a.create_revision > 0 && a.mod_revision >= a.create_revision);
    assert_eq!(client.get("t/missing", None).await.unwrap(), None);

    // put_if_absent: one Txn on Version == 0.
    assert!(
        !client
            .put_if_absent("t/a", b"x".to_vec(), Lease::None, None)
            .await
            .unwrap()
    );
    assert_eq!(client.get("t/a", None).await.unwrap().unwrap().data, b"1");
    assert!(
        client
            .put_if_absent("t/b", b"2".to_vec(), Lease::Attached, None)
            .await
            .unwrap()
    );
    let lease = client.lease_for("t/b").await.unwrap();
    assert_ne!(lease, 0);
    assert_eq!(
        client.get("t/b", None).await.unwrap().unwrap().lease_id,
        lease
    );

    // put_if_different: bytes, then the lease (§3.1 row 4).
    assert!(
        !client
            .put_if_different("t/a", b"1".to_vec(), Lease::None, None)
            .await
            .unwrap()
    );
    assert!(
        client
            .put_if_different("t/a", b"2".to_vec(), Lease::None, None)
            .await
            .unwrap()
    );
    assert!(
        client
            .put_if_different("t/a", b"2".to_vec(), Lease::Attached, None)
            .await
            .unwrap()
    );
    let a = client.get("t/a", None).await.unwrap().unwrap();
    assert_eq!(a.lease_id, client.lease_for("t/a").await.unwrap());
    assert!(
        !client
            .put_if_different("t/a", b"2".to_vec(), Lease::Attached, None)
            .await
            .unwrap()
    );

    // delete is idempotent.
    client.delete("t/a", None).await.unwrap();
    client.delete("t/a", None).await.unwrap();
    assert_eq!(client.get("t/a", None).await.unwrap(), None);

    // list_prefix over four pages of two, at one revision (§5.3).
    for i in 0..7 {
        client
            .put(&format!("p/{i}"), vec![b'0' + i], Lease::None, None)
            .await
            .unwrap();
    }
    client
        .put("p0", b"outside".to_vec(), Lease::None, None)
        .await
        .unwrap();
    client
        .put("q/x", b"outside".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let listed = client.list_prefix("p/", None).await.unwrap();
    let keys: Vec<&str> = listed.keys().map(String::as_str).collect();
    assert_eq!(keys, ["p/0", "p/1", "p/2", "p/3", "p/4", "p/5", "p/6"]);
    assert_eq!(listed["p/3"].data, b"3");
    client.delete_prefix("p/").await.unwrap();
    assert!(client.list_prefix("p/", None).await.unwrap().is_empty());
    assert!(client.get("p0", None).await.unwrap().is_some());
    assert!(client.get("q/x", None).await.unwrap().is_some());

    // txn: compares hold, then fail (§12 decision 9).
    let b = client.get("t/b", None).await.unwrap().unwrap();
    let exact = Compare::Exact {
        key: "t/b".into(),
        data: b.data.clone(),
        mod_revision: b.mod_revision,
        lease_id: b.lease_id,
    };
    let put_c = TxnPut {
        key: "t/c".into(),
        data: b"3".to_vec(),
        lease: Lease::Attached,
    };
    assert!(
        client
            .txn(vec![exact, Compare::Absent("t/c".into())], vec![put_c])
            .await
            .unwrap()
    );
    let c = client.get("t/c", None).await.unwrap().unwrap();
    assert_eq!(c.lease_id, client.lease_for("t/c").await.unwrap());
    let put_d = TxnPut {
        key: "t/d".into(),
        data: b"4".to_vec(),
        lease: Lease::None,
    };
    assert!(
        !client
            .txn(vec![Compare::Absent("t/c".into())], vec![put_d.clone()])
            .await
            .unwrap()
    );
    let stale = Compare::Exact {
        key: "t/b".into(),
        data: b.data,
        mod_revision: b.mod_revision,
        lease_id: 0,
    };
    assert!(!client.txn(vec![stale], vec![put_d]).await.unwrap());
    assert_eq!(client.get("t/d", None).await.unwrap(), None);

    // Values over MAX_VALUE are refused before the wire.
    assert!(matches!(
        client
            .put("t/big", vec![0; MAX_VALUE + 1], Lease::None, None)
            .await,
        Err(Error::TooLarge { .. })
    ));

    client.close().await;
    assert_eq!(client.get("t/b", None).await, Err(Error::Closed));
}

#[tokio::test]
async fn locks_exclude_and_guard() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let server = Server::start(&bin, "locks", temp_dir("locks"), None).await;
    let a = Arc::new(connect(server.config()).await);
    let b = Arc::new(connect(server.config()).await);

    let guard = a.lock("flowsdn/locks/x").await.unwrap();
    assert!(guard.key.starts_with("flowsdn/locks/x/"), "{}", guard.key);
    a.put("g/k", b"1".to_vec(), Lease::None, Some(&guard))
        .await
        .unwrap();
    assert_eq!(
        a.get("g/k", Some(&guard)).await.unwrap().unwrap().data,
        b"1"
    );
    assert_eq!(a.list_prefix("g/", Some(&guard)).await.unwrap().len(), 1);
    assert!(
        !a.put_if_absent("g/k", b"2".to_vec(), Lease::None, Some(&guard))
            .await
            .unwrap()
    );

    // b waits while a holds the lock.
    let contender = Arc::clone(&b);
    let waiting = tokio::spawn(async move { contender.lock("flowsdn/locks/x").await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!waiting.is_finished(), "b took a held lock");

    a.unlock(&guard).await.unwrap();
    let guard_b = tokio::time::timeout(WAIT, waiting)
        .await
        .expect("b acquires after unlock")
        .unwrap()
        .unwrap();
    assert_ne!(guard_b.key, guard.key);

    // a's guard no longer holds (§3.1 rule 2).
    assert_eq!(
        a.put("g/k", b"2".to_vec(), Lease::None, Some(&guard)).await,
        Err(Error::LockLeaseExpired)
    );
    assert_eq!(
        a.get("g/k", Some(&guard)).await,
        Err(Error::LockLeaseExpired)
    );
    assert_eq!(
        a.delete("g/k", Some(&guard)).await,
        Err(Error::LockLeaseExpired)
    );
    assert_eq!(
        a.put_if_absent("g/new", b"1".to_vec(), Lease::None, Some(&guard))
            .await,
        Err(Error::LockLeaseExpired)
    );
    assert_eq!(
        b.get("g/k", Some(&guard_b)).await.unwrap().unwrap().data,
        b"1"
    );
    b.unlock(&guard_b).await.unwrap();

    // Process-local exclusion: a second lock in one client waits too.
    let first = a.lock("flowsdn/locks/y").await.unwrap();
    let again = Arc::clone(&a);
    let second = tokio::spawn(async move { again.lock("flowsdn/locks/y").await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!second.is_finished());
    a.unlock(&first).await.unwrap();
    let second = tokio::time::timeout(WAIT, second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    a.unlock(&second).await.unwrap();

    a.close().await;
    b.close().await;
}

#[tokio::test]
async fn watch_lists_then_streams() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let server = Server::start(&bin, "watch", temp_dir("watch"), None).await;
    let client = connect(EtcdConfig {
        list_limit: 1,
        ..server.config()
    })
    .await;
    client
        .put("w/a", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    client
        .put("w/b", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    client
        .put("wx", b"outside".to_vec(), Lease::None, None)
        .await
        .unwrap();

    let mut rx = client.watch("w/").await.unwrap();
    let first = next(&mut rx).await;
    assert_eq!((first.kind, first.key.as_str()), (EventKind::Create, "w/a"));
    assert_eq!(first.value.unwrap().data, b"1");
    let second = next(&mut rx).await;
    assert_eq!(
        (second.kind, second.key.as_str()),
        (EventKind::Create, "w/b")
    );
    assert_eq!(next(&mut rx).await.kind, EventKind::ListDone);

    client
        .put("w/c", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let created = next(&mut rx).await;
    assert_eq!(
        (created.kind, created.key.as_str()),
        (EventKind::Create, "w/c")
    );
    client
        .put("w/c", b"2".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let modified = next(&mut rx).await;
    assert_eq!(
        (modified.kind, modified.key.as_str()),
        (EventKind::Modify, "w/c")
    );
    assert_eq!(modified.value.unwrap().data, b"2");
    client.delete("w/a", None).await.unwrap();
    let deleted = next(&mut rx).await;
    assert_eq!(
        (deleted.kind, deleted.key.as_str()),
        (EventKind::Delete, "w/a")
    );
    assert_eq!(deleted.value, None);
    client
        .put("wx", b"again".to_vec(), Lease::None, None)
        .await
        .unwrap();
    client
        .put("w/d", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let after = next(&mut rx).await;
    assert_eq!(after.key, "w/d", "a key outside the prefix leaked");

    client.close().await;
    let closed = tokio::time::timeout(WAIT, async { while rx.recv().await.is_some() {} }).await;
    assert!(closed.is_ok(), "the watch receiver closes with the client");
}

#[tokio::test]
async fn close_revokes_leased_keys() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let server = Server::start(&bin, "revoke", temp_dir("revoke"), None).await;
    let writer = connect(EtcdConfig {
        key_lease_ttl: Duration::from_secs(5),
        ..server.config()
    })
    .await;
    let reader = connect(server.config()).await;
    writer
        .put("l/k", b"1".to_vec(), Lease::Attached, None)
        .await
        .unwrap();
    writer
        .put("l/plain", b"1".to_vec(), Lease::None, None)
        .await
        .unwrap();
    let mut rx = reader.watch("l/").await.unwrap();
    assert_eq!(next(&mut rx).await.key, "l/k");
    assert_eq!(next(&mut rx).await.key, "l/plain");
    assert_eq!(next(&mut rx).await.kind, EventKind::ListDone);

    // The keepalive holds the 5 s lease past its TTL.
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(reader.get("l/k", None).await.unwrap().is_some());

    writer.close().await;
    let deleted = next(&mut rx).await;
    assert_eq!(
        (deleted.kind, deleted.key.as_str()),
        (EventKind::Delete, "l/k")
    );
    assert_eq!(reader.get("l/k", None).await.unwrap(), None);
    assert!(reader.get("l/plain", None).await.unwrap().is_some());
    reader.close().await;
}

#[tokio::test]
async fn status_reports_connected() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let server = Server::start(&bin, "status", temp_dir("status"), None).await;
    let client = connect(server.config()).await;
    let deadline = tokio::time::Instant::now() + WAIT;
    let status = loop {
        let status = client.status();
        if status.message.starts_with("etcd: 1/1 connected") {
            break status;
        }
        assert!(tokio::time::Instant::now() < deadline, "status: {status:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status.state, State::Ok);
    assert!(
        status.message.contains("lock leases=1"),
        "{}",
        status.message
    );
    assert!(
        status.message.contains("has-quorum=true"),
        "{}",
        status.message
    );
    assert!(
        status
            .message
            .contains(&format!("http://127.0.0.1:{} - ", server.port)),
        "{}",
        status.message
    );
    assert!(client.status_errors().is_some());
    assert!(client.status_errors().is_none());
    client.close().await;
}

// ---- mTLS ----

fn ec_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A certificate for `cn`: a self-signed CA when `issuer` is None, else a
/// leaf signed by it with `dns`/`ips` subject alternative names.
fn certificate(
    cn: &str,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    serial: u32,
    dns: &[&str],
    ips: &[&str],
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    match issuer {
        Some((ca, _)) => builder.set_issuer_name(ca.subject_name()).unwrap(),
        None => builder.set_issuer_name(&name).unwrap(),
    }
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    match issuer {
        None => {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()
                        .unwrap(),
                )
                .unwrap();
        }
        Some((ca, _)) => {
            builder
                .append_extension(BasicConstraints::new().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .key_encipherment()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            builder
                .append_extension(
                    ExtendedKeyUsage::new()
                        .server_auth()
                        .client_auth()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            if !dns.is_empty() || !ips.is_empty() {
                let mut san = SubjectAlternativeName::new();
                for name in dns {
                    san.dns(name);
                }
                for ip in ips {
                    san.ip(ip);
                }
                let extension = san
                    .build(&builder.x509v3_context(Some(&**ca), None))
                    .unwrap();
                builder.append_extension(extension).unwrap();
            }
        }
    }
    let signer = issuer.map_or(key, |(_, ca_key)| ca_key);
    builder.sign(signer, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn write_pem(dir: &Path, name: &str, pem: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, pem).unwrap();
    path
}

#[tokio::test]
async fn mtls_put_get_and_refuses_without_cert() {
    let Some(bin) = fastetcd() else {
        return;
    };
    let dir = temp_dir("mtls");
    let ca_key = ec_key();
    let ca = certificate("flowsdn test CA", &ca_key, None, 1, &[], &[]);
    let server_key = ec_key();
    let server_cert = certificate(
        "fastetcd",
        &server_key,
        Some((&ca, &ca_key)),
        2,
        &["localhost"],
        &["127.0.0.1"],
    );
    let client_key = ec_key();
    let client_cert = certificate("flowsdn", &client_key, Some((&ca, &ca_key)), 3, &[], &[]);
    let ca_file = write_pem(&dir, "ca.crt", &ca.to_pem().unwrap());
    let tls = ServerTls {
        cert: write_pem(&dir, "server.crt", &server_cert.to_pem().unwrap()),
        key: write_pem(
            &dir,
            "server.key",
            &server_key.private_key_to_pem_pkcs8().unwrap(),
        ),
        ca: ca_file.clone(),
    };
    let client_cert_file = write_pem(&dir, "client.crt", &client_cert.to_pem().unwrap());
    let client_key_file = write_pem(
        &dir,
        "client.key",
        &client_key.private_key_to_pem_pkcs8().unwrap(),
    );
    let server = Server::start(&bin, "mtls", dir, Some(&tls)).await;
    let endpoint = format!("https://localhost:{}", server.port);

    let client = connect(EtcdConfig {
        endpoints: vec![endpoint.clone()],
        trusted_ca_file: Some(ca_file.clone()),
        cert_file: Some(client_cert_file),
        key_file: Some(client_key_file),
        ..EtcdConfig::default()
    })
    .await;
    client
        .put("tls/k", b"secret".to_vec(), Lease::Attached, None)
        .await
        .unwrap();
    assert_eq!(
        client.get("tls/k", None).await.unwrap().unwrap().data,
        b"secret"
    );

    // Without a client certificate the server refuses the client.
    let refused = tokio::time::timeout(
        WAIT,
        EtcdBackend::connect(EtcdConfig {
            endpoints: vec![endpoint],
            trusted_ca_file: Some(ca_file),
            ..EtcdConfig::default()
        }),
    )
    .await;
    assert!(
        matches!(refused, Ok(Err(_))),
        "a client without a certificate connected"
    );
    client.close().await;
}
