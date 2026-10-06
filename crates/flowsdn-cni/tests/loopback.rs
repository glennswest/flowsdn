use flowsdn_cni::loopback::dispatch;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
};

fn invoke(name: &str, command: &str, conf: Value) -> flowsdn_cni::Result<Option<Value>> {
    dispatch(
        OsStr::new(name),
        command,
        &serde_json::to_vec(&conf).expect("fixture operation"),
        &BTreeMap::new(),
    )
}

#[test]
fn aliases_and_type_dispatch_do_not_contact_agent() {
    for name in ["/opt/cni/bin/loopback", "flowsdn-loopback", "flowsdn-cni"] {
        for kind in ["loopback", "flowsdn-loopback"] {
            let conf = json!({"cniVersion":"1.1.0", "type":kind});
            assert_eq!(
                invoke(name, "STATUS", conf.clone()).expect("fixture operation"),
                None
            );
            assert_eq!(
                invoke(name, "DEL", conf.clone()).expect("fixture operation"),
                None
            );
            assert_eq!(
                invoke(name, "GC", conf)
                    .expect_err("invalid fixture must fail")
                    .code,
                4
            );
        }
    }
    // Invocation name alone selects loopback, even without a config type.
    assert!(invoke("loopback", "STATUS", json!({"cniVersion":"1.0.0"})).is_ok());
    let version = invoke("loopback", "VERSION", Value::Null)
        .expect("fixture operation")
        .expect("fixture operation");
    assert_eq!(
        version
            .get("supportedVersions")
            .expect("supported versions"),
        &json!(["1.0.0", "1.1.0"])
    );
}

#[test]
fn invalid_input_fails_before_namespace_or_agent_access() {
    assert_eq!(
        invoke("loopback", "ADD", json!({"cniVersion":"0.4.0"}))
            .expect_err("invalid fixture must fail")
            .code,
        1
    );
    assert_eq!(
        dispatch(OsStr::new("loopback"), "ADD", b"{", &BTreeMap::new())
            .expect_err("invalid fixture must fail")
            .code,
        6
    );
    for command in ["ADD", "CHECK"] {
        assert!(
            invoke(
                "loopback",
                command,
                json!({"cniVersion":"1.1.0", "name":"lo"})
            )
            .expect_err("invalid fixture must fail")
            .message
            .contains("CNI_CONTAINERID")
        );
    }
    let env = BTreeMap::from([(
        "CNI_NETNS".into(),
        "/no-such-flowsdn-loopback-namespace".into(),
    )]);
    assert!(
        dispatch(
            OsStr::new("loopback"),
            "DEL",
            br#"{"cniVersion":"1.1.0"}"#,
            &env
        )
        .is_ok()
    );
}

#[test]
fn malformed_previous_result_fails_before_namespace_access() {
    let env = BTreeMap::from([
        ("CNI_CONTAINERID".into(), "test".into()),
        ("CNI_IFNAME".into(), "lo".into()),
        ("CNI_PATH".into(), "/unused".into()),
        ("CNI_NETNS".into(), "/nonexistent-flowsdn-netns".into()),
    ]);
    for previous in [
        json!({"cniVersion":"1.1.0", "ips":"bad"}),
        json!({"cniVersion":"1.1.0", "ips":[{"address":"127.0.0.1/99"}]}),
        json!({"cniVersion":"1.1.0", "ips":[{"address":"127.0.0.1/8", "interface":9}]}),
        json!({"cniVersion":"1.1.0", "interfaces":[{}]}),
        json!({"cniVersion":"1.1.0", "dns":{"nameservers":false}}),
    ] {
        let conf = json!({"cniVersion":"1.1.0", "name":"lo", "prevResult":previous});
        let error = dispatch(
            OsStr::new("loopback"),
            "ADD",
            &serde_json::to_vec(&conf).expect("fixture operation"),
            &env,
        )
        .expect_err("invalid fixture must fail");
        assert!(error.message.contains("prevResult"), "{error}");
    }
}

fn plugin(command: &str, conf: &Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_flowsdn-cni"))
        .env("CNI_COMMAND", command)
        .env("CNI_CONTAINERID", "loopback-test")
        .env("CNI_NETNS", "/proc/self/ns/net")
        .env("CNI_IFNAME", "ignored0")
        .env("CNI_PATH", "/unused")
        .env("FLOWSDN_SOCK", "/no-agent-loopback-test")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fixture operation");
    child
        .stdin
        .take()
        .expect("fixture operation")
        .write_all(&serde_json::to_vec(conf).expect("fixture operation"))
        .expect("fixture operation");
    child.wait_with_output().expect("fixture operation")
}

/// Requires Linux unshare and permission to create user/network namespaces.
/// Runs without host root; missing namespace support is a failure, not a skip.
#[test]
#[ignore = "requires Linux user/network namespaces"]
fn loopback_namespace() {
    if std::env::var_os("FLOWSDN_LOOPBACK_NS_CHILD").is_none() {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(std::env::current_exe().expect("fixture operation"))
            .args(["--exact", "loopback_namespace", "--ignored", "--nocapture"])
            .env("FLOWSDN_LOOPBACK_NS_CHILD", "1")
            .status()
            .expect("launch isolated namespace fixture");
        assert!(
            status.success(),
            "isolated loopback fixture failed: {status}"
        );
        return;
    }
    std::fs::write("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0")
        .expect("fixture requires IPv6 support");
    let connector = flowsdn_connector::Connector::open().expect("fixture operation");
    let original = connector.require_link("lo").expect("fixture operation");
    let conf = json!({"cniVersion":"1.1.0", "name":"loopback-test", "type":"loopback"});
    assert!(
        !plugin("CHECK", &conf).status.success(),
        "fresh lo must be down"
    );
    for _ in 0..2 {
        let output = plugin("ADD", &conf);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let result: Value = serde_json::from_slice(&output.stdout).expect("fixture operation");
        assert_eq!(
            result.pointer("/interfaces/0/name").expect("loopback name"),
            "lo"
        );
        let ips = result
            .get("ips")
            .expect("result IPs")
            .as_array()
            .expect("fixture operation");
        assert!(
            ips.iter()
                .any(|ip| ip.get("address").and_then(Value::as_str) == Some("127.0.0.1/8"))
        );
        assert!(
            ips.iter()
                .any(|ip| ip.get("address").and_then(Value::as_str) == Some("::1/128"))
        );
        assert!(plugin("CHECK", &conf).status.success());
    }
    assert_eq!(
        connector.require_link("lo").expect("fixture operation"),
        original,
        "identity and MTU unchanged"
    );
    let previous = json!({"cniVersion":"1.1.0", "interfaces":[{"name":"eth0"}], "ips":[]});
    let mut chained = conf.clone();
    chained
        .as_object_mut()
        .expect("config object")
        .insert("prevResult".into(), previous.clone());
    let output = plugin("ADD", &chained);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).expect("fixture operation"),
        previous
    );
    for _ in 0..2 {
        assert!(plugin("DEL", &conf).status.success());
        assert!(!plugin("CHECK", &conf).status.success());
    }
    std::fs::write("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "1").expect("fixture operation");
    let output = plugin("ADD", &conf);
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).expect("fixture operation");
    assert_eq!(
        result
            .get("ips")
            .expect("result IPs")
            .as_array()
            .expect("fixture operation")
            .len(),
        1,
        "IPv6 disabled"
    );
    connector
        .add_address(
            original.index,
            "192.0.2.1".parse().expect("fixture operation"),
            32,
        )
        .expect("fixture operation");
    assert!(
        !plugin("ADD", &conf).status.success(),
        "foreign lo address must fail"
    );
}
