use flowsdn_cni::loopback::dispatch;
use serde_json::{Value, json};
use std::{collections::BTreeMap, ffi::OsStr, io::Write, process::{Command, Stdio}};

fn invoke(name: &str, command: &str, conf: Value) -> flowsdn_cni::Result<Option<Value>> {
    dispatch(OsStr::new(name), command, &serde_json::to_vec(&conf).unwrap(), &BTreeMap::new())
}

#[test]
fn aliases_and_type_dispatch_do_not_contact_agent() {
    for name in ["/opt/cni/bin/loopback", "flowsdn-loopback", "flowsdn-cni"] {
        for kind in ["loopback", "flowsdn-loopback"] {
            let conf = json!({"cniVersion":"1.1.0", "type":kind});
            assert_eq!(invoke(name, "STATUS", conf.clone()).unwrap(), None);
            assert_eq!(invoke(name, "DEL", conf.clone()).unwrap(), None);
            assert_eq!(invoke(name, "GC", conf).unwrap_err().code, 4);
        }
    }
    // Invocation name alone selects loopback, even without a config type.
    assert!(invoke("loopback", "STATUS", json!({"cniVersion":"1.0.0"})).is_ok());
    let version = invoke("loopback", "VERSION", Value::Null).unwrap().unwrap();
    assert_eq!(version["supportedVersions"], json!(["1.0.0", "1.1.0"]));
}

#[test]
fn invalid_input_fails_before_namespace_or_agent_access() {
    assert_eq!(invoke("loopback", "ADD", json!({"cniVersion":"0.4.0"})).unwrap_err().code, 1);
    assert_eq!(dispatch(OsStr::new("loopback"), "ADD", b"{", &BTreeMap::new()).unwrap_err().code, 6);
    for command in ["ADD", "CHECK"] {
        assert!(invoke("loopback", command, json!({"cniVersion":"1.1.0", "name":"lo"})).unwrap_err().message.contains("CNI_CONTAINERID"));
    }
    let env = BTreeMap::from([("CNI_NETNS".into(), "/no-such-flowsdn-loopback-namespace".into())]);
    assert!(dispatch(OsStr::new("loopback"), "DEL", br#"{"cniVersion":"1.1.0"}"#, &env).is_ok());
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
        let error = dispatch(OsStr::new("loopback"), "ADD", &serde_json::to_vec(&conf).unwrap(), &env).unwrap_err();
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
        .env("CILIUM_SOCK", "/no-agent-loopback-test")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(conf).unwrap()).unwrap();
    child.wait_with_output().unwrap()
}

/// Requires Linux unshare and permission to create user/network namespaces.
/// Runs without host root; missing namespace support is a failure, not a skip.
#[test]
#[ignore = "requires Linux user/network namespaces"]
fn loopback_namespace() {
    if std::env::var_os("FLOWSDN_LOOPBACK_NS_CHILD").is_none() {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "loopback_namespace", "--ignored", "--nocapture"])
            .env("FLOWSDN_LOOPBACK_NS_CHILD", "1")
            .status().expect("launch isolated namespace fixture");
        assert!(status.success(), "isolated loopback fixture failed: {status}");
        return;
    }
    std::fs::write("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0").expect("fixture requires IPv6 support");
    let connector = flowsdn_connector::Connector::open().unwrap();
    let original = connector.require_link("lo").unwrap();
    let conf = json!({"cniVersion":"1.1.0", "name":"loopback-test", "type":"loopback"});
    assert!(!plugin("CHECK", &conf).status.success(), "fresh lo must be down");
    for _ in 0..2 {
        let output = plugin("ADD", &conf);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["interfaces"][0]["name"], "lo");
        let ips = result["ips"].as_array().unwrap();
        assert!(ips.iter().any(|ip| ip["address"] == "127.0.0.1/8"));
        assert!(ips.iter().any(|ip| ip["address"] == "::1/128"));
        assert!(plugin("CHECK", &conf).status.success());
    }
    assert_eq!(connector.require_link("lo").unwrap(), original, "identity and MTU unchanged");
    let previous = json!({"cniVersion":"1.1.0", "interfaces":[{"name":"eth0"}], "ips":[]});
    let mut chained = conf.clone();
    chained["prevResult"] = previous.clone();
    let output = plugin("ADD", &chained);
    assert!(output.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), previous);
    for _ in 0..2 {
        assert!(plugin("DEL", &conf).status.success());
        assert!(!plugin("CHECK", &conf).status.success());
    }
    std::fs::write("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "1").unwrap();
    let output = plugin("ADD", &conf);
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ips"].as_array().unwrap().len(), 1, "IPv6 disabled");
    connector.add_address(original.index, "192.0.2.1".parse().unwrap(), 32).unwrap();
    assert!(!plugin("ADD", &conf).status.success(), "foreign lo address must fail");
}
