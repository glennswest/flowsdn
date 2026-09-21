use flowsdn_cni::{AddBackend, AddRequest, CniError, Endpoint, Lease, Link, Result, add};
use flowsdn_ipam::{HostScope, Ipam, RangeOptions};
use std::{collections::BTreeMap, net::IpAddr};

fn request() -> AddRequest {
    let env = BTreeMap::from([
        ("CNI_CONTAINERID".into(), "sandbox-1".into()),
        ("CNI_IFNAME".into(), "eth0".into()),
        ("CNI_NETNS".into(), "/proc/123/ns/net".into()),
        ("CNI_PATH".into(), "/opt/cni/bin".into()),
        (
            "CNI_ARGS".into(),
            "K8S_POD_NAME=pod;K8S_POD_NAMESPACE=team;K8S_POD_UID=uid;Unknown=ignored".into(),
        ),
    ]);
    AddRequest::parse(
        br#"{"cniVersion":"1.1.0","name":"net","future-option":true}"#,
        &env,
    )
    .expect("valid request")
}
struct Backend {
    ipam: Ipam,
    fail: &'static str,
    cleanup_fail: bool,
    uncertain: bool,
    calls: Vec<String>,
}
impl Backend {
    fn new(fail: &'static str) -> Self {
        let v4 = HostScope::new(
            "198.18.0.0".parse().expect("fixture"),
            30,
            RangeOptions::default(),
        )
        .expect("pool");
        let v6 = HostScope::new(
            "2001:db8::".parse().expect("fixture"),
            126,
            RangeOptions::default(),
        )
        .expect("pool");
        Self {
            ipam: Ipam::new(Some(v4), Some(v6)).expect("IPAM"),
            fail,
            cleanup_fail: false,
            uncertain: false,
            calls: Vec::new(),
        }
    }
    fn step(&mut self, name: &str) -> Result<()> {
        self.calls.push(name.into());
        if self.fail == name
            || (self.cleanup_fail
                && matches!(
                    name,
                    "delete_endpoint" | "delete_link" | "release4" | "release6"
                ))
        {
            Err(CniError::internal(name))
        } else {
            Ok(())
        }
    }
    fn allocated(&self) -> usize {
        self.ipam
            .ipv4()
            .expect("v4")
            .allocated()
            .checked_add(self.ipam.ipv6().expect("v6").allocated())
            .expect("small pools")
    }
}
impl AddBackend for Backend {
    fn allocate(&mut self, r: &AddRequest) -> Result<Vec<Lease>> {
        self.step("allocate")?;
        let pair = self
            .ipam
            .allocate_next(&r.owner())
            .map_err(|e| CniError::internal(e.to_string()))?;
        // Intentionally unordered: the CNI transaction must normalize IPv6 first.
        Ok(vec![
            Lease {
                address: IpAddr::V4(pair.ipv4.expect("v4")),
                gateway: "198.18.0.254".parse().expect("fixture"),
                pool: "default".into(),
                expiration_uuid: "four".into(),
            },
            Lease {
                address: IpAddr::V6(pair.ipv6.expect("v6")),
                gateway: "2001:db8::ffff".parse().expect("fixture"),
                pool: "default".into(),
                expiration_uuid: "six".into(),
            },
        ])
    }
    fn create_link(&mut self, _: &AddRequest) -> Result<Link> {
        self.step("create_link")?;
        Ok(Link {
            host_name: "lxcfixture".into(),
            host_index: 7,
            host_mac: "02:00:00:00:00:01".into(),
            peer_mac: "02:00:00:00:00:02".into(),
        })
    }
    fn configure(&mut self, _: &AddRequest, _: &Link, leases: &[Lease]) -> Result<()> {
        assert!(leases.first().expect("lease").address.is_ipv6());
        self.step("configure")
    }
    fn create_endpoint(&mut self, r: &AddRequest, _: &Link, _: &[Lease]) -> Result<Endpoint> {
        assert_eq!(r.attachment_id(), "cni-attachment-id:sandbox-1:eth0");
        self.step("create_endpoint")?;
        Ok(Endpoint {
            mac_override: Some("02:00:00:00:00:03".into()),
        })
    }
    fn finalize(&mut self, _: &AddRequest, link: &mut Link, ep: &Endpoint) -> Result<()> {
        self.step("finalize")?;
        link.peer_mac = ep.mac_override.clone().expect("override");
        Ok(())
    }
    fn may_release_resources(&self) -> bool {
        !self.uncertain
    }
    fn delete_endpoint(&mut self, _: &AddRequest) -> Result<()> {
        self.step("delete_endpoint")
    }
    fn delete_link(&mut self, _: &Link) -> Result<()> {
        self.step("delete_link")
    }
    fn release(&mut self, l: &Lease) -> Result<()> {
        self.ipam
            .release(l.address)
            .map_err(|e| CniError::internal(e.to_string()))?;
        self.step(if l.address.is_ipv4() {
            "release4"
        } else {
            "release6"
        })
    }
}

#[test]
fn failed_stages_release_real_ipam_allocations_in_reverse_order() {
    for (stage, tail) in [
        ("allocate", vec![]),
        ("create_link", vec!["release4", "release6"]),
        ("configure", vec!["delete_link", "release4", "release6"]),
        (
            "create_endpoint",
            vec!["delete_link", "release4", "release6"],
        ),
        (
            "finalize",
            vec!["delete_endpoint", "delete_link", "release4", "release6"],
        ),
    ] {
        let mut backend = Backend::new(stage);
        let failure = add(&request(), 1450, &mut backend).expect_err("injected failure");
        assert_eq!(failure.primary.message, stage);
        assert!(failure.rollback_errors.is_empty());
        assert_eq!(backend.allocated(), 0);
        assert!(
            backend
                .calls
                .ends_with(&tail.into_iter().map(String::from).collect::<Vec<_>>())
        );
    }
}
#[test]
fn cleanup_failures_preserve_primary_and_do_not_stop_remaining_actions() {
    let mut backend = Backend::new("finalize");
    backend.cleanup_fail = true;
    let failure = add(&request(), 1450, &mut backend).expect_err("post-create failure");
    assert_eq!(failure.primary.message, "finalize");
    assert_eq!(
        failure
            .rollback_errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>(),
        ["delete_endpoint", "delete_link", "release4", "release6"]
    );
    assert_eq!(backend.allocated(), 0);
}
#[test]
fn successful_result_keeps_allocations_and_orders_ipv6_first() {
    let mut backend = Backend::new("");
    let result = add(&request(), 1450, &mut backend).expect("ADD");
    assert_eq!(backend.allocated(), 2);
    assert_eq!(
        result
            .pointer("/ips/0/gateway")
            .and_then(serde_json::Value::as_str),
        Some("2001:db8::ffff")
    );
    assert_eq!(
        result
            .pointer("/ips/1/interface")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        result
            .pointer("/routes/1/dst")
            .and_then(serde_json::Value::as_str),
        Some("::/0")
    );
    assert_eq!(
        result
            .pointer("/routes/3/mtu")
            .and_then(serde_json::Value::as_u64),
        Some(1450)
    );
    assert_eq!(
        result
            .pointer("/interfaces/1/mac")
            .and_then(serde_json::Value::as_str),
        Some("02:00:00:00:00:03")
    );
    assert_eq!(
        backend.calls,
        [
            "allocate",
            "create_link",
            "configure",
            "create_endpoint",
            "finalize"
        ]
    );
}
#[test]
fn unsupported_versions_and_missing_environment_fail_before_allocation() {
    assert_eq!(
        AddRequest::parse(br#"{"cniVersion":"0.4.0","name":"net"}"#, &BTreeMap::new())
            .expect_err("old version")
            .code,
        1
    );
    assert_eq!(
        AddRequest::parse(br#"{"cniVersion":"1.1.0","name":"net"}"#, &BTreeMap::new())
            .expect_err("missing env")
            .code,
        4
    );
    let mut r = request();
    r.version = "0.4.0".into();
    let mut backend = Backend::new("");
    assert!(add(&r, 1450, &mut backend).is_err());
    assert!(backend.calls.is_empty());
}

#[test]
fn ambiguous_endpoint_publication_retains_owned_backing_resources() {
    let mut backend = Backend::new("create_endpoint");
    backend.uncertain = true;
    let failure = add(&request(), 1450, &mut backend).expect_err("ambiguous PUT");
    assert!(
        failure
            .rollback_errors
            .iter()
            .any(|e| e.message.contains("retaining"))
    );
    assert!(
        !backend
            .calls
            .iter()
            .any(|c| c == "delete_link" || c.starts_with("release"))
    );
    assert_eq!(backend.ipam.ipv4().expect("v4").allocated(), 1);
    assert_eq!(backend.ipam.ipv6().expect("v6").allocated(), 1);
}
