#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;
use crate::rows::DeviceAddress;

fn addr(text: &str, prefix: u8, scope: u8, secondary: bool) -> DeviceAddress {
    DeviceAddress {
        addr: text.parse().unwrap(),
        prefix,
        scope,
        secondary,
    }
}
fn device(index: u32, name: &str, selected: bool, addresses: Vec<DeviceAddress>) -> Device {
    Device {
        index,
        name: name.into(),
        mtu: 1500,
        kind: "device".into(),
        up: true,
        oper_status: "up".into(),
        addresses,
        selected,
        ..Device::default()
    }
}
fn rows(out: &[NodeAddress]) -> Vec<(String, &str, bool, bool)> {
    out.iter()
        .map(|a| {
            (
                a.addr.to_string(),
                a.device.as_str(),
                a.primary,
                a.node_port,
            )
        })
        .collect()
}

#[test]
fn primaries_node_ports_and_ordering() {
    let devices = vec![
        device(1, "lo", false, vec![addr("127.0.0.1", 8, 254, false)]),
        device(
            2,
            "eth0",
            true,
            vec![
                addr("10.0.0.5", 24, 0, true),
                addr("192.0.2.5", 24, 0, false),
                addr("10.0.0.4", 24, 0, false),
                addr("fe80::1", 64, 253, false),
                addr("2001:db8::5", 64, 0, false),
            ],
        ),
        device(3, "eth1", false, vec![addr("198.51.100.9", 24, 0, false)]),
    ];
    let routes = vec![Route {
        table: 254,
        link_index: 2,
        dst: ("0.0.0.0".parse().unwrap(), 0),
        src: None,
        gw: Some("192.0.2.1".parse().unwrap()),
        scope: 0,
        priority: 0,
        proto: 3,
        kind: 1,
    }];
    let out = derive(&devices, &routes, &Settings::default());
    assert_eq!(
        rows(&out),
        vec![
            ("10.0.0.4".into(), "eth0", false, true),
            ("10.0.0.5".into(), "eth0", false, false),
            ("192.0.2.5".into(), "*", true, false),
            ("192.0.2.5".into(), "eth0", true, false),
            ("2001:db8::5".into(), "*", true, false),
            ("2001:db8::5".into(), "eth0", true, true),
        ],
        "public before private for primary; the first private for NodePort; link-local and unselected devices out; the fallback copies the default-route device's primaries"
    );
    // nodeport-addresses picks every address in the CIDRs instead.
    let settings = Settings {
        nodeport_cidrs: vec![("10.0.0.0".parse().unwrap(), 24)],
        ..Settings::default()
    };
    let out = derive(&devices, &routes, &settings);
    let node_ports: Vec<String> = out
        .iter()
        .filter(|a| a.node_port)
        .map(|a| a.addr.to_string())
        .collect();
    assert_eq!(node_ports, ["10.0.0.4", "10.0.0.5"]);
}

#[test]
fn the_host_device_and_local_table_aliases() {
    let devices = vec![
        device(2, "eth0", true, vec![addr("192.0.2.5", 24, 0, false)]),
        device(
            9,
            HOST_DEVICE,
            false,
            vec![
                addr("10.9.0.1", 32, 253, false),
                addr("fe80::9", 64, 253, false),
            ],
        ),
    ];
    let alias = Route {
        table: LOCAL_TABLE,
        link_index: 2,
        dst: ("203.0.113.7".parse().unwrap(), 32),
        src: None,
        gw: None,
        scope: SCOPE_HOST,
        priority: 0,
        proto: 2,
        kind: 2,
    };
    let out = derive(&devices, &[alias], &Settings::default());
    let host: Vec<_> = rows(&out)
        .into_iter()
        .filter(|r| r.1 == HOST_DEVICE)
        .collect();
    assert_eq!(
        host,
        vec![
            ("10.9.0.1".into(), HOST_DEVICE, true, false),
            ("fe80::9".into(), HOST_DEVICE, false, false)
        ],
        "the host device's link-scope addresses count, never as NodePort; its link-local is never primary"
    );
    let aliased = out
        .iter()
        .find(|a| a.addr.to_string() == "203.0.113.7")
        .unwrap();
    assert_eq!((aliased.device.as_str(), aliased.primary), ("eth0", false));
}
