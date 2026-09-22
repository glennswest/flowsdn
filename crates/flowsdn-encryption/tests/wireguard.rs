use flowsdn_encryption::wireguard::{Peer, PeerFlags, plan};
use netlink_packet_core::{Emitable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;
use netlink_packet_wireguard::{
    WireguardAllowedIpAttr as IpAttr, WireguardAttribute as Attr, WireguardMessage,
    WireguardPeerAttribute as PeerAttr,
};
use std::net::{IpAddr, Ipv6Addr};
fn peer() -> Peer {
    Peer {
        public_key: [9; 32],
        flags: PeerFlags::ReplaceAllowedIps | PeerFlags::UpdateOnly,
        endpoint: Some("[::1]:51871".parse().expect("endpoint")),
        keepalive: Some(25),
        allowed_ips: Vec::new(),
    }
}
fn decode(message: &WireguardMessage) -> WireguardMessage {
    let mut bytes = vec![0; message.buffer_len()];
    message.emit(&mut bytes);
    WireguardMessage::parse_with_param(&bytes, GenlHeader { cmd: 1, version: 1 })
        .expect("independent wire decode")
}
#[test]
fn thousands_of_ips_decode_and_reassemble_without_replacement_loss() {
    let mut input = peer();
    input.allowed_ips = (0u128..10_000)
        .map(|n| (IpAddr::V6(Ipv6Addr::from(n)), 128))
        .collect();
    let output = plan(7, true, &[input.clone()], 4096).expect("plan");
    assert!(output.len() > 50);
    let mut reconstructed = Vec::new();
    for (index, message) in output.iter().enumerate() {
        assert!(message.buffer_len().checked_add(20).expect("length") <= 4096);
        let decoded = decode(message);
        assert_eq!(decoded, *message);
        let mut device_replace = false;
        for attr in decoded.attributes {
            match attr {
                Attr::Flags(_) => device_replace = true,
                Attr::Peers(peers) => {
                    for p in peers {
                        for field in p.0 {
                            match field {
                                PeerAttr::PublicKey(key) => assert_eq!(key, input.public_key),
                                PeerAttr::Flags(flags) => {
                                    assert_eq!(
                                        flags.contains(PeerFlags::ReplaceAllowedIps),
                                        index == 0
                                    );
                                    assert!(flags.contains(PeerFlags::UpdateOnly));
                                }
                                PeerAttr::Endpoint(_) | PeerAttr::PersistentKeepalive(_) => {
                                    assert_eq!(index, 0)
                                }
                                PeerAttr::AllowedIps(ips) => {
                                    for ip in ips {
                                        let address =
                                            ip.0.iter()
                                                .find_map(|a| {
                                                    if let IpAttr::IpAddr(v) = a {
                                                        Some(*v)
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .expect("address");
                                        let cidr =
                                            ip.0.iter()
                                                .find_map(|a| {
                                                    if let IpAttr::Cidr(v) = a {
                                                        Some(*v)
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .expect("prefix");
                                        reconstructed.push((address, cidr));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(device_replace, index == 0);
    }
    assert_eq!(reconstructed, input.allowed_ips);
}
#[test]
fn append_remove_and_empty_replacement_keep_caller_flags() {
    for flags in [
        PeerFlags::empty(),
        PeerFlags::ReplaceAllowedIps,
        PeerFlags::RemoveMe,
    ] {
        let mut p = peer();
        p.flags = flags;
        p.endpoint = None;
        p.keepalive = None;
        let messages = plan(2, false, &[p], 128).expect("plan");
        assert_eq!(messages.len(), 1);
        for message in messages {
            for attr in decode(&message).attributes {
                if let Attr::Peers(peers) = attr {
                    for peer in peers {
                        assert!(peer.0.contains(&PeerAttr::Flags(flags)));
                    }
                }
            }
        }
    }
    let messages = plan(2, true, &[], 128).expect("clear all");
    assert_eq!(messages.len(), 1);
    assert!(
        decode(messages.first().expect("message"))
            .attributes
            .iter()
            .any(|a| matches!(a, Attr::Flags(_)))
    );
}
#[test]
fn validates_whole_plan_before_exposing_fragments() {
    let mut p = peer();
    assert!(plan(0, false, &[p.clone()], 4096).is_err());
    assert!(plan(1, false, &[p.clone()], 65_536).is_err());
    assert!(plan(1, false, &[p.clone(), p.clone()], 4096).is_err());
    p.allowed_ips.push((IpAddr::V6(Ipv6Addr::LOCALHOST), 129));
    assert!(plan(1, false, &[p.clone()], 4096).is_err());
    p.allowed_ips.clear();
    p.flags = PeerFlags::RemoveMe;
    assert!(plan(1, false, &[p], 4096).is_err());
}
#[test]
fn every_peer_gets_its_own_initial_replacement() {
    let mut a = peer();
    a.endpoint = None;
    a.keepalive = None;
    a.allowed_ips = (0u32..2000).map(|n| (IpAddr::V4(n.into()), 32)).collect();
    let mut b = a.clone();
    b.public_key = [8; 32];
    let mut first = std::collections::HashSet::new();
    for message in plan(9, false, &[a, b], 128).expect("small fragments") {
        for attr in decode(&message).attributes {
            if let Attr::Peers(peers) = attr {
                for p in peers {
                    let key =
                        p.0.iter()
                            .find_map(|a| {
                                if let PeerAttr::PublicKey(k) = a {
                                    Some(*k)
                                } else {
                                    None
                                }
                            })
                            .expect("key");
                    let initial = first.insert(key);
                    assert!(p.0.iter().any(|a|matches!(a,PeerAttr::Flags(f) if f.contains(PeerFlags::ReplaceAllowedIps)==initial)));
                }
            }
        }
    }
    assert_eq!(first.len(), 2);
}
