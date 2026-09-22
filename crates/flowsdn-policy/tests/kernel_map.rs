use flowsdn_bpf_abi::policy::{PolicyEntry, PolicyKey};
use flowsdn_identity::numeric::ClusterEncoding;
use flowsdn_policy::{
    kernel_map::{Context, Index, Outcome, Record, inherit_auth, prune_aggregate_duplicates, scan},
    oracle::Packet,
};
fn context() -> Context {
    Context {
        encoding: ClusterEncoding::new(255).expect("encoding"),
        local_cluster: 0,
    }
}
fn record(
    id: u32,
    proto: u8,
    port: u16,
    bits: u8,
    precedence: u32,
    auth: u8,
    explicit: bool,
) -> Record {
    let key = PolicyKey::new(id, true, proto, port, bits).expect("key");
    Record {
        key,
        entry: PolicyEntry::new(
            0,
            precedence & 255 == 255,
            u8::try_from(key.prefixlen.saturating_sub(40)).expect("prefix"),
            auth,
            explicit,
            precedence,
            0,
        )
        .expect("value"),
        origin: "rule".into(),
    }
}
fn packet(id: u32, port: u16) -> Packet {
    Packet {
        identity: id,
        egress: true,
        protocol: 6,
        port,
    }
}
fn compare(records: &[Record], identities: &[u32], all_ports: bool) {
    let index = Index::new(records).expect("index");
    let ports = if all_ports {
        (0..=u16::MAX).collect::<Vec<_>>()
    } else {
        vec![0, 1, 79, 80, 81, 255, 256, 511, 512, 1023, 1024, 65535]
    };
    for id in identities {
        for protocol in [0, 6, 17] {
            for egress in [false, true] {
                for port in &ports {
                    let p = Packet {
                        identity: *id,
                        egress,
                        protocol,
                        port: *port,
                    };
                    assert_eq!(
                        index.lookup(context(), p),
                        scan(records, context(), p),
                        "{p:?}"
                    );
                }
            }
        }
    }
}
#[test]
fn aggregate_auth_explicit_disable_and_wildcard_fallback() {
    // Ordinary cluster-local identities map to aggregate cluster11.
    let mut records = vec![
        record(1000, 6, 80, 16, 0x101, 0, false),
        record(flowsdn_identity::numeric::ReservedIdentity::AggregateCluster as u32, 6, 80, 16, 0x101, 1, true),
        record(0, 0, 0, 0, 0x2ff, 0, false),
    ];
    assert_eq!(
        scan(&records, context(), packet(1000, 80)),
        Ok(Outcome::Allow {
            proxy_port: 0,
            authentication: 1,
            cookie: 0
        })
    );
    // Explicit disabled on the chosen specific identity blocks inheritance.
    records.first_mut().expect("specific").entry.auth = 128;
    assert_eq!(
        scan(&records, context(), packet(1000, 80)),
        Ok(Outcome::Allow {
            proxy_port: 0,
            authentication: 0,
            cookie: 0
        })
    );
    assert_eq!(
        scan(&records, context(), packet(1000, 81)),
        Ok(Outcome::Deny)
    );
    compare(&records, &[1000, 1001, 2, 0, 14], false);
}
#[test]
fn longer_aggregate_prefix_wins_tie_but_precedence_wins_before_length() {
    let mut records = vec![
        record(1000, 0, 0, 0, 0x101, 0, false),
        record(flowsdn_identity::numeric::ReservedIdentity::AggregateCluster as u32, 6, 80, 16, 0x101, 2, true),
    ];
    assert!(matches!(
        scan(&records, context(), packet(1000, 80)),
        Ok(Outcome::Allow {
            authentication: 2,
            ..
        })
    ));
    records.first_mut().expect("specific").entry.precedence = 0x201;
    assert!(matches!(
        scan(&records, context(), packet(1000, 80)),
        Ok(Outcome::Allow {
            authentication: 0,
            ..
        })
    ));
    compare(&records, &[1000], true);
}
#[test]
fn explicit_auth_boundaries_propagate_only_as_derived_and_preserve_disable() {
    let records = vec![
        record(1000, 0, 0, 0, 0x101, 1, true),
        record(1000, 6, 0, 8, 0x101, 0, true),
        record(1000, 6, 80, 16, 0x101, 0, false),
        record(1000, 17, 53, 16, 0x101, 0, false),
    ];
    let output = inherit_auth(&records).expect("inherit");
    assert_eq!(output.get(2).expect("TCP").entry.auth, 0);
    assert_eq!(output.get(3).expect("UDP").entry.auth, 1);
    assert!(!output.get(3).expect("UDP").entry.has_explicit_auth_type());
    compare(&output, &[1000], false);
    let mut unprepared = records;
    unprepared.first_mut().expect("broad").entry.precedence = 0x201;
    assert!(inherit_auth(&unprepared).is_err());
}
#[test]
fn conservative_pruning_preserves_origins_and_rejects_invalid_kernel_keys() {
    let records = vec![
        record(1000, 6, 80, 16, 0x101, 1, true),
        record(flowsdn_identity::numeric::ReservedIdentity::AggregateCluster as u32, 6, 80, 16, 0x101, 1, true),
    ];
    let pruned = prune_aggregate_duplicates(&records, context()).expect("prune");
    assert_eq!(pruned.len(), 1);
    for port in 0..=u16::MAX {
        assert_eq!(
            scan(&records, context(), packet(1000, port)),
            scan(&pruned, context(), packet(1000, port))
        );
    }
    let mut distinct = records.clone();
    distinct.first_mut().expect("specific").origin = "other".into();
    assert_eq!(
        prune_aggregate_duplicates(&distinct, context())
            .expect("prune")
            .len(),
        2
    );
    let mut overlapping = records.clone();
    overlapping.push(record(1000, 0, 0, 0, 0x201, 0, false));
    assert_eq!(
        prune_aggregate_duplicates(&overlapping, context())
            .expect("prune")
            .len(),
        3
    );
    let mut malformed = records.clone();
    malformed.first_mut().expect("specific").key.dport = flowsdn_bpf_abi::Be16::new(81);
    malformed.first_mut().expect("specific").key.prefixlen = 56;
    assert!(Index::new(&malformed).is_err());
    let mut pass = records.clone();
    pass.first_mut().expect("specific").entry.precedence = 0x100;
    assert!(Index::new(&pass).is_err());
    let duplicate = vec![records.first().expect("first").clone(); 2];
    assert!(Index::new(&duplicate).is_err());
}
#[test]
fn deterministic_soak_gates_index_across_category_identities() {
    // Override for an extended reproducible soak without a separate harness.
    let iterations = std::env::var("FLOWSDN_POLICY_SOAK_CASES")
        .ok()
        .map(|s| s.parse::<u32>().expect("case count"))
        .unwrap_or(256);
    let ids = [
        0,
        11,
        12,
        13,
        14,
        1000,
        0x0100_0001,
        0x0200_0001,
        0x0001_0001,
    ];
    let mut state = 0x7327d001u64;
    for _ in 0..iterations {
        let mut records = Vec::new();
        for id in ids {
            for proto in [0, 6, 17] {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let b = state.to_le_bytes();
                let n = *b.first().expect("random");
                let priority = (u32::from(n >> 2).saturating_add(1)) << 8;
                let deny = n & 1 != 0;
                let explicit = n & 2 != 0;
                records.push(record(
                    id,
                    proto,
                    0,
                    if proto == 0 { 0 } else { 8 },
                    priority | if deny { 255 } else { 1 },
                    if deny { 0 } else { n % 3 },
                    !deny && explicit,
                ));
            }
        }
        compare(&records, &ids, false);
        records.reverse();
        compare(&records, &ids, false);
    }
}

#[test]
fn canonical_records_reject_unsupported_identity_scopes_and_redirect_rank_mismatch() {
    for id in [0x01000000,0x02000000,0x03000001,u32::MAX] {
        let invalid=record(id,6,80,16,0x101,0,false);
        assert!(Index::new(std::slice::from_ref(&invalid)).is_err());
        assert!(scan(&[invalid],context(),packet(1000,80)).is_err());
    }
    for id in [0,1,11,12,13,14,1000,0x01000001,0x02000001,0x00ffffff] {
        assert!(Index::new(&[record(id,6,80,16,0x101,0,false)]).is_ok());
    }
    let mut plain_redirect=record(1000,6,80,16,0x101,0,false);
    plain_redirect.entry.proxy_port=flowsdn_bpf_abi::Be16::new(15000);
    let redirect_without_port=record(1000,6,80,16,0x102,0,false);
    for invalid in [plain_redirect,redirect_without_port] {
        assert!(Index::new(std::slice::from_ref(&invalid)).is_err());
        assert!(scan(&[invalid],context(),packet(1000,80)).is_err());
    }
    for rank in [2,129,254] {
        let mut valid=record(1000,6,80,16,0x100|rank,0,false);
        valid.entry.proxy_port=flowsdn_bpf_abi::Be16::new(15000);
        let index=Index::new(std::slice::from_ref(&valid)).expect("valid redirect");
        assert_eq!(index.lookup(context(),packet(1000,80)),Ok(Outcome::Allow {proxy_port:15000,authentication:0,cookie:0}));
    }
}
