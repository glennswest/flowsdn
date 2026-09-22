use flowsdn_policy::{kernel_map::{Context,Record,Index,Outcome,scan,inherit_auth,prune_aggregate_duplicates},oracle::Packet};
use flowsdn_bpf_abi::policy::{PolicyKey,PolicyEntry};
use flowsdn_identity::numeric::ClusterEncoding;
fn context()->Context {Context {encoding:ClusterEncoding::new(255).expect("encoding"),local_cluster:0}}
fn record(id:u32,proto:u8,port:u16,bits:u8,precedence:u32,auth:u8,explicit:bool)->Record {
    let key=PolicyKey::new(id,true,proto,port,bits).expect("key");
    Record {key,entry:PolicyEntry::new(0,precedence&255==255,u8::try_from(key.prefixlen.saturating_sub(40)).expect("prefix"),auth,explicit,precedence,0).expect("value"),origin:"rule".into()}
}
fn packet(id:u32,port:u16)->Packet {Packet {identity:id,egress:true,protocol:6,port}}
fn compare(records:&[Record],identities:&[u32],all_ports:bool) {
    let index=Index::new(records).expect("index");
    let ports=if all_ports {(0..=u16::MAX).collect::<Vec<_>>()}else{vec![0,1,79,80,81,255,256,511,512,1023,1024,65535]};
    for id in identities {for protocol in [0,6,17] {for egress in [false,true] {for port in &ports {
        let p=Packet {identity:*id,egress,protocol,port:*port};assert_eq!(index.lookup(context(),p),scan(records,context(),p),"{p:?}");
    }}}}
}
#[test]
fn aggregate_auth_explicit_disable_and_wildcard_fallback() {
    // Ordinary cluster-local identities map to aggregate cluster14.
    let mut records=vec![record(1000,6,80,16,0x101,0,false),record(14,6,80,16,0x101,1,true),record(0,0,0,0,0x2ff,0,false)];
    assert_eq!(scan(&records,context(),packet(1000,80)),Ok(Outcome::Allow {proxy_port:0,authentication:1,cookie:0}));
    // Explicit disabled on the chosen specific identity blocks inheritance.
    records.first_mut().expect("specific").entry.auth=128;
    assert_eq!(scan(&records,context(),packet(1000,80)),Ok(Outcome::Allow {proxy_port:0,authentication:0,cookie:0}));
    assert_eq!(scan(&records,context(),packet(1000,81)),Ok(Outcome::Deny));
    compare(&records,&[1000,1001,2,0,14],false);
}
#[test]
fn longer_aggregate_prefix_wins_tie_but_precedence_wins_before_length() {
    let mut records=vec![record(1000,0,0,0,0x101,0,false),record(14,6,80,16,0x101,2,true)];
    assert!(matches!(scan(&records,context(),packet(1000,80)),Ok(Outcome::Allow {authentication:2,..})));
    records.first_mut().expect("specific").entry.precedence=0x201;
    assert!(matches!(scan(&records,context(),packet(1000,80)),Ok(Outcome::Allow {authentication:0,..})));
    compare(&records,&[1000],true);
}
#[test]
fn explicit_auth_boundaries_propagate_only_as_derived_and_preserve_disable() {
    let records=vec![record(1000,0,0,0,0x101,1,true),record(1000,6,0,8,0x101,0,true),record(1000,6,80,16,0x101,0,false),record(1000,17,53,16,0x101,0,false)];
    let output=inherit_auth(&records).expect("inherit");
    assert_eq!(output.get(2).expect("TCP").entry.auth,0);
    assert_eq!(output.get(3).expect("UDP").entry.auth,1);
    assert!(!output.get(3).expect("UDP").entry.has_explicit_auth_type());
    compare(&output,&[1000],false);
    let mut unprepared=records;unprepared.first_mut().expect("broad").entry.precedence=0x201;
    assert!(inherit_auth(&unprepared).is_err());
}
#[test]
fn conservative_pruning_preserves_origins_and_rejects_invalid_kernel_keys() {
    let records=vec![record(1000,6,80,16,0x101,1,true),record(14,6,80,16,0x101,1,true)];
    let pruned=prune_aggregate_duplicates(&records,context()).expect("prune");assert_eq!(pruned.len(),1);
    for port in 0..=u16::MAX {assert_eq!(scan(&records,context(),packet(1000,port)),scan(&pruned,context(),packet(1000,port)));}
    let mut distinct=records.clone();distinct.first_mut().expect("specific").origin="other".into();assert_eq!(prune_aggregate_duplicates(&distinct,context()).expect("prune").len(),2);
    let mut overlapping=records.clone();overlapping.push(record(1000,0,0,0,0x201,0,false));assert_eq!(prune_aggregate_duplicates(&overlapping,context()).expect("prune").len(),3);
    let mut malformed=records.clone();malformed.first_mut().expect("specific").key.dport=flowsdn_bpf_abi::Be16::new(81);malformed.first_mut().expect("specific").key.prefixlen=56;assert!(Index::new(&malformed).is_err());
    let mut pass=records.clone();pass.first_mut().expect("specific").entry.precedence=0x100;assert!(Index::new(&pass).is_err());
    let duplicate=vec![records.first().expect("first").clone();2];assert!(Index::new(&duplicate).is_err());
}
#[test]
fn deterministic_soak_gates_index_across_category_identities() {
    // Override for an extended reproducible soak without a separate harness.
    let iterations=std::env::var("FLOWSDN_POLICY_SOAK_CASES").ok().map(|s|s.parse::<u32>().expect("case count")).unwrap_or(256);
    let ids=[0,11,12,13,14,1000,0x0100_0001,0x0200_0001,0x0001_0001];
    let mut state=0x7327d001u64;
    for _ in 0..iterations {
        let mut records=Vec::new();
        for id in ids {for proto in [0,6,17] {
            state=state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b=state.to_le_bytes();let n=*b.first().expect("random");let priority=(u32::from(n>>2).saturating_add(1))<<8;
            let deny=n&1!=0;let explicit=n&2!=0;
            records.push(record(id,proto,0,if proto==0 {0}else{8},priority|if deny {255}else{1},if deny {0}else{n%3},!deny&&explicit));
        }}
        compare(&records,&ids,false);
        records.reverse();compare(&records,&ids,false);
    }
}
