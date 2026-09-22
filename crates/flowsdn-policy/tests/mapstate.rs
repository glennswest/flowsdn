use flowsdn_policy::{Error,mapstate::MapState,oracle::*,ports::PortRange};
fn base()->Rule {Rule {tier:Tier::Normal,priority:0.0,verdict:Verdict::Allow,egress:true,peer:Peer::Any,protocol:0,ports:PortRange::any(),authentication:None,proxy_port:0,listener_priority:0}}
fn compare_all_ports(rules:&[Rule],identity:u32,egress:bool,protocol:u8) {
    let compiled=MapState::compile(rules).expect("compile");
    for port in 0..=u16::MAX {
        let packet=Packet {identity,egress,protocol,port};
        assert_eq!(compiled.lookup(packet),evaluate(rules,packet).expect("oracle"),"packet={packet:?}, rules={rules:?}");
    }
}
#[test]
fn exhaustive_port_gate_covers_pass_deny_redirect_and_unknown_identity() {
    let rules=vec![
        Rule {tier:Tier::Admin,priority:1.0,verdict:Verdict::Pass,protocol:6,ports:PortRange::from_api(80,Some(95)).expect("range"),..base()},
        Rule {tier:Tier::Admin,priority:2.0,verdict:Verdict::Deny,..base()},
        Rule {peer:Peer::Identity(123),protocol:6,ports:PortRange::from_api(85,Some(90)).expect("range"),proxy_port:15000,listener_priority:1,..base()},
        Rule {proxy_port:15001,listener_priority:0,..base()},
        Rule {tier:Tier::Baseline,egress:false,..base()},
    ];
    for (identity,egress,protocol) in [(123,true,6),(124,true,6),(123,true,17),(123,false,6)] {compare_all_ports(&rules,identity,egress,protocol);}
}
fn random(state:&mut u64)->u32 {
    *state=state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    u32::try_from(*state>>32).expect("high half")
}
fn generated(seed:u64)->Vec<Rule> {
    let mut state=seed;
    (0..10).map(|_| {
        let mut rule=base();
        rule.tier=match random(&mut state)%4 {0=>Tier::Admin,1=>Tier::Normal,2=>Tier::Baseline,_=>Tier::Default};
        rule.priority=f64::from(random(&mut state)%3);
        rule.verdict=match random(&mut state)%3 {0=>Verdict::Deny,1=>Verdict::Pass,_=>Verdict::Allow};
        rule.egress=random(&mut state)&1!=0;
        rule.peer=match random(&mut state)%3 {0=>Peer::Any,1=>Peer::Identity(123),_=>Peer::Identity(456)};
        rule.protocol=match random(&mut state)%3 {0=>0,1=>6,_=>17};
        if rule.protocol!=0 {rule.ports=match random(&mut state)%5 {0=>PortRange::any(),1=>PortRange::from_api(80,Some(95)).expect("range"),2=>PortRange::from_api(90,Some(443)).expect("range"),3=>PortRange::from_api(1024,Some(2047)).expect("range"),_=>PortRange::from_api(65535,None).expect("port")};}
        if rule.verdict==Verdict::Allow && random(&mut state)&1!=0 {rule.proxy_port=if random(&mut state)&1!=0 {15000}else{15001};rule.listener_priority=u8::try_from(random(&mut state)%3).expect("small");}
        rule
    }).collect()
}
#[test]
fn deterministic_generated_policies_match_independent_oracle_and_update_order() {
    // Every boundary induced by generated intervals, both sides of each edge,
    // all identity/protocol equivalence classes and both traffic directions.
    let ports=[0,1,79,80,81,89,90,91,94,95,96,442,443,444,1023,1024,1025,2046,2047,2048,65534,65535];
    for seed in 0..192 {
        let mut rules=generated(seed);
        let compiled=MapState::compile(&rules).expect("compile");
        rules.reverse();
        let reversed=MapState::compile(&rules).expect("reverse");
        for identity in [0,123,456,789] {for protocol in [0,6,17,255] {for egress in [false,true] {for port in ports {
            let packet=Packet {identity,egress,protocol,port};
            let expected=evaluate(&rules,packet).expect("oracle");
            assert_eq!(compiled.lookup(packet),expected,"seed={seed}, packet={packet:?}");
            assert_eq!(reversed.lookup(packet),expected,"reversed seed={seed}");
        }}}}
    }
}
#[test]
fn coalescing_is_semantic_and_invalid_replacement_preserves_published_index() {
    let plain=base();
    let mut compiled=MapState::compile(std::slice::from_ref(&plain)).expect("compile");
    let packet=Packet {identity:123,egress:true,protocol:6,port:80};
    let count=compiled.interval_count();
    let equivalent=Rule {protocol:6,ports:PortRange::from_api(80,Some(95)).expect("range"),..plain.clone()};
    let with_equivalent=MapState::compile(&[plain.clone(),equivalent]).expect("compile");
    assert_eq!(with_equivalent.lookup(packet),compiled.lookup(packet));
    assert_eq!(with_equivalent.interval_count(),count.saturating_mul(2)); // additional protocol buckets, each coalesced
    let auth=Rule {authentication:Some(Authentication::Required),..plain.clone()};
    assert_eq!(compiled.replace(&[auth]),Err(Error::OracleAuthenticationUnsupported));
    assert_eq!(compiled.lookup(packet),evaluate(&[plain],packet).expect("oracle"));
    compiled.replace(&[]).expect("delete");assert_eq!(compiled.lookup(packet),Decision::Deny);
}
#[test]
fn signed_zero_priorities_are_equal_and_equal_redirects_keep_all_candidates() {
    let first=Rule {priority:-0.0,proxy_port:15000,listener_priority:2,..base()};
    let second=Rule {priority:0.0,proxy_port:15001,..first.clone()};
    compare_all_ports(&[first,second],123,true,6);
}
