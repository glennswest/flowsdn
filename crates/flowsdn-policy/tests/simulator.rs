use flowsdn_policy::{simulator::{self,Endpoint,Entry,Port,Selector},oracle::{Decision,Packet,Peer,Rule,Tier,Verdict},ports::PortRange};
use std::{collections::BTreeMap,path::PathBuf};
fn endpoint(id:u32,name:&str)->Endpoint { Endpoint { identity:id,labels:BTreeMap::from([("name".into(),name.into()),("namespace".into(),"default".into())]),named_ports:BTreeMap::from([((6,"http".into()),80)]) } }
fn entry()->Entry { Entry {subject:Selector::Any,peers:Selector::Any,default_deny:false,port:Port::Numeric(PortRange::any()),rule:Rule {tier:Tier::Normal,priority:0.0,verdict:Verdict::Allow,egress:true,peer:Peer::Any,protocol:0,ports:PortRange::any(),authentication:None,proxy_port:0,listener_priority:0}} }
fn compare(entries:&[Entry]) {
    let a=endpoint(100,"a");let peers=[endpoint(200,"b"),endpoint(300,"c"),endpoint(400,"other")];
    for egress in [false,true] {
        let compiled=simulator::compile(entries,&a,&peers,egress).expect("compile");
        for peer in &peers { for protocol in [6,17,1] { for port in [0,3,4,5,6,7,8,79,80,81,65535] {
            let (src,dst)=if egress {(&a,peer)}else{(peer,&a)};
            let expected=simulator::evaluate(entries,src,dst,egress,protocol,port).expect("simulate");
            assert_eq!(compiled.lookup(Packet {identity:peer.identity,egress,protocol,port}),expected,"peer={}, egress={egress}, protocol={protocol}, port={port}",peer.identity);
        } } }
    }
}
// Strict decoder of the already-harvested Go fuzz data envelope, not executable Go.
fn corpus_bytes(input:&str)->Vec<u8> {
    let literal=input.strip_prefix("go test fuzz v1\n[]byte(\"").and_then(|s|s.trim_end().strip_suffix("\")")).expect("Go fuzz envelope");
    let mut bytes=literal.bytes();let mut out=Vec::new();
    while let Some(b)=bytes.next() {
        if b!=b'\\' {out.push(b);continue;}
        let escaped=bytes.next().expect("escape");
        match escaped {
            b'x'|b'u'|b'U'=> {
                let count=match escaped {b'x'=>2,b'u'=>4,_=>8};
                let digits=bytes.by_ref().take(count).map(char::from).collect::<String>();assert_eq!(digits.len(),count);
                let value=u32::from_str_radix(&digits,16).expect("hex");
                if escaped==b'x' {out.push(u8::try_from(value).expect("byte"));} else {let c=char::from_u32(value).expect("unicode");let mut buf=[0;4];out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());}
            }
            b'a'=>out.push(7),b'b'=>out.push(8),b'f'=>out.push(12),b'n'=>out.push(10),b'r'=>out.push(13),b't'=>out.push(9),b'v'=>out.push(11),b'\\'=>out.push(b'\\'),b'"'=>out.push(b'"'),_=>panic!("unsupported corpus escape"),
        }
    } out
}
#[test]
fn all_27_reference_seeds_and_mutations_gate_frontend_and_index() {
    let dir=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fuzz/corpus/FuzzDistillPolicy");
    let mut paths=std::fs::read_dir(dir).expect("corpus").map(|e|e.expect("file").path()).collect::<Vec<_>>();paths.sort();assert_eq!(paths.len(),27);
    for path in paths {
        let bytes=corpus_bytes(&std::fs::read_to_string(&path).expect("fixture"));
        let entries=simulator::decode_seed(&bytes).expect("seed");compare(&entries);
        let mut reversed=entries.clone();reversed.reverse();compare(&reversed);
        for bit in 0..8 {
            let mut mutated=bytes.clone();for byte in mutated.iter_mut().take(8) {*byte^=1u8.checked_shl(bit).expect("bit");}
            compare(&simulator::decode_seed(&mutated).expect("mutation"));
        }
    }
}
#[test]
fn deterministic_byte_streams_include_empty_and_odd_tail_inputs() {
    let mut state=0xd19a44e5u64;
    for length in 0..128 {
        let bytes=(0..length).map(|_| {state=state.wrapping_mul(6364136223846793005).wrapping_add(1);state.to_le_bytes().first().copied().expect("byte")}).collect::<Vec<_>>();
        compare(&simulator::decode_seed(&bytes).expect("seed"));
    }
    assert_eq!(corpus_bytes("go test fuzz v1\n[]byte(\"é\\x00\\u0061\\n\")\n"),vec![0xc3,0xa9,0,b'a',10]);
}
#[test]
fn nil_peers_default_deny_and_pass_fallthrough_are_distinct() {
    let a=endpoint(100,"a");let b=endpoint(200,"b");
    let mut e=entry();e.peers=Selector::None;compare(&[e.clone()]);
    assert!(matches!(simulator::evaluate(&[e.clone()],&a,&b,true,6,80).expect("evaluate"),Decision::Allow {..}));
    e.default_deny=true;compare(&[e.clone()]);assert_eq!(simulator::evaluate(&[e],&a,&b,true,6,80),Ok(Decision::Deny));
    let mut pass=entry();pass.rule.verdict=Verdict::Pass;compare(&[pass.clone()]);
    assert_eq!(simulator::evaluate(&[pass],&a,&b,true,6,80),Ok(Decision::Deny));
    let mut not_selected=entry();not_selected.subject=Selector::None;not_selected.default_deny=true;compare(&[not_selected]);
}
#[test]
fn named_ports_use_destination_for_each_direction_and_recompile_changes() {
    for egress in [false,true] {let mut e=entry();e.default_deny=true;e.rule.egress=egress;e.rule.protocol=6;e.port=Port::Named("http".into());compare(&[e.clone()]);
        let a=endpoint(100,"a");let mut b=endpoint(200,"b");
        let old=simulator::compile(&[e.clone()],&a,&[b.clone()],egress).expect("compile");
        b.named_ports.clear();let new=simulator::compile(&[e],&a,&[b],egress).expect("compile");
        let packet=Packet {identity:200,egress,protocol:6,port:80};
        assert!(matches!(old.lookup(packet),Decision::Allow {..}));
        if egress {assert_eq!(new.lookup(packet),Decision::Deny);}else{assert!(matches!(new.lookup(packet),Decision::Allow {..}));}
    }
}
