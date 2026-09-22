use flowsdn_proxy::{ack::*, fqdn::local_identity, transparent_dns};
use std::{collections::BTreeMap, net::IpAddr};
fn node() -> IpAddr { "127.0.0.1".parse().expect("node") }
fn barrier() -> Barrier { Barrier::new(node(),17,9,100,BTreeMap::from([("NPDS".into(),4),("LDS".into(),6)])).expect("barrier") }
fn event(kind: &str, version:u64) -> Observation { Observation { node:node(),epoch:0,kind:kind.into(),nonce:version,version,nack:false } }
#[test]
fn both_acknowledgements_gate_the_commit_and_commit_is_one_shot() {
    let mut gate=barrier();
    assert_eq!(gate.commit(0),Err(Error::NotReady));
    gate.sent("NPDS",5,1).expect("newer response"); gate.sent("LDS",6,1).expect("listener");
    assert_eq!(gate.observe(&event("NPDS",5),2),Ok(true));
    assert_eq!(gate.commit(2),Err(Error::NotReady));
    gate.observe(&event("LDS",6),3).expect("ack");
    assert_eq!(gate.commit(4),Ok(CommitPermit {attempt:17,policy_revision:9}));
    assert_eq!(gate.commit(4),Err(Error::Terminal));
}
#[test]
fn stale_nonce_wrong_node_and_pre_first_ack_resume_cannot_open_barrier() {
    let mut gate=barrier(); gate.sent("NPDS",4,1).expect("send");
    assert_eq!(gate.observe(&event("NPDS",3),2),Ok(false));
    let wrong=Observation {node:"127.0.0.2".parse().expect("other"),..event("NPDS",4)};
    assert_eq!(gate.observe(&wrong,2),Ok(false));
    let future=Observation {version:5,..event("NPDS",4)};
    assert_eq!(gate.observe(&future,2),Err(Error::InvalidResponse));
    gate.observe(&event("NPDS",4),2).expect("ack");
    let epoch=gate.reconnect(3).expect("reconnect"); assert_eq!(epoch,1);
    gate.sent("NPDS",4,4).expect("resend"); gate.sent("LDS",6,4).expect("send");
    assert_eq!(gate.observe(&event("NPDS",4),5),Ok(false));
    gate.observe(&Observation {epoch,..event("LDS",6)},5).expect("new listener ack");
    assert_eq!(gate.commit(5),Err(Error::NotReady));
    gate.observe(&Observation {epoch,..event("NPDS",4)},5).expect("new policy ack");
    assert!(gate.commit(6).is_ok());
}
#[test]
fn nack_timeout_and_cancellation_never_grant_publication() {
    for explicit in [false,true] {
        let mut gate=barrier(); gate.sent("NPDS",4,0).expect("send");
        let nack=Observation { version:if explicit {4}else{3},nack:explicit,..event("NPDS",4) };
        assert_eq!(gate.observe(&nack,1),Ok(true)); assert_eq!(gate.state(),State::Rejected);
        assert_eq!(gate.observe(&event("NPDS",4),2),Err(Error::Terminal));
        assert_eq!(gate.commit(2),Err(Error::Terminal));
    }
    let mut gate=barrier(); gate.sent("NPDS",4,0).expect("send");
    assert_eq!(gate.observe(&event("NPDS",4),100),Err(Error::Terminal)); assert_eq!(gate.state(),State::TimedOut);
    let mut gate=barrier(); gate.cancel(); assert_eq!(gate.commit(1),Err(Error::Terminal));
}
#[test]
fn a_superseding_response_revokes_readiness_until_its_ack() {
    let mut gate=barrier();
    for (kind,version) in [("NPDS",4),("LDS",6)] { gate.sent(kind,version,1).expect("send"); gate.observe(&event(kind,version),2).expect("ack"); }
    assert_eq!(gate.state(),State::Ready);
    gate.sent("NPDS",5,3).expect("supersede");
    assert_eq!(gate.observe(&event("NPDS",4),4),Ok(false)); assert_eq!(gate.commit(4),Err(Error::NotReady));
    gate.observe(&event("NPDS",5),5).expect("new ack"); assert!(gate.commit(6).is_ok());
}
#[test]
fn expired_ready_gate_still_cannot_commit() {
    let mut gate=barrier();
    for (kind,version) in [("NPDS",4),("LDS",6)] { gate.sent(kind,version,1).expect("send"); gate.observe(&event(kind,version),2).expect("ack"); }
    assert_eq!(gate.commit(100),Err(Error::Terminal));
    assert_eq!(gate.state(),State::TimedOut);
}
#[test]
fn fqdn_restore_uses_shared_full_local_scope_without_partition() {
    for valid in [0x01000001,0x0100ffff,0x01010000,0x01ffffff] { assert_eq!(local_identity(valid).expect("local").get(),valid); }
    for invalid in [0,1,0x00ffffff,0x01000000,0x02000001,0x03000001,u32::MAX] { assert!(local_identity(invalid).is_err()); }
}
#[test]
fn explicit_dns_configuration_overrides_topology_default() {
    assert!(!transparent_dns(false,None)); assert!(transparent_dns(true,None));
    assert!(!transparent_dns(true,Some(false))); assert!(transparent_dns(false,Some(true)));
}
