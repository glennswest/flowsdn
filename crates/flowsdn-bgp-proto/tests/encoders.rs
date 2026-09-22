use flowsdn_bgp_proto::{*,capabilities::*,encode_update::*,messages::*,update::Prefix};
use std::{collections::BTreeSet,net::{IpAddr,Ipv4Addr}};
fn export()->Export{Export {family:Family::IPV4,next_hop:"192.0.2.1".parse().expect("hop"),local_asn:70000,external:true,four_octet_asn:false,as_sequence:vec![65001],local_preference:100,origin:0}}
#[test]
fn independently_specified_as_trans_and_as4_update_bytes() {
    let prefix=Prefix::new("203.0.113.0".parse().expect("prefix"),24).expect("prefix");
    let frames=export().announcements(&[prefix]).expect("export");
    let (frame,used)=decode(frames.first().expect("frame")).expect("decode framing");
    let expected=[0,0,0,33, 0x40,1,1,0, 0x40,2,6,2,2,0x5b,0xa0,0xfd,0xe9,
        0xc0,17,10,2,2,0,1,0x11,0x70,0,0,0xfd,0xe9, 0x40,3,4,192,0,2,1, 24,203,0,113];
    assert_eq!(frame.body,expected);assert_eq!(used,60);
    assert_eq!(update::validate(frame.body,false).expect("validate").announced,vec![prefix]);
    let mut internal=export();internal.external=false;internal.four_octet_asn=true;
    let frames=internal.announcements(&[prefix]).expect("internal");let (frame,_)=decode(frames.first().expect("frame")).expect("decode");
    let expected=[0,0,0,27,0x40,1,1,0,0x40,2,6,2,1,0,0,0xfd,0xe9,0x40,5,4,0,0,0,100,0x40,3,4,192,0,2,1,24,203,0,113];
    assert_eq!(frame.body,expected);
}
#[test]
fn split_updates_retain_all_nlri_and_never_exceed_the_frame_limit() {
    let prefixes=(0..2000u32).map(|n|Prefix::new(Ipv4Addr::from(0x0a000000u32.saturating_add(n)).into(),32).expect("prefix")).collect::<Vec<_>>();
    let frames=export().announcements(&prefixes).expect("split");assert!(frames.len()>1);
    let mut received=Vec::new();
    for bytes in frames {assert!(bytes.len()<=4096);let(frame,used)=decode(&bytes).expect("frame");assert_eq!(used,bytes.len());received.extend(update::validate(frame.body,false).expect("body").announced);}
    assert_eq!(received,prefixes);
    let frames=withdrawals(Family::IPV4,&prefixes).expect("withdraw split");let mut removed=Vec::new();
    for bytes in frames {assert!(bytes.len()<=4096);removed.extend(update::validate(decode(&bytes).expect("frame").0.body,true).expect("body").withdrawn);}
    assert_eq!(removed,prefixes);
}
#[test]
fn multiprotocol_encoding_withdrawals_and_end_of_rib_are_distinct() {
    let prefix=Prefix::new("2001:db8::".parse().expect("prefix"),32).expect("prefix");
    let mut cfg=export();cfg.family=Family::IPV6;cfg.next_hop="2001:db8::1".parse().expect("hop");cfg.four_octet_asn=true;
    let frames=cfg.announcements(&[prefix]).expect("MP");let(frame,_)=decode(frames.first().expect("frame")).expect("frame");
    assert_eq!(update::validate(frame.body,true).expect("MP").mp_announced,vec![prefix]);
    let frames=withdrawals(Family::IPV6,&[prefix]).expect("withdraw");
    assert_eq!(decode(frames.first().expect("frame")).expect("frame").0.body,[0,0,0,11,0x80,15,8,0,2,1,32,0x20,1,0x0d,0xb8]);
    assert_eq!(end_of_rib(Family::IPV4).expect("v4 EOR"),[0,0,0,0]);
    assert_eq!(end_of_rib(Family::IPV6).expect("v6 EOR"),[0,0,0,6,0x80,15,3,0,2,1]);
    assert!(update::validate(&end_of_rib(Family::IPV6).expect("EOR"),true).expect("EOR").mp_withdrawn.is_empty());
    let v4=Prefix::new("192.0.2.0".parse().expect("v4"),24).expect("v4");
    assert!(cfg.announcements(&[v4]).is_err());assert!(withdrawals(Family::IPV4,&[prefix]).is_err());
    cfg.family=Family::IPV4;assert!(cfg.announcements(&[v4]).is_ok()); // negotiated v4-over-v6 caller contract
}
#[test]
fn open_capability_and_auxiliary_codecs_have_independent_vectors() {
    let families=BTreeSet::from([Family::IPV4,Family::IPV6]);
    let mut local=local_open(70000,90,Ipv4Addr::new(192,0,2,1),&families).expect("OPEN");
    assert_eq!(local.asn,23456);assert_eq!(local.effective_asn().expect("AS4"),70000);
    let restart=graceful_restart(5000,true,&families).expect("GR");
    assert_eq!(restart.value,[0xcf,0xff,0,1,1,0,0,2,1,0]);
    local.capabilities.push(restart);local.capabilities.push(open::Capability {code:5,value:vec![0,1,0,1,0,2]});
    assert_eq!(open::Open::decode(&local.encode().expect("encode")).expect("decode"),local);
    let peer=local_open(65001,30,Ipv4Addr::new(192,0,2,2),&BTreeSet::from([Family::IPV4])).expect("peer");
    let accepted=negotiate(&local,&peer,65001).expect("negotiate");assert_eq!(accepted.hold_time,30);assert_eq!(accepted.families,BTreeSet::from([Family::IPV4]));
    let mut absent=peer;absent.capabilities.retain(|c|c.code!=1);assert_eq!(negotiate(&local,&absent,65001).expect_err("no families").subcode,7);
    assert_eq!(route_refresh(Family::IPV6).expect("refresh"),[0,2,0,1]);assert_eq!(decode_refresh(&[0,2,99,1]).expect("reserved ignored"),Family::IPV6);
    assert!(decode_refresh(&[0,2,0]).is_err());
    let notice=Notification {code:2,subcode:1,data:vec![0,4]};assert_eq!(notice.encode().expect("notice"),[2,1,0,4]);assert_eq!(Notification::decode(&[2,1,0,4]).expect("decode"),notice);
}
#[test]
fn invalid_export_is_rejected_before_any_frames_are_returned() {
    let prefix=Prefix::new("192.0.2.0".parse::<IpAddr>().expect("IP"),24).expect("prefix");
    let mut cfg=export();cfg.origin=3;assert!(cfg.announcements(&[prefix]).is_err());
    cfg=export();cfg.next_hop="0.0.0.0".parse().expect("IP");assert!(cfg.announcements(&[prefix]).is_err());
    cfg=export();cfg.as_sequence=vec![70000;1024];assert!(cfg.announcements(&[prefix]).is_err());
    assert!(cfg.announcements(&[]).is_err());
}
#[test]
fn graceful_restart_n_bit_does_not_change_restart_time_and_last_capability_wins() {
    let families=BTreeSet::from([Family::IPV4]);
    let mut local=local_open(65000,90,Ipv4Addr::new(192,0,2,1),&families).expect("OPEN");
    local.capabilities.push(graceful_restart(120,false,&families).expect("GR"));
    assert_eq!(local.capabilities.last().expect("GR").value,[0x40,120,0,1,1,0]);
    let mut peer=local_open(65001,90,Ipv4Addr::new(192,0,2,2),&families).expect("OPEN");
    assert!(graceful(&local,&peer).is_none());
    peer.capabilities.push(graceful_restart(30,true,&families).expect("GR"));
    let gr=graceful(&local,&peer).expect("negotiated");assert!(gr.notifications);assert_eq!(gr.local_restart_seconds,120);assert_eq!(gr.peer.seconds,30);assert!(gr.peer.restarting);assert!(gr.peer.forwarding.is_empty());
    peer.capabilities.push(open::Capability {code:64,value:vec![0,10,0,1,1,0x80]});
    let gr=graceful(&local,&peer).expect("last");assert!(!gr.notifications);assert_eq!(gr.peer.seconds,10);assert_eq!(gr.peer.forwarding,families);
    let hard=Notification {code:6,subcode:2,data:vec![3,b'b',b'y',b'e']}.hard_reset(true).expect("wrapped");
    assert_eq!(hard.encode().expect("wire"),[6,9,6,2,3,b'b',b'y',b'e']);assert!(!hard.permits_graceful_restart(true));
    let ordinary=Notification::unsupported_version();assert!(ordinary.permits_graceful_restart(true));assert!(!ordinary.permits_graceful_restart(false));assert_eq!(ordinary.clone().hard_reset(false).expect("legacy"),ordinary);
}
