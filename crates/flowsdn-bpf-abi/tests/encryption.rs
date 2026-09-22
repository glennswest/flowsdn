use flowsdn_bpf_abi::encryption::*;
fn config()->Config {Config {tunnel_mode:true,node_encryption:false,wireguard_ifindex:42}}
fn input(family:Family)->Input {Input {mark:0,family,valid_l3:true,neighbor_advertisement:false,source_identity:0,source_ipcache_identity:None,destination_key:None}}
fn redirect(mark:MarkUpdate)->Decision{Decision::Redirect {ifindex:42,mark}}
// Case names identify Cilium v1.20.1 encrypt_host.h scenarios, commit7d68cfb394.
// These are independently authored decision inputs, not copied packet fixtures.
#[test]
fn ten_dead_upstream_scenarios_map_to_explicit_decision_inputs() {
    let mut observed=Vec::new();
    for (family,suffix) in [(Family::Ipv4,"v4"),(Family::Ipv6,"v6")] {
        let mut packet=input(family);
        // Missing destination endpoint still has a covering PodCIDR LPM hit.
        packet.mark=0x0f00;packet.source_identity=0x00ff_ffff;packet.destination_key=Some(255);
        assert_eq!(decide(config(),packet),Ok(redirect(MarkUpdate::Identity(0x00ff_ffff))));observed.push(format!("encrypt_{suffix}_1_missing_dst"));
        // Source endpoint absent; source identity carried by host mark survives.
        assert_eq!(decide(config(),packet),Ok(redirect(MarkUpdate::Identity(0x00ff_ffff))));observed.push(format!("encrypt_{suffix}_2_src_mark"));
        packet.mark=0;packet.source_identity=0;
        assert_eq!(decide(config(),packet),Ok(Decision::Pass {already_encrypted:false}));observed.push(format!("encrypt_{suffix}_3_no_src_mark"));
        // Explicit destination hit replaces upstream's shared-map dependency:
        // case4's setup adds only source; cases1/2 left destination entries live.
        packet.source_ipcache_identity=Some(0x00ff_ffff);packet.destination_key=Some(255);
        assert_eq!(decide(config(),packet),Ok(redirect(MarkUpdate::Identity(0x00ff_ffff))));observed.push(format!("encrypt_{suffix}_4_no_src_mark_with_src_entry"));
        let mut overlay=input(family);overlay.mark=0x0400;
        assert_eq!(decide(config(),overlay),Ok(redirect(MarkUpdate::Preserve)));observed.push(format!("encrypt_{suffix}_vxlan"));
    }
    observed.sort();observed.dedup();assert_eq!(observed.len(),10);
}
#[test]
fn decisions_are_sensitive_to_policy_lookup_and_loop_prevention_not_case_names() {
    let mut p=input(Family::Ipv4);p.source_identity=1000;p.destination_key=Some(255);
    assert!(matches!(decide(config(),p),Ok(Decision::Redirect {..})));
    for key in [None,Some(0)] {p.destination_key=key;assert_eq!(decide(config(),p),Ok(Decision::Pass {already_encrypted:false}));}
    p.destination_key=Some(255);
    for id in [1,2,6,7,9,10,0x01010001,0x02000001] {p.source_identity=id;assert_eq!(decide(config(),p),Ok(Decision::Pass {already_encrypted:false}));}
    p.source_identity=1000;p.mark=0x0e00;p.valid_l3=false;
    assert_eq!(decide(config(),p),Ok(Decision::Pass {already_encrypted:true}));
    p.mark=0x0400;p.family=Family::Other;
    assert_eq!(decide(config(),p),Ok(redirect(MarkUpdate::Preserve)));
    p.mark=0;assert_eq!(decide(config(),p),Ok(Decision::Drop(DropReason::UnsupportedL2)));
    p.family=Family::Ipv4;assert_eq!(decide(config(),p),Ok(Decision::Drop(DropReason::InvalidPacket)));
}
#[test]
fn node_neighbor_exemption_proxy_bypass_and_invalid_inputs() {
    let mut p=input(Family::Ipv6);p.source_identity=1;p.destination_key=Some(255);
    let mut c=config();c.node_encryption=true;
    assert_eq!(decide(c,p),Ok(redirect(MarkUpdate::Identity(1))));
    p.neighbor_advertisement=true;assert_eq!(decide(c,p),Ok(Decision::Pass {already_encrypted:false}));
    p.neighbor_advertisement=false;p.source_identity=2;p.mark=0x0a00;
    assert_eq!(decide(config(),p),Ok(redirect(MarkUpdate::Identity(2))));
    assert_eq!(decide(c,p),Ok(Decision::Pass {already_encrypted:false}));
    p.source_identity=0;p.source_ipcache_identity=None;
    assert_eq!(decide(config(),p),Ok(Decision::Pass {already_encrypted:false}));
    for identity in [0x01000000,0x02000000,0x03000001] {p.source_identity=identity;assert_eq!(decide(config(),p),Ok(Decision::Drop(DropReason::InvalidIdentity)));}
    c.wireguard_ifindex=0;assert_eq!(decide(c,p),Err(InvalidInterface));
}
