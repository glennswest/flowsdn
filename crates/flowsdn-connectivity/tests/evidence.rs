use flowsdn_bpf_abi::ct::CtEntry;
use flowsdn_connectivity::*;
#[test]
fn group_windows_isolate_old_streams_and_refuse_incomplete_assertions() {
    let mut window = FlowWindow::new(2).expect("capacity");
    let first = window
        .begin(["node-a".into(), "node-b".into()])
        .expect("start");
    assert_eq!(window.begin(["node-c".into()]), Err(Error::AlreadyActive));
    window.push(&first, "node-a", 1).expect("flow");
    window.push(&first, "node-a", 2).expect("flow");
    assert_eq!(window.push(&first, "node-a", 3), Err(Error::Overflow));
    assert_eq!(window.finish(&first), Err(Error::IncompleteEvidence));
    assert_eq!(
        window.abort(&first).expect("diagnostics").get("node-a"),
        Some(&vec![1, 2])
    );
    let second = window.begin(["node-b".into()]).expect("next");
    assert_eq!(window.push(&first, "node-b", 4), Err(Error::StaleGroup));
    assert_eq!(window.push(&second, "node-a", 4), Err(Error::UnknownNode));
    window.push(&second, "node-b", 5).expect("new");
    assert_eq!(
        window.finish(&second).expect("complete").get("node-b"),
        Some(&vec![5])
    );
    let third = window.begin(["node-b".into()]).expect("loss group");
    window.mark_incomplete(&third).expect("loss");
    assert_eq!(window.finish(&third), Err(Error::IncompleteEvidence));
}
#[test]
fn ct_reuse_never_mislabels_expiry_or_report_time_as_creation() {
    let before = CtObservation {
        map_id: 17,
        tuple_key: vec![1; 14],
        entry: CtEntry {
            lifetime: 8000,
            last_tx_report: 42,
            last_rx_report: 43,
            ..CtEntry::default()
        },
    };
    assert_eq!(
        quiesced_ct_reuse(&before, &before),
        ReuseEvidence::SameMapAndQuiescedValue
    );
    let mut after = before.clone();
    after.map_id = 18;
    assert_eq!(
        quiesced_ct_reuse(&before, &after),
        ReuseEvidence::ChangedMap
    );
    after = before.clone();
    after.entry.lifetime = 9000;
    assert_eq!(
        quiesced_ct_reuse(&before, &after),
        ReuseEvidence::ChangedValue
    );
    after = before.clone();
    after.entry.last_tx_report = 44;
    assert_eq!(
        quiesced_ct_reuse(&before, &after),
        ReuseEvidence::ChangedValue
    );
    after = before.clone();
    after.tuple_key = vec![2; 14];
    assert_eq!(
        quiesced_ct_reuse(&before, &after),
        ReuseEvidence::ChangedKey
    );
    after = before.clone();
    after.map_id = 0;
    assert_eq!(
        quiesced_ct_reuse(&before, &after),
        ReuseEvidence::InvalidMapId
    );
}
#[test]
fn placements_distinguish_simulation_real_datapath_and_advisory_crosschecks() {
    assert!(placement(Lane::TrustedPrivileged).merge_gate_when_operational);
    assert_eq!(placement(Lane::DatapathScale).node_count, Some(5));
    assert_eq!(placement(Lane::SimulatedControlPlane).node_count, Some(100));
    assert!(!placement(Lane::SimulatedControlPlane).real_datapath);
    assert_eq!(placement(Lane::DedicatedArm64).cadence, Cadence::Nightly);
    let upstream = placement(Lane::UpstreamCrosscheck);
    assert_eq!(upstream.cadence, Cadence::Weekly);
    assert!(!upstream.merge_gate_when_operational);
}

#[test]
fn replaced_window_rejects_old_group_even_when_generation_matches() {
    let mut old = FlowWindow::<u8>::new(1).expect("old window");
    let stale = old.begin(["node".into()]).expect("old group");
    drop(old);
    let mut replacement = FlowWindow::new(1).expect("replacement");
    let current = replacement.begin(["node".into()]).expect("current group");
    assert_ne!(stale, current);
    assert_eq!(replacement.push(&stale, "node", 1), Err(Error::StaleGroup));
    assert_eq!(replacement.mark_incomplete(&stale), Err(Error::StaleGroup));
    assert_eq!(replacement.abort(&stale), Err(Error::StaleGroup));
    assert_eq!(replacement.finish(&stale), Err(Error::StaleGroup));
    replacement.push(&current, "node", 2).expect("current data");
    assert_eq!(
        replacement.finish(&current).expect("complete").get("node"),
        Some(&vec![2])
    );
}
