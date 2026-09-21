use flowsdn_health::connectivity_probe_interval;
#[test]
fn reference_probe_schedule_counts_ips_and_handles_empty_cluster() {
    for (count, nanos) in [(0,60_000_000_000u64),(1,41_588_830_833),(2,65_916_737_320),(16,169_992_800_643),(1024,415_946_873_494)] {
        let actual=connectivity_probe_interval(0.5,count).expect("valid").as_nanos();
        assert!(actual.abs_diff(u128::from(nanos)) <= 1);
    }
    for ratio in [-0.1,1.1,f64::NAN,f64::INFINITY] { assert!(connectivity_probe_interval(ratio,1).is_err()); }
    for ratio in [0.0,1.0] { assert!(connectivity_probe_interval(ratio,u32::MAX).is_ok()); }
}
