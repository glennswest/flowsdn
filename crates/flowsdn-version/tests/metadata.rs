#![allow(clippy::unwrap_used)]
#[path = "../build_support.rs"]
mod build_support;
use flowsdn_version::BuildInfo;
use std::collections::BTreeMap;

fn inputs() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("FLOWSDN_VERSION".into(), "1.2.3".into()),
        ("FLOWSDN_REVISION".into(), "abcd".into()),
        ("SOURCE_DATE_EPOCH".into(), "0".into()),
        ("FLOWSDN_RUSTC".into(), "rustc test".into()),
        ("TARGET".into(), "aarch64-unknown-linux-musl".into()),
    ])
}
#[test]
fn epoch_conversion_handles_leap_centuries_and_bounds() {
    for (input, expected) in [
        ("0", "1970-01-01T00:00:00Z"),
        ("951782400", "2000-02-29T00:00:00Z"),
        ("4107542400", "2100-03-01T00:00:00Z"),
        ("253402300799", "9999-12-31T23:59:59Z"),
    ] {
        assert_eq!(build_support::build_date(input).unwrap(), expected);
    }
    for bad in [
        "-1",
        "+1",
        " 0",
        "1.0",
        "",
        "253402300800",
        "999999999999999999999999",
    ] {
        assert!(build_support::build_date(bad).is_err());
    }
}
#[test]
fn injection_is_deterministic_and_development_cannot_claim_clean() {
    let mut input = inputs();
    input.insert("FLOWSDN_FEATURES".into(), "z, a,z, ,b".into());
    let release = build_support::metadata(input.clone(), false).unwrap();
    assert_eq!(
        release,
        build_support::metadata(input.clone(), false).unwrap()
    );
    assert_eq!(release.get("FLOWSDN_FEATURES").unwrap(), "a,b,z");
    assert_eq!(release.get("FLOWSDN_DIRTY").unwrap(), "false");
    assert_eq!(
        release.get("FLOWSDN_BPF_OBJECTS_SHA").unwrap(),
        "unavailable"
    );
    input.insert("FLOWSDN_DIRTY".into(), "false".into());
    assert_eq!(
        build_support::metadata(input, true)
            .unwrap()
            .get("FLOWSDN_DIRTY")
            .unwrap(),
        "true"
    );
}
#[test]
fn malformed_and_missing_metadata_are_rejected() {
    for key in [
        "FLOWSDN_VERSION",
        "FLOWSDN_REVISION",
        "SOURCE_DATE_EPOCH",
        "FLOWSDN_RUSTC",
        "TARGET",
    ] {
        let mut input = inputs();
        input.remove(key);
        assert!(build_support::metadata(input, false).is_err());
    }
    for value in ["bad\nvalue", "bad\rvalue", "bad\0value"] {
        assert!(build_support::clean(value).is_err());
    }
    let mut input = inputs();
    input.insert("FLOWSDN_DIRTY".into(), "yes".into());
    assert!(build_support::metadata(input, false).is_err());
    assert!(build_support::INPUTS.contains(&"FLOWSDN_REVISION"));
}
#[test]
fn current_json_and_metric_labels_preserve_build_identity() {
    let info = BuildInfo::current();
    let json = info.json();
    assert_eq!(json.get("version").unwrap(), info.version);
    assert_eq!(json.get("dirty").unwrap(), info.dirty);
    assert_eq!(
        json.get("features").unwrap().as_array().unwrap().len(),
        info.features.len()
    );
    assert_eq!(
        info.metric_labels().get("target"),
        Some(&info.target_triple)
    );
    assert_eq!(info.reference, "cilium/cilium@7d68cfb394");
}
