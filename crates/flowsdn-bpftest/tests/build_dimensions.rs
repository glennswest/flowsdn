//! #464: flowsdn-bpf has no build dimensions. The owner dropped the
//! `debug-events` and `test-hooks` features of spec 02 §6.2 and §12 item 11,
//! so every BPF object is a release object and the kernel tests run the
//! objects that ship. A feature added to flowsdn-bpf fails here until spec
//! 02 says what it is for.

#[test]
fn flowsdn_bpf_has_no_build_dimensions() {
    let manifest: toml::Table = include_str!("../../flowsdn-bpf/Cargo.toml")
        .parse()
        .expect("flowsdn-bpf/Cargo.toml");
    assert!(
        manifest.get("features").is_none(),
        "flowsdn-bpf has features: {:?}",
        manifest.get("features")
    );
    let spec = include_str!("../../../docs/spec/02-datapath-programs.md");
    assert!(spec.contains(
        "## Amendment — no debug-events or test-hooks build dimensions (#464, 2026-11-25)"
    ));
}
