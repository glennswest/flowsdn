//! `cargo xtask cloud-scan`: the ADR-0007 `cloud-fixture-scan` over
//! `tests/cloud/**`, then every scenario loaded (layout, numbering,
//! `scenario.toml`). It holds no credentials and reads no network.
use std::error::Error;
use std::path::Path;

pub fn scan(root: &Path) -> Result<(), Box<dyn Error>> {
    let cloud = root.join("tests").join("cloud");
    let scenarios = flowsdn_cloud_fixture::load_all(&cloud)?;
    let interactions: usize = scenarios.iter().map(|s| s.interactions.len()).sum();
    println!(
        "cloud-scan: {} clean: {} scenario(s), {interactions} interaction(s)",
        cloud.display(),
        scenarios.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Every build's `cargo test` scans the committed fixtures.
    #[test]
    fn committed_cloud_fixtures_are_clean() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace");
        if let Err(e) = super::scan(root) {
            panic!("{e}");
        }
    }
}
