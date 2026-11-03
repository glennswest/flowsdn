//! Recorded-response cloud fixtures (ADR-0007, spec 07 §9.1), the
//! provider-independent half: the fixture layout and its loader, the
//! capture-side scrubber, the `tests/cloud/**` scan, in-order replay matching
//! and a loopback HTTP replay server.
//!
//! Capture itself (`cargo xtask cloud-record`) needs a provider client that
//! sends requests and a throwaway account; neither exists yet (#391, #293).
pub mod canon;
pub mod fixture;
pub mod replay;
mod rules;
pub mod scan;
pub mod scrub;
pub mod server;

pub use fixture::{Error, Interaction, Meta, Provider, Request, Response, Scenario};
pub use replay::Replayer;
pub use rules::Class;
pub use scan::Finding;
pub use scrub::Scrubber;
pub use server::ReplayServer;

/// Loads every scenario under `root` (`tests/cloud`): the whole tree is
/// scanned first, then each `<provider>/<scenario>/` is read. A missing root
/// has no scenarios.
pub fn load_all(root: &std::path::Path) -> Result<Vec<Scenario>, Error> {
    let io = |e| Error::Io(root.to_path_buf(), e);
    let findings = scan::scan_dir(root).map_err(io)?;
    if !findings.is_empty() {
        return Err(Error::Scan(findings));
    }
    let mut scenarios = Vec::new();
    if !root.exists() {
        return Ok(scenarios);
    }
    let mut dirs = Vec::new();
    for provider in std::fs::read_dir(root).map_err(io)? {
        let provider = provider.map_err(io)?.path();
        if !provider.is_dir() {
            return Err(Error::Format(
                provider,
                "only provider directories belong here".into(),
            ));
        }
        for scenario in std::fs::read_dir(&provider).map_err(io)? {
            dirs.push(scenario.map_err(io)?.path());
        }
    }
    dirs.sort();
    for dir in dirs {
        scenarios.push(fixture::load(&dir)?);
    }
    Ok(scenarios)
}

#[cfg(test)]
mod tests {
    #[test]
    fn load_all_scans_the_tree_first() {
        let root = std::env::temp_dir().join(format!("flowsdn-load-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(super::load_all(&root).expect("missing root"), Vec::new());
        crate::fixture::write(&root, &crate::fixture::tests::scenario()).expect("write");
        assert_eq!(super::load_all(&root).expect("load").len(), 1);
        std::fs::write(root.join("aws").join("stray.txt"), "203.0.113.1 54.12.0.9").expect("write");
        assert!(matches!(super::load_all(&root), Err(super::Error::Scan(f)) if f.len() == 1));
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
