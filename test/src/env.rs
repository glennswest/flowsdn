//! What the runner gives the container (docs/test-standard.md) and where the
//! image keeps the binaries of the commit under test.
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Env {
    pub suite: String,
    /// The run's budget: `STORM_TIMEOUT`, else the standard's for the suite.
    pub timeout: Duration,
    /// Staged image tree (`/opt/flowsdn`): `bin/`, `fixtures/`, `bpf/`.
    pub root: PathBuf,
    /// Where declared host paths are mounted read-only (`/host`).
    pub host_root: PathBuf,
    /// Artifacts directory: `/results` when the runner provides it.
    pub results: PathBuf,
    /// `STORM_WAVE_MAX`: an upper bound on long's wave size.
    pub wave_max: Option<usize>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Env {
    pub fn from_env(suite: &str) -> Self {
        let standard = match suite {
            "short" => 120,
            "medium" => 1800,
            _ => 28_800,
        };
        let timeout = var("STORM_TIMEOUT")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(standard);
        let results = if Path::new("/results").is_dir() {
            PathBuf::from("/results")
        } else {
            std::env::temp_dir().join("flowsdn-test-results")
        };
        let _ = std::fs::create_dir_all(&results);
        Self {
            suite: suite.to_owned(),
            timeout: Duration::from_secs(timeout),
            root: var("FLOWSDN_TEST_ROOT").map_or_else(|| "/opt/flowsdn".into(), PathBuf::from),
            host_root: var("STORM_HOST_ROOT").map_or_else(|| "/host".into(), PathBuf::from),
            results,
            wave_max: var("STORM_WAVE_MAX").and_then(|v| v.trim().parse().ok()),
        }
    }
    pub fn agent(&self) -> PathBuf {
        self.root.join("bin/flowsdn-agent")
    }
    pub fn cni(&self) -> PathBuf {
        self.root.join("bin/flowsdn-cni")
    }
    pub fn fixture(&self, name: &str) -> PathBuf {
        self.root.join("fixtures").join(name)
    }
    pub fn bpf(&self, name: &str) -> PathBuf {
        self.root.join("bpf").join(name)
    }
    /// A host path as this container sees it under the read-only host mount.
    pub fn host(&self, path: &str) -> PathBuf {
        self.host_root.join(path.trim_start_matches('/'))
    }
}
