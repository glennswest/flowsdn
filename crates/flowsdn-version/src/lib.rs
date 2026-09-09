//! Build identity from packaging spec §§3.8.7 and 4.
//! Binaries inject their enabled features through `FLOWSDN_FEATURES`; this crate
//! cannot infer features of reverse dependencies. Absent BPF metadata is explicit.
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    pub version: &'static str,
    pub revision: &'static str,
    pub dirty: bool,
    pub build_date: &'static str,
    pub rustc: &'static str,
    pub bpf_toolchain: &'static str,
    pub bpf_linker: &'static str,
    pub bpf_objects_sha: &'static str,
    pub target_triple: &'static str,
    pub features: Vec<&'static str>,
    pub reference: &'static str,
    pub chart_compat: &'static str,
}
impl BuildInfo {
    pub fn current() -> Self {
        Self {
            version: env!("FLOWSDN_VERSION"), revision: env!("FLOWSDN_REVISION"),
            dirty: env!("FLOWSDN_DIRTY") == "true", build_date: env!("FLOWSDN_BUILD_DATE"),
            rustc: env!("FLOWSDN_RUSTC"), bpf_toolchain: env!("FLOWSDN_BPF_TOOLCHAIN"),
            bpf_linker: env!("FLOWSDN_BPF_LINKER"), bpf_objects_sha: env!("FLOWSDN_BPF_OBJECTS_SHA"),
            target_triple: env!("TARGET"), features: env!("FLOWSDN_FEATURES").split(',').filter(|s| !s.is_empty()).collect(),
            reference: "cilium/cilium@7d68cfb394", chart_compat: "1.20",
        }
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version, "revision": self.revision, "dirty": self.dirty,
            "build_date": self.build_date, "rustc": self.rustc, "bpf_toolchain": self.bpf_toolchain,
            "bpf_linker": self.bpf_linker, "bpf_objects_sha": self.bpf_objects_sha,
            "target_triple": self.target_triple, "features": self.features,
            "reference": self.reference, "chart_compat": self.chart_compat,
        })
    }
    /// Labels for a future `flowsdn_build_info` gauge whose value is 1.
    pub fn metric_labels(&self) -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("version", self.version), ("revision", self.revision), ("rustc", self.rustc),
            ("bpf_toolchain", self.bpf_toolchain), ("bpf_objects_sha", self.bpf_objects_sha),
            ("target", self.target_triple),
        ])
    }
}
