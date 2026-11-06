//! Kubernetes compatibility plans and guarded patch construction from spec 13.
//! Includes bounded HTTPS transport and built-in ListWatch state; no running controller.
#![forbid(unsafe_code)]

pub mod client;
pub mod crd;
pub mod patch;
pub mod plan;
pub mod schema;
pub mod version;
pub mod watch;

/// Reference schema provenance, independent of the owned API version v1alpha1.
pub const SCHEMA_VERSION: &str = "1.33.11";
pub const SCHEMA_VERSION_LABEL: &str = "io.flowsdn.k8s.crd.schema.version";
/// JSON is the baseline for built-in and custom resources. Protobuf remains
/// pending measured benefit and server capability evidence (#165).
pub const JSON_CONTENT_TYPE: &str = "application/json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
#[test]
fn not_found_is_only_a_404() {
    assert!(Error("Kubernetes HTTP 404; relist required".into()).is_not_found());
    assert!(!Error("Kubernetes HTTP 410; relist required".into()).is_not_found());
    assert!(!Error("Kubernetes list timeout; relist required".into()).is_not_found());
}
impl Error {
    /// The server answered 404: for a CRD's kind, not served yet.
    pub fn is_not_found(&self) -> bool {
        self.0.starts_with("Kubernetes HTTP 404;")
    }
}
