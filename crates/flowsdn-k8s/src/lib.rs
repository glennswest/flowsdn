//! Kubernetes compatibility plans and guarded patch construction from spec 13.
//! No HTTP client, discovery, informer, schema vendoring or controller is implemented.
#![forbid(unsafe_code)]

pub mod patch;
pub mod plan;
pub mod version;

pub const SCHEMA_VERSION: &str = "1.33.11";
pub const SCHEMA_VERSION_LABEL: &str = "io.cilium.k8s.crd.schema.version";
/// JSON is the baseline for built-in and custom resources. Protobuf remains
/// pending measured benefit and server capability evidence (#165).
pub const JSON_CONTENT_TYPE: &str = "application/json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for Error {}
