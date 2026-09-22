use crate::Error;
use std::time::Duration;
pub const DEFAULT_RESYNC: Duration = Duration::from_secs(300);
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IdentityMode {
    #[default]
    Crd,
    Kvstore,
}
impl IdentityMode {
    pub fn parse(mode: &str, kvstore: &str) -> Result<Self, Error> {
        if !matches!(kvstore, "" | "etcd") {
            return Err(Error("kvstore must be empty or etcd".into()));
        }
        match mode {
            "crd" => Ok(Self::Crd),
            "kvstore" if kvstore == "etcd" => Ok(Self::Kvstore),
            "kvstore" => Err(Error("kvstore identities require kvstore=etcd".into())),
            "doublewrite-readkvstore" | "doublewrite-readcrd" => Err(Error(
                "double-write is unsupported; drain before switching identity backends".into(),
            )),
            _ => Err(Error("unknown identity-allocation-mode".into())),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServicePlan {
    pub export_legacy: bool,
    pub export_slices: bool,
    pub import_legacy: bool,
    pub import_slices: bool,
}
pub fn service_plan(mode: &str) -> Result<ServicePlan, Error> {
    if mode != "prefer-legacy" {
        return Err(Error("only prefer-legacy is supported until the EndpointSlice consumer passes interoperability tests".into()));
    }
    Ok(ServicePlan {
        export_legacy: true,
        export_slices: true,
        import_legacy: true,
        import_slices: false,
    })
}
/// Reference peers may omit this capability (legacy-only). Slice-only peers
/// cannot provide backends to the currently supported legacy importer.
pub fn validate_peer_service_export(mode: Option<&str>) -> Result<(), Error> {
    match mode {
        None | Some("" | "services-and-endpointslices") => Ok(()),
        Some("endpointslices-only") => Err(Error(
            "peer exports only EndpointSlices; legacy service records are required".into(),
        )),
        Some(_) => Err(Error("unknown peer endpointSlicesExportMode".into())),
    }
}
/// Zero is explicit diagnostic opt-out, never selected automatically from a
/// server version claim. The caller must warn about its convergence implications.
pub fn resync_interval(explicit: Option<Duration>) -> Duration {
    explicit.unwrap_or(DEFAULT_RESYNC)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredFeatures {
    pub mcs_api: bool,
    pub mcs_install_crds: bool,
    pub endpoint_sync: bool,
}
impl Default for DeferredFeatures {
    fn default() -> Self {
        Self {
            mcs_api: false,
            mcs_install_crds: true,
            endpoint_sync: false,
        }
    }
}
impl DeferredFeatures {
    /// Accepted-but-ignored keys must produce named startup warnings.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        if self.mcs_api {
            warnings.push("clustermesh-enable-mcs-api is not implemented");
        }
        if self.mcs_install_crds {
            warnings.push("clustermesh-mcs-api-install-crds is not implemented");
        }
        if self.endpoint_sync {
            warnings.push("clustermesh-enable-endpoint-sync is not implemented");
        }
        warnings
    }
}
