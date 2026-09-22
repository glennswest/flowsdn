//! Stage-2 target planning, not a claim of implemented or certified features.
use std::collections::BTreeSet;
pub const GATEWAY_API_VERSION: &str = "1.6.1";
pub const PROFILES: &[&str] = &[
    "GATEWAY-GRPC",
    "GATEWAY-HTTP",
    "GATEWAY-TCP",
    "GATEWAY-TLS",
    "GATEWAY-UDP",
    "MESH-GRPC",
    "MESH-HTTP",
];
/// One sorted exemption constant. ListenerSet is temporarily stage 3; all
/// owners, reasons and removal acceptance targets are tracked in spec21 §12.
pub const EXEMPT_FEATURES: &[&str] = &[
    "BackendTLSPolicySANValidation",
    "GatewayBackendClientCertificate",
    "GatewayFrontendClientCertificateValidation",
    "GatewayHTTPSListenerDetectMisdirectedRequests",
    "HTTPRouteParentRefPort",
    "ListenerSet",
    "MeshConsumerRoute",
    "TLSRouteModeTerminate",
];
pub const SKIPPED_TESTS: &[&str] = &["HTTPRouteListenerPortMatching", "MeshConsumerRoute"];
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    ExemptionNotInCatalogue(String),
    GoldenMismatch,
    MissingImplementation(Vec<String>),
}
/// Require the pinned upstream catalogue and independently maintained expected
/// list to agree. A new upstream feature cannot be silently omitted on a bump.
pub fn checked_target(
    all: &BTreeSet<String>,
    golden: &BTreeSet<String>,
) -> Result<BTreeSet<String>, Error> {
    let mut target = all.clone();
    for feature in EXEMPT_FEATURES {
        if !target.remove(*feature) {
            return Err(Error::ExemptionNotInCatalogue((*feature).into()));
        }
    }
    if target != *golden {
        return Err(Error::GoldenMismatch);
    }
    Ok(target)
}
/// Publish only after the complete selected target has implementation evidence.
/// Caller must supply evidence, not an optimistic AllFeatures declaration.
pub fn supported_features(
    target: &BTreeSet<String>,
    implemented: &BTreeSet<String>,
) -> Result<Vec<String>, Error> {
    let missing: Vec<_> = target.difference(implemented).cloned().collect();
    if !missing.is_empty() {
        return Err(Error::MissingImplementation(missing));
    }
    Ok(target.iter().cloned().collect())
}
