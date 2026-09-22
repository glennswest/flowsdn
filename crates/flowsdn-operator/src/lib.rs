//! Operator planning primitives from spec 12. No controller or HTTP server.
pub mod ces;
pub mod lifecycle;
pub mod readiness;
pub mod taints;

pub const DEFAULT_CES_MODE: &str = "default";
pub const DEFAULT_IDENTITY_MANAGEMENT_MODE: &str = "agent";
pub const GATEWAY_CONTROLLER_NAME: &str = "io.cilium/gateway-controller";
pub const GATEWAY_OBJECT_PREFIX: &str = "cilium-gateway-";
pub const INGRESS_OBJECT_PREFIX: &str = "cilium-ingress-";
pub const SECRETS_NAMESPACE: &str = "cilium-secrets";
pub const OPERATOR_ROUTES: &[&str] = &[
    "/healthz",
    "/v1/healthz",
    "/v1/metrics/",
    "/v1/cluster",
    "/readyz",
];
