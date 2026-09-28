//! Operator planning primitives from spec 12. No controller or HTTP server.
pub mod ces;
pub mod lifecycle;
pub mod lease;
pub mod readiness;
pub mod registration;
pub mod taints;

pub const DEFAULT_CES_MODE: &str = "default";
pub const DEFAULT_IDENTITY_MANAGEMENT_MODE: &str = "agent";
pub const GATEWAY_CONTROLLER_NAME: &str = "io.flowsdn/gateway-controller";
pub const GATEWAY_OBJECT_PREFIX: &str = "flowsdn-gateway-";
pub const INGRESS_OBJECT_PREFIX: &str = "flowsdn-ingress-";
pub const SECRETS_NAMESPACE: &str = "flowsdn-secrets";
pub const OPERATOR_ROUTES: &[&str] = &[
    "/healthz",
    "/v1/healthz",
    "/v1/metrics/",
    "/v1/cluster",
    "/readyz",
];
