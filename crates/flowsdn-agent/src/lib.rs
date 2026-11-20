//! Agent endpoint state ownership from specification 08 §3.6–3.9.
//! Unix API serving; with the `kubernetes` feature, the Kubernetes controllers.
pub mod api;
pub mod cni_timing;
#[cfg(feature = "kubernetes")]
pub mod endpoint_crd;
pub mod endpoints;
pub mod events;
pub mod host_policy;
pub mod identity;
pub mod kubernetes;
pub mod l2_announce;
pub mod lb_ipam;
pub mod lease;
pub mod log;
#[cfg(feature = "kubernetes")]
pub mod operator;
#[cfg(feature = "kubernetes")]
pub mod node_crd;
pub mod policy;
pub mod services;
pub mod state;
pub mod tagging;
pub mod uplinks;
