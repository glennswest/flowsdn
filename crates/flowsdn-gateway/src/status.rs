//! Compatibility reason strings, separate from Config validation deviations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteKind {
    Http,
    Grpc,
    Tls,
    Tcp,
    Udp,
}
impl RouteKind {
    pub const fn missing_parent_reason(self) -> &'static str {
        match self {
            Self::Http => "InvalidHTTPRoute",
            Self::Grpc => "InvalidGRPCRoute",
            Self::Tls => "InvalidTLSRoute",
            Self::Tcp => "InvalidTCPRoute",
            Self::Udp => "InvalidUDPRoute",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GammaCondition {
    Attached,
    Programmed,
}
impl GammaCondition {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Attached => "gamma.cilium.io/GammaRoutesAttached",
            Self::Programmed => "gamma.cilium.io/GammaRoutesProgrammed",
        }
    }
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Attached => "Accepted",
            Self::Programmed => "Programmed",
        }
    }
    pub fn project(self, success: bool) -> serde_json::Value {
        serde_json::json!({"type":self.kind(), "status":if success {"True"} else {"False"}, "reason":self.reason(),
            "message":match self { Self::Attached => "Gamma Service has routes attached", Self::Programmed => "Gamma Service has been programmed" }})
    }
}
