//! The L7 record a listener emits (spec 16 §4.3's `LogRecord`, in process:
//! there is no access-log socket, ADR-0024): what the flow pipeline turns
//! into an L7 flow.
use crate::listener::Redirected;
use serde_json::{Value, json};
use std::net::SocketAddr;

/// Which way the redirected connection was going.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Egress,
    Ingress,
}

/// One L7 event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub direction: Direction,
    pub source: SocketAddr,
    pub source_identity: u32,
    pub destination: SocketAddr,
    /// The proxy port the datapath redirected to.
    pub proxy_port: u16,
    /// What the listener's protocol decided (`forwarded`, `denied`, …).
    pub verdict: String,
    /// Protocol detail (HTTP method and path, DNS name, …); null for none.
    pub detail: Value,
}
impl Record {
    /// A record of a redirected connection, before any protocol saw it.
    pub fn accepted(redirected: &Redirected, proxy_port: u16) -> Self {
        Self {
            direction: Direction::Egress,
            source: redirected.source,
            source_identity: redirected.identity,
            destination: redirected.original,
            proxy_port,
            verdict: "accepted".into(),
            detail: Value::Null,
        }
    }
    pub fn json(&self) -> Value {
        json!({
            "direction": match self.direction { Direction::Egress => "egress", Direction::Ingress => "ingress" },
            "source": self.source.to_string(),
            "source-identity": self.source_identity,
            "destination": self.destination.to_string(),
            "proxy-port": self.proxy_port,
            "verdict": self.verdict,
            "detail": self.detail,
        })
    }
}
