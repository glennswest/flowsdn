//! Transport and opt-in status planning. No sockets, CRD writes or secrets.
use crate::update::Prefix;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    None,
    Md5,
    TcpAo,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    UnsupportedTcpAo,
    InvalidPort,
    PassiveNeedsListener,
    StatusTooLarge,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transport {
    pub local_port: Option<u16>,
    pub peer_port: u16,
    pub passive: bool,
    pub auth: AuthMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPlan {
    pub listen: Option<u16>,
    pub initiate: bool,
    pub wait_in_active: bool,
}
impl Transport {
    pub fn plan(self) -> Result<SessionPlan, PlanError> {
        if self.auth == AuthMode::TcpAo {
            return Err(PlanError::UnsupportedTcpAo);
        }
        if self.peer_port == 0 || self.local_port == Some(0) {
            return Err(PlanError::InvalidPort);
        }
        if self.passive && self.local_port.is_none() {
            return Err(PlanError::PassiveNeedsListener);
        }
        Ok(SessionPlan {
            listen: self.local_port,
            initiate: !self.passive,
            wait_in_active: self.passive,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Advertisement {
    pub peer: String,
    pub prefix: Prefix,
    pub policy: String,
}
/// Default-off field projection. The caller serializes None by omission.
/// Reject oversized enabled snapshots, never silently truncate route status.
/// Inputs must describe acknowledged backend state, never pending desired work.
pub fn advertised_status(
    enabled: bool,
    rows: impl IntoIterator<Item = Advertisement>,
    maximum: usize,
) -> Result<Option<Vec<Advertisement>>, PlanError> {
    if !enabled {
        return Ok(None);
    }
    let mut result = std::collections::BTreeSet::new();
    for row in rows {
        result.insert(row);
        if result.len() > maximum {
            return Err(PlanError::StatusTooLarge);
        }
    }
    Ok(Some(result.into_iter().collect()))
}
