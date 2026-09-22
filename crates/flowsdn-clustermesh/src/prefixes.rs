//! Byte-range authorization planning. Authentication and request decoding remain
//! caller responsibilities. Unknown principals and all mutations must be denied.
use crate::Error;
pub fn validate_cluster(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        return Err(Error("invalid cluster name".into()));
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRange {
    start: Vec<u8>,
    end: Option<Vec<u8>>,
}
impl ReadRange {
    pub fn exact(key: impl Into<Vec<u8>>) -> Self {
        Self {
            start: key.into(),
            end: None,
        }
    }
    pub fn prefix(prefix: &[u8]) -> Result<Self, Error> {
        if prefix.is_empty() {
            return Err(Error("empty prefix would authorize every key".into()));
        }
        let mut end = prefix.to_vec();
        while let Some(last) = end.pop() {
            if let Some(next) = last.checked_add(1) {
                end.push(next);
                return Ok(Self {
                    start: prefix.to_vec(),
                    end: Some(end),
                });
            }
        }
        Err(Error("unbounded prefix unsupported".into()))
    }
    fn permits(&self, start: &[u8], end: Option<&[u8]>) -> bool {
        if start.is_empty() || start == [0] || end.is_some_and(|end| end == [0] || end <= start) {
            return false;
        }
        match (&self.end, end) {
            (None, None) => start == self.start,
            (Some(bound), None) => start >= self.start.as_slice() && start < bound.as_slice(),
            (Some(bound), Some(end)) => start >= self.start.as_slice() && end <= bound.as_slice(),
            (None, Some(_)) => false,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Role {
    Local,
    Remote,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rpc {
    Range,
    Watch,
    Put,
    Delete,
    Txn,
    Lease,
    Auth,
    Other,
}
#[derive(Clone, Debug)]
pub struct FrontPolicy {
    grants: Vec<ReadRange>,
}
impl FrontPolicy {
    /// `role` comes from an explicit authenticated CN-to-role map, never a
    /// caller-supplied role string. own_cluster is this server's cluster.
    pub fn for_role(role: Role, own_cluster: &str) -> Result<Self, Error> {
        validate_cluster(own_cluster)?;
        let mut grants = vec![ReadRange::prefix(b"cilium/.heartbeat")?];
        match role {
            Role::Local => {
                for prefix in ["cilium/cache/", "cilium/cluster-config/", "cilium/synced/"] {
                    grants.push(ReadRange::prefix(prefix.as_bytes())?);
                }
            }
            Role::Remote => {
                grants.push(ReadRange::prefix(b"cilium/state/")?);
                grants.push(ReadRange::exact(
                    format!("cilium/cluster-config/{own_cluster}").into_bytes(),
                ));
                grants.push(ReadRange::prefix(
                    format!("cilium/synced/{own_cluster}/").as_bytes(),
                )?);
            }
        }
        Ok(Self { grants })
    }
    /// Each complete request range must fit one grant; checking only its first
    /// key is insufficient. Reject Txn even if it appears read-only.
    pub fn permits(&self, rpc: Rpc, start: &[u8], end: Option<&[u8]>) -> bool {
        matches!(rpc, Rpc::Range | Rpc::Watch)
            && self.grants.iter().any(|grant| grant.permits(start, end))
    }
}
