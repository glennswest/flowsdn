//! Validated user-reserved names from identity specification §§3.2 and 4.4.
use crate::ReservedIdentity;
use alloc::{collections::BTreeMap, string::String};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedIdentityError {
    InvalidId,
    EmptyName,
    ReservedName,
    DuplicateId,
    DuplicateName,
}
impl fmt::Display for FixedIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "fixed identity ID must be decimal in 128..=255",
            Self::EmptyName => "fixed identity name must not be empty",
            Self::ReservedName => "fixed identity name collides with a built-in identity",
            Self::DuplicateId => "duplicate fixed identity ID",
            Self::DuplicateName => "duplicate fixed identity name",
        })
    }
}
impl core::error::Error for FixedIdentityError {}

/// Names are case-sensitive opaque names, as used by io.cilium.fixed-identity.
/// No source-prefix parsing or trimming changes their identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FixedIdentities {
    by_id: BTreeMap<u8, String>,
    by_name: BTreeMap<String, u8>,
}
impl FixedIdentities {
    /// Validate the entire mapping before returning a usable result. Distinct
    /// decimal spellings of the same number still collide.
    pub fn parse<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Self, FixedIdentityError> {
        let mut result = Self::default();
        for (raw_id, name) in entries {
            if raw_id.is_empty() || !raw_id.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FixedIdentityError::InvalidId);
            }
            let id = raw_id.parse::<u8>().ok().filter(|id| *id >= 128)
                .ok_or(FixedIdentityError::InvalidId)?;
            if name.is_empty() {
                return Err(FixedIdentityError::EmptyName);
            }
            if ReservedIdentity::from_name(name).is_some() || matches!(name,
                "etcd-operator" | "cilium-kvstore" | "kube-dns" | "eks-kube-dns" |
                "coredns" | "cilium-operator" | "eks-coredns") {
                return Err(FixedIdentityError::ReservedName);
            }
            if result.by_id.insert(id, String::from(name)).is_some() {
                return Err(FixedIdentityError::DuplicateId);
            }
            if result.by_name.insert(String::from(name), id).is_some() {
                return Err(FixedIdentityError::DuplicateName);
            }
        }
        Ok(result)
    }
    pub fn name(&self, id: u8) -> Option<&str> {
        self.by_id.get(&id).map(String::as_str)
    }
    pub fn id(&self, name: &str) -> Option<u8> {
        self.by_name.get(name).copied()
    }
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}
