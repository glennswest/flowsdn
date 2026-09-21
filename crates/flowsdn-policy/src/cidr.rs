//! CIDR importer planning. Exclusions need their own longest-prefix identity;
//! adding a DoesNotExist selector alone cannot split a covering peer identity.
use crate::Error;
use flowsdn_identity::cidr::CidrPrefix;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CidrRule { allow: CidrPrefix, except: BTreeSet<CidrPrefix> }
impl CidrRule {
    pub fn new(allow: CidrPrefix, except: impl IntoIterator<Item = CidrPrefix>) -> Result<Self, Error> {
        let except: BTreeSet<_> = except.into_iter().collect();
        if except.iter().any(|prefix| !allow.contains_prefix(*prefix)) { return Err(Error::InvalidException); }
        Ok(Self { allow, except })
    }
    /// All prefixes must be allocated and synchronized before publishing rules.
    pub fn import_prefixes(&self) -> BTreeSet<CidrPrefix> {
        std::iter::once(self.allow).chain(self.except.iter().copied()).collect()
    }
    /// Selector semantics for a resolved eligible peer identity. It is the
    /// importer's longest-prefix ipcache entries that isolate excepted traffic.
    pub fn selects(&self, peer: CidrPrefix) -> bool {
        self.allow.contains_prefix(peer) && !self.except.iter().any(|prefix| prefix.contains_prefix(peer))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixUpdate {
    pub allocate_before_publish: BTreeSet<CidrPrefix>,
    pub release_after_publish: BTreeSet<CidrPrefix>,
}
impl PrefixUpdate {
    pub fn between(old: &[CidrRule], new: &[CidrRule]) -> Self {
        let old: BTreeSet<_> = old.iter().flat_map(CidrRule::import_prefixes).collect();
        let new: BTreeSet<_> = new.iter().flat_map(CidrRule::import_prefixes).collect();
        Self { allocate_before_publish: new.difference(&old).copied().collect(),
            release_after_publish: old.difference(&new).copied().collect() }
    }
}
