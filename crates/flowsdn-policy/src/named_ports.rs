//! Resolved egress named-port contributions, rebuilt from every surviving
//! selector when any selector changes. No identity-wide blind delete is used.
use crate::Error;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Key { pub identity: u32, pub protocol: u8, pub port: u16 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contribution { pub key: Key, pub precedence: u32 }
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NamedPortState {
    selectors: BTreeMap<String, Vec<Contribution>>,
    desired: BTreeMap<Key, u32>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Changes { pub upserts: BTreeMap<Key, u32>, pub deletes: Vec<Key> }
impl NamedPortState {
    pub fn desired(&self) -> &BTreeMap<Key, u32> { &self.desired }
    /// Contributions have already resolved a named port for each selected peer.
    /// Empty contributions delete only this selector's ownership. Changes are
    /// returned as one plan; the caller publishes it under its policy revision.
    pub fn replace(&mut self, selector: &str, contributions: Vec<Contribution>) -> Result<Changes, Error> {
        if selector.is_empty() { return Err(Error::InvalidName); }
        if contributions.iter().any(|c| c.key.protocol == 0 || c.key.port == 0 || c.key.identity == 0) {
            return Err(Error::InvalidProtocol);
        }
        if contributions.is_empty() { self.selectors.remove(selector); }
        else { self.selectors.insert(selector.into(), contributions); }
        let mut desired: BTreeMap<Key, u32> = BTreeMap::new();
        for contribution in self.selectors.values().flatten() {
            desired.entry(contribution.key).and_modify(|value| *value = (*value).max(contribution.precedence))
                .or_insert(contribution.precedence);
        }
        let upserts = desired.iter().filter(|(key, value)| self.desired.get(key) != Some(value))
            .map(|(key, value)| (*key, *value)).collect();
        let deletes = self.desired.keys().filter(|key| !desired.contains_key(key)).copied().collect();
        self.desired = desired;
        Ok(Changes { upserts, deletes })
    }
}
