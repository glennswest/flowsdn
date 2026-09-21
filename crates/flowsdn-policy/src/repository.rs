//! Atomic resource replacement for one resolved subject policy, before kernel
//! publication. This does not parse CRDs or implement the agent REST handler.
use crate::{
    Error,
    oracle::{Rule, validate_subject},
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SubjectRepository {
    resources: BTreeMap<String, Vec<Rule>>,
    revision: u64,
}
impl SubjectRepository {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.resources.values().flatten()
    }
    /// Validate the complete candidate before replacing any existing rule.
    /// An error leaves both resource contents and revision unchanged.
    pub fn replace(&mut self, resource: &str, rules: Vec<Rule>) -> Result<u64, Error> {
        if resource.is_empty() {
            return Err(Error::InvalidName);
        }
        validate_subject(
            self.resources
                .iter()
                .filter(|(name, _)| name.as_str() != resource)
                .flat_map(|(_, rules)| rules.iter())
                .chain(rules.iter()),
        )?;
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        if rules.is_empty() {
            self.resources.remove(resource);
        } else {
            self.resources.insert(resource.into(), rules);
        }
        self.revision = revision;
        Ok(revision)
    }
    /// Spec §3.10 compatibility: empty repositories have no GET /policy body.
    /// HTTP serialization and schema-compatible rule JSON remain agent work.
    pub fn read_status(&self) -> u16 {
        if self.rules().next().is_none() {
            404
        } else {
            200
        }
    }
}
