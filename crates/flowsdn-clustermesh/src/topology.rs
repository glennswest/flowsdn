use crate::Error;
use flowsdn_identity::cidr::CidrPrefix;
use std::collections::BTreeMap;
/// Cross-cluster ownership only: same-cluster nested allocation ranges are
/// permitted. Replace validates against all peers before modifying the snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PodCidrs { clusters: BTreeMap<String, Vec<CidrPrefix>> }
impl PodCidrs {
    pub fn replace(&mut self, cluster: &str, prefixes: Vec<CidrPrefix>) -> Result<(), Error> {
        crate::prefixes::validate_cluster(cluster)?;
        for (peer, existing) in &self.clusters {
            if peer == cluster { continue; }
            for candidate in &prefixes {
                if existing.iter().any(|prefix| prefix.contains_prefix(*candidate) || candidate.contains_prefix(*prefix)) {
                    return Err(Error(format!("PodCIDR overlap between {cluster} and {peer}")));
                }
            }
        }
        self.clusters.insert(cluster.into(), prefixes);
        Ok(())
    }
    pub fn remove(&mut self, cluster: &str) -> Option<Vec<CidrPrefix>> { self.clusters.remove(cluster) }
    pub fn get(&self, cluster: &str) -> Option<&[CidrPrefix]> { self.clusters.get(cluster).map(Vec::as_slice) }
}
