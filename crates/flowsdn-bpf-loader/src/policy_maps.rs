//! The endpoint policy maps of the local-delivery object (ADR-0021):
//! `flowsdn_policy_ep`, `flowsdn_policy`, `flowsdn_ipcache` and the
//! read-only view of `flowsdn_policy_ct`. Contents are the agent's.
use super::{KernelResult, LocalDelivery};
use aya::{
    Ebpf,
    maps::{HashMap, IterableMap, LpmTrie, Map, MapData, MapError, lpm_trie::Key},
    programs::SchedClassifier,
};
use flowsdn_bpf_abi::{
    IpCacheKey, MapBytes, RemoteEndpointInfo,
    policy::{EndpointPolicyKey, PolicyCtKey, PolicyCtValue, PolicyEndpoint, PolicyEntry},
};

fn missing(error: &MapError) -> bool {
    match error {
        MapError::KeyNotFound => true,
        MapError::SyscallError(error) => error.io_error.kind() == std::io::ErrorKind::NotFound,
        _ => false,
    }
}

fn split<const N: usize, const M: usize>(bytes: [u8; N]) -> (u32, [u8; M]) {
    let mut prefix = [0; 4];
    let mut data = [0; M];
    prefix.copy_from_slice(bytes.get(..4).unwrap_or(&[0; 4]));
    if let Some(rest) = bytes.get(4..) {
        data.copy_from_slice(rest);
    }
    (u32::from_le_bytes(prefix), data)
}
fn join<const N: usize, const M: usize>(prefix: u32, data: [u8; M]) -> [u8; N] {
    let mut out = [0; N];
    if let Some(head) = out.get_mut(..4) {
        head.copy_from_slice(&prefix.to_le_bytes());
    }
    if let Some(rest) = out.get_mut(4..) {
        rest.copy_from_slice(&data);
    }
    out
}

/// Handles on the policy maps. [`LocalDelivery::policy`] is the owner's;
/// [`LocalDelivery::share_policy`] opens another set by map ID for a thread
/// of its own (the kernel serializes each map operation).
pub struct PolicyMaps {
    endpoints: HashMap<MapData, u32, [u8; 8]>,
    policy: LpmTrie<MapData, [u8; 12], [u8; 12]>,
    ipcache: LpmTrie<MapData, [u8; 20], [u8; 24]>,
    flows: HashMap<MapData, [u8; 40], [u8; 16]>,
}
const NAMES: [&str; 4] = [
    "flowsdn_policy_ep",
    "flowsdn_policy",
    "flowsdn_ipcache",
    "flowsdn_policy_ct",
];
impl PolicyMaps {
    pub(super) fn take(bpf: &mut Ebpf) -> KernelResult<Self> {
        let mut maps = Vec::new();
        for name in NAMES {
            maps.push(bpf.take_map(name).ok_or(format!("missing map {name}"))?);
        }
        Self::from_maps(maps)
    }
    fn from_maps(maps: Vec<Map>) -> KernelResult<Self> {
        let [endpoints, policy, ipcache, flows]: [Map; 4] =
            maps.try_into().map_err(|_| "policy map count")?;
        Ok(Self {
            endpoints: HashMap::try_from(endpoints)?,
            policy: LpmTrie::try_from(policy)?,
            ipcache: LpmTrie::try_from(ipcache)?,
            flows: HashMap::try_from(flows)?,
        })
    }
    fn ids(&self) -> KernelResult<[u32; 4]> {
        let data: [&MapData; 4] = [
            IterableMap::map(&self.endpoints),
            IterableMap::map(&self.policy),
            IterableMap::map(&self.ipcache),
            IterableMap::map(&self.flows),
        ];
        let mut ids = [0; 4];
        for (id, map) in ids.iter_mut().zip(data) {
            *id = map.info()?.id();
        }
        Ok(ids)
    }
}

impl LocalDelivery {
    /// The owner's handles on the policy maps.
    pub fn policy(&mut self) -> &mut PolicyMaps {
        &mut self.policy
    }
    /// Another set of handles on the same maps, for a thread of its own.
    pub fn share_policy(&self) -> KernelResult<PolicyMaps> {
        let mut maps = Vec::new();
        for id in self.policy.ids()? {
            maps.push(Map::from_map_data(MapData::from_id(id)?)?);
        }
        PolicyMaps::from_maps(maps)
    }
    /// The pod-ingress policy program, for the kernel packet-test harness.
    pub fn to_container_program(&self) -> KernelResult<&SchedClassifier> {
        Ok(self
            .bpf
            .program("to_container")
            .ok_or("missing to_container program")?
            .try_into()?)
    }
}

impl PolicyMaps {
    /// Enforce (or only track) the endpoint behind host interface `ifindex`.
    pub fn set_policy_endpoint(
        &mut self,
        ifindex: u32,
        endpoint: PolicyEndpoint,
    ) -> KernelResult<()> {
        if ifindex == 0 {
            return Err("policy endpoint needs an interface index".into());
        }
        self.endpoints.insert(ifindex, endpoint.to_bytes(), 0)?;
        Ok(())
    }
    /// Stop enforcing and tracking the endpoint behind `ifindex`; absent is fine.
    pub fn remove_policy_endpoint(&mut self, ifindex: u32) -> KernelResult<()> {
        match self.endpoints.remove(&ifindex) {
            Err(error) if !missing(&error) => Err(error.into()),
            _ => Ok(()),
        }
    }
    pub fn policy_endpoints(&self) -> KernelResult<Vec<(u32, PolicyEndpoint)>> {
        let mut out = Vec::new();
        for item in self.endpoints.iter() {
            let (ifindex, value) = item?;
            out.push((ifindex, PolicyEndpoint::from_bytes(value)));
        }
        Ok(out)
    }

    pub fn upsert_policy(
        &mut self,
        key: EndpointPolicyKey,
        entry: PolicyEntry,
    ) -> KernelResult<()> {
        let (prefix, data) = split::<16, 12>(key.to_bytes());
        self.policy
            .insert(&Key::new(prefix, data), entry.to_bytes(), 0)?;
        Ok(())
    }
    /// Remove one policy entry; absent is fine.
    pub fn remove_policy(&mut self, key: EndpointPolicyKey) -> KernelResult<()> {
        let (prefix, data) = split::<16, 12>(key.to_bytes());
        match self.policy.remove(&Key::new(prefix, data)) {
            Err(error) if !missing(&error) => Err(error.into()),
            _ => Ok(()),
        }
    }
    pub fn policy_entries(&self) -> KernelResult<Vec<(EndpointPolicyKey, PolicyEntry)>> {
        let mut out = Vec::new();
        for item in self.policy.iter() {
            let (key, value) = item?;
            let key = EndpointPolicyKey::from_bytes(join(key.prefix_len(), key.data()));
            out.push((key, PolicyEntry::from_bytes(value)));
        }
        Ok(out)
    }

    pub fn upsert_ipcache(
        &mut self,
        key: IpCacheKey,
        info: RemoteEndpointInfo,
    ) -> KernelResult<()> {
        let (prefix, data) = split::<24, 20>(key.to_bytes());
        self.ipcache
            .insert(&Key::new(prefix, data), info.to_bytes(), 0)?;
        Ok(())
    }
    /// Remove one ipcache prefix; absent is fine.
    pub fn remove_ipcache(&mut self, key: IpCacheKey) -> KernelResult<()> {
        let (prefix, data) = split::<24, 20>(key.to_bytes());
        match self.ipcache.remove(&Key::new(prefix, data)) {
            Err(error) if !missing(&error) => Err(error.into()),
            _ => Ok(()),
        }
    }
    pub fn ipcache_entries(&self) -> KernelResult<Vec<(IpCacheKey, RemoteEndpointInfo)>> {
        let mut out = Vec::new();
        for item in self.ipcache.iter() {
            let (key, value) = item?;
            let key = IpCacheKey::from_bytes(join(key.prefix_len(), key.data()));
            out.push((key, RemoteEndpointInfo::from_bytes(value)));
        }
        Ok(out)
    }

    /// The flows the endpoint programs remember as allowed.
    pub fn policy_flows(&self) -> KernelResult<Vec<(PolicyCtKey, PolicyCtValue)>> {
        let mut out = Vec::new();
        for item in self.flows.iter() {
            let (key, value) = item?;
            out.push((
                PolicyCtKey::from_bytes(key),
                PolicyCtValue::from_bytes(value),
            ));
        }
        Ok(out)
    }
}
