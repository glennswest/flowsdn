//! Live ownership for the initial local-delivery object.
//! This is not the full pin/reuse/upgrade loader or a policy-aware agent.
use aya::{
    Ebpf,
    maps::{HashMap, MapData},
    programs::{SchedClassifier, TcAttachType, links::Link, tc::SchedClassifierLink},
};
use flowsdn_bpf_abi::{
    MapBytes,
    endpoint::{EndpointInfo, EndpointKey},
};
use std::{collections::BTreeMap, error::Error, net::IpAddr, path::Path};

pub type KernelResult<T> = Result<T, Box<dyn Error>>;

/// Owns the loaded program, its attachments and an anonymous endpoint map.
/// Dropping the owner detaches its programs and releases its map descriptors.
/// Callers must supply trusted build artifacts and provision endpoint devices.
pub struct LocalDelivery {
    bpf: Ebpf,
    endpoints: HashMap<MapData, [u8; 20], [u8; 48]>,
    interfaces: BTreeMap<String, SchedClassifierLink>,
}
impl LocalDelivery {
    pub fn load(object: impl AsRef<Path>) -> KernelResult<Self> {
        let mut bpf = Ebpf::load_file(object)?;
        let endpoints =
            HashMap::try_from(bpf.take_map("cilium_lxc").ok_or("missing endpoint map")?)?;
        let program: &mut SchedClassifier = bpf
            .program_mut("local_delivery")
            .ok_or("missing local delivery program")?
            .try_into()?;
        program.load()?;
        Ok(Self {
            bpf,
            endpoints,
            interfaces: BTreeMap::new(),
        })
    }

    /// Attach once per ingress interface. No pins survive owner destruction.
    pub fn attach(&mut self, interface: &str) -> KernelResult<()> {
        if interface.is_empty() || interface.len() >= 16 || interface.contains('\0') {
            return Err("invalid network interface name".into());
        }
        if self.interfaces.contains_key(interface) {
            return Err("interface already attached".into());
        }
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("local_delivery")
            .ok_or("missing local delivery program")?
            .try_into()?;
        let id = program.attach(interface, TcAttachType::Ingress)?;
        let link = program.take_link(id)?;
        self.interfaces.insert(interface.to_owned(), link);
        Ok(())
    }

    /// Remove the owned attachment; retrying an already detached name succeeds.
    pub fn detach(&mut self, interface: &str) -> KernelResult<()> {
        if let Some(link) = self.interfaces.remove(interface) {
            link.detach()?;
        }
        Ok(())
    }

    /// Publish a non-host Ethernet endpoint for the local cluster.
    /// The current primitive cannot implement flagged endpoint modes.
    pub fn upsert(&mut self, address: IpAddr, endpoint: EndpointInfo) -> KernelResult<()> {
        if address.is_unspecified()
            || address.is_multicast()
            || address.is_loopback()
            || matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err("endpoint address must be unicast".into());
        }
        if endpoint.ifindex == 0 || endpoint.flags != 0 {
            return Err("unsupported endpoint interface or flags".into());
        }
        for mac in [endpoint.mac, endpoint.node_mac] {
            if mac == 0 || mac & 1 != 0 || mac >> 48 != 0 {
                return Err("endpoint MAC must be a six-byte unicast address".into());
            }
        }
        self.endpoints
            .insert(key(address), endpoint.to_bytes(), 0)?;
        Ok(())
    }

    /// Remove one family; a missing address returns Aya's map error.
    pub fn remove(&mut self, address: IpAddr) -> KernelResult<()> {
        self.endpoints.remove(&key(address))?;
        Ok(())
    }

    /// Delete a map entry during retryable endpoint teardown. Ignore only the
    /// kernel's missing-key error; permission and other syscall failures remain.
    pub fn remove_if_present(&mut self, address: IpAddr) -> KernelResult<()> {
        match self.endpoints.remove(&key(address)) {
            Ok(()) => Ok(()),
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Read-only access for the kernel packet-test harness.
    pub fn program(&self) -> KernelResult<&SchedClassifier> {
        Ok(self
            .bpf
            .program("local_delivery")
            .ok_or("missing local delivery program")?
            .try_into()?)
    }
}

fn key(address: IpAddr) -> [u8; 20] {
    match address {
        IpAddr::V4(ip) => EndpointKey::v4(ip.octets(), 0, 0),
        IpAddr::V6(ip) => EndpointKey::v6(ip.octets(), 0, 0),
    }
    .to_bytes()
}
