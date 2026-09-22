//! Live ownership for the initial local-delivery object.
//! This is not the full pin/reuse/upgrade loader or a policy-aware agent.
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap, Map, MapData, MapError, MapInfo, MapType},
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        links::{FdLink, Link, PinnedLink},
        tc::{SchedClassifierLink, TcAttachOptions},
    },
};
use flowsdn_bpf_abi::{
    MapBytes,
    endpoint::{EndpointInfo, EndpointKey},
};
use std::{
    collections::BTreeMap,
    error::Error,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[path = "tcx_identity.rs"]
mod tcx_identity;

pub type KernelResult<T> = Result<T, Box<dyn Error>>;

/// Owns the loaded program, its attachments and an anonymous endpoint map.
/// Anonymous owners detach on drop; pinned owners retain forwarding until explicit teardown.
/// Callers must supply trusted build artifacts and provision endpoint devices.
pub struct LocalDelivery {
    bpf: Ebpf,
    endpoints: HashMap<MapData, [u8; 20], [u8; 48]>,
    interfaces: BTreeMap<String, OwnedLink>,
    pin_root: Option<PathBuf>,
    map_id: u32,
}
enum OwnedLink {
    Ephemeral(SchedClassifierLink),
    Persistent { link: FdLink, path: PathBuf },
}
impl LocalDelivery {
    pub fn load(object: impl AsRef<Path>) -> KernelResult<Self> {
        Self::from_bpf(Ebpf::load_file(object)?, None)
    }
    fn from_bpf(mut bpf: Ebpf, pin_root: Option<PathBuf>) -> KernelResult<Self> {
        let map = bpf.take_map("cilium_lxc").ok_or("missing endpoint map")?;
        let map_id = match &map {
            Map::HashMap(data) => data.info()?.id(),
            _ => return Err("unexpected endpoint map type".into()),
        };
        let endpoints = HashMap::try_from(map)?;
        let program: &mut SchedClassifier = bpf
            .program_mut("local_delivery")
            .ok_or("missing local delivery program")?
            .try_into()?;
        program.load()?;
        Ok(Self {
            bpf,
            endpoints,
            interfaces: BTreeMap::new(),
            pin_root,
            map_id,
        })
    }

    /// Reuse a validated endpoint map and preserve TCX links across owner drop.
    /// The caller exclusively owns this dedicated bpffs directory and serializes
    /// restoration with its durable endpoint state. Never share it between agents.
    pub fn load_pinned(object: impl AsRef<Path>, root: &Path) -> KernelResult<Self> {
        use std::{fs, os::unix::ffi::OsStrExt};
        if !root.is_absolute()
            || root.as_os_str().as_bytes().contains(&0)
            || root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("pin root must be an absolute canonical path".into());
        }
        fs::create_dir_all(root)?;
        if fs::symlink_metadata(root)?.file_type().is_symlink() {
            return Err("pin root cannot be a symlink".into());
        }
        let map_path = root.join("cilium_lxc");
        match fs::symlink_metadata(&map_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err("map pin cannot be a symlink".into());
                }
                let info = MapInfo::from_pin(&map_path)?;
                if info.map_type()? != MapType::Hash
                    || info.key_size() != 20
                    || info.value_size() != 48
                    || info.max_entries() != 1024
                    || info.map_flags() != 1
                {
                    return Err(
                        "pinned endpoint map ABI differs; preserve it and refuse startup".into(),
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let bpf = EbpfLoader::new()
            .map_pin_path("cilium_lxc", &map_path)
            .load_file(object)?;
        Self::from_bpf(bpf, Some(root.to_owned()))
    }

    /// Stable kernel map ID for restart-preservation evidence.
    pub fn endpoint_map_id(&self) -> KernelResult<u32> {
        Ok(self.map_id)
    }

    /// Attach once per ingress interface, atomically updating owned pinned TCX links.
    pub fn attach(&mut self, interface: &str) -> KernelResult<()> {
        if interface.is_empty() || interface.len() >= 16 || interface.contains(['\0', '/']) {
            return Err("invalid network interface name".into());
        }
        if self.interfaces.contains_key(interface) {
            return Err("interface already attached".into());
        }
        let persistent = self
            .pin_root
            .as_ref()
            .map(|root| root.join(format!("ingress-{interface}")));
        let existing = if let Some(path) = &persistent {
            match std::fs::symlink_metadata(path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err("link pin cannot be a symlink".into());
                    }
                    let old = FdLink::from(PinnedLink::from_pin(path)?);
                    let info = tcx_identity::read(path)?;
                    if info.id != old.info()?.id() || !info.matches(interface, false)? {
                        return Err(
                            "pinned TCX link does not belong to the restored interface ingress"
                                .into(),
                        );
                    }
                    Some(old)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("local_delivery")
            .ok_or("missing local delivery program")?
            .try_into()?;
        let link = if let Some(path) = persistent {
            let reused = existing.is_some();
            let id = if let Some(old) = existing {
                program.attach_to_link(old.try_into()?)?
            } else {
                program.attach_with_options(
                    interface,
                    TcAttachType::Ingress,
                    TcAttachOptions::TcxOrder(LinkOrder::default()),
                )?
            };
            let fd: FdLink = program.take_link(id)?.try_into()?;
            let link = if reused {
                fd
            } else {
                FdLink::from(fd.pin(&path)?)
            };
            OwnedLink::Persistent { link, path }
        } else {
            let id = program.attach(interface, TcAttachType::Ingress)?;
            OwnedLink::Ephemeral(program.take_link(id)?)
        };
        self.interfaces.insert(interface.to_owned(), link);
        Ok(())
    }

    /// Remove the owned attachment; retrying an already detached name succeeds.
    pub fn detach(&mut self, interface: &str) -> KernelResult<()> {
        if interface.is_empty() || interface.len() >= 16 || interface.contains(['\0', '/']) {
            return Err("invalid network interface name".into());
        }
        if !self.interfaces.contains_key(interface)
            && let Some(root) = &self.pin_root {
                let path = root.join(format!("ingress-{interface}"));
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err("link pin cannot be a symlink".into());
                        }
                        let pinned = FdLink::from(PinnedLink::from_pin(&path)?);
                        let info = tcx_identity::read(&path)?;
                        if info.id != pinned.info()?.id() || !info.matches(interface, true)? {
                            return Err("refusing to detach a foreign pinned link".into());
                        }
                        let link: SchedClassifierLink = pinned.try_into()?;
                        std::fs::remove_file(path)?;
                        link.detach()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
        }
        // Keep the handle on unlink failure so teardown can be retried.
        if let Some(OwnedLink::Persistent { path, .. }) = self.interfaces.get(interface) {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(link) = self.interfaces.remove(interface) {
            match link {
                OwnedLink::Ephemeral(link) => link.detach()?,
                OwnedLink::Persistent { link, .. } => link.detach()?,
            }
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

    /// Preserve an existing map value before a retryable publication attempt.
    pub fn snapshot(&self, address: IpAddr) -> KernelResult<Option<[u8; 48]>> {
        match self.endpoints.get(&key(address), 0) {
            Ok(value) => Ok(Some(value)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn restore_snapshot(&mut self, address: IpAddr, old: Option<[u8; 48]>) -> KernelResult<()> {
        match old {
            Some(value) => self
                .endpoints
                .insert(key(address), value, 0)
                .map_err(Into::into),
            None => self.remove_if_present(address),
        }
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
