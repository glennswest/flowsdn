//! Live ownership of the socket-LB object (spec 05 §3.8): its eight cgroup
//! sock_addr programs attached to one cgroup v2 directory (normally the host
//! root, so every pod and host process is covered), and its service, backend,
//! reverse-socket and session-affinity maps. With a pin root the maps and links are pinned,
//! so translation and UDP reverse entries survive an agent restart; the new
//! owner attaches before it releases the old links.
use super::{KernelResult, Object};
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap, Map, MapData, MapError, MapInfo, MapType},
    programs::{
        CgroupAttachMode, CgroupSockAddr,
        links::{FdLink, PinnedLink},
    },
};
use flowsdn_lb::socket::{Maps, Op};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

/// The programs in `socket-lb`, by symbol name.
pub const PROGRAMS: [&str; 8] = [
    "sock4_connect",
    "sock4_sendmsg",
    "sock4_recvmsg",
    "sock4_getpeername",
    "sock6_connect",
    "sock6_sendmsg",
    "sock6_recvmsg",
    "sock6_getpeername",
];
/// (map name, type, key size, value size, max entries, flags) — spec 01 §2.2
/// names and §4.3 layouts; flowsdn sizes the reverse and affinity maps at
/// 64Ki. The affinity maps are the programs' own; the agent writes the
/// match map.
const MAPS: [(&str, MapType, u32, u32, u32, u32); 9] = [
    ("flowsdn_lb4_services", MapType::Hash, 12, 12, 65536, 1),
    ("flowsdn_lb4_backends", MapType::Hash, 4, 12, 65536, 1),
    ("flowsdn_lb4_reverse_sk", MapType::LruHash, 16, 8, 65536, 0),
    ("flowsdn_lb6_services", MapType::Hash, 24, 12, 65536, 1),
    ("flowsdn_lb6_backends", MapType::Hash, 4, 24, 65536, 1),
    ("flowsdn_lb6_reverse_sk", MapType::LruHash, 32, 20, 65536, 0),
    ("flowsdn_lb4_affinity", MapType::LruHash, 16, 16, 65536, 0),
    ("flowsdn_lb6_affinity", MapType::LruHash, 24, 16, 65536, 0),
    ("flowsdn_lb_affinity_match", MapType::Hash, 8, 1, 65536, 1),
];

pub struct SocketLb {
    bpf: Ebpf,
    services4: HashMap<MapData, [u8; 12], [u8; 12]>,
    backends4: HashMap<MapData, u32, [u8; 12]>,
    services6: HashMap<MapData, [u8; 24], [u8; 12]>,
    backends6: HashMap<MapData, u32, [u8; 24]>,
    affinity_match: HashMap<MapData, [u8; 8], u8>,
    pin_root: Option<PathBuf>,
    /// Owned links; unpinned ones detach when this owner drops.
    links: Vec<FdLink>,
}

fn take<K: aya::Pod, V: aya::Pod>(
    bpf: &mut Ebpf,
    name: &str,
) -> KernelResult<HashMap<MapData, K, V>> {
    let map = bpf
        .take_map(name)
        .ok_or_else(|| format!("socket-lb object has no map {name}"))?;
    match map {
        Map::HashMap(_) => Ok(HashMap::try_from(map)?),
        _ => Err(format!("socket-lb map {name} is not a hash map").into()),
    }
}

fn check_root(root: &Path) -> KernelResult<()> {
    if !root.is_absolute()
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
    Ok(())
}

impl SocketLb {
    /// Load the object. With `pin_root` (a directory this agent owns alone),
    /// reuse maps pinned there when their ABI matches and pin new ones; a
    /// pinned map with another layout refuses startup rather than be replaced.
    pub fn load(object: Object<'_>, pin_root: Option<&Path>) -> KernelResult<Self> {
        let mut loader = EbpfLoader::new();
        if let Some(root) = pin_root {
            check_root(root)?;
            for (name, kind, key, value, max, flags) in MAPS {
                let path = root.join(name);
                match fs::symlink_metadata(&path) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err("map pin cannot be a symlink".into());
                        }
                        let info = MapInfo::from_pin(&path)?;
                        if info.map_type()? != kind
                            || info.key_size() != key
                            || info.value_size() != value
                            || info.max_entries() != max
                            || info.map_flags() != flags
                        {
                            return Err(format!(
                                "pinned {name} ABI differs; preserve it and refuse startup"
                            )
                            .into());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                loader.map_pin_path(name, path);
            }
        }
        let mut bpf = loader.load(&object.read()?)?;
        let services4 = take(&mut bpf, "flowsdn_lb4_services")?;
        let backends4 = take(&mut bpf, "flowsdn_lb4_backends")?;
        let services6 = take(&mut bpf, "flowsdn_lb6_services")?;
        let backends6 = take(&mut bpf, "flowsdn_lb6_backends")?;
        let affinity_match = take(&mut bpf, "flowsdn_lb_affinity_match")?;
        for name in PROGRAMS {
            let program: &mut CgroupSockAddr = bpf
                .program_mut(name)
                .ok_or_else(|| format!("socket-lb object has no program {name}"))?
                .try_into()?;
            program.load()?;
        }
        Ok(Self {
            bpf,
            services4,
            backends4,
            services6,
            backends6,
            affinity_match,
            pin_root: pin_root.map(Path::to_owned),
            links: Vec::new(),
        })
    }

    /// Attach every program to the cgroup v2 directory `cgroup`, alongside
    /// other programs there (`BPF_F_ALLOW_MULTI`). Pinned links of an earlier
    /// owner are released only after the new ones are attached; while both
    /// run, the second sees an already translated address and leaves it.
    pub fn attach(&mut self, cgroup: &Path) -> KernelResult<()> {
        if !self.links.is_empty() {
            return Err("socket-lb is already attached".into());
        }
        if !cgroup.join("cgroup.procs").is_file() {
            return Err(format!("{} is not a cgroup v2 directory", cgroup.display()).into());
        }
        let directory = File::open(cgroup)?;
        for name in PROGRAMS {
            let program: &mut CgroupSockAddr = self
                .bpf
                .program_mut(name)
                .ok_or_else(|| format!("socket-lb object has no program {name}"))?
                .try_into()?;
            let id = program.attach(&directory, CgroupAttachMode::AllowMultiple)?;
            let link: FdLink = program.take_link(id)?.try_into()?;
            let link = match &self.pin_root {
                Some(root) => {
                    let path = root.join(format!("cgroup-{name}"));
                    let old = match fs::symlink_metadata(&path) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            return Err("link pin cannot be a symlink".into());
                        }
                        Ok(_) => Some(FdLink::from(PinnedLink::from_pin(&path)?)),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => return Err(e.into()),
                    };
                    if let Some(old) = old {
                        // Unpinned and closed, the earlier owner's link detaches.
                        fs::remove_file(&path)?;
                        drop(old);
                    }
                    FdLink::from(link.pin(&path)?)
                }
                None => link,
            };
            self.links.push(link);
        }
        Ok(())
    }

    /// Detach and unpin every link this owner holds or finds pinned.
    pub fn detach(&mut self) -> KernelResult<()> {
        if let Some(root) = &self.pin_root {
            for name in PROGRAMS {
                match fs::remove_file(root.join(format!("cgroup-{name}"))) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        self.links.clear();
        Ok(())
    }

    /// The service and backend maps as the kernel holds them now.
    pub fn dump(&self) -> KernelResult<Maps> {
        let mut maps = Maps::default();
        for row in self.services4.iter() {
            let (key, value) = row?;
            maps.services4.insert(key, value);
        }
        for row in self.backends4.iter() {
            let (key, value) = row?;
            maps.backends4.insert(key, value);
        }
        for row in self.services6.iter() {
            let (key, value) = row?;
            maps.services6.insert(key, value);
        }
        for row in self.backends6.iter() {
            let (key, value) = row?;
            maps.backends6.insert(key, value);
        }
        for key in self.affinity_match.keys() {
            maps.affinity_match.insert(key?);
        }
        Ok(maps)
    }

    /// Apply `ops` in order (flowsdn_lb::socket::plan). The first failure
    /// stops; planning again from [`Self::dump`] resumes where it stopped.
    pub fn apply(&mut self, ops: &[Op]) -> KernelResult<()> {
        for op in ops {
            match *op {
                Op::Backend4(id, value) => self.backends4.insert(id, value, 0)?,
                Op::Backend6(id, value) => self.backends6.insert(id, value, 0)?,
                Op::Service4(key, value) => self.services4.insert(key, value, 0)?,
                Op::Service6(key, value) => self.services6.insert(key, value, 0)?,
                Op::DeleteService4(key) => absent(self.services4.remove(&key))?,
                Op::DeleteService6(key) => absent(self.services6.remove(&key))?,
                Op::DeleteBackend4(id) => absent(self.backends4.remove(&id))?,
                Op::DeleteBackend6(id) => absent(self.backends6.remove(&id))?,
                Op::AffinityMatch(key) => self.affinity_match.insert(key, 0, 0)?,
                Op::DeleteAffinityMatch(key) => absent(self.affinity_match.remove(&key))?,
            }
        }
        Ok(())
    }
}

/// A delete of a key that is already gone has done its job.
fn absent(result: Result<(), MapError>) -> Result<(), MapError> {
    match result {
        Err(MapError::SyscallError(error))
            if error.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        other => other,
    }
}
