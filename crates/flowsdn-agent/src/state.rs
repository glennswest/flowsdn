//! Crash-safe endpoint directory publication and exclusive agent ownership.
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
pub const DEFAULT_ENDPOINT_ID_MAX: u16 = 4095;
/// The agent lock's file name under the state directory.
pub const LOCK: &str = "agent.lock";
/// How often [`Store::open_waiting`] tries the lock again.
pub const LOCK_RETRY: Duration = Duration::from_secs(1);
/// How often [`Store::open_waiting`] says who still holds the lock.
pub const HOLDER_REPORT: Duration = Duration::from_secs(30);

/// What the holder wrote into the lock file, at most one short line.
fn holder(path: &Path) -> String {
    let mut text = String::new();
    let read = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path.join(LOCK))
        .and_then(|file| file.take(512).read_to_string(&mut text));
    let line = text.lines().next().unwrap_or("").trim();
    match read {
        Ok(_) if !line.is_empty() => line.to_owned(),
        _ => "an agent that did not say who it is".to_owned(),
    }
}

/// This agent, as the lock file names it: pod (downward API `POD_NAMESPACE` /
/// `POD_NAME`, else the host name), pid, start time and cgroup (which carries
/// the pod and container on a kubelet node).
fn owner_line() -> String {
    let pod = match (std::env::var("POD_NAMESPACE"), std::env::var("POD_NAME")) {
        (Ok(namespace), Ok(name)) => format!("pod {namespace}/{name}"),
        (_, Ok(name)) => format!("pod {name}"),
        _ => format!(
            "host {}",
            fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|name| name.trim().to_owned())
                .unwrap_or_default()
        ),
    };
    let cgroup = fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| text.lines().next().map(str::to_owned))
        .unwrap_or_default();
    format!(
        "{pod}, pid {}, since {}, cgroup {cgroup}\n",
        std::process::id(),
        crate::log::now()
    )
}

/// State records retain unknown fields so restoration does not erase another
/// subsystem's persisted metadata. Validation only covers identity/index keys.
#[derive(Clone, Debug)]
pub struct Record {
    pub id: u16,
    pub attachment: String,
    pub document: Value,
}
impl Record {
    pub fn parse(document: Value) -> Result<Self> {
        // Missing legacy metadata means veth; an explicit incompatible mode
        // must never be silently restored with a different attachment driver.
        if let Some(mode) = document.get("DatapathMode")
            && mode.as_str() != Some("veth")
        {
            return Err("unsupported persisted endpoint datapath mode".into());
        }
        let id = document
            .get("ID")
            .and_then(Value::as_u64)
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or("invalid endpoint ID")?;
        let cid = document
            .get("dockerID")
            .and_then(Value::as_str)
            .unwrap_or("");
        let interface = document
            .get("ContainerIfName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if cid.is_empty() || interface.is_empty() {
            return Err("primary endpoint attachment is required".into());
        }
        Ok(Self {
            id,
            attachment: format!("cni-attachment-id:{cid}:{interface}"),
            document,
        })
    }
}

pub struct Store {
    path: PathBuf,
    _lock: Flock<File>,
}
impl Store {
    /// Open and lock the state directory; an error if another agent holds it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::try_open(path.as_ref())?.map_err(Into::into)
    }
    /// `Ok(Err(why))` when another agent holds the lock, naming it.
    fn try_open(path: &Path) -> Result<std::result::Result<Self, String>> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o770)
            .create(path)
            .map_err(|error| format!("creating {}: {error}", path.display()))?;
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err("state directory must be a real directory".into());
        }
        let path = fs::canonicalize(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path.join(LOCK))
            .map_err(|error| format!("opening {}: {error}", path.join(LOCK).display()))?;
        if !lock.metadata()?.is_file() {
            return Err("agent lock must be a regular file".into());
        }
        let mut lock = match Flock::lock(lock, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_, Errno::EWOULDBLOCK)) => {
                return Ok(Err(format!(
                    "state directory {} is held by another flowsdn agent ({}): \
                     two agents must never own one node's state",
                    path.display(),
                    holder(&path)
                )));
            }
            Err((_, errno)) => {
                return Err(format!("locking {}: {errno}", path.join(LOCK).display()).into());
            }
        };
        // Who holds it, for the next agent that finds it held (#404). Only a
        // diagnostic: the flock is the ownership, so a failed write is ignored.
        let _ = lock
            .set_len(0)
            .and_then(|()| lock.write_all(owner_line().as_bytes()));
        Ok(Ok(Self { path, _lock: lock }))
    }
    /// Open, waiting while another agent holds the lock (#404): an agent
    /// still stopping (a rolling update, or a node's former single-node
    /// cluster agent that its kubelet has not ended yet) must not make this one
    /// exit with a bare error and crash-loop. `waiting` is called with the
    /// holder when the wait starts and every [`HOLDER_REPORT`] after.
    pub fn open_waiting(path: impl AsRef<Path>, mut waiting: impl FnMut(&str)) -> Result<Self> {
        let path = path.as_ref();
        let mut reported: Option<Instant> = None;
        loop {
            match Self::try_open(path)? {
                Ok(store) => return Ok(store),
                Err(held) => {
                    if reported.is_none_or(|at| at.elapsed() >= HOLDER_REPORT) {
                        waiting(&held);
                        reported = Some(Instant::now());
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
            }
        }
    }
    /// Read only published numeric directories. Pending/failed regeneration
    /// directories are retained for diagnosis and never mistaken for endpoints.
    pub fn restore(&self) -> Result<Vec<Record>> {
        let mut records = BTreeMap::new();
        let mut attachments = BTreeSet::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = name.parse::<u16>() else {
                continue;
            };
            if id == 0 || name != id.to_string() {
                return Err("noncanonical endpoint directory ID".into());
            }
            if !entry.file_type()?.is_dir() {
                return Err("endpoint path must be a real directory".into());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(entry.path().join("ep_config.json"))?;
            if !file.metadata()?.is_file() {
                return Err("endpoint state must be a regular file".into());
            }
            let mut bytes = Vec::new();
            file.take(4_194_305).read_to_end(&mut bytes)?;
            if bytes.len() > 4_194_304 {
                return Err("endpoint state exceeds 4 MiB".into());
            }
            let record = Record::parse(serde_json::from_slice(&bytes)?)?;
            if record.id != id || !attachments.insert(record.attachment.clone()) {
                return Err("endpoint state ID mismatch or duplicate attachment".into());
            }
            records.insert(id, record);
        }
        Ok(records.into_values().collect())
    }
    /// Stage a new endpoint; existing state is never overwritten. Publish this
    /// recoverable intent before installing persistent forwarding. A publish
    /// error after rename is ambiguous; retain ownership until explicit cleanup.
    pub fn stage(&self, record: &Record) -> Result<Staged<'_>> {
        let parsed = Record::parse(record.document.clone())?;
        if parsed.id != record.id || parsed.attachment != record.attachment {
            return Err("record identity mismatch".into());
        }
        let destination = self.path.join(record.id.to_string());
        if destination.try_exists()? {
            return Err("endpoint state already exists".into());
        }
        let path = self.path.join(format!("{}_next", record.id));
        fs::DirBuilder::new().mode(0o770).create(&path)?;
        let staged = Staged {
            path,
            destination,
            published: false,
            _store: self,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staged.path.join("ep_config.json"))?;
        file.write_all(&serde_json::to_vec(&record.document)?)?;
        // Only the contents are synced, so a published record is never torn: a
        // restore refuses one it cannot parse. The directory entries need no
        // barrier (each is a journal commit an ADD waits for, #396). A record
        // lost to a power cut went with what it describes: the endpoint's links
        // and pinned maps do not survive the reboot, and restore drops a record
        // whose link is gone. An agent restart keeps the page cache.
        file.sync_all()?;
        Ok(staged)
    }
    /// Remove published state after datapath teardown. Only our known file is
    /// removed; unexpected contents stop removal instead of recursive cleanup.
    pub fn remove(&self, id: u16) -> Result<()> {
        if id == 0 {
            return Err("invalid endpoint ID".into());
        }
        let path = self.path.join(id.to_string());
        if !path.try_exists()? {
            return Ok(());
        }
        if !fs::symlink_metadata(&path)?.is_dir() {
            return Err("endpoint path must be a real directory".into());
        }
        for entry in fs::read_dir(&path)? {
            if entry?.file_name() != "ep_config.json" {
                return Err("endpoint directory still has other owned resources".into());
            }
        }
        match fs::remove_file(path.join("ep_config.json")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        fs::remove_dir(path)?;
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}

pub struct Staged<'a> {
    path: PathBuf,
    destination: PathBuf,
    published: bool,
    _store: &'a Store,
}
impl Staged<'_> {
    pub fn publish(mut self) -> Result<()> {
        // Store's exclusive process lock serializes all compliant writers. A
        // pre-existing target is always an error, including an empty directory.
        if self.destination.try_exists()? {
            return Err("endpoint state already exists".into());
        }
        fs::rename(&self.path, &self.destination)?;
        self.published = true;
        Ok(())
    }
}
impl Drop for Staged<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(self.path.join("ep_config.json"));
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// Lowest-free allocation for new endpoints; restore reserves the entire u16
/// namespace, including historical IDs above the current new-allocation limit.
pub struct IdPool {
    used: BTreeSet<u16>,
    max: u16,
}
impl Default for IdPool {
    fn default() -> Self {
        Self {
            used: BTreeSet::new(),
            max: DEFAULT_ENDPOINT_ID_MAX,
        }
    }
}
impl IdPool {
    /// Set the inclusive limit for new allocations. Restored IDs may exceed it.
    pub fn new(max: u32) -> Result<Self> {
        let max = u16::try_from(max)
            .ok()
            .filter(|max| *max != 0)
            .ok_or("endpoint-id-max must be in 1..=65535")?;
        Ok(Self {
            used: BTreeSet::new(),
            max,
        })
    }
    pub fn allocate(&mut self) -> Result<u16> {
        let id = (1..=self.max)
            .find(|id| !self.used.contains(id))
            .ok_or("endpoint ID pool exhausted")?;
        self.used.insert(id);
        Ok(id)
    }
    pub fn reserve(&mut self, id: u16) -> Result<()> {
        if id == 0 || !self.used.insert(id) {
            Err("invalid or duplicate endpoint ID".into())
        } else {
            Ok(())
        }
    }
    pub fn release(&mut self, id: u16) {
        self.used.remove(&id);
    }
}
