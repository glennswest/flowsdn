//! Crash-safe endpoint directory publication and exclusive agent ownership.
use nix::fcntl::{Flock, FlockArg};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet}, error::Error, fs::{self, File, OpenOptions},
    io::{Read, Write}, os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// State records retain unknown fields so restoration does not erase another
/// subsystem's persisted metadata. Validation only covers identity/index keys.
#[derive(Clone, Debug)]
pub struct Record { pub id: u16, pub attachment: String, pub document: Value }
impl Record {
    pub fn parse(document: Value) -> Result<Self> {
        let id = document.get("ID").and_then(Value::as_u64).and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0).ok_or("invalid endpoint ID")?;
        let cid = document.get("dockerID").and_then(Value::as_str).unwrap_or("");
        let interface = document.get("ContainerIfName").and_then(Value::as_str).unwrap_or("");
        if cid.is_empty() || interface.is_empty() { return Err("primary endpoint attachment is required".into()); }
        Ok(Self { id, attachment: format!("cni-attachment-id:{cid}:{interface}"), document })
    }
}

pub struct Store { path: PathBuf, _lock: Flock<File> }
impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        fs::DirBuilder::new().recursive(true).mode(0o770).create(path.as_ref())?;
        if !fs::symlink_metadata(path.as_ref())?.is_dir() { return Err("state directory must be a real directory".into()); }
        let path = fs::canonicalize(path)?;
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .mode(0o600).custom_flags(nix::libc::O_NOFOLLOW).open(path.join("agent.lock"))?;
        if !lock.metadata()?.is_file() { return Err("agent lock must be a regular file".into()); }
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| e)?;
        Ok(Self { path, _lock:lock })
    }
    /// Read only published numeric directories. Pending/failed regeneration
    /// directories are retained for diagnosis and never mistaken for endpoints.
    pub fn restore(&self) -> Result<Vec<Record>> {
        let mut records = BTreeMap::new();
        let mut attachments = BTreeSet::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue; };
            let Ok(id) = name.parse::<u16>() else { continue; };
            if id == 0 || name != id.to_string() { return Err("noncanonical endpoint directory ID".into()); }
            if !entry.file_type()?.is_dir() { return Err("endpoint path must be a real directory".into()); }
            let file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(entry.path().join("ep_config.json"))?;
            if !file.metadata()?.is_file() { return Err("endpoint state must be a regular file".into()); }
            let mut bytes = Vec::new();
            file.take(4_194_305).read_to_end(&mut bytes)?;
            if bytes.len() > 4_194_304 { return Err("endpoint state exceeds 4 MiB".into()); }
            let record = Record::parse(serde_json::from_slice(&bytes)?)?;
            if record.id != id || !attachments.insert(record.attachment.clone()) {
                return Err("endpoint state ID mismatch or duplicate attachment".into());
            }
            records.insert(id, record);
        }
        Ok(records.into_values().collect())
    }
    /// Stage a new endpoint; existing state is never overwritten. Caller loads
    /// the datapath before publish(), and drops this guard on failure.
    pub fn stage(&self, record: &Record) -> Result<Staged<'_>> {
        let parsed = Record::parse(record.document.clone())?;
        if parsed.id != record.id || parsed.attachment != record.attachment { return Err("record identity mismatch".into()); }
        let destination = self.path.join(record.id.to_string());
        if destination.try_exists()? { return Err("endpoint state already exists".into()); }
        let path = self.path.join(format!("{}_next", record.id));
        fs::DirBuilder::new().mode(0o770).create(&path)?;
        let staged = Staged { path, destination, published:false, _store:self };
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(staged.path.join("ep_config.json"))?;
        file.write_all(&serde_json::to_vec(&record.document)?)?;
        file.sync_all()?;
        File::open(&staged.path)?.sync_all()?;
        File::open(&self.path)?.sync_all()?;
        Ok(staged)
    }
    /// Remove published state after datapath teardown. Only our known file is
    /// removed; unexpected contents stop removal instead of recursive cleanup.
    pub fn remove(&self, id: u16) -> Result<()> {
        if id == 0 { return Err("invalid endpoint ID".into()); }
        let path = self.path.join(id.to_string());
        if !path.try_exists()? { return Ok(()); }
        if !fs::symlink_metadata(&path)?.is_dir() { return Err("endpoint path must be a real directory".into()); }
        for entry in fs::read_dir(&path)? {
            if entry?.file_name() != "ep_config.json" { return Err("endpoint directory still has other owned resources".into()); }
        }
        match fs::remove_file(path.join("ep_config.json")) {
            Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
        }
        fs::remove_dir(path)?;
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}

pub struct Staged<'a> { path: PathBuf, destination: PathBuf, published: bool, _store: &'a Store }
impl Staged<'_> {
    pub fn publish(mut self) -> Result<()> {
        // Store's exclusive process lock serializes all compliant writers. A
        // pre-existing target is always an error, including an empty directory.
        if self.destination.try_exists()? { return Err("endpoint state already exists".into()); }
        fs::rename(&self.path, &self.destination)?;
        self.published = true;
        File::open(self.destination.parent().ok_or("missing state parent")?)?.sync_all()?;
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
#[derive(Default)]
pub struct IdPool { used: BTreeSet<u16> }
impl IdPool {
    pub fn allocate(&mut self) -> Result<u16> {
        let id = (1..=4095).find(|id| !self.used.contains(id)).ok_or("endpoint ID pool exhausted")?;
        self.used.insert(id); Ok(id)
    }
    pub fn reserve(&mut self, id: u16) -> Result<()> {
        if id == 0 || !self.used.insert(id) { Err("invalid or duplicate endpoint ID".into()) } else { Ok(()) }
    }
    pub fn release(&mut self, id: u16) { self.used.remove(&id); }
}
