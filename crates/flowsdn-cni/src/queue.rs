//! Durable offline deletion queue from CNI specification §4.7 and §5.1.
use crate::{CniError, Result, delete::{DeleteQueueGuard, DeleteRequest}};
use nix::{errno::Errno, fcntl::{Flock, FlockArg}};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_ENTRIES: usize = 256;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn error(error: impl std::fmt::Display) -> CniError { CniError::internal(error.to_string()) }

#[derive(Clone, Debug)]
pub struct Queue { path: PathBuf }

impl Queue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        fs::DirBuilder::new().recursive(true).mode(0o755).create(path).map_err(error)?;
        ensure_directory(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(error)?;
        let path = fs::canonicalize(path).map_err(error)?;
        let lockfile = open_lockfile(&path)?;
        lockfile.sync_all().map_err(error)?;
        File::open(&path).and_then(|f| f.sync_all()).map_err(error)?;
        // Persist the directory entry too when this process created the queue.
        if let Some(parent) = path.parent() {
            File::open(parent).and_then(|f| f.sync_all()).map_err(error)?;
        }
        Ok(Self { path })
    }

    pub fn lock_shared(&self, timeout: Duration) -> Result<SharedGuard> {
        Ok(SharedGuard {
            _lock: lock(open_lockfile(&self.path)?, FlockArg::LockSharedNonblock, timeout)?,
            path: self.path.clone(), timeout,
        })
    }

    /// Hold this guard through replay and until the agent API is listening.
    pub fn lock_exclusive(&self, timeout: Duration) -> Result<ExclusiveGuard> {
        Ok(ExclusiveGuard {
            _lock: lock(open_lockfile(&self.path)?, FlockArg::LockExclusiveNonblock, timeout)?,
            path: self.path.clone(),
        })
    }
}

fn ensure_directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path).map_err(error)?.file_type().is_dir() {
        return Err(error("deletion queue must be a real directory"));
    }
    Ok(())
}

fn open_lockfile(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .mode(0o644).custom_flags(nix::libc::O_NOFOLLOW)
        .open(path.join("lockfile")).map_err(error)?;
    if !file.metadata().map_err(error)?.is_file() { return Err(error("queue lockfile is not a regular file")); }
    Ok(file)
}

fn lock(mut file: File, kind: FlockArg, timeout: Duration) -> Result<Flock<File>> {
    let start = Instant::now();
    loop {
        match Flock::lock(file, kind) {
            Ok(guard) => return Ok(guard),
            Err((returned, errno)) => {
                file = returned;
                if !matches!(errno, Errno::EWOULDBLOCK | Errno::EINTR) { return Err(error(errno)); }
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() { return Err(error("deletion queue lock timed out")); }
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }
    }
}

pub struct SharedGuard {
    _lock: Flock<File>,
    path: PathBuf,
    timeout: Duration,
}

impl SharedGuard {
    pub fn enqueue(&mut self, request: &DeleteRequest) -> Result<()> {
        let contents = request.queue_contents()?;
        let name = format!("{:x}.delete", Sha256::digest(&contents));
        let destination = self.path.join(name);
        // Shared protocol locks permit simultaneous writers. A separate flock
        // on the directory inode serializes our count-and-publish operation,
        // without adding another file to the interoperable queue layout.
        let directory = lock(File::open(&self.path).map_err(error)?,
            FlockArg::LockExclusiveNonblock, self.timeout)?;
        match read_regular(&destination) {
            Ok(existing) => {
                if existing != contents { return Err(error("deletion queue entry contents conflict")); }
                File::open(&destination).and_then(|f| f.sync_all()).map_err(error)?;
                directory.sync_all().map_err(error)?;
                return Ok(());
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(error(e)),
        }
        if entry_paths(&self.path)?.len() >= MAX_ENTRIES {
            return Err(error("deletion queue directory has too many entries; aborting"));
        }
        let (temporary, mut file) = Temporary::create(&self.path)?;
        file.set_permissions(fs::Permissions::from_mode(0o644)).map_err(error)?;
        file.write_all(&contents).map_err(error)?;
        file.sync_all().map_err(error)?;
        // Link publishes the complete inode atomically without overwriting an
        // existing request. The final filename never exposes a partial write.
        match fs::hard_link(&temporary.path, &destination) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if read_regular(&destination).map_err(error)? != contents {
                    return Err(error("deletion queue entry contents conflict"));
                }
            }
            Err(e) => return Err(error(e)),
        }
        directory.sync_all().map_err(error)?;
        drop(temporary);
        directory.sync_all().map_err(error)?;
        Ok(())
    }
}

impl DeleteQueueGuard for SharedGuard {
    fn enqueue(&mut self, request: &DeleteRequest) -> Result<()> {
        SharedGuard::enqueue(self, request)
    }
}

struct Temporary { path: PathBuf }

impl Temporary {
    fn create(directory: &Path) -> Result<(Self, File)> {
        for _ in 0..32 {
            let number = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(error)?.as_nanos();
            let path = directory.join(format!(".enqueue-{}-{timestamp}-{number}.tmp", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).mode(0o644).open(&path) {
                Ok(file) => return Ok((Self { path }, file)),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(error(e)),
            }
        }
        Err(error("could not create a unique deletion queue temporary file"))
    }
}

impl Drop for Temporary {
    fn drop(&mut self) { let _ = fs::remove_file(&self.path); }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayRequest {
    Container { container_id: String },
    Attachment { container_id: String, ifname: String },
}

pub struct Entry {
    path: PathBuf,
    /// Invalid or unreadable entries are returned individually, so replay can
    /// report each error and remove the entry regardless of deletion outcome.
    pub request: Result<ReplayRequest>,
}

impl Entry {
    pub fn filename(&self) -> &std::ffi::OsStr {
        self.path.file_name().unwrap_or_default()
    }
}

pub struct ExclusiveGuard {
    _lock: Flock<File>,
    path: PathBuf,
}

impl ExclusiveGuard {
    pub fn entries(&self) -> Result<Vec<Entry>> {
        Ok(entry_paths(&self.path)?.into_iter().map(|path| {
            let request = read_regular(&path).map_err(error).and_then(|bytes| decode(&bytes));
            Entry { path, request }
        }).collect())
    }

    pub fn remove(&mut self, entry: &Entry) -> Result<()> {
        if entry.path.parent() != Some(self.path.as_path()) {
            return Err(error("entry belongs to another deletion queue"));
        }
        match fs::remove_file(&entry.path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(error(e)),
        }
        File::open(&self.path).and_then(|f| f.sync_all()).map_err(error)
    }
}

fn entry_paths(path: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(error)? {
        let path = entry.map_err(error)?.path();
        if path.extension() == Some(OsString::from("delete").as_os_str()) { entries.push(path); }
    }
    entries.sort();
    Ok(entries)
}

fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(std::io::Error::other("queue entry is not a regular file")); }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<ReplayRequest> {
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) {
        let container_id = json.get("container-id").and_then(|v| v.as_str())
            .filter(|v| !v.is_empty()).ok_or_else(|| error("invalid container deletion entry"))?;
        return Ok(ReplayRequest::Container { container_id: container_id.to_owned() });
    }
    let text = std::str::from_utf8(bytes).map_err(error)?;
    let (container_id, ifname) = text.rsplit_once(':').ok_or_else(|| error("invalid attachment deletion entry"))?;
    if container_id.is_empty() || ifname.is_empty() {
        return Err(error("invalid attachment deletion entry"));
    }
    Ok(ReplayRequest::Attachment { container_id: container_id.to_owned(), ifname: ifname.to_owned() })
}
