//! A temporary child of this process's own cgroup v2 directory, holding only
//! this process; fixtures attach cgroup programs there and nowhere else.
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub struct Cgroup {
    original: PathBuf,
    pub temporary: PathBuf,
    moved: bool,
}
impl Cgroup {
    pub fn create() -> Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let path = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or("unified cgroup v2 membership required")?;
        if !path.starts_with('/')
            || Path::new(path).components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err("unsafe cgroup membership path".into());
        }
        let original = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err("cgroup v2 mount required".into());
        }
        // Make a child of our own current cgroup, never relocate another task.
        let temporary = original.join(format!(
            "flowsdn-socket-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&temporary)?;
        let mut guard = Self {
            original,
            temporary,
            moved: false,
        };
        fs::write(
            guard.temporary.join("cgroup.procs"),
            std::process::id().to_string(),
        )?;
        guard.moved = true;
        Ok(guard)
    }
    pub fn restore(&mut self) -> Result<()> {
        if self.moved {
            fs::write(
                self.original.join("cgroup.procs"),
                std::process::id().to_string(),
            )?;
            self.moved = false;
        }
        fs::remove_dir(&self.temporary)?;
        Ok(())
    }
}
impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.moved {
            if let Err(error) = fs::write(
                self.original.join("cgroup.procs"),
                std::process::id().to_string(),
            ) {
                eprintln!("failed to restore own cgroup membership: {error}");
                return;
            }
            self.moved = false;
        }
        if let Err(error) = fs::remove_dir(&self.temporary)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("failed to remove owned temporary cgroup: {error}");
        }
    }
}
