//! The health history (spec 00 §3.4.3, #456): every change of the health
//! table is appended as one JSON line to `<dir>/<binary>-health-history.log`,
//! rotated at [`MAX_BYTES`] with [`KEPT`] files (`.log`, `.log.1`,
//! `.log.2`). The caller formats the line; this keeps the files.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

/// Rotate when the current file would pass 10 MB.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// The current file and two rotated ones.
pub const KEPT: usize = 3;

/// An open history file.
#[derive(Debug)]
pub struct History {
    path: PathBuf,
    max_bytes: u64,
    file: File,
    size: u64,
}
impl History {
    /// Open (or create) `path` for appending, rotating at `max_bytes`.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> io::Result<Self> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            file,
            size,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Append `line` (a newline is added), rotating first when it would pass
    /// the limit. A line longer than the limit still fits in a fresh file.
    pub fn append(&mut self, line: &str) -> io::Result<()> {
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX).saturating_add(1);
        if self.size > 0 && self.size.saturating_add(len) > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }
    fn rotate(&mut self) -> io::Result<()> {
        // .1 -> .2 (replacing the oldest), current -> .1, a new current.
        for n in (1..KEPT.saturating_sub(1)).rev() {
            let from = rotated(&self.path, n);
            if from.exists() {
                fs::rename(&from, rotated(&self.path, n.saturating_add(1)))?;
            }
        }
        fs::rename(&self.path, rotated(&self.path, 1))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

/// `path` with `.n` appended (`.log.1`).
fn rotated(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// The last `limit` lines of the history at `path`, oldest first, across
/// its rotated files. Missing files are empty.
pub fn read(path: &Path, limit: usize) -> io::Result<Vec<String>> {
    let mut lines = std::collections::VecDeque::new();
    for n in (0..KEPT).rev() {
        let file = if n == 0 {
            path.to_owned()
        } else {
            rotated(path, n)
        };
        let file = match File::open(&file) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in BufReader::new(file).lines() {
            lines.push_back(line?);
            if lines.len() > limit {
                lines.pop_front();
            }
        }
    }
    Ok(lines.into_iter().collect())
}
