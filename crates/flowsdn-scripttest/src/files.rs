//! Confined fixture files and synchronous generic commands. Update mode remains
//! unimplemented. File reads and
//! writes are bounded to 8 MiB each; cat also bounds aggregate output. Text
//! commands reject non-UTF-8 input rather than changing bytes silently.
use crate::{
    Archive, CommandError, Control, Engine, Execution, ExpansionMode, RunError, State,
    expand_text_bounded,
};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const MAX_BYTES: usize = 8_388_608;
static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);
type Result<T> = std::result::Result<T, CommandError>;
fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}
fn io_error(error: io::Error) -> CommandError {
    fail(error.to_string())
}

#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    dir: Dir,
    data_root: PathBuf,
    data: Dir,
}

impl Drop for Workspace {
    fn drop(&mut self) {
        // A script may have removed directory read/write permission. Repair
        // owned entries through handles before the final capability cleanup.
        let mut remaining = usize::MAX;
        if let Ok(entries) = self.dir.entries() {
            for entry in entries.flatten() { let _ = remove_tree(&self.dir, Path::new(&entry.file_name()), 0, &mut remaining); }
        }
        // Remove through the owned directory handle; a replaced ambient path
        // must not redirect cleanup into another tree. Symlinks are not followed.
        if let Ok(dir) = self.dir.try_clone() {
            let _ = dir.remove_open_dir_all();
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Context {
    workspace: Arc<Workspace>,
    cwd: PathBuf,
}
impl PartialEq for Context {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.workspace, &other.workspace) && self.cwd == other.cwd
    }
}
impl Eq for Context {}

impl Context {
    fn metadata(&self, name: &str) -> Result<cap_std::fs::Metadata> {
        let path = Path::new(name);
        if path.is_absolute() && !path.starts_with(&self.workspace.root) {
            let relative = path.strip_prefix(&self.workspace.data_root)
                .map_err(|_| fail("read path is outside WORK and DATADIR"))?;
            self.workspace.data.metadata(relative).map_err(io_error)
        } else { self.workspace.dir.metadata(self.relative(name)?).map_err(io_error) }
    }
    fn relative(&self, name: &str) -> Result<PathBuf> {
        let path = Path::new(name);
        if name.is_empty() {
            return Err(fail("empty file path"));
        }
        if path.is_absolute() {
            path.strip_prefix(&self.workspace.root)
                .map(Path::to_path_buf)
                .map_err(|_| fail("write path is outside the script working root"))
        } else {
            Ok(self.cwd.join(path))
        }
    }
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = Path::new(name);
        let (dir, relative) = if path.is_absolute() && !path.starts_with(&self.workspace.root) {
            (
                &self.workspace.data,
                path.strip_prefix(&self.workspace.data_root)
                    .map(Path::to_path_buf)
                    .map_err(|_| fail("read path is outside WORK and DATADIR"))?,
            )
        } else {
            (&self.workspace.dir, self.relative(name)?)
        };
        let mut options = nonblocking_options();
        options.read(true);
        let file = dir.open_with(relative, &options).map_err(io_error)?;
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(fail("expected a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(
            u64::try_from(MAX_BYTES)
                .map_err(|_| fail("file limit overflow"))?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
        bounded(&bytes)?;
        Ok(bytes)
    }
    fn write(&self, name: &str, bytes: &[u8], parents: bool) -> Result<()> {
        bounded(bytes)?;
        let relative = self.relative(name)?;
        if parents && let Some(parent) = relative.parent() {
            self.workspace
                .dir
                .create_dir_all(parent)
                .map_err(io_error)?;
        }
        let mut options = nonblocking_options();
        options.write(true).create(true);
        let mut file = self
            .workspace
            .dir
            .open_with(relative, &options)
            .map_err(io_error)?;
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(fail("expected a regular file"));
        }
        // Truncate only after validating the opened descriptor. Checking a
        // pathname and then reopening it would leave a symlink/FIFO race.
        file.set_len(0).map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)
    }
}

/// Do not rename, unlink or chmod the owned root itself. Trailing `..` also
/// names a directory by its parent traversal rather than an owned entry.
fn mutable_entry(context: &Context, name: &str) -> Result<PathBuf> {
    let path = context.relative(name)?;
    if path.file_name().is_none() { return Err(fail("operation requires an entry below WORK")); }
    Ok(path)
}

pub(crate) fn exists(state: &mut State, args: &[String]) -> Result<Control> {
    let (flags, paths) = options(args, &["--readonly", "--exec"])?;
    if paths.is_empty() { return Err(fail("exists requires paths")); }
    let context = state.context()?;
    for path in paths {
        let metadata = context.metadata(&path)?;
        if flags.iter().any(|flag| flag == "--readonly") && !metadata.permissions().readonly() {
            return Err(fail("path has writable permission bits"));
        }
        if flags.iter().any(|flag| flag == "--exec") {
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 { return Err(fail("path has no executable permission bits")); }
            }
            #[cfg(not(unix))]
            { return Err(fail("exists --exec requires Unix permission semantics")); }
        }
    }
    Ok(Control::Continue)
}

pub(crate) fn mv(state: &mut State, args: &[String]) -> Result<Control> {
    let (_, paths) = options(args, &[])?;
    let [old, new] = paths.as_slice() else { return Err(fail("mv requires old and new paths")); };
    let context = state.context()?;
    context.workspace.dir.rename(mutable_entry(context, old)?, &context.workspace.dir, mutable_entry(context, new)?).map_err(io_error)?;
    Ok(Control::Continue)
}

pub(crate) fn chmod(state: &mut State, args: &[String]) -> Result<Control> {
    let (_, words) = options(args, &[])?;
    let (mode, paths) = words.split_first().ok_or_else(|| fail("chmod requires an octal mode and paths"))?;
    if paths.is_empty() || mode.is_empty() || !mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(fail("chmod requires an octal mode and paths"));
    }
    let mode = u32::from_str_radix(mode, 8).ok().filter(|mode| *mode <= 0o7777)
        .ok_or_else(|| fail("chmod mode must fit 07777"))?;
    let context = state.context()?;
    for path in paths {
        let mut options = nonblocking_options(); options.read(true);
        #[cfg(target_os = "linux")]
        { use cap_std::fs::OpenOptionsExt; options.custom_flags(libc::O_PATH | libc::O_NONBLOCK); }
        let file = context.workspace.dir.open_with(mutable_entry(context, path)?, &options).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            let root = context.workspace.dir.dir_metadata().map_err(io_error)?;
            if metadata.dev() == root.dev() && metadata.ino() == root.ino() {
                return Err(fail("chmod cannot change the owned WORK root through an alias"));
            }
        }
        set_mode(&file, mode)?;
    }
    Ok(Control::Continue)
}

fn set_mode(file: &cap_std::fs::File, mode: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
        // O_PATH grants no read/write access and cannot block on FIFO opens.
        // procfs addresses this still-owned descriptor; it does not re-resolve
        // the script pathname. Do not fall back to a potentially blocking open.
        fs::set_permissions(format!("/proc/self/fd/{}", file.as_raw_fd()), fs::Permissions::from_mode(mode)).map_err(io_error)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use cap_std::fs::PermissionsExt;
        file.set_permissions(cap_std::fs::Permissions::from_mode(mode)).map_err(io_error)
    }
    #[cfg(not(unix))]
    { let _ = (file, mode); Err(fail("numeric chmod requires Unix permission semantics")) }
}

pub(crate) fn symlink(state: &mut State, args: &[String]) -> Result<Control> {
    let words = if args.first().map(String::as_str) == Some("--") { args.get(1..).unwrap_or_default() } else { args };
    let [link, arrow, target] = words else { return Err(fail("symlink requires path -> target")); };
    if arrow != "->" || target.is_empty() { return Err(fail("symlink requires path -> target")); }
    if Path::new(target).is_absolute() { return Err(fail("absolute symlink targets are not supported by the capability workspace")); }
    let context = state.context()?;
    #[cfg(unix)]
    { context.workspace.dir.symlink(target, mutable_entry(context, link)?).map_err(io_error)?; }
    #[cfg(not(unix))]
    { let _ = context; return Err(fail("symlink command currently requires Unix")); }
    Ok(Control::Continue)
}

pub(crate) fn rm(state: &mut State, args: &[String]) -> Result<Control> {
    let (_, paths) = options(args, &[])?;
    if paths.is_empty() { return Err(fail("rm requires paths")); }
    let context = state.context()?;
    let mut remaining = 4096usize;
    for path in paths { remove_tree(&context.workspace.dir, &mutable_entry(context, &path)?, 0, &mut remaining)?; }
    Ok(Control::Continue)
}

fn remove_tree(parent: &Dir, path: &Path, depth: usize, remaining: &mut usize) -> Result<()> {
    if depth > 128 || *remaining == 0 { return Err(CommandError::LimitExceeded("rm exceeds 128 levels or 4096 entries")); }
    *remaining = remaining.saturating_sub(1);
    let metadata = match parent.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    if !metadata.is_dir() { return parent.remove_file(path).map_err(io_error); }
    let mut options = nonblocking_options(); options.read(true);
    #[cfg(all(unix, not(target_os = "linux")))]
    { use cap_std::fs::OpenOptionsExt; options.custom_flags(libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOFOLLOW); }
    #[cfg(target_os = "linux")]
    { use cap_std::fs::OpenOptionsExt; options.custom_flags(libc::O_PATH | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOFOLLOW); }
    let file = parent.open_with(path, &options).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_dir() { return Err(fail("directory changed during rm")); }
    #[cfg(unix)]
    { use cap_std::fs::PermissionsExt; set_mode(&file, metadata.permissions().mode() | 0o700)?; }
    let directory = Dir::from_std_file(file.into_std()).open_dir(".").map_err(io_error)?;
    for entry in directory.entries().map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        remove_tree(&directory, Path::new(&entry.file_name()), depth.saturating_add(1), remaining)?;
    }
    parent.remove_dir(path).map_err(io_error)
}

fn nonblocking_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options
}

fn bounded(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BYTES {
        Err(fail("file or output exceeds the 8 MiB limit"))
    } else {
        Ok(())
    }
}

impl State {
    /// Create an owned working directory under an explicitly selected parent.
    /// DATADIR is opened separately for read-only command access. All clones
    /// share ownership; the directory is removed when the last State is dropped.
    /// No process working directory or environment variable is changed.
    pub fn with_workspace(parent: &Path, datadir: &Path) -> io::Result<Self> {
        let parent = parent.canonicalize()?;
        let data_root = datadir.canonicalize()?;
        let data = Dir::open_ambient_dir(&data_root, ambient_authority())?;
        let mut selected = None;
        for _ in 0..128 {
            let root = parent.join(format!(
                "flowsdn-script-{}-{}",
                std::process::id(),
                NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    selected = Some(root);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let root = selected.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate script workspace",
            )
        })?;
        let dir = match Dir::open_ambient_dir(&root, ambient_authority()) {
            Ok(dir) => dir,
            Err(error) => {
                let _ = fs::remove_dir(&root);
                return Err(error);
            }
        };
        let workspace = Arc::new(Workspace {
            root,
            dir,
            data_root,
            data,
        });
        workspace.dir.create_dir("tmp")?;
        let mut state = State::default();
        for (key, value) in [
            ("WORK", workspace.root.clone()),
            ("PWD", workspace.root.clone()),
            ("TMPDIR", workspace.root.join("tmp")),
            ("DATADIR", workspace.data_root.clone()),
        ] {
            let value = value.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "workspace paths must be UTF-8")
            })?;
            state.environment.insert(key.into(), value.into());
        }
        state.files = Some(Context {
            workspace,
            cwd: PathBuf::new(),
        });
        Ok(state)
    }
    pub fn work_dir(&self) -> Option<&Path> {
        self.files
            .as_ref()
            .map(|files| files.workspace.root.as_path())
    }
    pub fn materialize(&self, archive: &Archive) -> Result<()> {
        let context = self
            .files
            .as_ref()
            .ok_or_else(|| fail("script has no working directory"))?;
        for file in archive.files() {
            let name = expand_text_bounded(
                file.name(),
                &self.environment,
                ExpansionMode::Plain,
                1,
                MAX_BYTES,
            )
            .map_err(|error| fail(error.to_string()))?;
            context
                .write(&name, file.data().as_bytes(), true)
                .map_err(|error| fail(format!("archive file {name}: {error}")))?;
        }
        Ok(())
    }
    fn context(&self) -> Result<&Context> {
        self.files
            .as_ref()
            .ok_or_else(|| fail("script has no working directory"))
    }
    fn actual_data(&self, name: &str) -> Result<Vec<u8>> {
        let bytes = match name {
            "stdout" => self.stdout.as_bytes().to_vec(),
            "stderr" => self.stderr.as_bytes().to_vec(),
            _ => return self.context()?.read(name),
        };
        bounded(&bytes)?;
        Ok(bytes)
    }
}

impl Engine {
    /// Materialize an archive and execute its script. Agent flags need a fixture
    /// adapter and are rejected here, rather than accepted without effect.
    pub fn run_archive(
        &self,
        archive: &Archive,
        state: &mut State,
    ) -> std::result::Result<Execution, RunError> {
        if !archive.flags().is_empty() {
            return Err(RunError {
                line: 1,
                command: "#!".into(),
                message: "agent fixture flags are not implemented".into(),
            });
        }
        state.materialize(archive).map_err(|error| RunError {
            line: 1,
            command: "archive".into(),
            message: error.to_string(),
        })?;
        self.run(archive.script(), state)
    }
}

fn options(args: &[String], allowed: &[&str]) -> Result<(Vec<String>, Vec<String>)> {
    let mut flags = Vec::new();
    let mut words = Vec::new();
    let mut parsing = true;
    for arg in args {
        if parsing && arg == "--" {
            parsing = false;
            continue;
        }
        if parsing && arg.starts_with('-') {
            if !allowed.contains(&arg.as_str()) {
                return Err(fail(format!("unsupported flag: {arg}")));
            }
            flags.push(arg.clone());
        } else {
            words.push(arg.clone());
        }
    }
    Ok((flags, words))
}
fn text(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| fail("text command requires UTF-8"))
}

pub(crate) fn cmp(state: &mut State, args: &[String]) -> Result<Control> {
    compare(state, args, false)
}
pub(crate) fn cmpenv(state: &mut State, args: &[String]) -> Result<Control> {
    compare(state, args, true)
}
fn compare(state: &mut State, args: &[String], expand: bool) -> Result<Control> {
    let (flags, paths) = options(args, &["-q", "--quiet"])?;
    let [left, right] = paths.as_slice() else {
        return Err(fail("cmp requires two files"));
    };
    let mut a = state.actual_data(left)?;
    let mut b = state.actual_data(right)?;
    if expand {
        a = expand_text_bounded(
            &text(a)?,
            &state.environment,
            ExpansionMode::Plain,
            1,
            MAX_BYTES,
        )
        .map_err(|e| fail(e.to_string()))?
        .into_bytes();
        b = expand_text_bounded(
            &text(b)?,
            &state.environment,
            ExpansionMode::Plain,
            1,
            MAX_BYTES,
        )
        .map_err(|e| fail(e.to_string()))?
        .into_bytes();
        bounded(&a)?;
        bounded(&b)?;
    }
    if a == b {
        return Ok(Control::Continue);
    }
    if flags.is_empty() {
        crate::engine::record_log(&mut state.log, &diff(left, &a, right, &b)?)?;
    }
    Err(fail("files differ"))
}
fn diff(left: &str, a: &[u8], right: &str, b: &[u8]) -> Result<String> {
    let (Ok(a), Ok(b)) = (std::str::from_utf8(a), std::str::from_utf8(b)) else {
        let mut output = String::new();
        for part in ["Binary files ", left, " and ", right, " differ"] {
            append_diagnostic(&mut output, part)?;
        }
        return Ok(output);
    };
    let a_count = a.lines().count();
    let b_count = b.lines().count();
    let mut output = String::new();
    for part in ["--- ", left, "\n+++ ", right, "\n"] {
        append_diagnostic(&mut output, part)?;
    }
    append_diagnostic(
        &mut output,
        &format!(
            "@@ -{},{} +{},{} @@\n",
            usize::from(a_count != 0),
            a_count,
            usize::from(b_count != 0),
            b_count
        ),
    )?;
    for (prefix, content) in [("-", a), ("+", b)] {
        for line in content.split_inclusive('\n') {
            append_diagnostic(&mut output, prefix)?;
            append_diagnostic(&mut output, line)?;
            if !line.ends_with('\n') {
                append_diagnostic(&mut output, "\n\\ No newline at end of file\n")?;
            }
        }
    }
    Ok(output)
}
fn append_diagnostic(output: &mut String, text: &str) -> Result<()> {
    if output.len().saturating_add(text.len()) > crate::engine::MAX_DIAGNOSTIC_BYTES {
        return Err(CommandError::LimitExceeded(
            "diagnostic exceeds 64 KiB limit",
        ));
    }
    output.push_str(text);
    Ok(())
}
pub(crate) fn empty(state: &mut State, args: &[String]) -> Result<Control> {
    let (flags, paths) = options(args, &["-q", "--quiet", "-t", "--trim"])?;
    let [path] = paths.as_slice() else {
        return Err(fail("empty requires one file"));
    };
    let data = state.actual_data(path)?;
    let mut content = data.as_slice();
    // Only newlines are trimmed; spaces and tabs remain data.
    if flags
        .iter()
        .any(|flag| matches!(flag.as_str(), "-t" | "--trim"))
    {
        while let Some(tail) = content.strip_prefix(b"\n") {
            content = tail;
        }
        while let Some(head) = content.strip_suffix(b"\n") {
            content = head;
        }
    }
    if content.is_empty() {
        return Ok(Control::Continue);
    }
    if !flags
        .iter()
        .any(|flag| matches!(flag.as_str(), "-q" | "--quiet"))
    {
        crate::engine::record_log(&mut state.log, &diff(path, content, "<empty>", b"")?)?;
    }
    Err(fail("file is not empty"))
}
pub(crate) fn cat(state: &mut State, args: &[String]) -> Result<Control> {
    if args.is_empty() {
        return Err(fail("cat requires files"));
    }
    let mut output = Vec::new();
    for path in args {
        output.extend(state.actual_data(path)?);
        bounded(&output)?;
    }
    state.publish(text(output)?, "");
    Ok(Control::Continue)
}
pub(crate) fn grep(state: &mut State, args: &[String]) -> Result<Control> {
    let mut words = Vec::new();
    let mut assertion = Vec::new();
    let mut flags = true;
    for arg in args {
        if flags && arg == "--" {
            flags = false;
            continue;
        }
        if flags && (arg == "-q" || arg.starts_with("--count=")) {
            assertion.push(arg.clone());
        } else if flags && arg.starts_with('-') {
            return Err(fail("unknown grep flag"));
        } else {
            words.push(arg);
        }
    }
    let [pattern, file] = words.as_slice() else {
        return Err(fail("grep requires a pattern and file"));
    };
    assertion.extend(["--".into(), (*pattern).clone()]);
    let data = text(state.actual_data(file)?)?;
    crate::engine::match_output(&data, &assertion, &mut state.log)
}
pub(crate) fn cp(state: &mut State, args: &[String]) -> Result<Control> {
    let (destination, sources) = args
        .split_last()
        .ok_or_else(|| fail("cp requires source and destination"))?;
    if sources.is_empty() {
        return Err(fail("cp requires source and destination"));
    }
    let context = state.context()?;
    let is_dir = context.workspace.dir.is_dir(context.relative(destination)?);
    if sources.len() > 1 && !is_dir {
        return Err(fail("multiple cp sources require a directory"));
    }
    for source in sources {
        let destination = if is_dir {
            let basename = Path::new(source)
                .file_name()
                .ok_or_else(|| fail("cp source has no basename"))?;
            Path::new(destination)
                .join(basename)
                .to_str()
                .ok_or_else(|| fail("cp path must be UTF-8"))?
                .to_owned()
        } else {
            destination.clone()
        };
        context.write(&destination, &state.actual_data(source)?, false)?;
    }
    Ok(Control::Continue)
}
pub(crate) fn mkdir(state: &mut State, args: &[String]) -> Result<Control> {
    if args.is_empty() {
        return Err(fail("mkdir requires paths"));
    }
    let context = state.context()?;
    for path in args {
        context
            .workspace
            .dir
            .create_dir_all(context.relative(path)?)
            .map_err(io_error)?;
    }
    Ok(Control::Continue)
}
pub(crate) fn cd(state: &mut State, args: &[String]) -> Result<Control> {
    let [path] = args else {
        return Err(fail("cd requires one directory"));
    };
    let context = state
        .files
        .as_mut()
        .ok_or_else(|| fail("script has no working directory"))?;
    let cwd = context
        .workspace
        .dir
        .canonicalize(context.relative(path)?)
        .map_err(io_error)?;
    context.workspace.dir.open_dir(&cwd).map_err(io_error)?;
    let cwd = cwd
        .components()
        .filter(|part| *part != std::path::Component::CurDir)
        .collect::<PathBuf>();
    let pwd = if cwd.as_os_str().is_empty() {
        context.workspace.root.clone()
    } else {
        context.workspace.root.join(&cwd)
    };
    state.environment.insert(
        "PWD".into(),
        pwd.to_str()
            .ok_or_else(|| fail("PWD must be UTF-8"))?
            .into(),
    );
    context.cwd = cwd;
    Ok(Control::Continue)
}
pub(crate) fn replace(state: &mut State, args: &[String]) -> Result<Control> {
    let (path, pairs) = args
        .split_last()
        .ok_or_else(|| fail("replace requires pairs and a file"))?;
    if !pairs.len().is_multiple_of(2) {
        return Err(fail("replace requires old/new pairs"));
    }
    let mut replacements = Vec::new();
    for pair in pairs.chunks_exact(2) {
        let [old, new] = pair else {
            return Err(fail("invalid replacement pair"));
        };
        let old = unescape(old)?;
        let new = unescape(new)?;
        if old.is_empty() {
            return Err(fail("empty replacement patterns are not implemented"));
        }
        replacements.push((old, new));
    }
    let context = state.context()?;
    let input = context.read(path)?;
    let mut rest = input.as_slice();
    let mut output = Vec::new();
    while !rest.is_empty() {
        if let Some((old, new)) = replacements.iter().find(|(old, _)| rest.starts_with(old)) {
            output.extend(new);
            rest = rest
                .get(old.len()..)
                .ok_or_else(|| fail("replacement offset"))?;
        } else if let Some((byte, tail)) = rest.split_first() {
            output.push(*byte);
            rest = tail;
        }
        bounded(&output)?;
    }
    context.write(path, &output, false)?;
    Ok(Control::Continue)
}
pub(crate) fn sed(state: &mut State, args: &[String]) -> Result<Control> {
    let [pattern, replacement, path] = args else {
        return Err(fail("sed requires pattern, replacement and file"));
    };
    let regex = regex::Regex::new(pattern).map_err(|_| fail("invalid sed pattern"))?;
    let context = state.context()?;
    let input = text(context.read(path)?)?;
    let mut output = String::new();
    for (index, line) in input.split('\n').enumerate() {
        if index != 0 {
            output.push('\n');
        }
        let mut previous = 0;
        for captures in regex.captures_iter(line) {
            let matched = captures
                .get(0)
                .ok_or_else(|| fail("missing whole regex match"))?;
            append_text(
                &mut output,
                line.get(previous..matched.start())
                    .ok_or_else(|| fail("invalid regex offsets"))?,
            )?;
            expand_capture(&mut output, replacement, &captures)?;
            previous = matched.end();
        }
        append_text(
            &mut output,
            line.get(previous..)
                .ok_or_else(|| fail("invalid regex offset"))?,
        )?;
    }
    context.write(path, output.as_bytes(), false)?;
    Ok(Control::Continue)
}
fn append_text(output: &mut String, text: &str) -> Result<()> {
    if output.len().saturating_add(text.len()) > MAX_BYTES {
        return Err(fail("file or output exceeds the 8 MiB limit"));
    }
    output.push_str(text);
    Ok(())
}
fn expand_capture(
    output: &mut String,
    replacement: &str,
    captures: &regex::Captures<'_>,
) -> Result<()> {
    let mut chars = replacement.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            let mut bytes = [0; 4];
            append_text(output, ch.encode_utf8(&mut bytes))?;
            continue;
        }
        if chars.peek() == Some(&'$') {
            chars.next();
            append_text(output, "$")?;
            continue;
        }
        let mut name = String::new();
        if chars.peek() == Some(&'{') {
            chars.next();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => name.push(ch),
                    None => return Err(fail("unterminated sed capture reference")),
                }
            }
            if name.is_empty() {
                return Err(fail("empty sed capture reference"));
            }
        } else {
            while let Some(ch) = chars
                .peek()
                .copied()
                .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            {
                chars.next();
                name.push(ch);
            }
            if name.is_empty() {
                append_text(output, "$")?;
                continue;
            }
        }
        let captured = if let Ok(index) = name.parse::<usize>() {
            captures.get(index)
        } else {
            captures.name(&name)
        };
        if let Some(captured) = captured {
            append_text(output, captured.as_str())?;
        }
    }
    Ok(())
}
fn unescape(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut bytes = [0; 4];
            output.extend(ch.encode_utf8(&mut bytes).as_bytes());
            continue;
        }
        let escaped = chars
            .next()
            .ok_or_else(|| fail("trailing replacement escape"))?;
        let literal = match escaped {
            'a' => Some(7),
            'b' => Some(8),
            'f' => Some(12),
            'n' => Some(b'\n'),
            'r' => Some(b'\r'),
            't' => Some(b'\t'),
            'v' => Some(11),
            '\\' => Some(b'\\'),
            '"' => Some(b'"'),
            '\'' => Some(b'\''),
            _ => None,
        };
        if let Some(byte) = literal {
            output.push(byte);
            continue;
        }
        let (digits, radix, initial) = match escaped {
            'x' => (2, 16, 0),
            'u' => (4, 16, 0),
            'U' => (8, 16, 0),
            '0'..='7' => (
                2,
                8,
                escaped
                    .to_digit(8)
                    .ok_or_else(|| fail("invalid octal escape"))?,
            ),
            _ => return Err(fail("unknown replacement escape")),
        };
        let mut value: u32 = initial;
        for _ in 0..digits {
            let digit = chars
                .next()
                .and_then(|ch| ch.to_digit(radix))
                .ok_or_else(|| fail("invalid replacement escape digits"))?;
            value = value
                .checked_mul(radix)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| fail("replacement escape overflow"))?;
        }
        if matches!(escaped, 'u' | 'U') {
            let ch =
                char::from_u32(value).ok_or_else(|| fail("invalid Unicode replacement escape"))?;
            let mut bytes = [0; 4];
            output.extend(ch.encode_utf8(&mut bytes).as_bytes());
        } else {
            output
                .push(u8::try_from(value).map_err(|_| fail("replacement escape exceeds a byte"))?);
        }
    }
    Ok(output)
}
