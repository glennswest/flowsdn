//! `cargo xtask kernel-check [SUITE]`: the commit's test suite on a real
//! kernel, without root (#292, #370). A build job is unprivileged, so nothing
//! in sc-build could load a BPF object; twice an unloadable one passed it and
//! was caught only by a hardware run. A build VM does have /dev/kvm, qemu and a
//! readable kernel, so this boots that kernel with an initramfs of `test/.stage`
//! (test/build.sh), `ip`, `nft`, `kmod` and the network modules, with `/test` as
//! PID 1 (test/src/vm_init.rs), and reads the suite's lines off the serial port.
//!
//! It is a check that the objects load and the fixtures pass on this kernel. It
//! is not a hardware pass: no node, no cluster, no stormcos release.
use serde_json::Value;
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// The longest a boot and suite may take; medium's own budget is 30 min.
const LIMIT: Duration = Duration::from_secs(1500);
const EXIT_MARK: &str = "@@FLOWSDN-EXIT ";
/// Userspace the suite's fixtures run (`ip`, `nft`) and the kernel's module
/// loader, found on PATH with their libraries.
const TOOLS: [&str; 3] = ["ip", "nft", "kmod"];
const DLOPENED: [&str; 3] = ["liblzma.so.5", "libzstd.so.1", "libz.so.1"];
/// What modprobe reads, then the module trees a veth, dummy or nft test needs.
const MODULE_INDEXES: [&str; 8] = [
    "modules.alias.bin",
    "modules.builtin.bin",
    "modules.builtin.alias.bin",
    "modules.dep.bin",
    "modules.softdep",
    "modules.symbols.bin",
    "modules.builtin.modinfo",
    "modules.order",
];
const MODULE_TREES: [&str; 5] = [
    "kernel/net",
    "kernel/lib",
    "kernel/crypto",
    "kernel/drivers/net/veth.ko.xz",
    "kernel/drivers/net/dummy.ko.xz",
];

/// An initramfs in the kernel's `newc` cpio format. Written by hand because a
/// device node cannot be created without root, and the kernel's console needs
/// one in the archive.
struct Cpio<W: Write> {
    out: W,
    written: u64,
    next_ino: u32,
    dirs: BTreeSet<String>,
}

impl<W: Write> Cpio<W> {
    fn new(out: W) -> Self {
        Self {
            out,
            written: 0,
            next_ino: 1,
            dirs: BTreeSet::new(),
        }
    }
    fn raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.out.write_all(bytes)?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.written = self.written.saturating_add(len);
        Ok(())
    }
    fn pad(&mut self) -> std::io::Result<()> {
        let padding = self
            .written
            .next_multiple_of(4)
            .saturating_sub(self.written);
        for _ in 0..padding {
            self.raw(&[0])?;
        }
        Ok(())
    }
    fn entry(
        &mut self,
        name: &str,
        mode: u32,
        rdev: (u32, u32),
        data: &[u8],
    ) -> std::io::Result<()> {
        let size = u32::try_from(data.len())
            .map_err(|_| std::io::Error::other(format!("{name}: too large for newc")))?;
        let namesize = u32::try_from(name.len().saturating_add(1))
            .map_err(|_| std::io::Error::other("name too long"))?;
        let ino = self.next_ino;
        self.next_ino = ino.saturating_add(1);
        let (major, minor) = rdev;
        // magic, ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
        // rdevmajor, rdevminor, namesize, check.
        let header = format!(
            "070701{ino:08X}{mode:08X}{:08X}{:08X}{:08X}{:08X}{size:08X}{:08X}{:08X}{major:08X}{minor:08X}{namesize:08X}{:08X}",
            0, 0, 1, 0, 0, 0, 0
        );
        self.raw(header.as_bytes())?;
        self.raw(name.as_bytes())?;
        self.raw(&[0])?;
        self.pad()?;
        self.raw(data)?;
        self.pad()
    }
    /// The directories above `name`, once each.
    fn parents(&mut self, name: &str) -> std::io::Result<()> {
        let mut prefix = String::new();
        let parts: Vec<&str> = name.split('/').collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if self.dirs.insert(prefix.clone()) {
                let dir = prefix.clone();
                self.entry(&dir, 0o040_755, (0, 0), &[])?;
            }
        }
        Ok(())
    }
    fn file(&mut self, name: &str, mode: u32, data: &[u8]) -> std::io::Result<()> {
        self.parents(name)?;
        self.entry(name, 0o100_000 | mode, (0, 0), data)
    }
    fn symlink(&mut self, name: &str, target: &str) -> std::io::Result<()> {
        self.parents(name)?;
        self.entry(name, 0o120_777, (0, 0), target.as_bytes())
    }
    fn char_device(&mut self, name: &str, rdev: (u32, u32)) -> std::io::Result<()> {
        self.parents(name)?;
        self.entry(name, 0o020_600, rdev, &[])
    }
    fn finish(mut self) -> std::io::Result<()> {
        self.entry("TRAILER!!!", 0, (0, 0), &[])?;
        self.out.flush()
    }
}

/// The absolute library paths in `ldd`'s output: the `=> path` of each line,
/// or the path that starts one (the loader). The vDSO has neither.
fn ldd_paths(output: &str) -> Vec<String> {
    let mut paths: Vec<String> = output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let text = line.split_once("=> ").map_or(line, |(_, right)| right);
            let path = text.split_whitespace().next()?;
            path.starts_with('/').then(|| path.to_owned())
        })
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

fn on_path(tool: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs = std::env::split_paths(&path).chain(["/usr/sbin".into(), "/usr/bin".into()]);
    for dir in dirs {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("{tool} is not on this machine").into())
}

fn mode_of(path: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

fn add_file<W: Write>(cpio: &mut Cpio<W>, name: &str, source: &Path) -> Result<(), Box<dyn Error>> {
    let data = fs::read(source).map_err(|e| format!("{}: {e}", source.display()))?;
    cpio.file(name, mode_of(source)?, &data)?;
    Ok(())
}

/// Every regular file under `root`, in a stable order, by its relative path.
fn walk(root: &Path, under: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), Box<dyn Error>> {
    let mut entries: Vec<_> = fs::read_dir(under)?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(root, &path, out)?;
        } else if path.is_file() {
            let relative = path.strip_prefix(root)?.to_string_lossy().into_owned();
            out.push((relative, path));
        }
    }
    Ok(())
}

fn build_initramfs(
    stage: &Path,
    release: &str,
    modules: &Path,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut cpio = Cpio::new(BufWriter::new(fs::File::create(path)?));
    // Fedora's merged /usr: the loader's path and the kernel's /sbin/modprobe.
    cpio.char_device("dev/console", (5, 1))?;
    for (link, target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/sbin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        cpio.symlink(link, target)?;
    }
    let mut staged = Vec::new();
    walk(stage, stage, &mut staged)?;
    for (name, source) in staged {
        // The image's empty mount points are for a pod's volumes.
        if !name.starts_with("mounts/") {
            add_file(&mut cpio, &name, &source)?;
        }
    }
    let mut libraries = BTreeSet::new();
    for tool in TOOLS {
        let binary = on_path(tool)?;
        add_file(&mut cpio, &format!("usr/sbin/{tool}"), &binary)?;
        let ldd = Command::new("ldd").arg(&binary).output()?;
        libraries.extend(ldd_paths(&String::from_utf8_lossy(&ldd.stdout)));
    }
    cpio.symlink("usr/sbin/modprobe", "kmod")?;
    // kmod opens its decompressors with dlopen, so ldd does not name them.
    libraries.extend(
        DLOPENED
            .iter()
            .map(|library| format!("/usr/lib64/{library}"))
            .filter(|path| Path::new(path).is_file()),
    );
    for library in libraries {
        // The guest resolves the same path; /lib64 is its symlink to usr/lib64.
        let name = library.trim_start_matches('/');
        let name = name
            .strip_prefix("lib64/")
            .map_or_else(|| name.to_owned(), |file| format!("usr/lib64/{file}"));
        add_file(&mut cpio, &name, Path::new(&library))?;
    }
    let guest_modules = format!("usr/lib/modules/{release}");
    for index in MODULE_INDEXES {
        let source = modules.join(index);
        if source.is_file() {
            add_file(&mut cpio, &format!("{guest_modules}/{index}"), &source)?;
        }
    }
    for tree in MODULE_TREES {
        let source = modules.join(tree);
        if source.is_file() {
            add_file(&mut cpio, &format!("{guest_modules}/{tree}"), &source)?;
        } else if source.is_dir() {
            let mut files = Vec::new();
            walk(modules, &source, &mut files)?;
            for (name, file) in files {
                add_file(&mut cpio, &format!("{guest_modules}/{name}"), &file)?;
            }
        }
    }
    cpio.finish()?;
    Ok(())
}

/// What the guest's console said, once it has ended.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    exit: Option<i32>,
    pass: u64,
    fail: u64,
    skip: u64,
    /// The datapath checks were skipped: the kernel lacks what they need.
    datapath_skipped: bool,
}

impl Outcome {
    fn line(&mut self, line: &str) {
        let line = line.trim();
        if let Some(code) = line.strip_prefix(EXIT_MARK) {
            self.exit = code.trim().parse().ok();
        }
        let Some(value) = line
            .starts_with('{')
            .then(|| serde_json::from_str::<Value>(line).ok())
            .flatten()
        else {
            return;
        };
        if let Some(summary) = value.get("summary") {
            let count = |key: &str| summary.get(key).and_then(Value::as_u64).unwrap_or(0);
            self.pass = count("pass");
            self.fail = count("fail");
            self.skip = count("skip");
        }
        if value.get("test").and_then(Value::as_str) == Some("datapath")
            && value.get("status").and_then(Value::as_str) == Some("skip")
        {
            self.datapath_skipped = true;
        }
    }
    /// A check that passes only when the suite really ran and said so.
    fn verdict(&self) -> Result<(), String> {
        match self.exit {
            None => Err("the guest ended without a result".into()),
            Some(code) if code != 0 => Err(format!(
                "suite exit {code}: {} pass, {} fail, {} skip",
                self.pass, self.fail, self.skip
            )),
            Some(_) if self.datapath_skipped => {
                Err("the datapath checks were skipped: nothing was loaded".into())
            }
            Some(_) if self.pass == 0 || self.fail > 0 => Err(format!(
                "no clean summary: {} pass, {} fail, {} skip",
                self.pass, self.fail, self.skip
            )),
            Some(_) => Ok(()),
        }
    }
}

fn boot(kernel: &Path, initramfs: &Path, suite: &str) -> Result<Outcome, Box<dyn Error>> {
    let cmdline = format!(
        "console=ttyS0 rdinit=/test panic=-1 loglevel=3 selinux=0 audit=0 flowsdn.suite={suite}"
    );
    let mut child = Command::new(on_path("qemu-system-x86_64")?)
        .args(["-enable-kvm", "-cpu", "host", "-machine", "q35"])
        .args(["-m", "4096", "-smp", "4"])
        .args(["-nodefaults", "-display", "none", "-serial", "stdio"])
        .arg("-no-reboot")
        .arg("-kernel")
        .arg(kernel)
        .arg("-initrd")
        .arg(initramfs)
        .arg("-append")
        .arg(&cmdline)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("qemu has no stdout")?;
    let (lines, console) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).split(b'\n').map_while(Result::ok) {
            if lines
                .send(String::from_utf8_lossy(&line).into_owned())
                .is_err()
            {
                return;
            }
        }
    });
    let start = Instant::now();
    let mut outcome = Outcome::default();
    loop {
        let left = LIMIT.saturating_sub(start.elapsed());
        match console.recv_timeout(left) {
            Ok(line) => {
                println!("{}", line.trim_end());
                outcome.line(&line);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                println!("kernel-check: no result in {} s", LIMIT.as_secs());
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(outcome)
}

pub fn run(root: &Path, suite: &str) -> Result<(), Box<dyn Error>> {
    let stage = root.join("test/.stage");
    if !stage.join("test").is_file() {
        return Err(format!("{} has no /test: run test/build.sh first", stage.display()).into());
    }
    let release = String::from_utf8(Command::new("uname").arg("-r").output()?.stdout)?;
    let release = release.trim();
    let modules = Path::new("/lib/modules").join(release);
    let kernel = modules.join("vmlinuz");
    for needed in [Path::new("/dev/kvm"), kernel.as_path()] {
        fs::File::open(needed).map_err(|e| format!("{}: {e}", needed.display()))?;
    }
    let tmp = std::env::var_os("TMPDIR").map_or_else(|| root.join("tmp"), PathBuf::from);
    fs::create_dir_all(&tmp)?;
    let initramfs = tmp.join("kernel-check.cpio");
    build_initramfs(&stage, release, &modules, &initramfs)?;
    let size = fs::metadata(&initramfs)?.len() / (1 << 20);
    println!("kernel-check: {suite} on {release}, initramfs {size} MB");
    let outcome = boot(&kernel, &initramfs, suite)?;
    let _ = fs::remove_file(&initramfs);
    outcome.verdict()?;
    println!(
        "kernel-check: {suite} on {release}: {} pass, 0 fail, {} skip",
        outcome.pass, outcome.skip
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cpio, Outcome, ldd_paths};

    fn outcome(lines: &[&str]) -> Outcome {
        let mut outcome = Outcome::default();
        lines.iter().for_each(|line| outcome.line(line));
        outcome
    }

    #[test]
    fn newc_entries_are_aligned_and_end_in_the_trailer() -> std::io::Result<()> {
        let mut bytes = Vec::new();
        let mut cpio = Cpio::new(&mut bytes);
        cpio.file("a/b", 0o755, b"hello")?;
        cpio.char_device("dev/console", (5, 1))?;
        cpio.finish()?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // The directory, the file, /dev, the device and the trailer.
        assert_eq!(text.matches("070701").count(), 5);
        assert_eq!(bytes.len() % 4, 0);
        assert!(text.contains("hello"));
        assert!(text.contains("TRAILER!!!"));
        // Each header starts on a four-byte boundary, as the kernel requires.
        for (offset, _) in text.match_indices("070701") {
            assert_eq!(offset % 4, 0, "header at {offset}");
        }
        // Mode (regular, 0755) and size of the file.
        assert!(text.contains(&format!("{:08X}", 0o100_755)));
        Ok(())
    }

    #[test]
    fn device_nodes_carry_their_numbers() -> std::io::Result<()> {
        let mut bytes = Vec::new();
        let mut cpio = Cpio::new(&mut bytes);
        cpio.char_device("console", (5, 1))?;
        cpio.finish()?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert_eq!(text.get(14..22), Some("00002180"), "mode");
        assert_eq!(text.get(78..86), Some("00000005"), "rdevmajor");
        assert_eq!(text.get(86..94), Some("00000001"), "rdevminor");
        Ok(())
    }

    #[test]
    fn ldd_output_gives_absolute_paths_only() {
        let output = "\tlinux-vdso.so.1 (0x00007ffd)\n\tlibbpf.so.1 => /lib64/libbpf.so.1 (0x00007f)\n\tlibc.so.6 => /lib64/libc.so.6 (0x00007e)\n\t/lib64/ld-linux-x86-64.so.2 (0x00007d)\n";
        assert_eq!(
            ldd_paths(output),
            [
                "/lib64/ld-linux-x86-64.so.2",
                "/lib64/libbpf.so.1",
                "/lib64/libc.so.6"
            ]
        );
        assert!(ldd_paths("\tnot a dynamic executable\n").is_empty());
    }

    #[test]
    fn only_a_suite_that_ran_and_passed_passes() {
        let clean = [
            r#"{"test":"preflight","status":"pass","ms":0,"detail":""}"#,
            r#"{"summary":{"pass":20,"fail":0,"skip":2}}"#,
            "@@FLOWSDN-EXIT 0\r",
        ];
        assert_eq!(outcome(&clean).verdict(), Ok(()));
        assert!(outcome(&[]).verdict().is_err(), "no result");
        assert!(
            outcome(&clean[..2]).verdict().is_err(),
            "a guest that died before its result"
        );
        assert!(
            outcome(&[
                r#"{"summary":{"pass":3,"fail":1,"skip":0}}"#,
                "@@FLOWSDN-EXIT 1"
            ])
            .verdict()
            .is_err()
        );
        // Exit 0 with nothing loaded is not a pass: the kernel lacked TCX or BTF.
        assert!(
            outcome(&[
                r#"{"test":"datapath","status":"skip","ms":0,"detail":"requires"}"#,
                r#"{"summary":{"pass":0,"fail":0,"skip":1}}"#,
                "@@FLOWSDN-EXIT 0"
            ])
            .verdict()
            .is_err()
        );
        assert!(
            outcome(&[
                r#"{"summary":{"pass":0,"fail":0,"skip":0}}"#,
                "@@FLOWSDN-EXIT 0"
            ])
            .verdict()
            .is_err()
        );
    }
}
