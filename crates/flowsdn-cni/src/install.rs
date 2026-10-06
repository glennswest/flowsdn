//! Atomic executable installation from spec 09 §3.12 and ADR-0012.
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug)]
pub struct InstallOptions {
    pub source: PathBuf,
    pub cni_dir: PathBuf,
    pub overwrite_plugin: bool,
    pub overwrite_loopback: bool,
}

impl InstallOptions {
    /// An explicit source avoids assuming the packaging layout or copying the agent.
    pub fn from_env(source: PathBuf, env: &BTreeMap<OsString, OsString>) -> Self {
        let host = env
            .get(&OsString::from("HOST_PREFIX"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/host"));
        Self {
            source,
            cni_dir: env
                .get(&OsString::from("CNI_DIR"))
                .map(PathBuf::from)
                .unwrap_or_else(|| host.join("opt/cni")),
            overwrite_plugin: env
                .get(&OsString::from("OVERWRITE_PLUGIN"))
                .is_none_or(|v| v != "false"),
            overwrite_loopback: env
                .get(&OsString::from("OVERWRITE_LOOPBACK"))
                .is_some_and(|v| v == "true"),
        }
    }
}

#[derive(Debug, Default)]
pub struct InstallReport {
    pub plugin_replaced: bool,
    pub loopback_replaced: bool,
    pub warnings: Vec<String>,
}

/// Replace directory entries, never truncate existing binaries or follow their
/// symlinks. The bin directory must be controlled by the installer/operator.
/// Each name is published atomically; the set of aliases is not a transaction.
pub fn install(options: &InstallOptions) -> io::Result<InstallReport> {
    let bin = options.cni_dir.join("bin");
    fs::create_dir_all(&bin)?;
    let plugin = bin.join("flowsdn-cni");
    let existing = exists(&plugin)?;
    let mut report = InstallReport::default();
    if options.overwrite_plugin || !existing {
        copy_atomic(&options.source, &plugin)?;
        report.plugin_replaced = true;
    } else if !fs::symlink_metadata(&plugin)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "retained flowsdn-cni must be a regular file",
        ));
    }
    // The golden's path for the same executable.
    link_atomic(&plugin, &bin.join("flowsdn"))?;
    let loopback = bin.join("loopback");
    // Loopback installation is best effort, including inability to inspect it.
    let loopback_result = (|| {
        if options.overwrite_loopback || !exists(&loopback)? {
            copy_atomic(&options.source, &loopback)?;
            report.loopback_replaced = true;
        }
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = loopback_result {
        report
            .warnings
            .push(format!("could not install loopback: {error}"));
    }
    Ok(report)
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn temporary(destination: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(
        destination
            .file_name()
            .expect("installer destination has a filename"),
    );
    name.push(format!(
        ".new.{}.{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    destination.with_file_name(name)
}
fn copy_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    let mut input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CNI source must be a regular file",
        ));
    }
    let (temporary, mut output) = loop {
        let path = temporary(destination);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => break (Temporary(path), file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    io::copy(&mut input, &mut output)?;
    output.set_permissions(fs::Permissions::from_mode(0o755))?;
    output.sync_all()?;
    fs::rename(&temporary.0, destination)
}
fn link_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    let temporary = loop {
        let path = temporary(destination);
        match fs::hard_link(source, &path) {
            Ok(()) => break Temporary(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    fs::rename(&temporary.0, destination)
}

/// The network configuration the kubelet loads: the first file in the conf
/// dir by name. `00-` so a leftover conflist from another CNI (`05-...`)
/// cannot win. The plugin type is flowsdn's own executable name (#294).
pub const CONFLIST_NAME: &str = "00-flowsdn.conflist";

pub fn conflist() -> String {
    serde_json::json!({
        "cniVersion": "1.1.0",
        "name": "flowsdn",
        "plugins": [{"type": "flowsdn-cni"}],
    })
    .to_string()
}

/// Write [`conflist`] into `dir` atomically (a reader never sees a partial
/// file); returns its path.
pub fn write_conflist(dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let destination = dir.join(CONFLIST_NAME);
    let (temporary, mut output) = loop {
        let path = temporary(&destination);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
        {
            Ok(file) => break (Temporary(path), file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    io::Write::write_all(&mut output, conflist().as_bytes())?;
    output.sync_all()?;
    fs::rename(&temporary.0, &destination)?;
    Ok(destination)
}

/// `flowsdn-cni install`: what a node's agent pod runs before the agent.
/// Copies this executable into `$CNI_DIR/bin` (default `$HOST_PREFIX/opt/cni`)
/// under its plugin names and `loopback`, then writes the conflist into
/// `$CNI_CONF_DIR` (default `$HOST_PREFIX/etc/cni/net.d`).
pub fn install_node(
    source: PathBuf,
    env: &BTreeMap<OsString, OsString>,
) -> io::Result<(InstallReport, PathBuf)> {
    let options = InstallOptions::from_env(source, env);
    let report = install(&options)?;
    let conf_dir = env
        .get(&OsString::from("CNI_CONF_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env.get(&OsString::from("HOST_PREFIX"))
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/host"))
                .join("etc/cni/net.d")
        });
    Ok((report, write_conflist(&conf_dir)?))
}

#[cfg(test)]
mod node_install_tests {
    use super::*;

    #[test]
    fn installs_plugin_names_and_writes_the_conflist() {
        let root = std::env::temp_dir().join(format!(
            "flowsdn-install-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("root");
        let source = root.join("plugin");
        fs::write(&source, b"#!plugin").expect("source");
        let env: BTreeMap<OsString, OsString> = [(
            OsString::from("HOST_PREFIX"),
            root.join("host").into_os_string(),
        )]
        .into();
        let (report, conf) = install_node(source, &env).expect("install");
        assert!(report.plugin_replaced);
        for name in ["flowsdn-cni", "flowsdn", "loopback"] {
            let path = root.join("host/opt/cni/bin").join(name);
            assert_eq!(fs::read(&path).expect("installed"), b"#!plugin", "{name}");
        }
        assert_eq!(conf, root.join("host/etc/cni/net.d").join(CONFLIST_NAME));
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(&conf).expect("conflist")).expect("JSON");
        assert_eq!(
            written
                .pointer("/plugins/0/type")
                .and_then(serde_json::Value::as_str),
            Some("flowsdn-cni")
        );
        // Rewriting is atomic and idempotent; no temporary files remain.
        install_node(root.join("plugin"), &env).expect("reinstall");
        let leftovers = fs::read_dir(root.join("host/etc/cni/net.d"))
            .expect("conf dir")
            .count();
        assert_eq!(leftovers, 1);
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
