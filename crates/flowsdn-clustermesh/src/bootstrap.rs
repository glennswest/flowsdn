//! Offline peer-bundle installation. Immutable credentials plus one atomic
//! config rename keep readers on a complete generation. No TLS handshake or
//! certificate issuance is performed; PEM validation here is structural only.
use crate::{Error, prefixes::validate_cluster};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
const MAX_BUNDLE: u64 = 4 * 1024 * 1024;
// Deliberately no Debug implementation: this object contains a private key.
pub struct Bundle {
    cluster: String,
    endpoints: Vec<String>,
    ca: String,
    cert: String,
    key: String,
}
fn invalid() -> Error {
    Error("invalid peer bundle (expected cluster, endpoints and PEM credentials)".into())
}
fn io_error(_: std::io::Error) -> Error {
    Error("peer bundle filesystem operation failed".into())
}
fn no_symlinks(path: &Path) -> Result<(), Error> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(Error("parent traversal is not allowed".into()));
        }
        checked.push(component.as_os_str());
        match fs::symlink_metadata(&checked) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(Error(
                    "symlinks are not allowed in bundle/config paths".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}
fn pem(value: &str, labels: &[&str]) -> bool {
    let mut rest = value.trim();
    let mut count = 0usize;
    while !rest.is_empty() {
        let Some(label) = labels
            .iter()
            .find(|label| rest.starts_with(&format!("-----BEGIN {label}-----")))
        else {
            return false;
        };
        let Some((_, body)) = rest.split_once('\n') else {
            return false;
        };
        let end = format!("-----END {label}-----");
        let Some((body, tail)) = body.split_once(&end) else {
            return false;
        };
        let encoded = body
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if encoded.len() < 4
            || encoded.len() % 4 != 0
            || !encoded
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return false;
        }
        count = count.saturating_add(1);
        rest = tail.trim();
    }
    count > 0
}
fn endpoint(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.contains(['/', '?', '#', '@']) {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u16>().ok().is_none_or(|port| port == 0)
    {
        return false;
    }
    if let Some(address) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return address.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Bundle {
    pub fn read(path: &Path) -> Result<Self, Error> {
        no_symlinks(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.len() > MAX_BUNDLE
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Error(
                "bundle must be a regular owner-only file no larger than 4 MiB".into(),
            ));
        }
        let mut text = String::new();
        Read::by_ref(&mut file)
            .take(MAX_BUNDLE.saturating_add(1))
            .read_to_string(&mut text)
            .map_err(io_error)?;
        if u64::try_from(text.len()).map_err(|_| invalid())? > MAX_BUNDLE {
            return Err(invalid());
        }
        Self::parse(&text)
    }
    pub fn parse(text: &str) -> Result<Self, Error> {
        if u64::try_from(text.len()).map_err(|_| invalid())? > MAX_BUNDLE {
            return Err(invalid());
        }
        let value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
        let object = value.as_object().ok_or_else(invalid)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "cluster" | "endpoints" | "ca_pem" | "cert_pem" | "key_pem"
            )
        }) {
            return Err(invalid());
        }
        let string = |key| object.get(key).and_then(Value::as_str).ok_or_else(invalid);
        let cluster = string("cluster")?.to_owned();
        validate_cluster(&cluster)?;
        let endpoints = object
            .get("endpoints")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| endpoint(value))
                    .map(str::to_owned)
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if endpoints.is_empty()
            || endpoints.len() > 32
            || endpoints
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != endpoints.len()
        {
            return Err(invalid());
        }
        let ca = string("ca_pem")?.to_owned();
        let cert = string("cert_pem")?.to_owned();
        let key = string("key_pem")?.to_owned();
        if !pem(&ca, &["CERTIFICATE"])
            || !pem(&cert, &["CERTIFICATE"])
            || !pem(&key, &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])
        {
            return Err(invalid());
        }
        Ok(Self {
            cluster,
            endpoints,
            ca,
            cert,
            key,
        })
    }
    pub fn cluster(&self) -> &str {
        &self.cluster
    }
}
struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn create_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
fn config_target(path: &Path, replace: bool) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && replace => Ok(()),
        Ok(_) => Err(Error(
            "peer config exists; use --replace for a regular file".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}
/// config_dir must be private from untrusted writers; all existing ancestors
/// must be nonsymlink paths. Same-user adversarial filesystem mutation is outside
/// this offline tool's trust boundary. A stale lock needs explicit operator
/// removal after verifying the previous process is gone; never auto-steal it.
pub fn install(
    bundle: &Bundle,
    config_dir: &Path,
    replace: bool,
    dry_run: bool,
) -> Result<(), Error> {
    no_symlinks(config_dir)?;
    if !config_dir.is_dir() {
        return Err(Error("config directory must already exist".into()));
    }
    let root = fs::canonicalize(config_dir).map_err(io_error)?;
    if fs::metadata(&root).map_err(io_error)?.permissions().mode() & 0o022 != 0 {
        return Err(Error(
            "config directory must not be writable by group or others".into(),
        ));
    }
    let target = root.join(&bundle.cluster);
    config_target(&target, replace)?;
    if dry_run {
        return Ok(());
    }
    let lockpath = root.join(".flowsdn-connect.lock");
    let lockfile=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&lockpath).map_err(|_|Error("config directory is locked; verify any previous writer before clearing a stale lock".into()))?;
    let _lock = Lock(lockpath);
    drop(lockfile);
    config_target(&target, replace)?;
    let materials = root.join(".flowsdn-peer-material");
    match fs::symlink_metadata(&materials) {
        Ok(meta)
            if meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.permissions().mode() & 0o077 == 0 => {}
        Ok(_) => return Err(Error("unsafe peer material directory".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&materials)
                .map_err(io_error)?;
        }
        Err(error) => return Err(io_error(error)),
    }
    let generation = loop {
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error("system clock predates epoch".into()))?
            .as_nanos();
        let candidate = materials.join(format!(
            "{}-{}-{time}-{serial}",
            bundle.cluster,
            std::process::id()
        ));
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        }
    };
    let prepare = (|| {
        let ca = generation.join(format!("{}.etcd-client-ca.crt", bundle.cluster));
        let cert = generation.join(format!("{}.etcd-client.crt", bundle.cluster));
        let key = generation.join(format!("{}.etcd-client.key", bundle.cluster));
        create_file(&ca, bundle.ca.as_bytes())?;
        create_file(&cert, bundle.cert.as_bytes())?;
        create_file(&key, bundle.key.as_bytes())?;
        let quote = |value: &str| serde_json::to_string(value).map_err(|_| invalid());
        let mut yaml = String::from("endpoints:\n");
        for address in &bundle.endpoints {
            yaml.push_str(&format!("- {}\n", quote(address)?));
        }
        for (field, path) in [
            ("trusted-ca-file", ca),
            ("cert-file", cert),
            ("key-file", key),
        ] {
            yaml.push_str(&format!(
                "{field}: {}\n",
                quote(path.to_str().ok_or_else(invalid)?)?
            ));
        }
        let staged = generation.join("config");
        create_file(&staged, yaml.as_bytes())?;
        File::open(&generation)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        File::open(&materials)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        config_target(&target, replace)?;
        fs::rename(&staged, &target).map_err(io_error)?;
        Ok::<(), Error>(())
    })();
    if prepare.is_err() {
        let _ = fs::remove_dir_all(&generation);
        return prepare;
    }
    // After publication never delete the generation, even if directory fsync
    // reports failure: the active config may already reference these files.
    File::open(&root)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            Error("peer config published but directory durability could not be confirmed".into())
        })
}
