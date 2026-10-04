//! What the datapath checks need of the machine. A kernel without what flowsdn
//! requires is a skip (the machine lacks it, flowsdn did not fail); a pod
//! without the privileges `test/requires.toml` declares, or an incomplete
//! image, is infrastructure (exit 2).
use crate::env::Env;
use std::{fs, path::Path};

pub enum Preflight {
    Ready(String),
    Skip(String),
    Infrastructure(String),
}

/// `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and `CAP_BPF` bit numbers.
const CAPABILITIES: [(u32, &str); 3] = [(12, "NET_ADMIN"), (21, "SYS_ADMIN"), (39, "BPF")];

pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// `major.minor` of a release string such as `6.17.1-300.fc43.x86_64`.
pub fn version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn effective_capabilities() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let hex = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(hex.trim(), 16).ok()
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join(tool).is_file())
    })
}

pub fn check(env: &Env) -> Preflight {
    let release = kernel_release();
    match version(&release) {
        Some(v) if v >= (6, 6) => {}
        _ => {
            return Preflight::Skip(format!(
                "requires: kernel >= 6.6 (TCX); this machine runs {release:?}"
            ));
        }
    }
    if !Path::new("/sys/kernel/btf/vmlinux").is_file() {
        return Preflight::Skip(
            "requires: kernel BTF (/sys/kernel/btf/vmlinux, CONFIG_DEBUG_INFO_BTF)".into(),
        );
    }
    let caps = effective_capabilities().unwrap_or(0);
    let missing: Vec<&str> = CAPABILITIES
        .iter()
        .filter(|(bit, _)| caps.checked_shr(*bit).is_none_or(|v| v & 1 == 0))
        .map(|(_, name)| *name)
        .collect();
    if !missing.is_empty() {
        return Preflight::Infrastructure(format!(
            "pod lacks CAP_{}: test/requires.toml declares privileged = true for this suite",
            missing.join(", CAP_")
        ));
    }
    let staged = [env.agent(), env.cni(), env.bpf("local-delivery")];
    if let Some(absent) = staged.iter().find(|p| !p.is_file()) {
        return Preflight::Infrastructure(format!(
            "image incomplete: {} missing (test/build.sh stages it)",
            absent.display()
        ));
    }
    if let Some(tool) = ["ip", "nft"].into_iter().find(|t| !on_path(t)) {
        return Preflight::Infrastructure(format!("image incomplete: {tool} not on PATH"));
    }
    Preflight::Ready(format!("kernel {release}, BTF present, privileged"))
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn parses_kernel_releases() {
        assert_eq!(version("6.17.1-300.fc43.x86_64"), Some((6, 17)));
        assert_eq!(version("6.6.0"), Some((6, 6)));
        assert_eq!(version("5.15"), Some((5, 15)));
        assert_eq!(version("garbage"), None);
        assert!(version("6.1.90").is_some_and(|v| v < (6, 6)));
    }
}
