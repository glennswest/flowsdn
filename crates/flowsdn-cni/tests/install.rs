use flowsdn_cni::install::{InstallOptions, install};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp"));
        fs::create_dir_all(&root).expect("installer fixture operation succeeds");
        let path = root.join(format!(
            "cni-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("installer fixture operation succeeds");
        Self(path)
    }
    fn options(&self) -> InstallOptions {
        let source = self.0.join("source");
        fs::write(&source, b"rust-plugin-v1").expect("installer fixture operation succeeds");
        InstallOptions {
            source,
            cni_dir: self.0.join("cni"),
            overwrite_cilium: true,
            overwrite_loopback: false,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn copies_executable_and_links_all_compatibility_names() {
    let fixture = Fixture::new();
    let options = fixture.options();
    let report = install(&options).expect("installer fixture operation succeeds");
    assert!(report.plugin_replaced && report.loopback_replaced && report.warnings.is_empty());
    let bin = options.cni_dir.join("bin");
    let canonical =
        fs::metadata(bin.join("cilium-cni")).expect("installer fixture operation succeeds");
    for name in ["cilium-cni", "flowsdn-cni", "flowsdn", "loopback"] {
        let metadata = fs::metadata(bin.join(name)).expect("installer fixture operation succeeds");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
        assert_eq!(
            fs::read(bin.join(name)).expect("installer fixture operation succeeds"),
            b"rust-plugin-v1"
        );
        if name != "loopback" {
            assert_eq!(metadata.ino(), canonical.ino());
        }
    }
    // Replacing a running binary must leave an already opened inode unchanged.
    let old = fs::File::open(bin.join("cilium-cni")).expect("installer fixture operation succeeds");
    fs::write(&options.source, b"rust-plugin-v2").expect("installer fixture operation succeeds");
    install(&options).expect("installer fixture operation succeeds");
    assert_ne!(
        old.metadata()
            .expect("installer fixture operation succeeds")
            .ino(),
        fs::metadata(bin.join("cilium-cni"))
            .expect("installer fixture operation succeeds")
            .ino()
    );
    assert_eq!(
        fs::read(bin.join("flowsdn-cni")).expect("installer fixture operation succeeds"),
        b"rust-plugin-v2"
    );
    assert_eq!(
        fs::read(bin.join("loopback")).expect("installer fixture operation succeeds"),
        b"rust-plugin-v1"
    );
}

#[test]
fn overwrite_flags_preserve_plugin_and_replace_loopback_independently() {
    let fixture = Fixture::new();
    let mut options = fixture.options();
    install(&options).expect("installer fixture operation succeeds");
    options.overwrite_cilium = false;
    options.overwrite_loopback = true;
    fs::write(&options.source, b"replacement").expect("installer fixture operation succeeds");
    let report = install(&options).expect("installer fixture operation succeeds");
    assert!(!report.plugin_replaced && report.loopback_replaced);
    let bin = options.cni_dir.join("bin");
    assert_eq!(
        fs::read(bin.join("flowsdn")).expect("installer fixture operation succeeds"),
        b"rust-plugin-v1"
    );
    assert_eq!(
        fs::read(bin.join("loopback")).expect("installer fixture operation succeeds"),
        b"replacement"
    );
}

#[test]
fn replacement_does_not_write_through_foreign_symlinks() {
    let fixture = Fixture::new();
    let mut options = fixture.options();
    let bin = options.cni_dir.join("bin");
    fs::create_dir_all(&bin).expect("installer fixture operation succeeds");
    let foreign = fixture.0.join("foreign");
    fs::write(&foreign, b"do-not-change").expect("installer fixture operation succeeds");
    for name in ["cilium-cni", "flowsdn-cni", "flowsdn", "loopback"] {
        symlink(&foreign, bin.join(name)).expect("installer fixture operation succeeds");
    }
    options.overwrite_loopback = true;
    install(&options).expect("installer fixture operation succeeds");
    assert_eq!(
        fs::read(foreign).expect("installer fixture operation succeeds"),
        b"do-not-change"
    );
    for name in ["cilium-cni", "flowsdn-cni", "flowsdn", "loopback"] {
        assert!(
            fs::symlink_metadata(bin.join(name))
                .expect("installer fixture operation succeeds")
                .is_file()
        );
    }
}

#[test]
fn retained_symlink_is_rejected_and_loopback_failure_is_warning() {
    let fixture = Fixture::new();
    let mut options = fixture.options();
    let bin = options.cni_dir.join("bin");
    fs::create_dir_all(&bin).expect("installer fixture operation succeeds");
    symlink(&options.source, bin.join("cilium-cni")).expect("installer fixture operation succeeds");
    options.overwrite_cilium = false;
    assert!(
        install(&options)
            .expect_err("installation must reject invalid destination")
            .to_string()
            .contains("regular file")
    );
    options.overwrite_cilium = true;
    options.overwrite_loopback = true;
    fs::create_dir(bin.join("loopback")).expect("installer fixture operation succeeds");
    let report = install(&options).expect("installer fixture operation succeeds");
    assert!(report.plugin_replaced && !report.loopback_replaced);
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(
        fs::read_dir(&bin)
            .expect("installer fixture operation succeeds")
            .count(),
        4,
        "staging files must be cleaned"
    );
}

#[test]
fn source_failure_preserves_previous_installation() {
    let fixture = Fixture::new();
    let mut options = fixture.options();
    install(&options).expect("installer fixture operation succeeds");
    options.source = fixture.0.join("missing");
    assert!(install(&options).is_err());
    assert_eq!(
        fs::read(options.cni_dir.join("bin/cilium-cni"))
            .expect("installer fixture operation succeeds"),
        b"rust-plugin-v1"
    );
}

#[test]
fn environment_defaults_and_overrides_match_contract() {
    let source = PathBuf::from("plugin");
    let mut env = BTreeMap::<OsString, OsString>::new();
    let defaults = InstallOptions::from_env(source.clone(), &env);
    assert_eq!(defaults.cni_dir, PathBuf::from("/host/opt/cni"));
    assert!(defaults.overwrite_cilium && !defaults.overwrite_loopback);
    env.insert("HOST_PREFIX".into(), "/mounted".into());
    assert_eq!(
        InstallOptions::from_env(source.clone(), &env).cni_dir,
        PathBuf::from("/mounted/opt/cni")
    );
    env.insert("CNI_DIR".into(), "/custom".into());
    env.insert("OVERWRITE_CILIUM".into(), "false".into());
    env.insert("OVERWRITE_LOOPBACK".into(), "true".into());
    let options = InstallOptions::from_env(source, &env);
    assert_eq!(options.cni_dir, PathBuf::from("/custom"));
    assert!(!options.overwrite_cilium && options.overwrite_loopback);
}
