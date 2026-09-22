#![cfg(unix)]
use std::{fs,path::{Path,PathBuf},process::{Command,Output},os::unix::fs::{PermissionsExt,symlink},sync::atomic::{AtomicU64,Ordering}};
use serde_json::json;
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Sandbox(PathBuf);
impl Sandbox {fn new()->Self {let dir=std::env::temp_dir().join(format!("flowsdn-connect-test-{}-{}",std::process::id(),SERIAL.fetch_add(1,Ordering::Relaxed)));fs::create_dir(&dir).expect("dir");fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).expect("permissions");Self(dir)}}
impl Drop for Sandbox {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
const CERT:&str="-----BEGIN CERTIFICATE-----\nMAAA\n-----END CERTIFICATE-----\n";
const KEY:&str="-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n";
fn bundle(path:&Path,cluster:&str,endpoint:&str) {
    fs::write(path,json!({"cluster":cluster,"endpoints":[endpoint],"ca_pem":CERT,"cert_pem":CERT,"key_pem":KEY}).to_string()).expect("bundle");
    fs::set_permissions(path,fs::Permissions::from_mode(0o600)).expect("mode");
}
fn command(bundle:&Path,dir:&Path,options:&[&str])->Output {
    Command::new(env!("CARGO_BIN_EXE_flowsdn-cli")).args(["clustermesh","connect","--bundle"]).arg(bundle).arg("--config-dir").arg(dir).args(options).output().expect("cli")
}
fn certificates(config:&Path)->Vec<PathBuf> {
    let yaml=fs::read_to_string(config).expect("config");
    let documents=yaml_rust2::YamlLoader::load_from_str(&yaml).expect("yaml");
    let document=documents.first().expect("document").as_hash().expect("map");
    ["trusted-ca-file","cert-file","key-file"].into_iter().map(|key|PathBuf::from(document.get(&yaml_rust2::Yaml::String(key.into())).expect("field").as_str().expect("path"))).collect()
}
#[test]
fn installs_complete_generation_with_private_modes_and_no_secret_output() {
    let sandbox=Sandbox::new();let path=sandbox.0.join("bundle.json");bundle(&path,"east","https://east.mesh.example:2379");
    let out=command(&path,&sandbox.0,&[]);assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout),"Installed peer east\n");
    for output in [&out.stdout,&out.stderr] {assert!(!String::from_utf8_lossy(output).contains("AQIDBA"));}
    let config=sandbox.0.join("east");assert_eq!(fs::metadata(&config).expect("stat").permissions().mode()&0o777,0o400);
    for file in certificates(&config) {assert!(file.is_file());assert_eq!(fs::metadata(&file).expect("stat").permissions().mode()&0o777,0o400);assert_eq!(fs::metadata(file.parent().expect("parent")).expect("stat").permissions().mode()&0o777,0o700);}
    assert!(!sandbox.0.join(".flowsdn-connect.lock").exists());
}
#[test]
fn replacement_keeps_old_credentials_and_requires_explicit_flag() {
    let sandbox=Sandbox::new();let path=sandbox.0.join("bundle.json");bundle(&path,"east","https://east.mesh.example:2379");
    assert!(command(&path,&sandbox.0,&[]).status.success());
    let config=sandbox.0.join("east");let old=fs::read(&config).expect("old");let old_files=certificates(&config);
    bundle(&path,"east","https://[2001:db8::2]:2379");
    assert!(!command(&path,&sandbox.0,&[]).status.success());assert_eq!(fs::read(&config).expect("unchanged"),old);
    assert!(command(&path,&sandbox.0,&["--replace"]).status.success());assert_ne!(fs::read(&config).expect("new"),old);
    for file in old_files {assert!(file.exists(),"readers of oldconfig retain usablepaths");}
    for file in certificates(&config) {assert!(file.exists());}
}
#[test]
fn dry_run_and_invalid_inputs_do_not_modify_active_state() {
    let sandbox=Sandbox::new();let path=sandbox.0.join("bundle.json");bundle(&path,"east","https://east.mesh.example:2379");
    assert!(command(&path,&sandbox.0,&["--dry-run"]).status.success());assert!(!sandbox.0.join("east").exists());assert!(!sandbox.0.join(".flowsdn-peer-material").exists());
    assert!(command(&path,&sandbox.0,&[]).status.success());let old=fs::read(sandbox.0.join("east")).expect("config");
    for endpoint in ["http://east:2379","https://user:secret@east:2379","https://east:0","https://east:65536","https://east:2379/path","https://../east:2379"] {
        bundle(&path,"east",endpoint);assert!(!command(&path,&sandbox.0,&["--replace"]).status.success());assert_eq!(fs::read(sandbox.0.join("east")).expect("same"),old);
    }
    bundle(&path,"../escape","https://east:2379");assert!(!command(&path,&sandbox.0,&[]).status.success());
    fs::write(&path,"{\"key_pem\":\"DO-NOT-PRINT-THIS\"").expect("malformed");
    let out=command(&path,&sandbox.0,&["--replace"]);assert!(!out.status.success());assert!(!String::from_utf8_lossy(&out.stderr).contains("DO-NOT-PRINT-THIS"));
}
#[test]
fn symlinks_unsafe_modes_and_lock_conflicts_fail_closed() {
    let sandbox=Sandbox::new();let path=sandbox.0.join("bundle.json");bundle(&path,"east","https://east:2379");
    let link=sandbox.0.join("bundle-link");symlink(&path,&link).expect("link");assert!(!command(&link,&sandbox.0,&[]).status.success());
    let dirlink=sandbox.0.join("directory-link");symlink(&sandbox.0,&dirlink).expect("dirlink");assert!(!command(&path,&dirlink,&[]).status.success());
    let foreign=sandbox.0.join("foreign");fs::write(&foreign,"keep").expect("foreign");symlink(&foreign,sandbox.0.join("east")).expect("targetlink");
    assert!(!command(&path,&sandbox.0,&["--replace"]).status.success());assert_eq!(fs::read_to_string(&foreign).expect("foreign"),"keep");fs::remove_file(sandbox.0.join("east")).expect("unlink");
    fs::set_permissions(&path,fs::Permissions::from_mode(0o644)).expect("mode");assert!(!command(&path,&sandbox.0,&[]).status.success());fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(sandbox.0.join(".flowsdn-connect.lock"),"").expect("lock");assert!(!command(&path,&sandbox.0,&[]).status.success());assert!(!sandbox.0.join("east").exists());
}
#[test]
fn material_directory_attack_cannot_replace_existing_config() {
    let sandbox=Sandbox::new();let path=sandbox.0.join("bundle.json");bundle(&path,"east","https://east:2379");
    let existing=sandbox.0.join("east");fs::write(&existing,"original").expect("existing");
    symlink(&sandbox.0,sandbox.0.join(".flowsdn-peer-material")).expect("link");
    assert!(!command(&path,&sandbox.0,&["--replace"]).status.success());assert_eq!(fs::read_to_string(existing).expect("existing"),"original");assert!(!sandbox.0.join(".flowsdn-connect.lock").exists());
}
