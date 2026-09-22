//! Validation runner, not a container runtime. Never accepts unresolved filters.
use serde_json::Value;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct Comparison {
    arg: u32,
    op: i32,
    a: u64,
    b: u64,
}
#[derive(Debug)]
struct Rule {
    names: Vec<String>,
    action: u32,
    args: Vec<Comparison>,
}
#[derive(Debug)]
struct Profile {
    default: u32,
    architectures: Vec<String>,
    rules: Vec<Rule>,
}

fn fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let map = value.as_object().ok_or("expected object")?;
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unsupported profile field".into());
    }
    Ok(())
}
fn action(name: &str, errno: Option<&Value>) -> Result<u32, String> {
    if name != "SCMP_ACT_ERRNO" && errno.is_some() {
        return Err("errno requires ERRNO action".into());
    }
    Ok(match name {
        "SCMP_ACT_ALLOW" => 0x7fff0000,
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => 0,
        "SCMP_ACT_KILL_PROCESS" => 0x80000000,
        "SCMP_ACT_ERRNO" => {
            let errno = errno.map_or(Ok(1), |v| v.as_u64().ok_or("invalid errno"))?;
            if errno == 0 || errno > 4095 {
                return Err("errno out of range".into());
            }
            0x00050000 | u32::try_from(errno).map_err(|_| "errno overflow")?
        }
        _ => return Err("unsupported action".into()),
    })
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {key}"))
}
fn list(value: &Value, key: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or("missing array")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "non-string in array".into())
        })
        .collect()
}
fn parse(value: &Value) -> Result<Profile, String> {
    fields(
        value,
        &[
            "defaultAction",
            "defaultErrnoRet",
            "architectures",
            "syscalls",
            "flags",
        ],
    )?;
    if let Some(flags) = value.get("flags") {
        if !flags.as_array().is_some_and(Vec::is_empty) {
            return Err("nonempty flags unsupported".into());
        }
    }
    let default = action(text(value, "defaultAction")?, value.get("defaultErrnoRet"))?;
    if default == 0x7fff0000 {
        return Err("default ALLOW prohibited".into());
    }
    let architectures = list(value, "architectures")?;
    if architectures.is_empty() {
        return Err("explicit architectures required".into());
    }
    let mut rules = Vec::new();
    for rule in value
        .get("syscalls")
        .and_then(Value::as_array)
        .ok_or("missing syscalls")?
    {
        fields(rule, &["names", "action", "errnoRet", "args"])?;
        let names = list(rule, "names")?;
        if names.is_empty()
            || names.iter().any(|n| {
                n.is_empty()
                    || !n
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
        {
            return Err("invalid syscall names".into());
        }
        let action = action(text(rule, "action")?, rule.get("errnoRet"))?;
        let mut args = Vec::new();
        if let Some(comparisons) = rule.get("args") {
            for cmp in comparisons.as_array().ok_or("invalid args")? {
                fields(cmp, &["index", "value", "valueTwo", "op"])?;
                let index = cmp
                    .get("index")
                    .and_then(Value::as_u64)
                    .ok_or("missing arg index")?;
                if index > 5 {
                    return Err("argument index exceeds five".into());
                }
                let op = match text(cmp, "op")? {
                    "SCMP_CMP_NE" => 1,
                    "SCMP_CMP_LT" => 2,
                    "SCMP_CMP_LE" => 3,
                    "SCMP_CMP_EQ" => 4,
                    "SCMP_CMP_GE" => 5,
                    "SCMP_CMP_GT" => 6,
                    "SCMP_CMP_MASKED_EQ" => 7,
                    _ => return Err("unsupported comparison".into()),
                };
                let a = cmp
                    .get("value")
                    .and_then(Value::as_u64)
                    .ok_or("invalid comparison value")?;
                let b = cmp
                    .get("valueTwo")
                    .map_or(Ok(0), |v| v.as_u64().ok_or("invalid valueTwo"))?;
                if op != 7 && b != 0 {
                    return Err("valueTwo only supported for MASKED_EQ".into());
                }
                args.push(Comparison {
                    arg: u32::try_from(index).map_err(|_| "index overflow")?,
                    op,
                    a,
                    b,
                });
            }
        }
        rules.push(Rule {
            names,
            action,
            args,
        });
    }
    Ok(Profile {
        default,
        architectures,
        rules,
    })
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod native {
    use super::{Comparison, Profile};
    use std::{
        ffi::{CString, c_void},
        ptr::NonNull,
    };
    type Init = unsafe extern "C" fn(u32) -> *mut c_void;
    type Release = unsafe extern "C" fn(*mut c_void);
    type Load = unsafe extern "C" fn(*mut c_void) -> i32;
    type ArchNative = unsafe extern "C" fn() -> u32;
    type ArchAdd = unsafe extern "C" fn(*mut c_void, u32) -> i32;
    type Resolve = unsafe extern "C" fn(*const libc::c_char) -> i32;
    type Add = unsafe extern "C" fn(*mut c_void, u32, i32, u32, *const Comparison) -> i32;
    struct Library(NonNull<c_void>);
    impl Drop for Library {
        fn drop(&mut self) {
            // SAFETY: unique live dlopen handle; all contexts have been released.
            unsafe {
                libc::dlclose(self.0.as_ptr());
            }
        }
    }
    impl Library {
        fn open() -> Result<Self, String> {
            // SAFETY: static NUL-terminated soname; immediate binding, local symbols.
            NonNull::new(unsafe {
                libc::dlopen(
                    c"libseccomp.so.2".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            })
            .map(Self)
            .ok_or_else(|| "cannot load libseccomp.so.2".into())
        }
        fn symbol(&self, name: &std::ffi::CStr) -> Result<*mut c_void, String> {
            // SAFETY: library remains alive; name is NUL-terminated.
            let ptr = unsafe { libc::dlsym(self.0.as_ptr(), name.as_ptr()) };
            if ptr.is_null() {
                Err(format!(
                    "missing libseccomp symbol {}",
                    name.to_string_lossy()
                ))
            } else {
                Ok(ptr)
            }
        }
    }
    struct Context<'a> {
        ptr: NonNull<c_void>,
        release: Release,
        _library: &'a Library,
    }
    impl Drop for Context<'_> {
        fn drop(&mut self) {
            // SAFETY: context was returned by seccomp_init, released exactly once before library unload.
            unsafe {
                (self.release)(self.ptr.as_ptr());
            }
        }
    }
    fn checked(result: i32, operation: &str) -> Result<(), String> {
        if result < 0 {
            Err(format!(
                "{operation}: {} ({result})",
                std::io::Error::from_raw_os_error(result.saturating_neg())
            ))
        } else {
            Ok(())
        }
    }
    pub fn install(profile: &Profile) -> Result<(), String> {
        let library = Library::open()?;
        // SAFETY: each checked symbol name and exact C ABI signature matches
        // libseccomp's public seccomp.h API. Library outlives every call/context.
        let (init, release, load, arch_native, arch_add, resolve, add) = unsafe {
            (
                std::mem::transmute::<*mut c_void, Init>(library.symbol(c"seccomp_init")?),
                std::mem::transmute::<*mut c_void, Release>(library.symbol(c"seccomp_release")?),
                std::mem::transmute::<*mut c_void, Load>(library.symbol(c"seccomp_load")?),
                std::mem::transmute::<*mut c_void, ArchNative>(
                    library.symbol(c"seccomp_arch_native")?,
                ),
                std::mem::transmute::<*mut c_void, ArchAdd>(library.symbol(c"seccomp_arch_add")?),
                std::mem::transmute::<*mut c_void, Resolve>(
                    library.symbol(c"seccomp_syscall_resolve_name")?,
                ),
                std::mem::transmute::<*mut c_void, Add>(library.symbol(c"seccomp_rule_add_array")?),
            )
        };
        // SAFETY: no arguments; initialized function pointer held by live library.
        let native = unsafe { arch_native() };
        let architectures: Vec<u32> = profile
            .architectures
            .iter()
            .map(|name| match name.as_str() {
                "SCMP_ARCH_X86_64" => Ok(0xc000003e),
                "SCMP_ARCH_X86" => Ok(0x40000003),
                "SCMP_ARCH_X32" => Ok(0x4000003e),
                "SCMP_ARCH_AARCH64" => Ok(0xc00000b7),
                "SCMP_ARCH_ARM" => Ok(0x40000028),
                _ => Err("unsupported architecture".to_owned()),
            })
            .collect::<Result<_, _>>()?;
        if !architectures.contains(&native) {
            return Err("profile excludes native architecture".into());
        }
        let family: &[u32] = match native {
            0xc000003e => &[0xc000003e, 0x40000003, 0x4000003e],
            0xc00000b7 => &[0xc00000b7, 0x40000028],
            _ => return Err("unsupported native architecture".into()),
        };
        if architectures.iter().any(|a| !family.contains(a)) {
            return Err("foreign architecture family".into());
        }
        // SAFETY: validated action token. Null allocation failure is handled.
        let ptr = NonNull::new(unsafe { init(profile.default) }).ok_or("seccomp_init failed")?;
        let context = Context {
            ptr,
            release,
            _library: &library,
        };
        let mut added = std::collections::BTreeSet::from([native]);
        for arch in architectures {
            if added.insert(arch) {
                // SAFETY: live context and supported architecture token.
                checked(
                    unsafe { arch_add(context.ptr.as_ptr(), arch) },
                    "seccomp_arch_add",
                )?;
            }
        }
        for rule in &profile.rules {
            for name in &rule.names {
                let c_name = CString::new(name.as_str()).map_err(|_| "NUL in syscall")?;
                // SAFETY: NUL-terminated live name, resolver borrows it only for this call.
                let number = unsafe { resolve(c_name.as_ptr()) };
                if number == -1 {
                    return Err(format!("unknown syscall {name}"));
                }
                if rule.action == profile.default {
                    // libseccomp rejects explicit default-action rules. They
                    // are redundant only when no differently-acting rule can
                    // overlap; never erase a deny exception to an ALLOW rule.
                    if profile
                        .rules
                        .iter()
                        .any(|other| other.action != profile.default && other.names.contains(name))
                    {
                        return Err(format!(
                            "default-action rule overlaps another action for {name}"
                        ));
                    }
                    continue;
                }
                let count = u32::try_from(rule.args.len()).map_err(|_| "too many comparisons")?;
                // SAFETY: repr(C) comparisons exactly match scmp_arg_cmp; array
                // remains live for call. libseccomp copies its values.
                checked(
                    unsafe {
                        add(
                            context.ptr.as_ptr(),
                            rule.action,
                            number,
                            count,
                            rule.args.as_ptr(),
                        )
                    },
                    &format!("seccomp_rule_add_array {name}"),
                )?;
            }
        }
        // SAFETY: complete validated context. libseccomp enables no_new_privs
        // by default, then installs an inherited filter in this single thread.
        checked(unsafe { load(context.ptr.as_ptr()) }, "seccomp_load")?;
        Ok(())
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: enforce PROFILE.json -- COMMAND [ARGS...]")?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        return Err("expected -- after profile".into());
    }
    let command = args.next().ok_or("missing command")?;
    let value = serde_json::from_slice(&std::fs::read(path)?)?;
    let profile = parse(&value)?;
    let mut command = std::process::Command::new(command);
    command.args(args);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        native::install(&profile)?;
        Err(command.exec().into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, command);
        Err("enforcement requires Linux".into())
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("seccomp enforce: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn strict_oci_parser_rejects_unresolved_and_unknown_fields() {
        for rule in [
            json!({"names":["read"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_BPF"]}}),
            json!({"names":["read"],"action":"SCMP_ACT_NOTIFY"}),
            json!({"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":6,"value":0,"op":"SCMP_CMP_EQ"}]}),
        ] {
            assert!(parse(&json!({"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],"syscalls":[rule]})).is_err());
        }
    }
    #[test]
    fn all_comparisons_and_errno_bits_are_exact() {
        for (name, expected) in [
            ("SCMP_CMP_NE", 1),
            ("SCMP_CMP_LT", 2),
            ("SCMP_CMP_LE", 3),
            ("SCMP_CMP_EQ", 4),
            ("SCMP_CMP_GE", 5),
            ("SCMP_CMP_GT", 6),
            ("SCMP_CMP_MASKED_EQ", 7),
        ] {
            let profile = parse(&json!({"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":38,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":7,"op":name}]}]})).expect("profile");
            assert_eq!(profile.default, 0x00050026);
            assert_eq!(
                profile
                    .rules
                    .first()
                    .and_then(|r| r.args.first())
                    .map(|c| c.op),
                Some(expected)
            );
        }
        assert!(action("SCMP_ACT_ERRNO", Some(&json!(65535))).is_err());
        assert!(action("SCMP_ACT_ALLOW", Some(&json!(1))).is_err());
    }
}
