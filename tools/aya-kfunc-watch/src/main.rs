//! Does this aya relocate a kfunc call? (#315)
//!
//! `flowsdn-aya-kfunc-watch OBJECT [--load]` loads the `loader-kfunc` object
//! (a call to `bpf_sock_destroy` from `iter/tcp`) with the aya it was built
//! against. Relocation needs no privileges, so it runs anywhere; `--load` also
//! loads the program into the kernel (privileged, never attached or run).
//!
//! Exit 0: the kfunc still cannot be relocated: aya has no extern relocation
//!         (`UnknownFunction`), or it has but the object carries no `.ksyms`
//!         entry for it (`ExternNotFound`).
//! Exit 3: aya relocates it (and, with `--load`, the kernel accepted it).
//! Exit 1: anything else: the check itself needs attention.
use std::process::ExitCode;

const MISSING: u8 = 0;
const RELOCATES: u8 = 3;
const BROKEN: u8 = 1;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(object) = args.next() else {
        eprintln!("usage: flowsdn-aya-kfunc-watch OBJECT [--load]");
        return ExitCode::from(BROKEN);
    };
    let load = args.next().as_deref() == Some("--load");
    let bytes = match std::fs::read(&object) {
        Ok(bytes) => bytes,
        Err(e) => return outcome(BROKEN, &format!("read {object}: {e}")),
    };
    let mut ebpf = match aya::EbpfLoader::new().load(&bytes) {
        Ok(ebpf) => ebpf,
        // aya 0.14: RelocationError { function: "sock_destroy_probe",
        // error: UnknownFunction { .. } } -- the call is resolved only against
        // functions in the object, never kernel BTF.
        Err(e) if format!("{e:?}").contains("UnknownFunction") => {
            return outcome(MISSING, &format!("aya has no extern relocation: {e:?}"));
        }
        // aya main since aya-rs/aya#1372 (2026-07-09) resolves externs listed
        // in the object's `.ksyms` BTF datasec, as C's `__ksym` emits them.
        // bpf-linker (0.11.1) drops a Rust `extern "C"` function from BTF, so
        // the object lists none: the gap is now on the object side.
        Err(e) if format!("{e:?}").contains("ExternNotFound") => {
            return outcome(
                MISSING,
                &format!("aya resolves .ksyms externs, but the object has no .ksyms entry: {e:?}"),
            );
        }
        Err(e) => return outcome(BROKEN, &format!("load failed otherwise: {e:?}")),
    };
    if !load {
        return outcome(RELOCATES, "relocated bpf_sock_destroy (kernel load not run)");
    }
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let iter: &mut aya::programs::Iter = ebpf
            .program_mut("sock_destroy_probe")
            .ok_or("no sock_destroy_probe program")?
            .try_into()?;
        iter.load("tcp", &aya::Btf::from_sys_fs()?)?;
        Ok(())
    })();
    match result {
        Ok(()) => outcome(RELOCATES, "relocated bpf_sock_destroy and the kernel loaded it"),
        Err(e) => outcome(BROKEN, &format!("relocated, but the kernel load failed: {e:?}")),
    }
}

fn outcome(code: u8, detail: &str) -> ExitCode {
    let word = match code {
        MISSING => "missing",
        RELOCATES => "relocates",
        _ => "broken",
    };
    println!("{word}: {detail}");
    ExitCode::from(code)
}
