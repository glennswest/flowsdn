//! Isolated kernel tests of pinned Aya global replacement and XDP fragments.
use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::{SchedClassifier, TestRun, TestRunOptions, Xdp},
};
use std::{error::Error, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn globals(path: &Path, value: Option<u32>) -> Result<()> {
    let mut loader = EbpfLoader::new();
    if let Some(value) = &value {
        // Deliberately exercise the exact historical API named in issue #3;
        // Aya0.14 aliases it to override_global without changing semantics.
        #[allow(deprecated)]
        loader.set_global("__config_probe", value, true);
    }
    let mut bpf = loader.load_file(path)?;
    let state: Array<MapData, u32> =
        Array::try_from(bpf.take_map("FEATURE_STATE").ok_or("feature map")?)?;
    let program: &mut SchedClassifier = bpf
        .program_mut("global_probe")
        .ok_or("global program")?
        .try_into()?;
    program.load()?;
    let frame = [0_u8; 64];
    let result = program.test_run(TestRunOptions {
        data_in: Some(&frame),
        ..Default::default()
    })?;
    ensure(result.return_value == 0, "global probe did not pass")?;
    ensure(
        state.get(&0, 0)? == value.unwrap_or(17),
        ".rodata.config replacement not observed",
    )?;
    println!("PASS .rodata.config value={}", value.unwrap_or(17));
    Ok(())
}
fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: loader-features PATH_TO_FEATURE_OBJECT [PATH_TO_KFUNC_OBJECT]")?;
    if path=="--kfunc-only" {
        let object=std::env::args_os().nth(2).ok_or("--kfunc-only requires an object")?;
        return probe_kfunc(Path::new(&object));
    }
    let path = Path::new(&path);
    globals(path, None)?;
    globals(path, Some(0x12345678))?;
    let wrong = 1_u64;
    ensure(
        EbpfLoader::new()
            .override_global("__config_probe", &wrong, true)
            .load_file(path)
            .is_err(),
        "wrong-size global was accepted",
    )?;
    let missing = 1_u32;
    ensure(
        EbpfLoader::new()
            .override_global("__config_missing", &missing, true)
            .load_file(path)
            .is_err(),
        "missing required global was accepted",
    )?;
    println!("PASS missing/wrong-size required globals rejected");
    let mut bpf = EbpfLoader::new().load_file(path)?;
    let state: Array<MapData, u32> =
        Array::try_from(bpf.take_map("FEATURE_STATE").ok_or("feature map")?)?;
    let mut jumbo = vec![0_u8; 9000];
    jumbo
        .get_mut(12..14)
        .ok_or("Ethernet header")?
        .copy_from_slice(&[8, 0]);
    let ordinary: &mut Xdp = bpf
        .program_mut("ordinary_xdp")
        .ok_or("ordinary XDP")?
        .try_into()?;
    ordinary.load()?;
    match ordinary.test_run(TestRunOptions {data_in:Some(&jumbo),..Default::default()}) {
        Ok(result)=>println!("OBSERVED ordinary XDP accepts 9000-byte test-run, verdict={}",result.return_value),
        Err(error)=>println!("OBSERVED ordinary XDP rejects 9000-byte test-run: {error}"),
    }
    let fragmented: &mut Xdp = bpf
        .program_mut("fragmented_xdp")
        .ok_or("fragmented XDP")?
        .try_into()?;
    fragmented.load()?;
    let result = fragmented.test_run(TestRunOptions {
        data_in: Some(&jumbo),
        ..Default::default()
    })?;
    ensure(result.return_value == 2, "fragmented XDP did not pass")?;
    ensure(
        state.get(&1, 0)? == 9000,
        "XDP total buffer helper did not observe non-linear input",
    )?;
    let total=state.get(&1,0)?;let linear=state.get(&2,0)?;
    println!("OBSERVED fragmented XDP total={total} linear={linear}");
    ensure(total>linear,"test-run did not demonstrate non-linear XDP data")?;
    println!("PASS fragmented XDP non-linear packet execution; inspect BPF_PROG_LOAD trace to independently confirm prog_flags");
    if let Some(kfunc) = std::env::args_os().nth(2) {
        probe_kfunc(Path::new(&kfunc))?;
    } else {
        println!("NOT RUN bpf_sock_destroy: supply separate load-only object as second argument");
    }
    Ok(())
}

fn probe_kfunc(kfunc:&Path)->Result<()> {
        // Load only: never attach or create/read an iterator FD. Preserve all
        // relocation/verifier failures as errors, not feature-success skips.
        let mut object = EbpfLoader::new().load_file(kfunc)?;
        let iter: &mut aya::programs::Iter = object
            .program_mut("sock_destroy_probe")
            .ok_or("kfunc program")?
            .try_into()?;
        iter.load("tcp", &aya::Btf::from_sys_fs()?)?;
        println!(
            "PASS bpf_sock_destroy external relocation and iterator verifier load (not executed)"
        );
    Ok(())
}
