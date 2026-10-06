//! `__sk_buff` `ctx_in`/`ctx_out` field matrix (spec 18 §3.3(d), §9.1, #256).
//!
//! For each field flowsdn's corpus may set, run the `skb-ctx` probe through
//! `BPF_PROG_TEST_RUN` with only that field set in a zero-padded 256-byte
//! `ctx_in`, and record whether the kernel accepted it, whether the program
//! saw it, and what `ctx_out` carried back. `ifindex` is also run against a
//! missing ifindex and a dummy device created in this private netns, which
//! settles whether it must name a real device. Prints one JSON line per field
//! and a final summary line; exits nonzero if a field the corpus relies on
//! (spec 18 §3.3(d)) is unusable on this kernel. Never attaches anything.
use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::SchedClassifier,
};
use nix::sched::{CloneFlags, unshare};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    os::fd::{AsFd, AsRawFd},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Spec 18 §3.3: a buffer larger than `sizeof(struct __sk_buff)` (192),
/// zero-padded, so kernels that grow the struct keep working.
const CTX: usize = 256;
/// Unset map slots read as this, distinguishing "not copied" from zero.
const SENTINEL: u64 = u64::MAX;

/// Written by `ctx_observe` / `ctx_write_extra` (crates/flowsdn-bpf skb-ctx).
const WRITE_MARK: u64 = 0x5a5a_0001;
const WRITE_PRIORITY: u64 = 7;
const WRITE_CB: [u64; 5] = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4];
const WRITE_TC_INDEX: u64 = 0x42;
const WRITE_TSTAMP: u64 = 0x1122_3344;

struct Field {
    name: &'static str,
    offset: usize,
    width: usize,
    slot: u32,
    value: u64,
    /// What a program writes back, and which program writes it.
    written: Option<(u64, bool)>,
    /// Spec 18 §3.3(d): the corpus sets it; unusable means a spec bug.
    relied_upon: bool,
}

fn fields() -> Vec<Field> {
    let f = |name, offset, width, slot, value, written, relied_upon| Field {
        name,
        offset,
        width,
        slot,
        value,
        written,
        relied_upon,
    };
    let mut all = vec![
        f(
            "mark",
            8,
            4,
            0,
            0x1234_5678,
            Some((WRITE_MARK, false)),
            true,
        ),
        f("priority", 32, 4, 1, 5, Some((WRITE_PRIORITY, false)), true),
    ];
    for (i, write) in WRITE_CB.iter().enumerate() {
        let name = ["cb[0]", "cb[1]", "cb[2]", "cb[3]", "cb[4]"]
            .get(i)
            .copied()
            .unwrap_or("cb");
        let index = u32::try_from(i).unwrap_or(0);
        all.push(f(
            name,
            48_usize.saturating_add(i.saturating_mul(4)),
            4,
            2_u32.saturating_add(index),
            0xa0_u64.saturating_add(u64::from(index)),
            Some((*write, false)),
            true,
        ));
    }
    all.extend([
        f("ifindex", 40, 4, 7, 1, None, true),
        f(
            "tstamp",
            152,
            8,
            8,
            1_000_000_123,
            Some((WRITE_TSTAMP, true)),
            true,
        ),
        f("wire_len", 160, 4, 9, 1500, None, true),
        f("gso_segs", 164, 4, 10, 3, None, true),
        f("gso_size", 176, 4, 11, 1400, None, true),
        f("hwtstamp", 184, 8, 12, 2_000_000_456, None, true),
        f(
            "tc_index",
            44,
            4,
            13,
            0x21,
            Some((WRITE_TC_INDEX, true)),
            false,
        ),
        f("ingress_ifindex", 36, 4, 14, 1, None, false),
    ]);
    all
}

fn put(buffer: &mut [u8], offset: usize, width: usize, value: u64) -> Result<()> {
    let bytes = value.to_le_bytes();
    let source = bytes.get(..width).ok_or("field width")?;
    buffer
        .get_mut(offset..offset.saturating_add(width))
        .ok_or("field offset")?
        .copy_from_slice(source);
    Ok(())
}

fn get(buffer: &[u8], offset: usize, width: usize) -> Result<u64> {
    let mut bytes = [0u8; 8];
    bytes
        .get_mut(..width)
        .ok_or("field width")?
        .copy_from_slice(
            buffer
                .get(offset..offset.saturating_add(width))
                .ok_or("field offset")?,
        );
    Ok(u64::from_le_bytes(bytes))
}

/// 64-byte Ethernet/IPv4/UDP frame: the skb the context is applied to.
fn frame() -> [u8; 64] {
    let mut f = [0u8; 64];
    let header: [u8; 34] = [
        0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00, // Ethernet
        0x45, 0, 0, 50, 0, 0, 0x40, 0, 64, 17, 0, 0, // IPv4 header
        198, 18, 0, 1, 198, 18, 0, 2, // addresses
    ];
    for (slot, byte) in f.iter_mut().zip(header) {
        *slot = byte;
    }
    f
}

#[allow(unsafe_code)]
mod syscall {
    use std::{io, os::fd::RawFd};
    #[repr(C)]
    #[derive(Default)]
    struct Attr {
        prog_fd: u32,
        retval: u32,
        data_size_in: u32,
        data_size_out: u32,
        data_in: u64,
        data_out: u64,
        repeat: u32,
        duration: u32,
        ctx_size_in: u32,
        ctx_size_out: u32,
        ctx_in: u64,
        ctx_out: u64,
        flags: u32,
        cpu: u32,
        batch_size: u32,
        padding: u32,
    }
    const _: () = assert!(std::mem::size_of::<Attr>() == 80);
    /// `BPF_PROG_TEST_RUN` with packet data and a context; returns the verdict.
    pub fn run(
        fd: RawFd,
        data: &[u8],
        data_out: &mut [u8],
        ctx: &[u8],
        ctx_out: &mut [u8],
    ) -> io::Result<u32> {
        let size = |n: usize| u32::try_from(n).map_err(|_| io::Error::other("buffer too large"));
        let mut attr = Attr {
            prog_fd: u32::try_from(fd).map_err(|_| io::Error::other("negative BPF fd"))?,
            data_size_in: size(data.len())?,
            data_size_out: size(data_out.len())?,
            data_in: data.as_ptr() as u64,
            data_out: data_out.as_mut_ptr() as u64,
            ctx_size_in: size(ctx.len())?,
            ctx_size_out: size(ctx_out.len())?,
            ctx_in: ctx.as_ptr() as u64,
            ctx_out: ctx_out.as_mut_ptr() as u64,
            repeat: 1,
            ..Default::default()
        };
        // SAFETY: repr(C) is the Linux bpf_attr.test layout (80 bytes); all four
        // buffers stay valid for this synchronous syscall and the kernel writes
        // only within their declared sizes. BPF_PROG_TEST_RUN is command 10.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_bpf,
                10u32,
                &raw mut attr,
                std::mem::size_of::<Attr>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(attr.retval)
        }
    }
}

struct Probe {
    observe: i32,
    extra: Option<i32>,
    observed: Array<MapData, u64>,
}

impl Probe {
    fn clear(&mut self) -> Result<()> {
        for slot in 0..16 {
            self.observed.set(slot, SENTINEL, 0)?;
        }
        Ok(())
    }
    /// Run `fd` with `ctx`; `Err` carries the errno when the kernel refuses.
    fn run(&self, fd: i32, ctx: &[u8; CTX]) -> std::result::Result<[u8; CTX], i32> {
        let data = frame();
        let mut data_out = [0u8; 256];
        let mut ctx_out = [0u8; CTX];
        syscall::run(fd, &data, &mut data_out, ctx, &mut ctx_out)
            .map(|_| ctx_out)
            .map_err(|e| e.raw_os_error().unwrap_or(-1))
    }
}

fn errno_name(errno: i32) -> String {
    match errno {
        nix::libc::EINVAL => "EINVAL".into(),
        nix::libc::ENODEV => "ENODEV".into(),
        nix::libc::EPERM => "EPERM".into(),
        524 => "ENOTSUPP".into(),
        other => format!("errno {other}"),
    }
}

fn measure(probe: &mut Probe, field: &Field) -> Result<Value> {
    probe.clear()?;
    let mut ctx = [0u8; CTX];
    put(&mut ctx, field.offset, field.width, field.value)?;
    let out = match probe.run(probe.observe, &ctx) {
        Err(errno) => {
            return Ok(json!({
                "field": field.name, "settable": false, "error": errno_name(errno),
                "relied_upon": field.relied_upon,
            }));
        }
        Ok(out) => out,
    };
    let seen = probe.observed.get(&field.slot, 0)?;
    let back = get(&out, field.offset, field.width)?;
    let mut row = json!({
        "field": field.name, "settable": true, "set": field.value,
        "program_saw": seen, "copied_in": seen == field.value,
        "ctx_out": back, "relied_upon": field.relied_upon,
    });
    if let Some((written, extra)) = field.written {
        let out = if extra {
            match probe.extra {
                None => None,
                Some(fd) => probe.run(fd, &ctx).ok(),
            }
        } else {
            Some(out)
        };
        let returned = out
            .map(|o| get(&o, field.offset, field.width))
            .transpose()?;
        if let Some(object) = row.as_object_mut() {
            object.insert("program_wrote".into(), json!(written));
            object.insert(
                "copied_out".into(),
                returned.map_or(Value::Null, |r| json!(r == written)),
            );
        }
    }
    Ok(row)
}

/// The `ifindex` question: advisory, or must it name a device in this netns?
fn ifindex_device(probe: &mut Probe) -> Result<Value> {
    let mut try_index = |index: u64| -> Result<Value> {
        probe.clear()?;
        let mut ctx = [0u8; CTX];
        put(&mut ctx, 40, 4, index)?;
        Ok(match probe.run(probe.observe, &ctx) {
            Ok(_) => json!({"accepted": true, "program_saw": probe.observed.get(&7, 0)?}),
            Err(errno) => json!({"accepted": false, "error": errno_name(errno)}),
        })
    };
    let missing = try_index(0x7fff_fff0)?;
    let status = Command::new("ip")
        .args(["link", "add", "flowsdnctx0", "type", "dummy"])
        .status()?;
    let dummy = if status.success() {
        let index: u64 = fs::read_to_string("/sys/class/net/flowsdnctx0/ifindex")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .or_else(|| {
                // sysfs shows the original netns; ask ip instead.
                let out = Command::new("ip")
                    .args(["-o", "link", "show", "flowsdnctx0"])
                    .output()
                    .ok()?;
                String::from_utf8_lossy(&out.stdout)
                    .split(':')
                    .next()?
                    .trim()
                    .parse()
                    .ok()
            })
            .ok_or("dummy ifindex")?;
        let mut row = try_index(index)?;
        if let Some(object) = row.as_object_mut() {
            object.insert("ifindex".into(), json!(index));
        }
        row
    } else {
        json!({"accepted": false, "error": "could not create a dummy device"})
    };
    let requires_device = missing.get("accepted") == Some(&json!(false))
        && dummy.get("accepted") == Some(&json!(true));
    Ok(json!({
        "field": "ifindex-device", "missing_ifindex": missing, "dummy_device": dummy,
        "requires_real_device": requires_device,
    }))
}

fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: skb-ctx-matrix PATH_TO_SKB_CTX_OBJECT")?;
    // ifindex 1 is this namespace's loopback; nothing outside it is touched.
    unshare(CloneFlags::CLONE_NEWNET)?;
    let mut bpf = EbpfLoader::new().load_file(&path)?;
    let observed: Array<MapData, u64> =
        Array::try_from(bpf.take_map("OBSERVED").ok_or("OBSERVED map")?)?;
    let observe: &mut SchedClassifier = bpf
        .program_mut("ctx_observe")
        .ok_or("ctx_observe")?
        .try_into()?;
    observe.load()?;
    let observe_fd = observe.fd()?.as_fd().as_raw_fd();
    let extra: &mut SchedClassifier = bpf
        .program_mut("ctx_write_extra")
        .ok_or("ctx_write_extra")?
        .try_into()?;
    let extra_fd = match extra.load() {
        Ok(()) => Some(extra.fd()?.as_fd().as_raw_fd()),
        Err(error) => {
            println!(
                "{}",
                json!({"field": "tc_index/tstamp writes", "verifier": error.to_string()})
            );
            None
        }
    };
    let mut probe = Probe {
        observe: observe_fd,
        extra: extra_fd,
        observed,
    };
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    probe.clear()?;
    let baseline = probe.run(observe_fd, &[0u8; CTX]).map_err(errno_name);
    println!(
        "{}",
        json!({"field": "baseline", "zero_ctx_256_bytes": baseline.is_ok(),
               "error": baseline.as_ref().err()})
    );
    let mut summary = serde_json::Map::new();
    let mut unusable = Vec::new();
    for field in fields() {
        let row = measure(&mut probe, &field)?;
        println!("{row}");
        let usable = row.get("copied_in") == Some(&json!(true));
        let label = match (
            row.get("settable") == Some(&json!(true)),
            usable,
            row.get("copied_out"),
        ) {
            (false, _, _) => format!(
                "rejected:{}",
                row.get("error").and_then(Value::as_str).unwrap_or("?")
            ),
            (true, false, _) => "accepted-not-copied".to_owned(),
            (true, true, Some(Value::Bool(true))) => "in+out".to_owned(),
            (true, true, Some(Value::Bool(false))) => "in,not-out".to_owned(),
            (true, true, _) => "in".to_owned(),
        };
        if field.relied_upon && !usable {
            unusable.push(field.name);
        }
        summary.insert(field.name.into(), json!(label));
    }
    let device = ifindex_device(&mut probe)?;
    println!("{device}");
    summary.insert(
        "ifindex-requires-device".into(),
        device
            .get("requires_real_device")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let ok = baseline.is_ok() && unusable.is_empty();
    println!(
        "{}",
        json!({"kernel": kernel, "relied_upon_usable": ok, "unusable": unusable, "matrix": summary})
    );
    if ok {
        Ok(())
    } else {
        // One short line last: the runner reports only a log's last line.
        let baseline = match &baseline {
            Ok(_) => "ok".to_owned(),
            Err(error) => error.clone(),
        };
        Err(format!(
            "on {kernel}: zero-ctx baseline {baseline}; relied-upon fields unusable: {}",
            unusable.join(",")
        )
        .into())
    }
}
