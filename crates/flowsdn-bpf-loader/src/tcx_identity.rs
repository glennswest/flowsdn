//! Exact TCX identity query absent from Aya 0.14's public LinkInfo accessors.
//! Uses Aya's generated Linux UAPI; no hand-maintained struct offsets.
#![allow(unsafe_code)]
use super::KernelResult;
use aya_obj::generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_link_info, bpf_link_type};
use std::{
    ffi::CString,
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};
pub struct Identity {
    pub id: u32,
    ifindex: u32,
    attach_type: u32,
}
impl Identity {
    pub fn matches(&self, interface: &str, allow_detached: bool) -> KernelResult<bool> {
        let name = CString::new(interface)?;
        // SAFETY: name remains a valid NUL-terminated string for the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Ok(self.attach_type == bpf_attach_type::BPF_TCX_INGRESS as u32
            && ((index != 0 && index == self.ifindex)
                || (allow_detached && index == 0 && self.ifindex == 0)))
    }
}
pub fn read(path: &Path) -> KernelResult<Identity> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: generated UAPI objects are integer-only C records/unions. Zero
    // initialization clears reserved fields. All pointers below remain live for
    // their synchronous syscalls; the successful new FD has a single owner.
    unsafe {
        let mut attr: bpf_attr = zeroed();
        attr.__bindgen_anon_4.pathname = path.as_ptr() as u64;
        let fd = libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET as u32,
            &attr,
            size_of::<bpf_attr>(),
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = OwnedFd::from_raw_fd(i32::try_from(fd)?);
        let mut info: bpf_link_info = zeroed();
        let mut attr: bpf_attr = zeroed();
        attr.info.bpf_fd = u32::try_from(fd.as_raw_fd())?;
        attr.info.info_len = u32::try_from(size_of::<bpf_link_info>())?;
        attr.info.info = (&raw mut info) as u64;
        if libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32,
            &mut attr,
            size_of::<bpf_attr>(),
        ) < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if info.type_ != bpf_link_type::BPF_LINK_TYPE_TCX as u32 {
            return Err("pinned link is not TCX".into());
        }
        let tcx = info.__bindgen_anon_1.tcx;
        Ok(Identity {
            id: info.id,
            ifindex: tcx.ifindex,
            attach_type: tcx.attach_type,
        })
    }
}
