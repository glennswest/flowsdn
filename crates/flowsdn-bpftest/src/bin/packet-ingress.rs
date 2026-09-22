//! Privileged AF_PACKET direction test against the Rust smoke classifier.
//! All links live in an anonymous network namespace destroyed on process exit.
use aya::{Ebpf,maps::{Array,MapData},programs::{SchedClassifier,TcAttachType}};
use nix::sched::{unshare,CloneFlags};
use std::{error::Error,io::ErrorKind,net::UdpSocket,process::Command,time::Duration};
type Result<T>=std::result::Result<T,Box<dyn Error>>;
fn ensure(ok:bool,message:&str)->Result<()> {if ok{Ok(())}else{Err(message.into())}}
fn ip(args:&[&str])->Result<()> {let output=Command::new("ip").args(args).output()?;ensure(output.status.success(),&format!("ip {}: {}",args.join(" "),String::from_utf8_lossy(&output.stderr)))}
// AF_PACKET UAPI wrappers only; all descriptors have RAII ownership.
#[allow(unsafe_code)]
mod raw {
    use super::*;
    use nix::libc;
    use std::{ffi::CString,mem::{size_of,zeroed},os::fd::{AsRawFd,FromRawFd,OwnedFd}};
    pub struct Socket {fd:OwnedFd,address:libc::sockaddr_ll}
    impl Socket {
        pub fn new(interface:&str)->Result<Self> {
            let name=CString::new(interface)?;
            // SAFETY: name is NUL-terminated and live through the synchronous call.
            let index=unsafe{libc::if_nametoindex(name.as_ptr())};ensure(index!=0,"interface missing")?;
            // SAFETY: socket returns a new descriptor; no borrowed pointers.
            let fd=unsafe{libc::socket(libc::AF_PACKET,libc::SOCK_RAW|libc::SOCK_CLOEXEC,i32::from(0x0800_u16.to_be()))};
            if fd<0{return Err(std::io::Error::last_os_error().into());}
            // SAFETY: the successful descriptor is newly allocated and owned once.
            let fd=unsafe{OwnedFd::from_raw_fd(fd)};
            // SAFETY: sockaddr_ll contains only integer fields, zero is valid.
            let mut address:libc::sockaddr_ll=unsafe{zeroed()};
            address.sll_family=u16::try_from(libc::AF_PACKET)?;address.sll_protocol=0x0800_u16.to_be();address.sll_ifindex=i32::try_from(index)?;address.sll_halen=6;
            address.sll_addr.get_mut(..6).ok_or("address size")?.copy_from_slice(&[2,0,0,0,0,1]);
            // SAFETY: address and its full checked size remain valid for bind.
            let result=unsafe{libc::bind(fd.as_raw_fd(),(&raw const address).cast(),u32::try_from(size_of::<libc::sockaddr_ll>())?)};
            if result<0{return Err(std::io::Error::last_os_error().into());}
            Ok(Self {fd,address})
        }
        pub fn send(&self,frame:&[u8])->Result<()> {
            // SAFETY: both immutable buffers remain live through sendto; their
            // lengths match the allocations and descriptor belongs to self.
            let sent=unsafe{libc::sendto(self.fd.as_raw_fd(),frame.as_ptr().cast(),frame.len(),0,(&raw const self.address).cast(),u32::try_from(size_of::<libc::sockaddr_ll>())?)};
            if sent<0{return Err(std::io::Error::last_os_error().into());}ensure(usize::try_from(sent)?==frame.len(),"short raw send")
        }
        pub fn capture(&self,expected:&[u8])->Result<()> {
            let mut poll=libc::pollfd {fd:self.fd.as_raw_fd(),events:libc::POLLIN,revents:0};
            // SAFETY: one initialized pollfd remains exclusively borrowed.
            let ready=unsafe{libc::poll(&raw mut poll,1,1000)};
            if ready<0{return Err(std::io::Error::last_os_error().into());}ensure(ready==1,"packet capture timed out")?;
            let mut frame=vec![0;2048];
            // SAFETY: frame is writable for its stated capacity; MSG_TRUNC
            // reports full datagram length, which is bounds-checked below.
            let size=unsafe{libc::recv(self.fd.as_raw_fd(),frame.as_mut_ptr().cast(),frame.len(),libc::MSG_TRUNC)};
            if size<0{return Err(std::io::Error::last_os_error().into());}
            ensure(frame.get(..usize::try_from(size)?)==Some(expected),"captured frame differs or was truncated")
        }
    }
}
fn packet(size:usize,port:u16,tag:u8)->Result<Vec<u8>> {
    ensure((64..=1500).contains(&size),"packet size out of range")?;
    let mut frame=vec![0;size];
    frame.get_mut(..14).ok_or("Ethernet header")?.copy_from_slice(&[2,0,0,0,0,1,2,0,0,0,0,2,8,0]);
    let [hi,lo]=u16::try_from(size-14)?.to_be_bytes();
    let header=frame.get_mut(14..34).ok_or("IPv4 header")?;
    header.copy_from_slice(&[0x45,0,hi,lo,0,0,0,0,64,17,0,0,192,0,2,2,192,0,2,1]);
    let mut checksum=0_u32;
    for pair in header.chunks_exact(2){let pair=<[u8;2]>::try_from(pair)?;checksum+=u32::from(u16::from_be_bytes(pair));}
    while checksum>0xffff{checksum=(checksum&0xffff)+(checksum>>16);}
    header.get_mut(10..12).ok_or("checksum")?.copy_from_slice(&(!u16::try_from(checksum)?).to_be_bytes());
    frame.get_mut(34..36).ok_or("source port")?.copy_from_slice(&40000_u16.to_be_bytes());
    frame.get_mut(36..38).ok_or("destination port")?.copy_from_slice(&port.to_be_bytes());
    frame.get_mut(38..40).ok_or("UDP length")?.copy_from_slice(&u16::try_from(size-34)?.to_be_bytes());
    frame.get_mut(42..).ok_or("payload")?.fill(tag);Ok(frame)
}
fn absent(receiver:&UdpSocket)->Result<()> {let mut bytes=[0;1600];match receiver.recv(&mut bytes){Err(error) if matches!(error.kind(),ErrorKind::WouldBlock|ErrorKind::TimedOut)=>Ok(()),Err(error)=>Err(error.into()),Ok(_)=>Err("packet unexpectedly reached UDP receiver".into())}}
fn main()->Result<()> {
    let object=std::env::args_os().nth(1).ok_or("usage: packet-ingress PATH_TO_SMOKE_OBJECT")?;
    let before=std::fs::read_link("/proc/self/ns/net")?;unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(std::fs::read_link("/proc/self/ns/net")?!=before,"namespace isolation failed")?;
    ip(&["link","add","target0","type","veth","peer","name","inject0"])?;
    for (name,mac) in [("target0","02:00:00:00:00:01"),("inject0","02:00:00:00:00:02")] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"),"1")?;
        ip(&["link","set",name,"address",mac,"up"])?;
    }
    ip(&["addr","add","192.0.2.1/24","dev","target0"])?;
    let receiver=UdpSocket::bind("192.0.2.1:0")?;receiver.set_read_timeout(Some(Duration::from_millis(200)))?;
    let port=receiver.local_addr()?.port();
    let mut bpf=Ebpf::load_file(object)?;let mut state:Array<MapData,u32>=Array::try_from(bpf.take_map("SMOKE_STATE").ok_or("smoke map missing")?)?;
    let program:&mut SchedClassifier=bpf.program_mut("smoke").ok_or("smoke program missing")?.try_into()?;program.load()?;
    ensure(SchedClassifier::query_tcx("target0",TcAttachType::Ingress)?.1.is_empty(),"unexpected initial attachment")?;
    let link=program.attach("target0",TcAttachType::Ingress)?;
    ensure(SchedClassifier::query_tcx("target0",TcAttachType::Ingress)?.1.len()==1,"TCX attachment missing")?;
    for size in [64,128,1500] {
        // Fresh capture sockets prevent previous outgoing copies from being
        // mistaken for the current incoming frame.
        let direct=packet(size,port,1)?;let target=raw::Socket::new("target0")?;let capture=raw::Socket::new("inject0")?;
        state.set(0,0,0)?;state.set(1,0,0)?;target.send(&direct)?;capture.capture(&direct)?;absent(&receiver)?;
        ensure(state.get(&0,0)?==0,"send on target unexpectedly ran its ingress classifier")?;
        println!("PASS size={size}: target send bypasses target TCX ingress, peer captured exact frame");
        for (verdict,tag) in [(0,2),(2,3),(0,4)] {
            let frame=packet(size,port,tag)?;let sender=raw::Socket::new("inject0")?;
            state.set(0,0,0)?;state.set(1,verdict,0)?;sender.send(&frame)?;
            if verdict==0 {let mut payload=[0;1600];let got=receiver.recv(&mut payload)?;ensure(payload.get(..got)==frame.get(42..),"UDP payload changed")?;}else{absent(&receiver)?;}
            ensure(state.get(&0,0)?==u32::try_from(size)?,"peer injection did not reach target classifier with exact frame length")?;
            println!("PASS size={size} verdict={verdict}: peer send executes target TCX ingress");
        }
    }
    program.detach(link)?;ensure(SchedClassifier::query_tcx("target0",TcAttachType::Ingress)?.1.is_empty(),"TCX link did not detach")?;
    println!("PASS: AF_PACKET injection direction, UDP pass/drop/recovery, map observations, capture and detach");Ok(())
}
