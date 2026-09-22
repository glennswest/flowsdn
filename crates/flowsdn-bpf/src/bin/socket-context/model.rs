//! Pure address rewrite fixture, shared by direct tests and BPF wrappers.
//! Documentation addresses enter; loopback addresses leave. No socket is opened.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Address {pub family:u32,pub ipv4:u32,pub ipv6:[u32;4],pub port:u32}
pub fn rewrite4(address:&mut Address)->u32 {
    if address.family!=2 {return 0;}
    if address.ipv4==u32::from_ne_bytes([192,0,2,80]) && address.port==u32::from(80u16.to_be()) {
        address.ipv4=u32::from_ne_bytes([127,0,0,1]);address.port=u32::from(18080u16.to_be());
    } 1
}
pub fn rewrite6(address:&mut Address)->u32 {
    if address.family!=10 {return 0;}
    if address.ipv6==[u32::from_ne_bytes([0x20,1,0x0d,0xb8]),0,0,u32::from_ne_bytes([0,0,0,0x80])] && address.port==u32::from(80u16.to_be()) {
        address.ipv6=[0,0,0,u32::from_ne_bytes([0,0,0,1])];address.port=u32::from(18080u16.to_be());
    } 1
}
