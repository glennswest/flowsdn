//! Kernel test-run assertions; never attaches to a host interface.
use aya::{EbpfLoader, maps::{HashMap, MapData}, programs::{SchedClassifier, TestRun, TestRunOptions}};
use flowsdn_bpf_abi::endpoint::{EndpointInfo, EndpointKey};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> { if ok { Ok(()) } else { Err(message.into()) } }
fn put(packet: &mut [u8], offset: usize, data: &[u8]) -> Result<()> {
    let end = offset.checked_add(data.len()).ok_or("overflow")?;
    packet.get_mut(offset..end).ok_or("short packet")?.copy_from_slice(data); Ok(())
}
fn packet(v6: bool, local: bool) -> Result<Vec<u8>> {
    let mut frame = vec![0; 80];
    if v6 {
        put(&mut frame,12,&[0x86,0xdd])?;
        put(&mut frame,14,&[0x60,0,0,0,0,8,17,64])?;
        put(&mut frame,38,&[0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,if local {2} else {99}])?;
        put(&mut frame,54,&[0x12,0x34,0x56,0x78,0,8,0,1])?;
    } else {
        put(&mut frame,12,&[8,0])?;
        put(&mut frame,14,&[0x45,0,0,28,0,0,0,0,64,17,0,0,198,18,0,1,198,18,0,if local {2} else {99}])?;
        put(&mut frame,34,&[0x12,0x34,0x56,0x78,0,8,0,0])?;
        // IPv4 header checksum for this synthetic packet.
        let mut sum = 0_u32;
        for bytes in frame.get(14..34).ok_or("header")?.chunks_exact(2) {
            sum = sum.checked_add(u32::from(u16::from_be_bytes(bytes.try_into()?))).ok_or("checksum overflow")?;
        }
        while sum > 0xffff { sum = (sum & 0xffff).checked_add(sum >> 16).ok_or("checksum fold")?; }
        put(&mut frame,24,&(!u16::try_from(sum)?).to_be_bytes())?;
    }
    Ok(frame)
}
fn run(program: &SchedClassifier, input: &[u8], expected: u32) -> Result<Vec<u8>> {
    let mut output = vec![0; 2048];
    let result = program.test_run(TestRunOptions { data_in: Some(input), data_out: Some(&mut output), repeat: 1, ..Default::default() })?;
    ensure(result.return_value == expected, &format!("verdict {}, expected {expected}",result.return_value))?;
    let length = usize::try_from(result.data_size_out)?;
    ensure(length <= output.len(),"output overrun")?;
    output.truncate(length); Ok(output)
}
fn main() -> Result<()> {
    let path = std::env::args_os().nth(1).ok_or("usage: uplink-ingress LOCAL_DELIVERY_OBJECT")?;
    let mut bpf = EbpfLoader::new().load_file(path)?;
    let mut endpoints: HashMap<MapData,[u8;20],[u8;48]> = HashMap::try_from(bpf.take_map("cilium_lxc").ok_or("endpoint map")?)?;
    let endpoint = EndpointInfo { ifindex: 1, mac: 0x020100000002, node_mac: 0x020000000002, ..Default::default() };
    endpoints.insert(EndpointKey::v4([198,18,0,2],0,0).to_bytes(),endpoint.to_bytes(),0)?;
    endpoints.insert(EndpointKey::v6("2001:db8::2".parse::<std::net::Ipv6Addr>()?.octets(),0,0).to_bytes(),endpoint.to_bytes(),0)?;
    let program: &mut SchedClassifier = bpf.program_mut("uplink_ingress").ok_or("uplink program")?.try_into()?;
    program.load()?;
    for ethertype in [[8,6],[0x88,0xcc],[0x81,0x00]] {
        let mut frame = vec![0;80]; put(&mut frame,12,&ethertype)?;
        ensure(run(program,&frame,0)? == frame,"non-IP pass mutated frame")?;
    }
    for v6 in [false,true] {
        let remote = packet(v6,false)?;
        ensure(run(program,&remote,0)? == remote,"unowned IP pass mutated frame")?;
        let local = packet(v6,true)?;
        let forwarded = run(program,&local,7)?;
        ensure(forwarded.get(if v6 {21} else {22}) == Some(&63),"hop reduction missing")?;
        ensure(forwarded.get(..12) == Some([2,0,0,0,1,2,2,0,0,0,0,2].as_slice()),"endpoint MAC rewrite")?;
        for hop in [0,1] {
            let mut bad = local.clone(); put(&mut bad,if v6 {21} else {22},&[hop])?; run(program,&bad,2)?;
        }
        let mut bad = local.clone(); put(&mut bad,14,&[0x75])?; run(program,&bad,2)?;
        let mut bad = local.clone(); put(&mut bad,if v6 {18} else {16},&[0xff,0xff])?; run(program,&bad,2)?;
        let mut bad = local.clone(); put(&mut bad,if v6 {18} else {16},&[0,0])?; run(program,&bad,2)?;
        let mut truncated = local.clone(); truncated.truncate(if v6 {54} else {34}); run(program,&truncated,2)?;
        if !v6 { let mut bad = local.clone(); put(&mut bad,14,&[0x44])?; run(program,&bad,2)?; }
        let key = if v6 { EndpointKey::v6("2001:db8::2".parse::<std::net::Ipv6Addr>()?.octets(),0,0) } else { EndpointKey::v4([198,18,0,2],0,0) };
        endpoints.insert(key.to_bytes(),EndpointInfo::default().to_bytes(),0)?;
        run(program,&local,2)?;
        endpoints.remove(&key.to_bytes())?;
        ensure(run(program,&local,0)? == local,"deleted endpoint must return to stack")?;
    }
    // Ordinary NDP multicast must remain available to the host stack.
    let mut ndp = packet(true,false)?;
    put(&mut ndp,20,&[58,255])?;
    put(&mut ndp,38,&"ff02::1:ff00:2".parse::<std::net::Ipv6Addr>()?.octets())?;
    put(&mut ndp,54,&[135,0])?;
    ensure(run(program,&ndp,0)? == ndp,"NDP pass mutated frame")?;
    println!("PASS uplink ARP/non-IP/NDP/unowned-IP pass; known IPv4/IPv6 endpoint redirect, malformed/hop/invalid endpoint drop; deletion pass");
    Ok(())
}
