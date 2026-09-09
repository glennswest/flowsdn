//! Fixture adapter joining the real CNI transaction, host IPAM and BPF loader.
//! Only the fixture's platform operations use `ip`; this is not the CNI binary.
use super::{Endpoint as Process, Result, ip, key, mac};
use flowsdn_cni::{AddBackend, AddRequest, CniError, Endpoint, Lease, Link};
use flowsdn_ipam::Ipam;
use flowsdn_bpf_loader::kernel::LocalDelivery;
use flowsdn_bpf_abi::endpoint::EndpointInfo;
use std::process::Command;

fn adapt<T>(result: Result<T>) -> flowsdn_cni::Result<T> { result.map_err(|e|CniError::internal(e.to_string())) }
pub fn gateway(v6: bool) -> &'static str { if v6 {"2001:db8:1::ffff"} else {"198.18.0.254"} }

pub struct Backend<'a> {
    pub process: &'a mut Process,
    pub driver: &'a mut LocalDelivery,
    pub ipam: &'a mut Ipam,
    pub fail_finalize: bool,
    pub info: Option<EndpointInfo>,
}
impl Backend<'_> {
    pub fn request(&self) -> AddRequest {
        AddRequest {version:"1.1.0".into(),container_id:format!("fixture-{}",self.process.id),ifname:"eth0".into(),netns:format!("/proc/{}/ns/net",self.process.child.id()),cni_path:"/opt/cni/bin".into(),pod_name:format!("pod-{}",self.process.id),pod_namespace:"fixture".into(),pod_uid:format!("uid-{}",self.process.id)}
    }
}
impl AddBackend for Backend<'_> {
    fn allocate(&mut self,r:&AddRequest)->flowsdn_cni::Result<Vec<Lease>> {
        // This fixture reserves deterministic addresses to compare packet bytes.
        // The independently tested allocate_next path supplies arbitrary free IPs.
        let v6=adapt(key(self.process.id,true))?; let v4=adapt(key(self.process.id,false))?;
        self.ipam.allocate(v6,&r.owner()).map_err(|e|CniError::internal(e.to_string()))?;
        if let Err(e)=self.ipam.allocate(v4,&r.owner()) { let _=self.ipam.release(v6); return Err(CniError::internal(e.to_string())); }
        [v6,v4].into_iter().map(|address|Ok(Lease {address,gateway:gateway(address.is_ipv6()).parse().map_err(|e|CniError::internal(format!("fixture gateway: {e}")))?,pool:"default".into(),expiration_uuid:String::new()})).collect()
    }
    fn create_link(&mut self,_:&AddRequest)->flowsdn_cni::Result<Link> {
        let id=self.process.id; let host=format!("p{id}"); let peer=format!("e{id}");
        adapt(ip(&["link","add",&host,"type","veth","peer","name",&peer]))?;
        let setup=(||->Result<Link> {
            ip(&["link","set",&host,"address",&mac(id,true),"mtu","1500","up"])?;
            ip(&["link","set",&peer,"netns",&self.process.child.id().to_string()])?;
            let output=Command::new("ip").args(["-o","link","show","dev",&host]).output()?;
            super::ensure(output.status.success(),"link inspection failed")?;
            let index=std::str::from_utf8(&output.stdout)?.split(':').next().ok_or("missing ifindex")?.parse()?;
            self.info=Some(EndpointInfo {ifindex:index,lxc_id:u16::from(id),mac:u64::from_le_bytes([2,0,0,0,1,id,0,0]),node_mac:u64::from_le_bytes([2,0,0,0,0,id,0,0]),..Default::default()});
            Ok(Link {host_name:host.clone(),host_index:index,host_mac:mac(id,true),peer_mac:mac(id,false)})
        })();
        if setup.is_err() {let _=ip(&["link","del",&host]);}
        adapt(setup)
    }
    fn configure(&mut self,_:&AddRequest,_:&Link,_:&[Lease])->flowsdn_cni::Result<()> { adapt(self.process.configure()) }
    fn create_endpoint(&mut self,_:&AddRequest,link:&Link,leases:&[Lease])->flowsdn_cni::Result<Endpoint> {
        let info=self.info.ok_or_else(||CniError::internal("missing endpoint information"))?;
        let mut installed=Vec::new();
        let install=(||->Result<()> { for lease in leases {self.driver.upsert(lease.address,info)?;installed.push(lease.address);} self.driver.attach(&link.host_name)?; Ok(())})();
        if install.is_err() {for ip in installed {let _=self.driver.remove(ip);}}
        adapt(install)?; Ok(Endpoint {mac_override:None})
    }
    fn finalize(&mut self,_:&AddRequest,_:&mut Link,_:&Endpoint)->flowsdn_cni::Result<()> {
        if self.fail_finalize {Err(CniError::internal("injected post-create failure"))} else {Ok(())}
    }
    fn delete_endpoint(&mut self,_:&AddRequest)->flowsdn_cni::Result<()> {
        let mut error=None;
        for v6 in [true,false] {
            let result=key(self.process.id,v6).and_then(|ip|self.driver.remove(ip));
            if let Err(e)=result {error.get_or_insert_with(||CniError::internal(e.to_string()));}
        }
        if let Err(e)=self.driver.detach(&format!("p{}",self.process.id)) {error.get_or_insert_with(||CniError::internal(e.to_string()));}
        match error {Some(error)=>Err(error),None=>Ok(())}
    }
    fn delete_link(&mut self,link:&Link)->flowsdn_cni::Result<()> {adapt(ip(&["link","del",&link.host_name]))}
    fn release(&mut self,lease:&Lease)->flowsdn_cni::Result<()> {self.ipam.release(lease.address).map_err(|e|CniError::internal(e.to_string()))}
}
