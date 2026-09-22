//! Primary endpoint creation, deletion and restoration with real map ownership.
//! Identity/policy reconciliation and API request authorization remain caller work.
use crate::state::{DEFAULT_ENDPOINT_ID_MAX, IdPool, Record, Result, Store};
use flowsdn_bpf_abi::endpoint::EndpointInfo;
use flowsdn_bpf_loader::kernel::LocalDelivery;
use flowsdn_connector::Connector;
use flowsdn_ipam::Ipam;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn kernel<T>(result: flowsdn_bpf_loader::kernel::KernelResult<T>) -> Result<T> {
    result.map_err(|e| e.to_string().into())
}
fn mac(value: &str) -> Result<u64> {
    let bytes = value
        .split(':')
        .map(|v| u8::from_str_radix(v, 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let [a, b, c, d, e, f]: [u8; 6] = bytes.try_into().map_err(|_| "invalid endpoint MAC")?;
    Ok(u64::from_le_bytes([a, b, c, d, e, f, 0, 0]))
}
fn addresses(document: &Value) -> Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for key in ["IPv6", "IPv4"] {
        let raw = text(document, key);
        if !raw.is_empty() {
            let ip: IpAddr = raw.parse()?;
            if ip.is_ipv4() != (key == "IPv4") {
                return Err("endpoint address family mismatch".into());
            }
            addresses.push(ip);
        }
    }
    if addresses.is_empty() {
        return Err("endpoint has no address".into());
    }
    Ok(addresses)
}
fn info(record: &Record) -> Result<EndpointInfo> {
    Ok(EndpointInfo {
        ifindex: record
            .document
            .get("IfIndex")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("invalid host ifindex")?,
        lxc_id: record.id,
        mac: mac(text(&record.document, "LXCMAC"))?,
        node_mac: mac(text(&record.document, "NodeMAC"))?,
        ..EndpointInfo::default()
    })
}

// One host interface has exactly one endpoint attachment owner. Validate before
// any map/link mutation: rollback of a failed second attach must never detach
// the first owner's live program.
fn validate_interface_owners<'a>(records: impl IntoIterator<Item = &'a Record>) -> Result<()> {
    let mut names = BTreeSet::new();
    let mut indices = BTreeSet::new();
    for record in records {
        let name = text(&record.document, "IfName");
        let index = record
            .document
            .get("IfIndex")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or("invalid host ifindex")?;
        if name.is_empty() || !names.insert(name) || !indices.insert(index) {
            return Err("endpoint host interface already owned or invalid".into());
        }
    }
    Ok(())
}

pub struct Manager {
    store: Store,
    ids: IdPool,
    records: BTreeMap<String, Record>,
    addresses: BTreeMap<IpAddr, String>,
    deleting: BTreeSet<String>,
    driver: LocalDelivery,
    ipam: Ipam,
}
impl Manager {
    /// Restore into a fresh object before the caller exposes its API. Stale or
    /// incompatible links fail startup; this layer cannot decide Kubernetes GC.
    pub fn restore(path: &Path, object: &Path, ipam: Ipam) -> Result<Self> {
        Self::restore_with_id_max(path, object, ipam, u32::from(DEFAULT_ENDPOINT_ID_MAX))
    }
    /// Restore all persisted nonzero u16 IDs, limiting only new allocations.
    /// Invalid limits fail before acquiring state ownership or loading BPF.
    pub fn restore_with_id_max(
        path: &Path,
        object: &Path,
        ipam: Ipam,
        id_max: u32,
    ) -> Result<Self> {
        Self::restore_with_pins(path, object, ipam, id_max, None)
    }
    pub fn restore_with_pins(
        path: &Path,
        object: &Path,
        ipam: Ipam,
        id_max: u32,
        pin_root: Option<&Path>,
    ) -> Result<Self> {
        let ids = IdPool::new(id_max)?;
        let store = Store::open(path)?;
        let records = store.restore()?;
        validate_interface_owners(&records)?;
        let mut unique_addresses = BTreeSet::new();
        for record in &records {
            for ip in addresses(&record.document)? {
                if !unique_addresses.insert(ip) {
                    return Err("duplicate persisted endpoint address".into());
                }
            }
        }
        let mut manager = Self {
            store,
            ids,
            records: BTreeMap::new(),
            addresses: BTreeMap::new(),
            deleting: BTreeSet::new(),
            driver: kernel(match pin_root {
                Some(root) => LocalDelivery::load_pinned(object, root),
                None => LocalDelivery::load(object),
            })?,
            ipam,
        };
        let connector = Connector::open()?;
        // Validate every persisted identity/address before installing any link.
        let mut viable = Vec::new();
        let mut stale = Vec::new();
        for record in records {
            let Some(link) = connector.link(text(&record.document, "IfName"))? else {
                // Defer every mutation until all other live identities validate.
                info(&record)?;
                stale.push(record);
                continue;
            };
            manager.ids.reserve(record.id)?;
            let endpoint = info(&record)?;
            if link.index != endpoint.ifindex || mac_value(&link.mac)? != endpoint.node_mac {
                return Err("restored endpoint host link no longer matches persisted state".into());
            }
            let owner = format!(
                "{}/{}",
                text(&record.document, "K8sNamespace"),
                text(&record.document, "K8sPodName")
            );
            for ip in addresses(&record.document)? {
                if manager
                    .addresses
                    .insert(ip, record.attachment.clone())
                    .is_some()
                {
                    return Err("duplicate restored endpoint address".into());
                }
                manager.ipam.allocate(ip, &owner)?;
            }
            viable.push(record);
        }
        for record in &stale {
            for ip in addresses(&record.document)? {
                // A stale durable record cannot authorize removal of another
                // endpoint's map value after interrupted publication/reuse.
                if let Some(old) = kernel(manager.driver.snapshot(ip))? {
                    use flowsdn_bpf_abi::MapBytes;
                    if old != info(record)?.to_bytes() {
                        return Err(
                            "stale endpoint map ownership differs; preserve forwarding".into()
                        );
                    }
                }
            }
        }
        for record in stale {
            kernel(manager.driver.detach(text(&record.document, "IfName")))?;
            for ip in addresses(&record.document)? {
                kernel(manager.driver.remove_if_present(ip))?;
            }
            manager.store.remove(record.id)?;
        }
        for record in viable {
            manager.install(&record)?;
            manager.records.insert(record.attachment.clone(), record);
        }
        Ok(manager)
    }
    /// IPAM allocations precede endpoint publication; adapters own expiration
    /// timers for unclaimed allocations. A failed create never releases IPs.
    pub fn ipam_mut(&mut self) -> &mut Ipam {
        &mut self.ipam
    }
    pub fn get(&self, attachment: &str) -> Option<&Record> {
        self.records.get(attachment)
    }
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }
    /// Initial health checks live host-link identity and incomplete teardown.
    /// It does not claim policy convergence or detect external BPF replacement.
    pub fn healthy(&self, attachment: &str) -> Result<bool> {
        let Some(record) = self.records.get(attachment) else {
            return Ok(false);
        };
        if self.deleting.contains(attachment) {
            return Ok(false);
        }
        let Some(link) = Connector::open()?.link(text(&record.document, "IfName"))? else {
            return Ok(false);
        };
        let endpoint = info(record)?;
        Ok(link.index == endpoint.ifindex && mac_value(&link.mac)? == endpoint.node_mac)
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn create(&mut self, mut document: Value) -> Result<u16> {
        let id = self.ids.allocate()?;
        let result = (|| {
            document
                .as_object_mut()
                .ok_or("endpoint document must be an object")?
                .insert("ID".into(), json!(id));
            let record = Record::parse(document)?;
            if self.records.contains_key(&record.attachment) {
                return Err("endpoint attachment already exists".into());
            }
            validate_interface_owners(self.records.values().chain(std::iter::once(&record)))?;
            let ips = addresses(&record.document)?;
            let owner = format!(
                "{}/{}",
                text(&record.document, "K8sNamespace"),
                text(&record.document, "K8sPodName")
            );
            for ip in &ips {
                let scope = if ip.is_ipv4() {
                    self.ipam.ipv4()
                } else {
                    self.ipam.ipv6()
                }
                .ok_or("endpoint family is disabled")?;
                if self.addresses.contains_key(ip) || scope.dump().get(ip) != Some(&owner) {
                    return Err(
                        "endpoint address is not exclusively allocated to this owner".into(),
                    );
                }
            }
            let endpoint = info(&record)?;
            let link = Connector::open()?.require_link(text(&record.document, "IfName"))?;
            if link.index != endpoint.ifindex || mac_value(&link.mac)? != endpoint.node_mac {
                return Err("endpoint host link identity mismatch".into());
            }
            for ip in &ips {
                if kernel(self.driver.snapshot(*ip))?.is_some() {
                    return Err(
                        "endpoint map address already owned; reconcile before create".into(),
                    );
                }
            }
            // Publish recoverable intent before any persistent forwarding.
            // Register ownership before publish: a directory rename may succeed
            // even when the following durability barrier reports failure.
            let staged = self.store.stage(&record)?;
            for ip in &ips {
                self.addresses.insert(*ip, record.attachment.clone());
            }
            self.records
                .insert(record.attachment.clone(), record.clone());
            self.deleting.insert(record.attachment.clone());
            staged.publish()?;
            if let Err(error) = install(&mut self.driver, &record) {
                // Retain ID, addresses and durable intent on any uncertain
                // rollback. DEL/restart can then complete recovery safely.
                if uninstall(&mut self.driver, &record).is_ok()
                    && self.store.remove(record.id).is_ok()
                {
                    for ip in ips {
                        self.addresses.remove(&ip);
                    }
                    self.records.remove(&record.attachment);
                    self.deleting.remove(&record.attachment);
                }
                return Err(error);
            }
            self.deleting.remove(&record.attachment);
            Ok(id)
        })();
        if result.is_err() && !self.records.values().any(|record| record.id == id) {
            self.ids.release(id);
        }
        result
    }
    pub fn delete(&mut self, attachment: &str) -> Result<bool> {
        let Some(record) = self.records.get(attachment).cloned() else {
            return Ok(false);
        };
        // Keep indexes and ID reserved on any error so deletion can be retried.
        self.deleting.insert(attachment.to_owned());
        uninstall(&mut self.driver, &record)?;
        Connector::open()?.delete(text(&record.document, "IfName"))?;
        self.store.remove(record.id)?;
        for ip in addresses(&record.document)? {
            self.ipam.release(ip)?;
            self.addresses.remove(&ip);
        }
        self.records.remove(attachment);
        self.deleting.remove(attachment);
        self.ids.release(record.id);
        Ok(true)
    }
    fn install(&mut self, record: &Record) -> Result<()> {
        install(&mut self.driver, record)
    }
}
fn mac_value(bytes: &[u8]) -> Result<u64> {
    let [a, b, c, d, e, f]: [u8; 6] = bytes.try_into().map_err(|_| "invalid Ethernet link MAC")?;
    Ok(u64::from_le_bytes([a, b, c, d, e, f, 0, 0]))
}
fn install(driver: &mut LocalDelivery, record: &Record) -> Result<()> {
    let endpoint = info(record)?;
    let mut installed = Vec::new();
    let outcome = (|| {
        for ip in addresses(&record.document)? {
            let old = kernel(driver.snapshot(ip))?;
            kernel(driver.upsert(ip, endpoint))?;
            installed.push((ip, old));
        }
        kernel(driver.attach(text(&record.document, "IfName")))
    })();
    if outcome.is_err() {
        for (ip, old) in installed {
            kernel(driver.restore_snapshot(ip, old))?;
        }
    }
    outcome
}
fn uninstall(driver: &mut LocalDelivery, record: &Record) -> Result<()> {
    kernel(driver.detach(text(&record.document, "IfName")))?;
    // Map deletes need to remain idempotent if a prior teardown was interrupted.
    for ip in addresses(&record.document)? {
        kernel(driver.remove_if_present(ip))?;
    }
    Ok(())
}

#[cfg(test)]
mod interface_ownership_tests {
    use super::*;
    fn record(id: u16, name: &str, index: u32) -> Record {
        Record::parse(json!({"ID":id,"dockerID":format!("container-{id}"),
            "ContainerIfName":"eth0","IfName":name,"IfIndex":index,
            "IPv4":format!("198.18.0.{id}")}))
        .expect("record")
    }
    #[test]
    fn distinct_attachment_and_address_cannot_reuse_host_interface() {
        let live = record(1, "host-one", 10);
        let alias = record(2, "host-one", 10);
        assert_ne!(live.attachment, alias.attachment);
        assert_ne!(
            addresses(&live.document).expect("IP"),
            addresses(&alias.document).expect("IP")
        );
        // This exact preflight runs on create before stage/install, and on
        // restore before loading the BPF object or cleaning stale state.
        assert!(validate_interface_owners([&live, &alias]).is_err());
        assert!(validate_interface_owners([&live, &record(2, "host-one", 11)]).is_err());
        assert!(validate_interface_owners([&live, &record(2, "renamed", 10)]).is_err());
        assert!(validate_interface_owners([&live, &record(2, "host-two", 11)]).is_ok());
        assert!(validate_interface_owners([&live]).is_ok());
    }
}
