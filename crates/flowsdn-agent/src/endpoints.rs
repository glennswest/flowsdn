//! Primary endpoint creation, deletion and restoration with real map ownership.
//! Identity/policy reconciliation and API request authorization remain caller work.
use crate::state::{IdPool, Record, Result, Store};
use flowsdn_bpf_abi::endpoint::EndpointInfo;
use flowsdn_bpf_loader::kernel::LocalDelivery;
use flowsdn_connector::Connector;
use flowsdn_ipam::Ipam;
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr, path::Path};

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

pub struct Manager {
    store: Store,
    ids: IdPool,
    records: BTreeMap<String, Record>,
    addresses: BTreeMap<IpAddr, String>,
    driver: LocalDelivery,
    ipam: Ipam,
}
impl Manager {
    /// Restore into a fresh object before the caller exposes its API. Stale or
    /// incompatible links fail startup; this layer cannot decide Kubernetes GC.
    pub fn restore(path: &Path, object: &Path, ipam: Ipam) -> Result<Self> {
        let store = Store::open(path)?;
        let records = store.restore()?;
        let mut manager = Self {
            store,
            ids: IdPool::default(),
            records: BTreeMap::new(),
            addresses: BTreeMap::new(),
            driver: kernel(LocalDelivery::load(object))?,
            ipam,
        };
        let connector = Connector::open()?;
        // Validate every persisted identity/address before installing any link.
        let mut viable = Vec::new();
        for record in records {
            let Some(link) = connector.link(text(&record.document, "IfName"))? else {
                // DEL may remove the peer while the agent is down. Its host
                // link disappears too; no live endpoint remains to restore.
                manager.store.remove(record.id)?;
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
            // Stage only after all caller-provided identity fields are checked.
            // Split field borrows allow the stage to keep Store's lock alive.
            let staged = self.store.stage(&record)?;
            install(&mut self.driver, &record)?;
            if let Err(error) = staged.publish() {
                let _ = uninstall(&mut self.driver, &record);
                let _ = self.store.remove(record.id);
                return Err(error);
            }
            for ip in ips {
                self.addresses.insert(ip, record.attachment.clone());
            }
            self.records.insert(record.attachment.clone(), record);
            Ok(id)
        })();
        if result.is_err() {
            self.ids.release(id);
        }
        result
    }
    pub fn delete(&mut self, attachment: &str) -> Result<bool> {
        let Some(record) = self.records.get(attachment).cloned() else {
            return Ok(false);
        };
        // Keep indexes and ID reserved on any error so deletion can be retried.
        uninstall(&mut self.driver, &record)?;
        Connector::open()?.delete(text(&record.document, "IfName"))?;
        self.store.remove(record.id)?;
        for ip in addresses(&record.document)? {
            self.ipam.release(ip)?;
            self.addresses.remove(&ip);
        }
        self.records.remove(attachment);
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
            kernel(driver.upsert(ip, endpoint))?;
            installed.push(ip);
        }
        kernel(driver.attach(text(&record.document, "IfName")))
    })();
    if outcome.is_err() {
        for ip in installed {
            let _ = driver.remove(ip);
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
