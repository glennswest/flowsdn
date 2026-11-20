//! The XDP prefilter's API state (#467, spec 08 §4.4 rows 28–30; the
//! reference's `enable-xdp-prefilter`): a revisioned deny list of source
//! CIDRs, realized in the local-delivery object's `flowsdn_cidr_*` maps and
//! dropped at XDP on the uplinks (`kubernetes.xdp-prefilter`).
//!
//! As the reference's prefilter: the revision starts at 1 and every
//! successful `PATCH` (add) or `DELETE` (remove) increments it. A request
//! carries the revision it was made against; a different one (other than 0,
//! which skips the check) fails with 500 and changes nothing. A CIDR that
//! does not parse is 461. A `DELETE` of a CIDR that is not denied fails with
//! 500. A failed map write undoes the request's earlier writes. The list
//! lives in the agent: a restart starts again at revision 1 with the maps
//! emptied.
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};

/// What the deny maps must do.
pub trait DenyMaps {
    fn insert(&mut self, address: IpAddr, prefix: u8) -> Result<(), String>;
    fn remove(&mut self, address: IpAddr, prefix: u8) -> Result<(), String>;
}

/// A failed request: the HTTP status and the reference's `Error` text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub message: String,
}
fn refuse<T>(status: u16, message: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        status,
        message: message.into(),
    })
}

/// `address/prefix` with the host bits cleared; None when it is not a CIDR.
pub fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = text.trim().split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let network = match address {
        IpAddr::V4(v4) => {
            let width = 32u32.checked_sub(u32::from(prefix))?;
            let mask = u32::MAX.checked_shl(width).unwrap_or(0);
            IpAddr::from(std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let width = 128u32.checked_sub(u32::from(prefix))?;
            let mask = u128::MAX.checked_shl(width).unwrap_or(0);
            IpAddr::from(std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    };
    Some((network, prefix))
}

/// The prefilter's deny list and revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prefilter {
    revision: i64,
    deny: BTreeSet<(IpAddr, u8)>,
}
impl Default for Prefilter {
    fn default() -> Self {
        Self {
            revision: 1,
            deny: BTreeSet::new(),
        }
    }
}

impl Prefilter {
    /// The `Prefilter` model: `spec` and `status.realized` (the maps hold
    /// exactly the list, so they are the same).
    pub fn json(&self) -> Value {
        let spec = json!({
            "revision": self.revision,
            "deny": self.deny.iter().map(|(a, p)| format!("{a}/{p}")).collect::<Vec<_>>(),
        });
        json!({"spec": spec, "status": {"realized": spec}})
    }

    /// A `PrefilterSpec` body: its revision and CIDRs.
    fn spec(body: &Value) -> Result<(i64, Vec<(IpAddr, u8)>), Refusal> {
        let revision = match body.get("revision") {
            None | Some(Value::Null) => 0,
            Some(value) => match value.as_i64() {
                Some(revision) => revision,
                None => return refuse(500, "revision must be an integer"),
            },
        };
        let mut cidrs = Vec::new();
        for item in body
            .get("deny")
            .and_then(Value::as_array)
            .map_or(&[] as &[Value], Vec::as_slice)
        {
            let text = item.as_str().unwrap_or_default();
            match parse_cidr(text) {
                Some(cidr) => cidrs.push(cidr),
                None => return refuse(461, format!("Invalid CIDR prefix: {text}")),
            }
        }
        Ok((revision, cidrs))
    }

    fn check(&self, revision: i64) -> Result<(), Refusal> {
        if revision != 0 && revision != self.revision {
            return refuse(
                500,
                format!("Latest revision is {} not {revision}", self.revision),
            );
        }
        Ok(())
    }

    /// `PATCH /prefilter`: deny the body's CIDRs.
    pub fn patch(&mut self, body: &Value, maps: &mut dyn DenyMaps) -> Result<Value, Refusal> {
        let (revision, cidrs) = Self::spec(body)?;
        self.check(revision)?;
        let mut done: Vec<(IpAddr, u8)> = Vec::new();
        for (address, prefix) in cidrs {
            if self.deny.contains(&(address, prefix)) || done.contains(&(address, prefix)) {
                continue;
            }
            if let Err(error) = maps.insert(address, prefix) {
                for (a, p) in &done {
                    let _ = maps.remove(*a, *p);
                }
                return refuse(500, format!("deny {address}/{prefix}: {error}"));
            }
            done.push((address, prefix));
        }
        self.deny.extend(done);
        self.revision = self.revision.saturating_add(1);
        Ok(self.json())
    }

    /// `DELETE /prefilter`: stop denying the body's CIDRs.
    pub fn delete(&mut self, body: &Value, maps: &mut dyn DenyMaps) -> Result<Value, Refusal> {
        let (revision, cidrs) = Self::spec(body)?;
        self.check(revision)?;
        if let Some((address, prefix)) = cidrs.iter().find(|c| !self.deny.contains(c)) {
            return refuse(500, format!("{address}/{prefix} is not in the prefilter"));
        }
        let mut done: Vec<(IpAddr, u8)> = Vec::new();
        for (address, prefix) in cidrs {
            if done.contains(&(address, prefix)) {
                continue;
            }
            if let Err(error) = maps.remove(address, prefix) {
                for (a, p) in &done {
                    let _ = maps.insert(*a, *p);
                }
                return refuse(500, format!("allow {address}/{prefix}: {error}"));
            }
            done.push((address, prefix));
        }
        for cidr in &done {
            self.deny.remove(cidr);
        }
        self.revision = self.revision.saturating_add(1);
        Ok(self.json())
    }
}

impl DenyMaps for flowsdn_bpf_loader::kernel::PrefilterMaps {
    fn insert(&mut self, address: IpAddr, prefix: u8) -> Result<(), String> {
        flowsdn_bpf_loader::kernel::PrefilterMaps::insert(self, address, prefix)
            .map_err(|e| e.to_string())
    }
    fn remove(&mut self, address: IpAddr, prefix: u8) -> Result<(), String> {
        flowsdn_bpf_loader::kernel::PrefilterMaps::remove(self, address, prefix)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[path = "prefilter_tests.rs"]
mod tests;
