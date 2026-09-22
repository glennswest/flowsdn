//! Guarded cluster ownership planning. No UUID generation, persistence or etcd
//! transaction transport is implemented. Callers must execute the entire plan
//! atomically and reread/replan after any comparison failure.
use crate::{Error, prefixes::validate_cluster};
use serde_json::Value;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceUuid(String);
impl InstanceUuid {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                }
            })
            && value.bytes().any(|byte| byte != b'0' && byte != b'-');
        if !valid {
            return Err(Error(
                "instance UUID must be nonzero canonical lowercase UUID text".into(),
            ));
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub value: Vec<u8>,
    pub mod_revision: u64,
    pub lease_id: Option<i64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Guard {
    pub key: String,
    /// None means compare Version(key)==0. Otherwise compare both exact bytes
    /// and mod_revision; lease association is captured by the observer and must also be compared.
    pub expected: Option<Record>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lease {
    None,
    Config(i64),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Put {
    pub key: String,
    pub value: Vec<u8>,
    pub lease: Lease,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimPlan {
    pub guards: Vec<Guard>,
    pub puts: Vec<Put>,
}
fn validate_record(record: Option<&Record>) -> Result<(), Error> {
    if record.is_some_and(|record| record.mod_revision == 0 || record.lease_id == Some(0)) {
        return Err(Error(
            "existing record requires positive mod_revision and a nonzero lease ID when leased"
                .into(),
        ));
    }
    Ok(())
}
pub fn plan_claim(
    cluster: &str,
    instance: &InstanceUuid,
    owner: Option<&Record>,
    config: Option<&Record>,
    desired: &Value,
    desired_lease_id: i64,
) -> Result<ClaimPlan, Error> {
    validate_cluster(cluster)?;
    if desired_lease_id == 0 {
        return Err(Error("config requires a nonzero lease ID".into()));
    }
    validate_record(owner)?;
    validate_record(config)?;
    let owner_key = format!("flowsdn/cluster-owners/{cluster}");
    let config_key = format!("cilium/cluster-config/{cluster}");
    if let Some(owner) = owner
        && (owner.lease_id.is_some() || owner.value != instance.as_str().as_bytes())
    {
        return Err(Error(
            "cluster name owned by a different instance or unsafe leased guard".into(),
        ));
    }
    if let Some(config) = config {
        let existing: Value = serde_json::from_slice(&config.value)
            .map_err(|_| Error("invalid existing cluster config".into()))?;
        if existing
            .pointer("/capabilities/flowsdnInstanceUUID")
            .and_then(Value::as_str)
            != Some(instance.as_str())
        {
            return Err(Error(
                "foreign or unstamped cluster config; explicit offline migration required".into(),
            ));
        }
        if owner.is_none() {
            return Err(Error(
                "stamped config lacks durable owner; explicit recovery required".into(),
            ));
        }
    }
    let mut stamped = desired.clone();
    let object = stamped
        .as_object_mut()
        .ok_or_else(|| Error("cluster config must be an object".into()))?;
    if !object
        .get("id")
        .and_then(Value::as_u64)
        .is_some_and(|id| (1..=511).contains(&id))
    {
        return Err(Error("cluster config requires a valid nonzero ID".into()));
    }
    let capabilities = object
        .entry("capabilities")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()
        .ok_or_else(|| Error("capabilities must be an object".into()))?;
    capabilities.insert(
        "flowsdnInstanceUUID".into(),
        Value::String(instance.as_str().into()),
    );
    let value = serde_json::to_vec(&stamped).map_err(|error| Error(error.to_string()))?;
    let mut puts = Vec::new();
    if owner.is_none() {
        puts.push(Put {
            key: owner_key.clone(),
            value: instance.as_str().as_bytes().to_vec(),
            lease: Lease::None,
        });
    }
    if config
        .is_none_or(|config| config.value != value || config.lease_id != Some(desired_lease_id))
    {
        puts.push(Put {
            key: config_key.clone(),
            value,
            lease: Lease::Config(desired_lease_id),
        });
    }
    Ok(ClaimPlan {
        guards: vec![
            Guard {
                key: owner_key,
                expected: owner.cloned(),
            },
            Guard {
                key: config_key,
                expected: config.cloned(),
            },
        ],
        puts,
    })
}
