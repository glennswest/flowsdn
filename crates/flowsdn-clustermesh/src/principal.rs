//! Binding between a verified mTLS peer and the prefix policy. This module does
//! not verify certificates. Its input must come only from a trusted TLS adapter
//! after chain, validity, client-auth purpose and peer-identity verification.
use crate::{
    Error,
    prefixes::{FrontPolicy, Role, Rpc, validate_cluster},
};
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone, Debug)]
pub struct AuthenticatedPrincipal {
    name: String,
    issuer: Arc<()>,
}
#[derive(Debug)]
pub struct Bindings {
    own_cluster: String,
    roles: BTreeMap<String, Role>,
    issuer: Arc<()>,
}
impl Bindings {
    pub fn new(
        own_cluster: &str,
        entries: impl IntoIterator<Item = (String, Role)>,
    ) -> Result<Self, Error> {
        validate_cluster(own_cluster)?;
        let mut roles = BTreeMap::new();
        for (name, role) in entries {
            if name.is_empty()
                || name.chars().any(char::is_control)
                || roles.insert(name, role).is_some()
            {
                return Err(Error("invalid or duplicate principal binding".into()));
            }
        }
        Ok(Self {
            own_cluster: own_cluster.into(),
            roles,
            issuer: Arc::new(()),
        })
    }
    /// Bind exactly one verified leaf-certificate CN. Never pass an RPC field,
    /// unverified certificate, request header or a SAN copied by the client.
    pub fn bind_verified_certificate(
        &self,
        common_names: &[&str],
    ) -> Result<AuthenticatedPrincipal, Error> {
        let [name] = common_names else {
            return Err(Error("one verified certificate CN is required".into()));
        };
        if !self.roles.contains_key(*name) {
            return Err(Error("unknown authenticated principal".into()));
        }
        Ok(AuthenticatedPrincipal {
            name: (*name).into(),
            issuer: self.issuer.clone(),
        })
    }
    /// Atomic replacement validates the entire candidate first. Existing
    /// sessions are checked against the current bindings on every request.
    pub fn replace(
        &mut self,
        entries: impl IntoIterator<Item = (String, Role)>,
    ) -> Result<(), Error> {
        let next = Self::new(&self.own_cluster, entries)?;
        self.roles = next.roles;
        Ok(())
    }
    pub fn permits(
        &self,
        principal: &AuthenticatedPrincipal,
        rpc: Rpc,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> bool {
        if !Arc::ptr_eq(&self.issuer, &principal.issuer) {
            return false;
        }
        self.roles
            .get(&principal.name)
            .and_then(|role| FrontPolicy::for_role(role.clone(), &self.own_cluster).ok())
            .is_some_and(|policy| policy.permits(rpc, start, end))
    }
}
