//! Spec03 owns the number space: FQDN shares the complete local scope with CIDR
//! and CIDR-group allocation. This validates requested/restore IDs, not ownership.
use flowsdn_identity::{IdentityError, NumericIdentity, Scope};
pub fn local_identity(value: u32) -> Result<NumericIdentity, IdentityError> {
    let identity = NumericIdentity::new(value)?;
    if identity.scope() != Scope::Local { return Err(IdentityError::OutsideAllocationRange); }
    Ok(identity)
}
