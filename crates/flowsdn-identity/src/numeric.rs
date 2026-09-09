//! Supported numeric identity ranges, reserved IDs and ClusterMesh encoding.
//! This module uses only core; no allocator, backend, or label trust is implied.

use core::fmt;

pub const WIRE_MAX: u32 = 0x00ff_ffff;
pub const MAX_SUPPORTED_IDENTITY: u32 = 0x02ff_ffff;
pub const FIRST_ALLOCATED_GLOBAL: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    Global,
    Local,
    RemoteNode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    ExceedsU32,
    UnsupportedScope,
    EmptyScopedIdentity,
    InvalidScopeIndex,
    ScopedIdentityOnWire,
    InvalidClusterLimit,
    InvalidClusterId,
    ClusterUnset,
    MarkCollision,
    ScopedIdentityHasNoGlobalCluster,
    OutsideAllocationRange,
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ExceedsU32 => "identity exceeds u32",
            Self::UnsupportedScope => "identity has an unsupported scope",
            Self::EmptyScopedIdentity => "scoped identity index must be nonzero",
            Self::InvalidScopeIndex => "identity index exceeds the scope range",
            Self::ScopedIdentityOnWire => {
                "scoped identities cannot be encoded in a 24-bit wire field"
            }
            Self::InvalidClusterLimit => "maximum connected clusters must be 255 or 511",
            Self::InvalidClusterId => "cluster ID exceeds the configured cluster range",
            Self::ClusterUnset => "meshing requires a nonzero cluster ID",
            Self::MarkCollision => {
                "cluster ID bit 0x80 conflicts with the selected IPAM or chaining mode"
            }
            Self::ScopedIdentityHasNoGlobalCluster => {
                "scoped identity has no global cluster encoding"
            }
            Self::OutsideAllocationRange => "identity is outside the cluster allocation range",
        })
    }
}
impl core::error::Error for IdentityError {}

/// Validated representation. Zero and reserved holes remain readable; validation
/// is distinct from permission to allocate a number.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NumericIdentity(u32);
impl NumericIdentity {
    pub const fn new(value: u32) -> Result<Self, IdentityError> {
        match value >> 24 {
            0 => Ok(Self(value)),
            1 | 2 if value & WIRE_MAX != 0 => Ok(Self(value)),
            1 | 2 => Err(IdentityError::EmptyScopedIdentity),
            _ => Err(IdentityError::UnsupportedScope),
        }
    }
    pub const fn get(self) -> u32 {
        self.0
    }
    pub const fn scope(self) -> Scope {
        match self.0 >> 24 {
            0 => Scope::Global,
            1 => Scope::Local,
            _ => Scope::RemoteNode,
        }
    }
    pub const fn local(index: u32) -> Result<Self, IdentityError> {
        Self::scoped(index, 0x0100_0000)
    }
    pub const fn remote_node(index: u32) -> Result<Self, IdentityError> {
        Self::scoped(index, 0x0200_0000)
    }
    const fn scoped(index: u32, scope: u32) -> Result<Self, IdentityError> {
        if index == 0 {
            return Err(IdentityError::EmptyScopedIdentity);
        }
        if index > WIRE_MAX {
            return Err(IdentityError::InvalidScopeIndex);
        }
        Ok(Self(scope | index))
    }
    pub const fn from_le_bytes(bytes: [u8; 4]) -> Result<Self, IdentityError> {
        Self::new(u32::from_le_bytes(bytes))
    }
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    pub const fn from_be_bytes(bytes: [u8; 4]) -> Result<Self, IdentityError> {
        Self::new(u32::from_be_bytes(bytes))
    }
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
    pub const fn is_cidr(self) -> bool {
        matches!(self.scope(), Scope::Local)
    }
    pub const fn is_world(self) -> bool {
        matches!(self.0, 2 | 9 | 10) || self.is_cidr()
    }
    pub fn class(self) -> IdentityClass {
        match self.scope() {
            Scope::Local => IdentityClass::Local,
            Scope::RemoteNode => IdentityClass::RemoteNode,
            Scope::Global => {
                if let Some(reserved) = ReservedIdentity::from_number(self.0) {
                    return IdentityClass::Reserved(reserved);
                }
                match self.0 {
                    100 | 101 | 107..=109 | 115 => IdentityClass::DeprecatedReserved,
                    102..=106 | 110..=114 => IdentityClass::WellKnown,
                    128..=255 => IdentityClass::UserReserved,
                    256.. => IdentityClass::Global,
                    _ => IdentityClass::UnallocatedReserved,
                }
            }
        }
    }
    /// Fold family-specific world IDs only at tunnel encoding. Scoped identities
    /// are rejected before any high bits can be lost.
    pub const fn tunnel_id(self) -> Result<WireIdentity, IdentityError> {
        if self.0 > WIRE_MAX {
            return Err(IdentityError::ScopedIdentityOnWire);
        }
        Ok(WireIdentity(if matches!(self.0, 9 | 10) {
            2
        } else {
            self.0
        }))
    }
}
impl TryFrom<u32> for NumericIdentity {
    type Error = IdentityError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl TryFrom<u64> for NumericIdentity {
    type Error = IdentityError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(u32::try_from(value).map_err(|_| IdentityError::ExceedsU32)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityClass {
    Reserved(ReservedIdentity),
    UnallocatedReserved,
    DeprecatedReserved,
    WellKnown,
    UserReserved,
    Global,
    Local,
    RemoteNode,
}

macro_rules! reserved {
    ($($variant:ident = $number:literal => $name:literal),+ $(,)?) => {
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum ReservedIdentity { $($variant = $number),+ }
        impl ReservedIdentity {
            pub const fn numeric(self) -> NumericIdentity { NumericIdentity(self as u32) }
            pub const fn name(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            pub const fn from_number(number: u32) -> Option<Self> { match number { $($number => Some(Self::$variant)),+, _ => None } }
            pub fn from_name(name: &str) -> Option<Self> { match name { $($name => Some(Self::$variant)),+, _ => None } }
        }
    };
}
reserved! {
    Unknown = 0 => "unknown", Host = 1 => "host", World = 2 => "world",
    Unmanaged = 3 => "unmanaged", Health = 4 => "health", Init = 5 => "init",
    RemoteNode = 6 => "remote-node", KubeApiserver = 7 => "kube-apiserver",
    Ingress = 8 => "ingress", WorldIpv4 = 9 => "world-ipv4", WorldIpv6 = 10 => "world-ipv6",
    AggregateCluster = 11 => "aggregate-cluster", AggregateClusterMesh = 12 => "aggregate-cluster-mesh",
    AggregateWorld = 13 => "aggregate-world", AggregateRemoteNode = 14 => "aggregate-remote-node",
}
/// Order specified by §4.4; zero is the non-aggregated wildcard.
pub const ALL_AGGREGATES: [ReservedIdentity; 5] = [
    ReservedIdentity::Unknown,
    ReservedIdentity::AggregateRemoteNode,
    ReservedIdentity::AggregateWorld,
    ReservedIdentity::AggregateCluster,
    ReservedIdentity::AggregateClusterMesh,
];
/// Numbers only: their label model and enable/disable flag belong to the owner.
pub const WELL_KNOWN_IDENTITIES: [u32; 10] = [102, 103, 104, 105, 106, 110, 111, 112, 113, 114];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}
/// A lossless 24-bit wire value. `new` validates width without world folding;
/// use NumericIdentity::tunnel_id for the tunnel-specific world conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireIdentity(u32);
impl WireIdentity {
    pub const fn new(identity: NumericIdentity) -> Result<Self, IdentityError> {
        if identity.0 > WIRE_MAX {
            Err(IdentityError::ScopedIdentityOnWire)
        } else {
            Ok(Self(identity.0))
        }
    }
    pub const fn get(self) -> u32 {
        self.0
    }
    pub const fn to_be_bytes(self) -> [u8; 3] {
        let [_, a, b, c] = self.0.to_be_bytes();
        [a, b, c]
    }
    pub const fn from_be_bytes([a, b, c]: [u8; 3]) -> Self {
        Self(u32::from_be_bytes([0, a, b, c]))
    }
    /// Single-stack world remains 2; dual-stack receive selects world by L3.
    pub const fn received(self, family: IpFamily, dual_stack: bool) -> NumericIdentity {
        NumericIdentity(if self.0 == 2 && dual_stack {
            match family {
                IpFamily::V4 => 9,
                IpFamily::V6 => 10,
            }
        } else {
            self.0
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRange {
    pub min: NumericIdentity,
    pub max: NumericIdentity,
}
impl AllocationRange {
    pub const fn contains(self, identity: NumericIdentity) -> bool {
        identity.0 >= self.min.0 && identity.0 <= self.max.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterEncoding {
    max_clusters: u16,
    shift: u32,
}
impl ClusterEncoding {
    pub const fn new(max_clusters: u16) -> Result<Self, IdentityError> {
        match max_clusters {
            255 => Ok(Self {
                max_clusters,
                shift: 16,
            }),
            511 => Ok(Self {
                max_clusters,
                shift: 15,
            }),
            _ => Err(IdentityError::InvalidClusterLimit),
        }
    }
    pub const fn max_clusters(self) -> u16 {
        self.max_clusters
    }
    pub const fn shift(self) -> u32 {
        self.shift
    }
    pub const fn index_mask(self) -> u32 {
        match self.shift {
            16 => 0xffff,
            _ => 0x7fff,
        }
    }
    fn validate_cluster(self, cluster: u16) -> Result<(), IdentityError> {
        if cluster > self.max_clusters {
            Err(IdentityError::InvalidClusterId)
        } else {
            Ok(())
        }
    }
    /// Zero is permitted for standalone allocation, but not for ClusterMesh.
    /// `mark_sensitive` is true for ENI, Alibaba IPAM or aws-cni chaining.
    pub fn validate_meshing(self, cluster: u16, mark_sensitive: bool) -> Result<(), IdentityError> {
        self.validate_cluster(cluster)?;
        if cluster == 0 {
            return Err(IdentityError::ClusterUnset);
        }
        if mark_sensitive && cluster & 0x80 != 0 {
            return Err(IdentityError::MarkCollision);
        }
        Ok(())
    }
    pub fn allocation_range(self, cluster: u16) -> Result<AllocationRange, IdentityError> {
        self.validate_cluster(cluster)?;
        let prefix = u32::from(cluster) << self.shift;
        Ok(AllocationRange {
            min: NumericIdentity(if cluster == 0 {
                FIRST_ALLOCATED_GLOBAL
            } else {
                prefix
            }),
            max: NumericIdentity(prefix | self.index_mask()),
        })
    }
    /// Index zero is allocatable in nonzero clusters; cluster zero reserves 0..255.
    pub fn global(self, cluster: u16, index: u32) -> Result<NumericIdentity, IdentityError> {
        let range = self.allocation_range(cluster)?;
        if index > self.index_mask() {
            return Err(IdentityError::OutsideAllocationRange);
        }
        let identity = NumericIdentity((u32::from(cluster) << self.shift) | index);
        if range.contains(identity) {
            Ok(identity)
        } else {
            Err(IdentityError::OutsideAllocationRange)
        }
    }
    pub fn global_cluster_id(self, identity: NumericIdentity) -> Result<u16, IdentityError> {
        if !matches!(identity.scope(), Scope::Global) {
            return Err(IdentityError::ScopedIdentityHasNoGlobalCluster);
        }
        // The mask is at most nine bits, so this conversion cannot truncate.
        Ok(
            u16::try_from((identity.0 >> self.shift) & u32::from(self.max_clusters))
                .expect("nine-bit cluster ID"),
        )
    }
    /// Numeric half of remote allocator validation. The caller must separately
    /// check the required cluster label and connection capability agreement.
    pub fn validate_remote_allocated(
        self,
        cluster: u16,
        identity: NumericIdentity,
    ) -> Result<(), IdentityError> {
        self.validate_meshing(cluster, false)?;
        if self.allocation_range(cluster)?.contains(identity) {
            Ok(())
        } else {
            Err(IdentityError::OutsideAllocationRange)
        }
    }
    /// Remote ipcache pairs additionally permit all numeric reserved IDs <256,
    /// including holes/deprecated IDs; this does not authorize allocating them.
    pub fn validate_remote_ipcache(
        self,
        cluster: u16,
        identity: NumericIdentity,
    ) -> Result<(), IdentityError> {
        self.validate_meshing(cluster, false)?;
        if identity.0 < FIRST_ALLOCATED_GLOBAL || self.allocation_range(cluster)?.contains(identity)
        {
            Ok(())
        } else {
            Err(IdentityError::OutsideAllocationRange)
        }
    }
    pub fn aggregate_for(
        self,
        identity: NumericIdentity,
        local_cluster: u16,
    ) -> Result<ReservedIdentity, IdentityError> {
        self.validate_cluster(local_cluster)?;
        if matches!(identity.0, 0 | 11..=14) {
            return Ok(ReservedIdentity::from_number(identity.0).expect("aggregate ID"));
        }
        Ok(match identity.scope() {
            Scope::Local => ReservedIdentity::AggregateWorld,
            Scope::RemoteNode => ReservedIdentity::AggregateRemoteNode,
            Scope::Global if identity.0 < 100 => ReservedIdentity::Unknown,
            Scope::Global if self.global_cluster_id(identity)? == local_cluster => {
                ReservedIdentity::AggregateCluster
            }
            Scope::Global => ReservedIdentity::AggregateClusterMesh,
        })
    }
}
