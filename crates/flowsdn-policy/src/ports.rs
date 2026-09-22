//! Validated API port ranges and canonical masked-port expansion (spec §5.2).
use crate::Error;
use flowsdn_bpf_abi::policy::PolicyKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    start: u16,
    end: u16,
}
impl PortRange {
    pub const fn any() -> Self {
        Self {
            start: 0,
            end: u16::MAX,
        }
    }
    pub fn from_api(port: u16, end_port: Option<u16>) -> Result<Self, Error> {
        if let Some(end) = end_port {
            if port == 0 {
                return Err(Error::ZeroStartRange);
            }
            if end < port {
                return Err(Error::InvalidPortRange);
            }
            Ok(Self { start: port, end })
        } else if port == 0 {
            Ok(Self::any())
        } else {
            Ok(Self {
                start: port,
                end: port,
            })
        }
    }
    pub const fn bounds(self) -> (u16, u16) {
        (self.start, self.end)
    }
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
    pub const fn is_any(self) -> bool {
        self.start == 0 && self.end == u16::MAX
    }
    /// Minimal disjoint power-of-two intervals covering this inclusive range.
    pub fn blocks(self) -> Vec<PortBlock> {
        let mut cursor = u32::from(self.start);
        let end = u32::from(self.end);
        let mut blocks = Vec::new();
        while cursor <= end {
            let remaining = end.saturating_sub(cursor).saturating_add(1);
            let alignment_bits = if cursor == 0 {
                16
            } else {
                cursor.trailing_zeros().min(16)
            };
            let size_bits = 31u32.saturating_sub(remaining.leading_zeros());
            let bits = alignment_bits.min(size_bits);
            blocks.push(PortBlock {
                port: u16::try_from(cursor).expect("cursor is within u16 range"),
                prefix: u8::try_from(16u32.saturating_sub(bits)).expect("prefix at most 16"),
            });
            cursor = cursor.saturating_add(1u32.checked_shl(bits).expect("block fits in u32"));
        }
        blocks
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortBlock {
    pub port: u16,
    pub prefix: u8,
}
impl PortBlock {
    pub fn matches(self, port: u16) -> bool {
        if self.prefix > 16 {
            return false;
        }
        let mask = u16::MAX
            .checked_shl(u32::from(16u8.saturating_sub(self.prefix)))
            .unwrap_or(0);
        port & mask == self.port & mask
    }
    pub fn policy_key(self, identity: u32, egress: bool, protocol: u8) -> Result<PolicyKey, Error> {
        PolicyKey::new(identity, egress, protocol, self.port, self.prefix)
            .map_err(|_| Error::InvalidProtocol)
    }
}
