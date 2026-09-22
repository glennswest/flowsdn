//! Deterministic resolved-gateway selection. Does not resolve policy selectors,
//! assess liveness, publish cohort configuration, or install maps.
use crate::Error;
use std::net::Ipv4Addr;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Selection {
    #[default]
    Modulo,
    Rendezvous,
}
impl Selection {
    pub fn parse(value: &str, all_flowsdn_confirmed: bool) -> Result<Self, Error> {
        match value {
            "modulo" => Ok(Self::Modulo),
            "rendezvous" if all_flowsdn_confirmed => Ok(Self::Rendezvous),
            "rendezvous" => Err(Error(
                "rendezvous requires a coordinated all-flowsdn cluster configuration",
            )),
            _ => Err(Error("unknown egress gateway selection algorithm")),
        }
    }
}
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}
fn score(uid: &[u8], gateway: Ipv4Addr) -> u64 {
    uid.iter()
        .copied()
        .chain(gateway.octets())
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
}
/// Preserves duplicate resolved gateway slots for reference modulo semantics.
/// Empty input is the no-gateway drop sentinel, never a local-route fallback.
pub fn choose(
    uid: &[u8],
    gateways: &[Ipv4Addr],
    selection: Selection,
) -> Result<Option<Ipv4Addr>, Error> {
    if gateways.is_empty() {
        return Ok(None);
    }
    let mut gateways = gateways.to_vec();
    gateways.sort();
    match selection {
        Selection::Modulo => {
            let count = u32::try_from(gateways.len()).map_err(|_| Error("too many gateways"))?;
            let index = fnv1a32(uid)
                .checked_rem(count)
                .ok_or(Error("empty gateways"))?;
            let index = usize::try_from(index).map_err(|_| Error("gateway index overflow"))?;
            Ok(gateways.get(index).copied())
        }
        Selection::Rendezvous => {
            // Tie goes to the numerically smallest address, independently of
            // input ordering and architecture.
            let mut winner = None;
            for gateway in gateways {
                let candidate = score(uid, gateway);
                if winner.is_none_or(|(best, _)| candidate > best) {
                    winner = Some((candidate, gateway));
                }
            }
            Ok(winner.map(|(_, gateway)| gateway))
        }
    }
}
