//! WireGuard host-egress decision core from encryption specification §3.1.9.
//! Callers parse the packet, resolve ipcache LPM entries and decode any source
//! mark first. This module neither encrypts bytes nor performs kernel redirects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub tunnel_mode: bool,
    pub node_encryption: bool,
    pub wireguard_ifindex: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    pub mark: u32,
    pub family: Family,
    pub valid_l3: bool,
    pub neighbor_advertisement: bool,
    /// Source identity already recovered by the host hook; zero asks for the
    /// source ipcache fallback. Scoped identities must never be mark-encoded.
    pub source_identity: u32,
    pub source_ipcache_identity: Option<u32>,
    /// None is an ipcache miss; Some(0) is a present, non-encrypting destination.
    pub destination_key: Option<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkUpdate {
    Preserve,
    Identity(u32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    UnsupportedL2,
    InvalidPacket,
    InvalidIdentity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Pass {
        already_encrypted: bool,
    },
    Drop(DropReason),
    /// Always device egress (redirect flags0). Apply mark update before redirect.
    Redirect {
        ifindex: u32,
        mark: MarkUpdate,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidInterface;
pub fn decide(config: Config, input: Input) -> Result<Decision, InvalidInterface> {
    if config.wireguard_ifindex == 0 {
        return Err(InvalidInterface);
    }
    let magic = input.mark & 0x0f00;
    if magic == 0x0e00 {
        return Ok(Decision::Pass {
            already_encrypted: true,
        });
    }
    if config.tunnel_mode && magic == 0x0400 {
        return Ok(Decision::Redirect {
            ifindex: config.wireguard_ifindex,
            mark: MarkUpdate::Preserve,
        });
    }
    if input.family == Family::Other {
        return Ok(Decision::Drop(DropReason::UnsupportedL2));
    }
    if !input.valid_l3 {
        return Ok(Decision::Drop(DropReason::InvalidPacket));
    }
    let clear = Decision::Pass {
        already_encrypted: false,
    };
    if config.node_encryption && input.family == Family::Ipv6 && input.neighbor_advertisement {
        return Ok(clear);
    }
    let identity = if input.source_identity == 0 {
        let Some(id) = input.source_ipcache_identity else {
            return Ok(clear);
        };
        id
    } else {
        input.source_identity
    };
    let scope = identity >> 24;
    if scope > 2 || (scope != 0 && identity & 0x00ff_ffff == 0) {
        return Ok(Decision::Drop(DropReason::InvalidIdentity));
    }
    let proxy_bypass = !config.node_encryption && matches!(magic, 0x0800 | 0x0a00);
    let world = matches!(identity, 2 | 9 | 10) || scope == 1;
    let remote = matches!(identity, 6 | 7) || scope == 2;
    if !proxy_bypass && (world || remote || (!config.node_encryption && identity == 1)) {
        return Ok(clear);
    }
    if input.destination_key.is_none_or(|key| key == 0) {
        return Ok(clear);
    }
    // Source identity must fit the wire mark even if a proxy bypassed source
    // policy. A scoped identity requires an adapter path that preserves it
    // out-of-band; truncation into a24-bit mark would change its meaning.
    if scope != 0 {
        return Ok(Decision::Drop(DropReason::InvalidIdentity));
    }
    Ok(Decision::Redirect {
        ifindex: config.wireguard_ifindex,
        mark: MarkUpdate::Identity(identity),
    })
}
