//! Maglev lookup shared by the datapath and the agent (spec 05 §2, §3.13,
//! §5.1; spec 02 §3.12): the table size, the hash seeds, and the flow hash
//! that picks a table entry. The agent builds each table with
//! `flowsdn_lb::maglev::table`; the uplink NodePort program reads entry
//! `flow_hash % TABLE_SIZE`. Every node must agree on all of it, so none of it
//! is configurable: the seeds are the reference's default
//! `bpf-lb-maglev-hash-seed` (`JLfvgnHc2kaSUFaI`).

/// Entries per table (`bpf-lb-maglev-table-size` default, a supported prime).
pub const TABLE_SIZE: u32 = 16381;
/// [`TABLE_SIZE`] as an array length.
pub const TABLE_LEN: usize = 16381;
/// Seed bytes 0–3: MurmurHash3 seed for the table permutations.
pub const SEED_MURMUR: u32 = 0x24b7_ef82;
/// Seed bytes 4–7: the IPv4 flow hash seed (`hash_init4_seed`).
pub const SEED_V4: u32 = 0x71dc_da46;
/// Seed bytes 8–11: the IPv6 flow hash seed (`hash_init6_seed`).
pub const SEED_V6: u32 = 0x9250_5688;
/// Master-slot algorithm byte that selects Maglev (spec 01 §4.3).
pub const ALGORITHM_MAGLEV: u8 = 2;

/// Linux `jhash.h` `JHASH_INITVAL`.
const JHASH_INITVAL: u32 = 0xdead_beef;

#[inline(always)]
fn mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(4);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(6);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(8);
    b = b.wrapping_add(a);
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(16);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(19);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(4);
    b = b.wrapping_add(a);
    (a, b, c)
}
#[inline(always)]
fn finish(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c.wrapping_sub(b.rotate_left(24))
}
/// Linux `jhash_3words`.
#[inline(always)]
pub fn jhash_3words(a: u32, b: u32, c: u32, seed: u32) -> u32 {
    // The initial value includes the length in bytes, 3 words.
    let init = seed.wrapping_add(JHASH_INITVAL).wrapping_add(12);
    finish(
        a.wrapping_add(init),
        b.wrapping_add(init),
        c.wrapping_add(init),
    )
}

/// Both ports in one word: the frontend port high, the client port low.
#[inline(always)]
fn ports(client_port: u16, front_port: u16) -> u32 {
    u32::from(front_port).wrapping_shl(16) | u32::from(client_port)
}
/// The IPv4 flow hash (reference `hash_from_tuple_v4`): client address,
/// ports and protocol. Addresses and ports are their numeric values. Callers
/// pass client port 0 for a session-affinity service, so a client keeps its
/// backend.
#[inline(always)]
pub fn flow_hash4(client: [u8; 4], client_port: u16, front_port: u16, proto: u8) -> u32 {
    jhash_3words(
        u32::from_be_bytes(client),
        ports(client_port, front_port),
        u32::from(proto),
        SEED_V4,
    )
}
/// The IPv6 flow hash (reference `hash_from_tuple_v6`): the client
/// address's first three words mixed, then its last word, the ports and the
/// protocol, then the seed.
#[inline(always)]
pub fn flow_hash6(client: [u8; 16], client_port: u16, front_port: u16, proto: u8) -> u32 {
    let [
        w0,
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        w7,
        w8,
        w9,
        w10,
        w11,
        w12,
        w13,
        w14,
        w15,
    ] = client;
    let (a, b, c) = mix(
        u32::from_be_bytes([w0, w1, w2, w3]),
        u32::from_be_bytes([w4, w5, w6, w7]),
        u32::from_be_bytes([w8, w9, w10, w11]),
    );
    let (a, b, c) = mix(
        a.wrapping_add(u32::from_be_bytes([w12, w13, w14, w15])),
        b.wrapping_add(ports(client_port, front_port)),
        c.wrapping_add(u32::from(proto)),
    );
    finish(a.wrapping_add(SEED_V6), b, c)
}
/// The table entry a flow hash selects.
#[inline(always)]
pub fn entry(hash: u32) -> u32 {
    hash.checked_rem(TABLE_SIZE).unwrap_or(0)
}
