use flowsdn_bpf_abi::maglev::*;

// Vectors from an independent transcription of Linux `jhash.h` (tmp scratch,
// not shipped); they pin the arithmetic against slips in either copy.
#[test]
fn jhash_3words_vectors() {
    assert_eq!(jhash_3words(0, 0, 0, 0), 0x1b68_e557);
    assert_eq!(jhash_3words(1, 2, 3, 4), 0x8103_143f);
}

#[test]
fn flow_hash_vectors() {
    assert_eq!(flow_hash4([198, 51, 100, 9], 40000, 30080, 6), 0x2087_44fa);
    let client = "2001:db8:3::9"
        .parse::<core::net::Ipv6Addr>()
        .expect("address")
        .octets();
    assert_eq!(flow_hash6(client, 40000, 30080, 17), 0x4f41_9f05);
}

#[test]
fn flow_hash_inputs_matter() {
    let base = flow_hash4([198, 51, 100, 9], 40000, 30080, 6);
    assert_ne!(base, flow_hash4([198, 51, 100, 10], 40000, 30080, 6));
    assert_ne!(base, flow_hash4([198, 51, 100, 9], 40001, 30080, 6));
    assert_ne!(base, flow_hash4([198, 51, 100, 9], 40000, 30081, 6));
    assert_ne!(base, flow_hash4([198, 51, 100, 9], 40000, 30080, 17));
}

#[test]
fn entries_are_in_the_table() {
    assert_eq!(entry(TABLE_SIZE), 0);
    assert_eq!(Some(entry(u32::MAX)), u32::MAX.checked_rem(TABLE_SIZE));
    assert_eq!(TABLE_LEN, TABLE_SIZE as usize);
}
