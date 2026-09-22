// Vector: cilium/cilium 7d68cfb394 pkg/maglev/maglev_test.go, Apache-2.0.
// Copyright Authors of Cilium (RLE fixture). Rust assertions independently written.
use flowsdn_lb::maglev::{Backend, hash, table};
fn b(n: u32, id: u32, weight: u16) -> Backend {
    Backend {
        id,
        address: std::net::Ipv4Addr::from(n).into(),
        port: u16::try_from(n).expect("port"),
        protocol: "TCP",
        cluster: 0,
        internal: false,
        weight,
    }
}
#[test]
fn weighted_vector_and_permutation() {
    let expected: Vec<u32> = include_str!("maglev-weighted.rle")
        .trim()
        .split(',')
        .flat_map(|r| {
            let (id, count) = r.split_once('(').expect("run");
            std::iter::repeat_n(
                id.parse().expect("id"),
                count.trim_end_matches(')').parse().expect("count"),
            )
        })
        .collect();
    let mut inputs = vec![b(1, 0, 2), b(3, 1, 13), b(4, 2, 111), b(5, 3, 10)];
    assert_eq!(table(&inputs, 251, 0x24b7ef82).expect("table"), expected);
    inputs.reverse();
    assert_eq!(table(&inputs, 251, 0x24b7ef82).expect("table"), expected);
}
#[test]
fn removal_disruption() {
    let inputs = [b(1, 1, 1), b(2, 2, 1), b(3, 3, 1)];
    let before = table(&inputs, 1021, 0x24b7ef82).expect("before");
    let after = table(inputs.get(..2).expect("two"), 1021, 0x24b7ef82).expect("after");
    assert!(
        before
            .iter()
            .zip(&after)
            .filter(|(a, b)| **a != 3 && a != b)
            .count()
            < 11
    );
    assert!(after.iter().all(|v| *v == 1 || *v == 2));
}
#[test]
fn empty_single_and_hash() {
    assert_eq!(hash(b"", 0), (0, 0));
    assert_eq!(hash(b"hello", 0), (0xcbd8a7b341bd9b02, 0x5b1e906a48ae1d19));
    for size in [251, 509, 1021] {
        assert!(table(&[], size, 0).expect("empty").is_empty());
        assert_eq!(
            table(&[b(1, 1, 1)], size, 0).expect("single"),
            vec![1; size]
        );
    }
    assert!(table(&[b(1, 1, 0)], 251, 0).is_err());
}
#[test]
fn weighted_removal() {
    let inputs = [b(1, 1, 2), b(2, 2, 13), b(3, 3, 111), b(4, 4, 10)];
    let before = table(&inputs, 1021, 0x24b7ef82).expect("before");
    let after = table(inputs.get(1..).expect("remaining"), 1021, 0x24b7ef82).expect("after");
    assert!(before.iter().filter(|v| **v == 3).count() > 800);
    assert!(after.iter().all(|v| [2, 3, 4].contains(v)));
}
