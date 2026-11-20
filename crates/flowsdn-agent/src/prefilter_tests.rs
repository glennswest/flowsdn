use super::*;

/// A recording map; `fail` names a CIDR whose write fails.
#[derive(Default)]
struct Fake {
    entries: BTreeSet<(IpAddr, u8)>,
    fail: Option<(IpAddr, u8)>,
}
impl DenyMaps for Fake {
    fn insert(&mut self, address: IpAddr, prefix: u8) -> Result<(), String> {
        if self.fail == Some((address, prefix)) {
            return Err("map full".into());
        }
        self.entries.insert((address, prefix));
        Ok(())
    }
    fn remove(&mut self, address: IpAddr, prefix: u8) -> Result<(), String> {
        if self.fail == Some((address, prefix)) {
            return Err("busy".into());
        }
        self.entries.remove(&(address, prefix));
        Ok(())
    }
}
fn cidr(text: &str) -> (IpAddr, u8) {
    parse_cidr(text).expect("cidr")
}
fn spec(revision: i64, deny: &[&str]) -> Value {
    json!({"revision": revision, "deny": deny})
}

#[test]
fn cidrs_parse_to_their_network() {
    assert_eq!(parse_cidr("192.0.2.77/24"), Some(cidr("192.0.2.0/24")));
    assert_eq!(parse_cidr("2001:db8::1/32"), Some(cidr("2001:db8::/32")));
    assert_eq!(
        parse_cidr("0.0.0.0/0"),
        Some((IpAddr::from([0, 0, 0, 0]), 0))
    );
    for bad in ["192.0.2.1", "192.0.2.1/33", "x/8", "2001:db8::/129", ""] {
        assert_eq!(parse_cidr(bad), None, "{bad}");
    }
}

#[test]
fn patch_and_delete_follow_the_revision() {
    let mut state = Prefilter::default();
    let mut maps = Fake::default();
    assert_eq!(
        state.json(),
        json!({"spec":{"revision":1,"deny":[]},"status":{"realized":{"revision":1,"deny":[]}}})
    );
    let got = state
        .patch(
            &spec(1, &["198.51.100.0/24", "203.0.113.9/32", "2001:db8::/48"]),
            &mut maps,
        )
        .expect("patch");
    assert_eq!(got.pointer("/spec/revision"), Some(&json!(2)));
    assert_eq!(
        got.pointer("/status/realized/deny"),
        Some(&json!([
            "198.51.100.0/24",
            "203.0.113.9/32",
            "2001:db8::/48"
        ]))
    );
    assert_eq!(maps.entries.len(), 3);
    // A stale revision changes nothing.
    let stale = state
        .patch(&spec(1, &["192.0.2.0/24"]), &mut maps)
        .expect_err("stale");
    assert_eq!(
        stale,
        Refusal {
            status: 500,
            message: "Latest revision is 2 not 1".into()
        }
    );
    assert_eq!(maps.entries.len(), 3);
    // Revision 0 skips the check; a CIDR already denied is not written twice.
    state
        .patch(&spec(0, &["198.51.100.0/24", "192.0.2.0/24"]), &mut maps)
        .expect("patch 0");
    assert_eq!(state.json().pointer("/spec/revision"), Some(&json!(3)));
    let got = state
        .delete(&spec(3, &["203.0.113.9/32"]), &mut maps)
        .expect("delete");
    assert_eq!(got.pointer("/spec/revision"), Some(&json!(4)));
    assert!(!maps.entries.contains(&cidr("203.0.113.9/32")));
    let absent = state
        .delete(&spec(4, &["203.0.113.9/32"]), &mut maps)
        .expect_err("absent");
    assert_eq!(absent.status, 500);
    assert!(
        absent.message.contains("not in the prefilter"),
        "{}",
        absent.message
    );
}

#[test]
fn an_invalid_cidr_is_461_and_changes_nothing() {
    let mut state = Prefilter::default();
    let mut maps = Fake::default();
    let refused = state
        .patch(&spec(1, &["198.51.100.0/24", "nonsense"]), &mut maps)
        .expect_err("invalid");
    assert_eq!(refused.status, 461);
    assert!(maps.entries.is_empty());
    assert_eq!(state, Prefilter::default());
    let refused = state
        .delete(&spec(1, &["10.0.0.0/40"]), &mut maps)
        .expect_err("invalid");
    assert_eq!(refused.status, 461);
}

#[test]
fn a_failed_map_write_undoes_the_request() {
    let mut state = Prefilter::default();
    let mut maps = Fake {
        fail: Some(cidr("192.0.2.0/24")),
        ..Fake::default()
    };
    let refused = state
        .patch(&spec(1, &["198.51.100.0/24", "192.0.2.0/24"]), &mut maps)
        .expect_err("map full");
    assert_eq!(refused.status, 500);
    assert!(maps.entries.is_empty(), "the first write was undone");
    assert_eq!(state, Prefilter::default(), "revision and list unchanged");
}
