#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
use super::{
    cache::{Cache, IDENTITY_BASE, Limits},
    message::{self, rcode},
    pattern::{self, Selector},
};
use serde_json::json;
use std::net::IpAddr;

#[test]
fn patterns_are_the_reference_strings() {
    assert_eq!(pattern::name_regex("Example.COM"), r"^example\.com\.$");
    assert_eq!(
        pattern::pattern_regex("*.cilium.io").unwrap(),
        "^[-a-zA-Z0-9_]*[.]cilium[.]io[.]$"
    );
    assert_eq!(
        pattern::pattern_regex("**.cilium.io").unwrap(),
        "^([-a-zA-Z0-9_]+([.][-a-zA-Z0-9_]+){0,})[.]cilium[.]io[.]$"
    );
    assert_eq!(pattern::pattern_regex("*").unwrap(), pattern::ALL);
    assert_eq!(pattern::pattern_regex("**.").unwrap(), pattern::ALL);
    assert_eq!(
        pattern::pattern_regex("sub*.example.com").unwrap(),
        "^sub[-a-zA-Z0-9_]*[.]example[.]com[.]$"
    );
    assert!(pattern::pattern_regex("bad/pattern").is_err());
    assert!(pattern::pattern_regex(&"a".repeat(256)).is_err());
}

#[test]
fn selectors_match_as_the_reference_does() {
    let one = Selector::parse(&json!({"matchPattern": "*.example.com"})).unwrap();
    let re = one.compiled().unwrap();
    assert!(re.is_match("www.example.com."));
    assert!(!re.is_match("a.b.example.com."), "one * stays in one label");
    assert!(!re.is_match("example.com.evil."));
    let deep = Selector::parse(&json!({"matchPattern": "**.example.com"})).unwrap();
    assert!(deep.compiled().unwrap().is_match("a.b.example.com."));
    let name = Selector::parse(&json!({"matchName": "api.example.com"})).unwrap();
    let re = name.compiled().unwrap();
    assert!(re.is_match("api.example.com."));
    assert!(!re.is_match("apixexample.com."), "the dot is literal");
    assert_eq!(name.key(), "MatchName: api.example.com, MatchPattern: ");
    assert!(Selector::parse(&json!({})).is_err());
}

#[test]
fn a_query_and_its_answers_are_read() {
    let query = message::query(0x1234, "WWW.Example.com", message::TYPE_A);
    let question = message::question(&query).unwrap();
    assert_eq!(question.id, 0x1234);
    assert_eq!(question.name, "www.example.com.");
    assert_eq!(question.qtype, message::TYPE_A);
    let ip: IpAddr = "203.0.113.20".parse().unwrap();
    let ip6: IpAddr = "2001:db8::20".parse().unwrap();
    let response = message::response(
        &query,
        &[("www.example.com", 30, ip), ("www.example.com", 20, ip6)],
    )
    .unwrap();
    let answers = message::answers(&response, &question).unwrap();
    assert_eq!(answers.rcode, rcode::NOERROR);
    assert_eq!(answers.ips, vec![ip, ip6]);
    assert_eq!(answers.names, vec!["www.example.com.".to_owned()]);
    assert_eq!(answers.ttl, 20);
    // Another ID is not this query's answer.
    let other = message::query(0x9999, "www.example.com", message::TYPE_A);
    let other = message::question(&other).unwrap();
    assert!(message::answers(&response, &other).is_none());
    // A response is not a query.
    assert!(message::question(&response).is_none());
}

#[test]
fn a_cname_chain_gives_its_names_the_addresses() {
    let query = message::query(7, "alias.example.com", message::TYPE_A);
    let question = message::question(&query).unwrap();
    let mut response = message::reply(&query, &question, rcode::NOERROR).unwrap();
    response[7] = 2;
    // alias.example.com CNAME (pointer to offset 12) -> real.example.net
    let mut cname = vec![0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60];
    let target = [
        4, b'r', b'e', b'a', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'n', b'e',
        b't', 0,
    ];
    cname.extend_from_slice(&(target.len() as u16).to_be_bytes());
    let target_at = response.len() + cname.len();
    cname.extend_from_slice(&target);
    response.extend_from_slice(&cname);
    // real.example.net A 198.51.100.1, the owner a pointer to the target.
    response.extend_from_slice(&[
        0xc0,
        target_at as u8,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        5,
        0,
        4,
        198,
        51,
        100,
        1,
    ]);
    let answers = message::answers(&response, &question).unwrap();
    assert_eq!(
        answers.names,
        vec![
            "alias.example.com.".to_owned(),
            "real.example.net.".to_owned()
        ]
    );
    assert_eq!(answers.ips, vec!["198.51.100.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(answers.ttl, 5);
}

#[test]
fn hostile_messages_are_refused_not_followed() {
    // A pointer to itself.
    let mut looped = message::query(1, "a", message::TYPE_A);
    looped.truncate(12);
    looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert!(message::question(&looped).is_none());
    // Cut short.
    let query = message::query(1, "example.com", message::TYPE_A);
    for cut in 0..query.len() {
        assert!(message::question(&query[..cut]).is_none(), "cut at {cut}");
    }
    assert!(message::servfail_header(&[1]).is_none());
}

#[test]
fn refusals_keep_the_id_and_question() {
    let query = message::query(0xbeef, "denied.example.com", message::TYPE_AAAA);
    let question = message::question(&query).unwrap();
    let reply = message::reply(&query, &question, rcode::REFUSED).unwrap();
    assert_eq!(&reply[..2], &[0xbe, 0xef]);
    assert_eq!(reply[2] & 0x80, 0x80, "QR");
    assert_eq!(reply[2] & 0x01, 0x01, "RD kept");
    assert_eq!(reply[3] & 0x0f, rcode::REFUSED);
    assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&reply[12..], &query[12..question.end]);
}

#[test]
fn the_cache_expires_names_and_numbers_addresses() {
    let mut cache = Cache::new(Limits {
        min_ttl: 0,
        max_ips_per_name: 2,
    });
    let a: IpAddr = "203.0.113.1".parse().unwrap();
    let b: IpAddr = "203.0.113.2".parse().unwrap();
    let c: IpAddr = "203.0.113.3".parse().unwrap();
    assert!(cache.insert(&["one.example.".into()], &[a], 10, 100));
    assert_eq!(cache.identity(&a), Some(IDENTITY_BASE + 1));
    assert!(cache.insert(&["two.example.".into()], &[b], 30, 100));
    assert_eq!(cache.identity(&b), Some(IDENTITY_BASE + 2));
    // A longer TTL extends without a change to what is allowed.
    assert!(!cache.insert(&["one.example.".into()], &[a], 20, 100));
    assert_eq!(cache.ips(|n| n == "one.example."), [a].into());
    assert!(!cache.expire(119));
    assert!(cache.expire(120), "one.example. expired at 120");
    assert!(cache.ips(|n| n == "one.example.").is_empty());
    assert_eq!(cache.identity(&a), None);
    assert_eq!(
        cache.identity(&b),
        Some(IDENTITY_BASE + 2),
        "numbers are stable"
    );
    // The per-name limit keeps the latest to expire.
    cache.insert(&["two.example.".into()], &[a, c], 60, 100);
    assert_eq!(cache.ips(|n| n == "two.example."), [a, c].into());
    // min-ttl raises a short TTL.
    let mut floor = Cache::new(Limits {
        min_ttl: 300,
        max_ips_per_name: 10,
    });
    floor.insert(&["x.".into()], &[a], 1, 0);
    assert!(!floor.expire(299));
    assert!(floor.expire(300));
    assert!(floor.is_empty());
}
