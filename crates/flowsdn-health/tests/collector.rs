//! #456: probe scheduling and staleness, with injected times, and one real
//! probe thread.
use flowsdn_health::{
    State,
    collector::{Collector, Thresholds},
};
use std::time::{Duration, Instant};

#[test]
fn staleness_follows_the_thresholds() {
    let t = Thresholds::default();
    let start = Instant::now();
    let at = |secs| start + Duration::from_secs(secs);
    let c: Collector<&'static str> = Collector::new();
    c.register("kubernetes", start);
    c.register("api", start);
    assert!(!c.ran_once(), "nothing ran yet");
    assert_eq!(c.stale(at(5), &t), None, "young and unrun is not stale");
    c.begin("api", at(1));
    c.finish("api", at(1), "ok");
    c.begin("kubernetes", at(1));
    c.finish("kubernetes", at(2), "synced");
    assert!(c.ran_once());
    assert_eq!(c.last("kubernetes"), Some("synced"));
    // kubernetes starts a run and never finishes it: stuck.
    c.begin("kubernetes", at(10));
    c.begin("api", at(10));
    c.finish("api", at(10), "ok");
    assert_eq!(
        c.stale(at(20), &t),
        None,
        "10 s outstanding is under the warning"
    );
    c.begin("api", at(25));
    c.finish("api", at(25), "ok");
    let (state, message) = c.stale(at(26), &t).expect("warning");
    assert_eq!(state, State::Warning);
    assert_eq!(message, "probe kubernetes has not completed for 16s");
    let (state, message) = c.stale(at(71), &t).expect("failure");
    assert_eq!(state, State::Failure);
    assert!(
        message.starts_with("probe kubernetes has not completed for 61s"),
        "{message}"
    );
    // The last result stays readable while the probe is stuck.
    assert_eq!(c.last("kubernetes"), Some("synced"));
    // A probe whose thread stopped running it: its result ages out.
    let quiet: Collector<u8> = Collector::new();
    quiet.register("p", start);
    quiet.begin("p", at(0));
    quiet.finish("p", at(0), 1);
    assert_eq!(
        quiet.stale(at(61), &t),
        Some((State::Failure, "probe p has no result for 61s".into()))
    );
    // Never finished at all: outstanding since registration.
    let never: Collector<u8> = Collector::new();
    never.register("p", start);
    assert_eq!(
        never.stale(at(16), &t).map(|(s, _)| s),
        Some(State::Warning)
    );
}

#[test]
fn spawned_probes_run_repeatedly() {
    let c: Collector<u32> = Collector::new();
    let mut n = 0u32;
    c.spawn("count", Duration::from_millis(10), move || {
        n = n.saturating_add(1);
        n
    })
    .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.last("count").unwrap_or(0) < 3 {
        assert!(
            Instant::now() < deadline,
            "the probe thread did not run three times"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(c.ran_once());
    assert_eq!(c.stale(Instant::now(), &Thresholds::default()), None);
}
