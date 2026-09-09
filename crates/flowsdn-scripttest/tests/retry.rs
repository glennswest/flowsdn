#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{CommandError, Control, Engine, RunOptions, State};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn options() -> RunOptions {
    let mut options = RunOptions::with_timeout(Duration::from_secs(3)).unwrap();
    options.retry_interval = Duration::from_millis(1);
    options.max_retry_interval = Duration::from_millis(5);
    options
}
fn settle(engine: &mut Engine, count: usize) {
    engine
        .register_command("settled", false, move |state, _| {
            if state.retry_count >= count {
                Ok(Control::Continue)
            } else {
                Err(CommandError::Failure("snapshot is stale".into()))
            }
        })
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn retries_reexecute_preceding_commands_conditions_and_expansions() {
    let mut engine = Engine::new();
    engine
        .register_command("refresh", false, |state, _| {
            let next = state
                .environment
                .get("attempt")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or_default()
                .saturating_add(1);
            state.environment.insert("attempt".into(), next.to_string());
            Ok(Control::Continue)
        })
        .unwrap();
    engine
        .register_condition("ready", false, |state, _| Ok(state.retry_count >= 1))
        .unwrap();
    settle(&mut engine, 1);
    let mut state = State::default();
    engine.run_async("# earlier\nenv prior=${prior}x\n# assertion\nrefresh\n[ready] echo $attempt\n* settled", &mut state, &options()).await.unwrap();
    assert_eq!(state.environment.get("prior").unwrap(), "x");
    assert_eq!(state.environment.get("attempt").unwrap(), "2");
    assert_eq!(state.stdout, "2\n");
    assert_eq!(state.retry_count, 1);
    assert!(
        state
            .log
            .iter()
            .any(|line| line.contains("retry succeeded after 1 retries"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn negative_retry_and_persistent_side_effects_use_whole_section() {
    let mut engine = Engine::new();
    engine
        .register_command("eventually-fails", false, |state, _| {
            if state.retry_count >= 2 {
                Err(CommandError::Failure("expected transition".into()))
            } else {
                Ok(Control::Continue)
            }
        })
        .unwrap();
    let mut state = State::default();
    engine
        .run_async(
            "env accumulated=${accumulated}x\n!* eventually-fails",
            &mut state,
            &options(),
        )
        .await
        .unwrap();
    assert_eq!(state.environment.get("accumulated").unwrap(), "xxx");
    assert_eq!(state.retry_count, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn an_ordinary_failure_during_replay_restarts_the_section_again() {
    let mut engine = Engine::new();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    engine
        .register_command("prepare", false, move |_, _| {
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(CommandError::Failure("transient prepare".into()))
            } else {
                Ok(Control::Continue)
            }
        })
        .unwrap();
    settle(&mut engine, 1);
    engine
        .run_async("prepare\n* settled", &mut State::default(), &options())
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn later_unmarked_failure_is_not_retried_after_assertion_succeeds() {
    let mut engine = Engine::new();
    settle(&mut engine, 1);
    let mut state = State::default();
    let error = engine
        .run_async(
            "env attempts=${attempts}x\n* settled\nstdout absent",
            &mut state,
            &options(),
        )
        .await
        .unwrap_err();
    assert!(error.message.contains("pattern"));
    assert_eq!(state.environment.get("attempts").unwrap(), "xx");
}

#[tokio::test(flavor = "current_thread")]
async fn default_backoff_doubles_and_caps_at_five_hundred_milliseconds() {
    let mut engine = Engine::new();
    settle(&mut engine, 4);
    let mut state = State::default();
    engine
        .run_async(
            "* settled",
            &mut state,
            &RunOptions::with_timeout(Duration::from_secs(5)).unwrap(),
        )
        .await
        .unwrap();
    let waits: Vec<_> = state
        .log
        .iter()
        .filter(|line| line.contains("delay "))
        .collect();
    for (line, delay) in waits.iter().zip([100, 200, 400, 500]) {
        assert!(line.contains(&format!("delay {delay} ms")), "{line}");
    }
    assert_eq!(waits.len(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn deadline_reports_section_and_last_failure_without_extra_attempt() {
    let mut engine = Engine::new();
    settle(&mut engine, usize::MAX);
    let mut state = State::default();
    let error = engine
        .run_async(
            "# current snapshot\n* settled",
            &mut state,
            &RunOptions::with_timeout(Duration::from_millis(30)).unwrap(),
        )
        .await
        .unwrap_err();
    for part in [
        "current snapshot",
        "deadline",
        "last failure",
        "snapshot is stale",
    ] {
        assert!(error.message.contains(part), "{error}");
    }
    assert_eq!(state.retry_count, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn nonmaskable_failures_never_retry_even_under_negative_retry() {
    for failure in [
        CommandError::Cancelled,
        CommandError::Deadline,
        CommandError::LimitExceeded("budget"),
        CommandError::ProcessOwnershipLost,
    ] {
        for prefix in ["*", "!*"] {
            let mut engine = Engine::new();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let failure = failure.clone();
            engine
                .register_command("fatal", false, move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Err(failure.clone())
                })
                .unwrap();
            assert!(
                engine
                    .run_async(
                        &format!("{prefix} fatal"),
                        &mut State::default(),
                        &options()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_intervals_and_unsupported_background_retry_are_rejected() {
    let mut invalid = options();
    invalid.retry_interval = Duration::ZERO;
    assert!(
        Engine::new()
            .run_async("echo ignored", &mut State::default(), &invalid)
            .await
            .unwrap_err()
            .message
            .contains("retry intervals")
    );
    for script in ["* exec ignored &", "!* exec ignored &"] {
        assert!(
            Engine::new()
                .run_async(script, &mut State::default(), &options())
                .await
                .unwrap_err()
                .message
                .contains("background exec")
        );
    }
    for script in ["* echo ok", "!* echo ok"] {
        assert!(
            Engine::new()
                .run(script, &mut State::default())
                .unwrap_err()
                .message
                .contains("run_async")
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn retry_count_resets_at_section_boundaries_without_resetting_environment() {
    let mut engine = Engine::new();
    settle(&mut engine, 1);
    engine
        .register_command("fresh", false, |state, _| {
            if state.retry_count == 0 {
                Ok(Control::Continue)
            } else {
                Err(CommandError::Failure("retry count leaked".into()))
            }
        })
        .unwrap();
    let mut state = State::default();
    engine
        .run_async(
            "env kept=value\n* settled\n# next\nfresh",
            &mut state,
            &options(),
        )
        .await
        .unwrap();
    assert_eq!(state.environment.get("kept").unwrap(), "value");
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_during_backoff_reports_the_last_failed_assertion() {
    let mut engine = Engine::new();
    settle(&mut engine, usize::MAX);
    let options = RunOptions::default();
    let cancellation = options.cancellation.clone();
    let cancel = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancellation.cancel();
    });
    let error = engine
        .run_async("# readiness\n* settled", &mut State::default(), &options)
        .await
        .unwrap_err();
    assert!(
        error.message.contains("readiness")
            && error.message.contains("cancelled")
            && error.message.contains("snapshot is stale"),
        "{error}"
    );
    cancel.await.unwrap();
}
