#![cfg(all(target_os = "linux", feature = "process-fixture"))]
#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Engine, RunOptions, State};
use std::{fs, path::Path, time::Duration};

fn state() -> State {
    let mut state = State::with_workspace(&std::env::temp_dir(), &std::env::temp_dir()).unwrap();
    state.environment.insert("CHILD".into(), env!("CARGO_BIN_EXE_scripttest-fixture").into());
    state
}
async fn ready(path: &Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(value) = fs::read_to_string(path) {
                if let Ok(pid) = value.parse() { return pid; }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.unwrap()
}
async fn removed(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while path.exists() { tokio::time::sleep(Duration::from_millis(5)).await; }
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn launch_clears_buffers_wait_aggregates_in_launch_order() {
    let mut state = state();
    Engine::new().run_async(
        "echo previous\nexec $CHILD delayed-output 100 first &\nempty stdout\nempty stderr\nexec $CHILD delayed-output 0 second &\nwait",
        &mut state, &RunOptions::default(),
    ).await.unwrap();
    assert_eq!(state.stdout, "first\nsecond\n");
    assert_eq!(state.stderr, "err:first\nerr:second\n");
    let output_logs: Vec<_> = state.log.iter().filter(|line| line.contains("[stdout]")).collect();
    assert!(output_logs.first().unwrap().contains("first"));
    assert!(output_logs.get(1).unwrap().contains("second"));
    Engine::new().run_async("wait", &mut state, &RunOptions::default()).await.unwrap();
    assert_eq!(state.stdout, "");
    assert_eq!(state.stderr, "");
}

#[tokio::test(flavor = "current_thread")]
async fn background_jobs_snapshot_environment_and_cwd_at_launch() {
    let mut state = state();
    Engine::new().run_async("mkdir first\ncd first\nenv FIXTURE_VALUE=before\nexec $CHILD report &\ncd ..\nenv FIXTURE_VALUE=after\nwait", &mut state, &RunOptions::default()).await.unwrap();
    assert!(state.stdout.contains("value=before\n"));
    assert!(state.stdout.contains(&format!("cwd={}\n", state.work_dir().unwrap().join("first").display())));
}

#[tokio::test(flavor = "current_thread")]
async fn wait_applies_each_job_status_and_joins_all_unexpected_exits() {
    let mut state = state();
    let engine = Engine::new();
    engine.run_async("! exec $CHILD exit 7 &\n? exec $CHILD exit 8 &\nexec $CHILD exit 0 &\nwait", &mut state, &RunOptions::default()).await.unwrap();
    let error = engine.run_async("exec $CHILD exit 7 &\nexec $CHILD exit 8 &\nwait", &mut state, &RunOptions::default()).await.unwrap_err();
    assert!(error.message.contains("line 1:"));
    assert!(error.message.contains("line 2:"));
    assert!(error.message.contains("7"));
    assert!(error.message.contains("8"));
    let error = engine.run_async("! exec $CHILD exit 0 &\nwait", &mut state, &RunOptions::default()).await.unwrap_err();
    assert!(error.message.contains("unexpected success"));
}

#[tokio::test(flavor = "current_thread")]
async fn wait_flags_and_non_async_background_commands_are_harness_errors() {
    for script in ["! wait --all", "? wait extra", "echo no &", "wait &"] {
        let error = Engine::new().run_async(script, &mut state(), &RunOptions::default()).await.unwrap_err();
        assert!(error.message.contains("wait takes no arguments") || error.message.contains("only exec"), "{error}");
    }
    for script in ["exec ignored &", "! wait"] {
        assert!(Engine::new().run(script, &mut state()).unwrap_err().message.contains("run_async"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn normal_end_stop_and_script_error_cancel_and_reap_pending_children() {
    for ending in ["", "\nstop", "\nunknown-command"] {
        let mut state = state();
        let root = state.work_dir().unwrap().to_owned();
        let error = Engine::new().run_async(&format!("exec $CHILD sleep pid &\nexec $CHILD await-file pid{ending}"), &mut state, &RunOptions::default()).await.unwrap_err();
        assert!(error.message.contains("cancelled"), "{error}");
        let pid = ready(&root.join("pid")).await;
        assert!(!Path::new(&format!("/proc/{pid}")).exists(), "direct child must be reaped");
        drop(state);
        removed(&root).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_wait_cleans_all_jobs_and_workspace() {
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let task = tokio::spawn(async move {
        Engine::new().run_async("exec $CHILD sleep first &\nexec $CHILD sleep second &\nwait", &mut state, &RunOptions::default()).await
    });
    let first = ready(&root.join("first")).await;
    let second = ready(&root.join("second")).await;
    task.abort();
    let _ = task.await;
    removed(&root).await;
    assert!(!Path::new(&format!("/proc/{first}")).exists());
    assert!(!Path::new(&format!("/proc/{second}")).exists());
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_during_wait_cannot_be_hidden_by_job_or_wait_status() {
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let options = RunOptions::default();
    let cancellation = options.cancellation.clone();
    let cancel = tokio::spawn(async move { ready(&root.join("pid")).await; cancellation.cancel(); });
    let error = Engine::new().run_async("! exec $CHILD sleep pid &\n! wait", &mut state, &options).await.unwrap_err();
    assert!(error.message.contains("cancelled"), "{error}");
    cancel.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn queued_output_is_bounded_across_jobs_before_aggregation() {
    let mut state = state();
    let error = Engine::new().run_async("exec $CHILD bytes 600 &\nexec $CHILD bytes 600 &\n! wait", &mut state, &RunOptions::default()).await.unwrap_err();
    assert!(error.message.contains("8 MiB combined"), "{error}");
    assert!(state.stdout.len().saturating_add(state.stderr.len()) <= 8_388_608);
}

#[tokio::test(flavor = "current_thread")]
async fn job_count_is_bounded_and_failure_cleans_previously_started_jobs() {
    let mut state = state();
    let script = "exec $CHILD exit 0 &\n".repeat(33);
    let error = Engine::new().run_async(&script, &mut state, &RunOptions::default()).await.unwrap_err();
    assert!(error.message.contains("job limit of 32"), "{error}");
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_errors_are_deferred_to_the_jobs_own_expected_status() {
    let mut state = state();
    Engine::new().run_async("! exec /nonexistent/fixture-program &\nwait", &mut state, &RunOptions::default()).await.unwrap();
    assert!(state.log.iter().any(|line| line.contains("expected failure")));
}

#[tokio::test(flavor = "current_thread")]
async fn background_invalid_utf8_preserves_deadline_and_drains_other_jobs() {
    let mut state = state();
    let options = RunOptions::with_timeout(Duration::from_millis(300)).unwrap();
    let error = Engine::new().run_async("! exec $CHILD invalid-sleep &\nexec $CHILD exit 0 &\n! wait", &mut state, &options).await.unwrap_err();
    assert!(error.message.contains("deadline"), "{error}");
}
