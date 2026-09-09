#![cfg(all(target_os = "linux", feature = "process-fixture"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use flowsdn_scripttest::{Engine, RunOptions, State};
use std::{fs, path::{Path, PathBuf}, time::Duration};

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
async fn dead(pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Orphan zombies are already terminated; their reaping belongs to
            // their new parent, not to this harness process.
            let status = fs::read_to_string(format!("/proc/{pid}/stat"));
            if status.as_ref().is_err() || status.as_ref().is_ok_and(|text| text.rsplit_once(')').is_some_and(|(_, fields)| fields.trim_start().starts_with('Z'))) { return; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.unwrap();
}

#[test]
fn sync_exec_is_a_harness_error_even_for_negative_assertions() {
    for prefix in ["", "! ", "? "] {
        let error = Engine::new().run(&format!("{prefix}exec ignored"), &mut state()).unwrap_err();
        assert!(error.message.contains("requires run_async"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn child_uses_script_cwd_environment_arguments_and_both_buffers() {
    let mut state = state();
    state.environment.insert("FIXTURE_VALUE".into(), "hello world".into());
    let cwd = std::env::current_dir().unwrap();
    let original_home = std::env::var_os("HOME");
    let options = RunOptions::default();
    Engine::new().run_async("mkdir child\ncd child\nexec $CHILD report '$FIXTURE_VALUE' $FIXTURE_VALUE\nstderr '^diagnostic$'", &mut state, &options).await.unwrap();
    assert!(state.stdout.contains(&format!("cwd={}\n", state.work_dir().unwrap().join("child").display())));
    assert!(state.stdout.contains("value=hello world\nseparator=false\npath_separator=false\nhome=false\n"));
    assert!(state.stdout.contains("args=$FIXTURE_VALUE|hello world\n"));
    assert_eq!(std::env::current_dir().unwrap(), cwd);
    assert_eq!(std::env::var_os("HOME"), original_home);
}

#[tokio::test(flavor = "current_thread")]
async fn exit_expectations_and_conditions_share_the_existing_engine_contract() {
    let mut state = state();
    let options = RunOptions::default();
    let engine = Engine::new();
    let execution = engine.run_async("! exec $CHILD exit 7\n? exec $CHILD exit 8\nexec $CHILD exit 0\n[!linux] exec ignored", &mut state, &options).await.unwrap();
    assert_eq!(execution.commands_run, 3);
    assert_eq!(execution.commands_skipped, 1);
    assert!(engine.run_async("! exec $CHILD exit 0", &mut state, &options).await.unwrap_err().message.contains("unexpected success"));
    assert!(engine.run_async("exec $CHILD exit 2", &mut state, &options).await.unwrap_err().message.contains("process exited"));
    assert!(engine.run_async("exec bare-program", &mut state, &options).await.unwrap_err().message.contains("explicit script PATH"));
}

#[tokio::test(flavor = "current_thread")]
async fn deadline_is_not_an_expected_failure_and_reaps_the_child() {
    let mut state = state();
    let pidfile = state.work_dir().unwrap().join("pid");
    let options = RunOptions::with_timeout(Duration::from_millis(300)).unwrap();
    let error = Engine::new().run_async("! exec $CHILD sleep pid", &mut state, &options).await.unwrap_err();
    assert!(error.message.contains("deadline"));
    let pid = ready(&pidfile).await;
    dead(pid).await;
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists(), "direct child must be reaped");
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_sends_sigint_before_forced_cleanup() {
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let options = RunOptions::default();
    let cancellation = options.cancellation.clone();
    let pidfile = root.join("pid");
    let cancel = tokio::spawn(async move { let pid = ready(&pidfile).await; cancellation.cancel(); pid });
    let error = Engine::new().run_async("? exec $CHILD interrupt pid interrupted", &mut state, &options).await.unwrap_err();
    assert!(error.message.contains("cancelled"));
    assert_eq!(fs::read_to_string(root.join("interrupted")).unwrap(), "interrupted");
    dead(cancel.await.unwrap()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_run_future_still_terminates_and_reaps_child() {
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let pidfile = root.join("pid");
    let task = tokio::spawn(async move { Engine::new().run_async("exec $CHILD sleep pid", &mut state, &RunOptions::default()).await });
    let pid = ready(&pidfile).await;
    task.abort();
    let _ = task.await;
    dead(pid).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while root.exists() { tokio::time::sleep(Duration::from_millis(5)).await; }
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn output_overflow_is_fatal_and_bounded_even_under_negative_status() {
    let mut state = state();
    let error = Engine::new().run_async("! exec $CHILD spam", &mut state, &RunOptions::default()).await.unwrap_err();
    assert!(error.message.contains("8 MiB"));
    assert!(state.stdout.len() <= 8_388_608);
}

#[tokio::test(flavor = "current_thread")]
async fn leader_exit_cleans_descendants_holding_output_pipes() {
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let options = RunOptions::with_timeout(Duration::from_secs(5)).unwrap();
    Engine::new().run_async("exec $CHILD descendant descendant-pid", &mut state, &options).await.unwrap();
    let pid = ready(&root.join("descendant-pid")).await;
    dead(pid).await;
}

#[test]
fn timeout_constructor_rejects_clock_overflow() {
    assert!(RunOptions::with_timeout(Duration::MAX).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_utf8_cannot_hide_a_deadline_behind_negative_status() {
    let mut state = state();
    let options = RunOptions::with_timeout(Duration::from_millis(300)).unwrap();
    let error = Engine::new().run_async("! exec $CHILD invalid-sleep", &mut state, &options).await.unwrap_err();
    assert!(error.message.contains("deadline"), "{error}");
}
