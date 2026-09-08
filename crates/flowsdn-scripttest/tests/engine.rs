#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Archive, CommandError, Control, Engine, State};
use std::collections::BTreeMap;

#[test]
fn synthetic_txtar_executes_environment_output_and_stop() {
    let archive = Archive::parse(
        "# Populate values\nenv name=world\necho hello $name\nstdout '^hello world$'\nenv --from-stdout greeting\n# Expected failures are assertions\n! stdout absent\n? stdout absent\necho '$greeting' ${greeting}\nstdout '^\\$greeting hello world$'\n! stop 'finished successfully'\nunknown-after-stop\n-- expected --\n$greeting hello world\n",
    ).unwrap();
    let mut state = State::default();
    let execution = Engine::new().run(archive.script(), &mut state).unwrap();
    assert!(execution.stopped);
    assert_eq!(execution.commands_run, 9);
    assert_eq!(state.stdout, archive.files().first().unwrap().data());
    assert_eq!(state.environment.get("greeting").unwrap(), "hello world");
    assert!(state.log.iter().any(|message| message == "finished successfully"));
}

#[test]
fn conditions_select_commands_and_validate_prefix_arity() {
    let mut engine = Engine::new();
    engine.register_condition("enabled", false, |state, _| Ok(state.environment.contains_key("enabled"))).unwrap();
    engine.register_condition("feature", true, |_, suffix| Ok(suffix == "present")).unwrap();
    let mut state = State::default();
    let execution = engine.run(
        "[enabled] echo skipped\n[!enabled] [feature:present] echo chosen\n[feature:missing] echo skipped\n",
        &mut state,
    ).unwrap();
    assert_eq!(execution.commands_run, 1);
    assert_eq!(execution.commands_skipped, 2);
    assert_eq!(state.stdout, "chosen\n");
    for script in [
        "[unknown] echo x", "[feature] echo x", "[feature:] echo x", "[enabled:suffix] echo x",
        "[enabled] [unknown] echo x",
    ] {
        let error = engine.run(script, &mut state).unwrap_err();
        assert_eq!(error.line, 1);
        assert!(error.message.contains("condition"));
    }
}

#[test]
fn cancellation_and_deadlines_never_satisfy_negative_assertions() {
    let mut engine = Engine::new();
    engine.register_command("cancel", false, |_, _| Err(CommandError::Cancelled)).unwrap();
    engine.register_command("deadline", false, |_, _| Err(CommandError::Deadline)).unwrap();
    for command in ["cancel", "deadline"] {
        for prefix in ["", "! ", "? "] {
            let mut state = State::default();
            let error = engine.run(&format!("{prefix}{command}\necho must-not-run"), &mut state).unwrap_err();
            assert_eq!(error.line, 1);
            assert!(state.stdout.is_empty());
        }
    }
}

#[test]
fn mismatched_status_stops_before_the_next_command() {
    for script in ["! echo succeeded\necho must-not-run", "stdout absent\necho must-not-run"] {
        let mut state = State::default();
        let error = Engine::new().run(script, &mut state).unwrap_err();
        assert_eq!(error.line, 1);
        assert!(!state.stdout.contains("must-not-run"));
    }
    let mut state = State::default();
    let execution = Engine::new().run("? echo success\n! stdout missing\necho final", &mut state).unwrap();
    assert_eq!(execution.commands_run, 3);
    assert_eq!(state.stdout, "final\n");
}

#[test]
fn unsupported_constructs_and_unknown_commands_cannot_hide_behind_status() {
    for script in ["! missing", "? missing", "echo x &", "* echo x", "!* stdout x"] {
        let mut state = State::default();
        assert!(Engine::new().run(script, &mut state).is_err(), "{script}");
        assert!(state.stdout.is_empty());
    }
    let error = Engine::new().run("# first\necho 'unterminated", &mut State::default()).unwrap_err();
    assert_eq!(error.line, 2);
    let error = Engine::new().run("! echo ${broken", &mut State::default()).unwrap_err();
    assert!(error.message.contains("variable"));
}

#[test]
fn output_publication_and_expected_failures_preserve_buffers() {
    let mut engine = Engine::new();
    engine.register_command("produce", false, |state, _| {
        state.publish("out\n", "err\n");
        Err(CommandError::Failure("deliberate".into()))
    }).unwrap();
    let mut state = State::default();
    engine.run("! produce\nstdout '^out$'\nstderr '^err$'\nenv name=value", &mut state).unwrap();
    assert_eq!(state.stdout, "out\n");
    assert_eq!(state.stderr, "err\n");
    engine.run("echo replacement", &mut state).unwrap();
    assert_eq!(state.stdout, "replacement\n");
    assert!(state.stderr.is_empty());
}

#[test]
fn pattern_substitutions_are_literal_and_flags_select_pattern_argument() {
    let mut state = State::new(BTreeMap::from([("path".into(), "/tmp/a.b+[c]".into())]));
    let engine = Engine::new();
    engine.run("echo $path\nstdout -q --count=1 ^${path}$\n! stdout '^/tmp/axb'", &mut state).unwrap();
    engine.run("env pattern=-a.b\necho -a.b\nstdout -- $pattern", &mut state).unwrap();
    assert_eq!(state.stdout, "-a.b\n");
    engine.run("! stdout --count=2 -- $pattern", &mut state).unwrap();
}

#[test]
fn environment_dump_queries_and_mutations_have_deterministic_output() {
    let mut state = State::default();
    let engine = Engine::new();
    engine.run("env b=second a=first\nenv a b missing", &mut state).unwrap();
    assert_eq!(state.stdout, "a=first\nb=second\nmissing=\n");
    engine.run("env", &mut state).unwrap();
    let lines: Vec<_> = state.stdout.lines().collect();
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(lines, sorted);
    assert!(state.environment.contains_key("/"));
    assert!(state.environment.contains_key(":"));
    engine.run("echo '  shared value  '\nenv --from-stdout a b", &mut state).unwrap();
    assert_eq!(state.environment.get("a").unwrap(), "shared value");
    assert_eq!(state.environment.get("b").unwrap(), "shared value");
}

#[test]
fn registry_collisions_and_execution_budget_are_explicit() {
    let mut engine = Engine::new();
    assert!(engine.register_command("echo", false, |_, _| Ok(Control::Continue)).is_err());
    assert!(engine.register_command("", false, |_, _| Ok(Control::Continue)).is_err());
    assert!(engine.register_condition("linux", false, |_, _| Ok(true)).is_err());
    assert!(engine.register_condition("bad:suffix", true, |_, _| Ok(true)).is_err());
    engine.set_max_commands(1);
    let mut state = State::default();
    let error = engine.run("echo first\necho second", &mut state).unwrap_err();
    assert_eq!(error.line, 2);
    assert!(error.message.contains("limit"));
    assert_eq!(state.stdout, "first\n");
}
