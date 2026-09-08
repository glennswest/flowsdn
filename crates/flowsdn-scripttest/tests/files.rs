#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Archive, Engine, State};
use std::fs;

fn workspace() -> State {
    State::with_workspace(&std::env::temp_dir(), &std::env::temp_dir()).unwrap()
}

#[test]
fn materialization_preserves_bytes_expands_names_and_cleans_owned_root() {
    let root;
    {
        let mut state = workspace();
        root = state.work_dir().unwrap().to_owned();
        state
            .environment
            .insert("name".into(), "nested/value".into());
        let archive = Archive::parse(
            "\n-- ${name} --\n$WORK stays literal\n-- duplicate --\nfirst\n-- duplicate --\nlast",
        )
        .unwrap();
        state.materialize(&archive).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("nested/value")).unwrap(),
            "$WORK stays literal\n"
        );
        assert_eq!(fs::read_to_string(root.join("duplicate")).unwrap(), "last");
        assert!(root.join("tmp").is_dir());
        assert_eq!(
            state.environment.get("PWD").unwrap(),
            root.to_str().unwrap()
        );
        let clone = state.clone();
        drop(state);
        assert!(root.exists(), "a cloned state retains the workspace");
        drop(clone);
    }
    assert!(!root.exists());
}

#[test]
fn synthetic_archive_executes_file_assertions_copy_and_per_script_cd() {
    let mut state = workspace();
    let process_cwd = std::env::current_dir().unwrap();
    let archive = Archive::parse(
        "# file commands\ncat one two\ncmp stdout expected\ncp stdout copied\nmkdir nested\ncp one two nested\ncd nested\ncmp one $WORK/one\ncat one\ngrep --count=1 '^one$' two\n! grep missing one\ncd ..\ncmp copied expected\nempty -t blank\n! empty -t spaces\nstop\n-- one --\none\n-- two --\none two\n-- expected --\none\none two\n-- blank --\n\n\n-- spaces --\n \t\n",
    ).unwrap();
    let error = Engine::new().run_archive(&archive, &mut state).unwrap_err();
    // A mismatched fixture assertion must stop at the actual failing command.
    assert_eq!(error.command, "grep");
    assert!(error.message.contains("pattern count"));
    assert_eq!(std::env::current_dir().unwrap(), process_cwd);
    Engine::new().run("grep --count=1 '^one two$' two\ncd ..\ncmp copied expected\nempty -t blank\n! empty -t spaces", &mut state).unwrap();
    assert_eq!(
        state.environment.get("PWD").unwrap(),
        state.work_dir().unwrap().to_str().unwrap()
    );
}

#[test]
fn cmpenv_expands_both_inputs_and_diff_preserves_missing_newline() {
    let mut state = workspace();
    let archive =
        Archive::parse("env x=value\ncmpenv a b\n! cmp a b\n-- a --\n$x\n-- b --\nvalue\n")
            .unwrap();
    Engine::new().run_archive(&archive, &mut state).unwrap();
    assert!(
        state
            .log
            .iter()
            .any(|entry| entry.contains("--- a\n+++ b\n@@"))
    );
    fs::write(state.work_dir().unwrap().join("a"), "same").unwrap();
    fs::write(state.work_dir().unwrap().join("b"), "same\n").unwrap();
    let before = state.log.len();
    assert!(Engine::new().run("cmp a b", &mut state).is_err());
    assert!(
        state
            .log
            .iter()
            .skip(before)
            .any(|entry| entry.contains("No newline at end of file"))
    );
    let before = state.log.len();
    assert!(Engine::new().run("cmp --quiet a b", &mut state).is_err());
    assert_eq!(state.log.len(), before);
}

#[test]
fn replace_is_single_pass_and_decodes_byte_and_unicode_escapes() {
    let mut state = workspace();
    let archive = Archive::parse(
        "replace a b b c original\ncmp original expected\nreplace '\\n' '\\t' '\\x63' '\\u2603' original\ncmp original final\n-- original --\na b\n-- expected --\nb c\n-- final --\nb ☃\t",
    ).unwrap();
    Engine::new().run_archive(&archive, &mut state).unwrap();
    let bytes = fs::read(state.work_dir().unwrap().join("original")).unwrap();
    assert_eq!(bytes, "b ☃\t".as_bytes());
    for command in [
        "replace '' value original",
        "replace '\\q' value original",
        "replace one original",
    ] {
        assert!(Engine::new().run(command, &mut state).is_err());
        assert_eq!(
            fs::read(state.work_dir().unwrap().join("original")).unwrap(),
            bytes
        );
    }
}

#[test]
fn sed_runs_per_line_and_capture_replacement_does_not_expand_environment() {
    let mut state = workspace();
    let archive = Archive::parse(
        "env 1=wrong\nsed '^(a)([0-9])$' '${2}-$1-$$' original\ncmp original expected\nsed '^' X original\ncmp original prefixed\n-- original --\na1\na2\n-- expected --\n1-a-$\n2-a-$\n-- prefixed --\nX1-a-$\nX2-a-$\nX",
    ).unwrap();
    Engine::new().run_archive(&archive, &mut state).unwrap();
}

#[test]
fn binary_compare_and_copy_are_exact_but_text_commands_reject_invalid_utf8() {
    let mut state = workspace();
    fs::write(state.work_dir().unwrap().join("binary"), [0, 255, 1]).unwrap();
    Engine::new()
        .run("cp binary duplicate\ncmp binary duplicate", &mut state)
        .unwrap();
    assert_eq!(
        fs::read(state.work_dir().unwrap().join("duplicate")).unwrap(),
        [0, 255, 1]
    );
    assert!(
        Engine::new()
            .run("cat binary", &mut state)
            .unwrap_err()
            .message
            .contains("UTF-8")
    );
    assert!(
        Engine::new()
            .run("grep pattern binary", &mut state)
            .is_err()
    );
}

#[test]
fn paths_cannot_escape_workspace_or_modify_read_only_data_directory() {
    let outside = workspace();
    let outside_root = outside.work_dir().unwrap().to_owned();
    fs::write(outside_root.join("sentinel"), "unchanged").unwrap();
    let mut state = State::with_workspace(&std::env::temp_dir(), &outside_root).unwrap();
    for name in ["../escaped", "/absolute-escape"] {
        let archive = Archive::parse(&format!("-- {name} --\nnot allowed")).unwrap();
        assert!(state.materialize(&archive).is_err());
    }
    let sibling_prefix = format!("{}-other/file", state.work_dir().unwrap().display());
    assert!(
        state
            .materialize(&Archive::parse(&format!("-- {sibling_prefix} --\nnot allowed")).unwrap())
            .is_err()
    );
    Engine::new()
        .run("cat $DATADIR/sentinel\nstdout '^unchanged$'", &mut state)
        .unwrap();
    for script in ["cp stdout $DATADIR/sentinel", "mkdir ../escaped", "cd .."] {
        assert!(Engine::new().run(script, &mut state).is_err());
    }
    assert_eq!(
        fs::read_to_string(outside_root.join("sentinel")).unwrap(),
        "unchanged"
    );
}

#[cfg(unix)]
#[test]
fn symlink_escapes_are_denied_and_cleanup_does_not_follow_them() {
    use std::os::unix::fs::symlink;
    let outside = workspace();
    let target = outside.work_dir().unwrap().join("sentinel");
    fs::write(&target, "unchanged").unwrap();
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    symlink(outside.work_dir().unwrap(), root.join("escape")).unwrap();
    Engine::new().run("echo changed", &mut state).unwrap();
    assert!(
        Engine::new()
            .run("cp stdout escape/sentinel", &mut state)
            .is_err()
    );
    assert!(
        state
            .materialize(&Archive::parse("-- escape/sentinel --\nchanged").unwrap())
            .is_err()
    );
    drop(state);
    assert!(!root.exists());
    assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
}

#[test]
fn file_size_limit_and_unimplemented_flags_fail_explicitly() {
    let mut state = workspace();
    fs::File::create(state.work_dir().unwrap().join("large"))
        .unwrap()
        .set_len(8_388_609)
        .unwrap();
    assert!(
        Engine::new()
            .run("cat large", &mut state)
            .unwrap_err()
            .message
            .contains("8 MiB")
    );
    assert!(
        Engine::new()
            .run_archive(
                &Archive::parse("#! --agent-option=true\necho ignored").unwrap(),
                &mut state
            )
            .is_err()
    );
    assert!(
        Engine::new()
            .run("cmp --update large large", &mut state)
            .is_err()
    );
    assert!(
        Engine::new()
            .run("cat missing", &mut State::default())
            .unwrap_err()
            .message
            .contains("working directory")
    );
}

#[test]
fn cmpenv_caps_repeated_substitutions_while_building_output() {
    let mut state = workspace();
    state.environment.insert("x".into(), "v".repeat(2048));
    fs::write(
        state.work_dir().unwrap().join("expanding"),
        "$x".repeat(4097),
    )
    .unwrap();
    fs::write(state.work_dir().unwrap().join("expected"), "").unwrap();
    let error = Engine::new()
        .run("cmpenv expanding expected", &mut state)
        .unwrap_err();
    assert!(error.message.contains("expansion exceeds byte limit"));
    assert!(state.log.is_empty());
}

#[test]
fn individual_diffs_and_cumulative_grep_logs_have_hard_limits() {
    let mut state = workspace();
    fs::write(state.work_dir().unwrap().join("left"), "a".repeat(40_000)).unwrap();
    fs::write(state.work_dir().unwrap().join("right"), "b".repeat(40_000)).unwrap();
    // Quota exhaustion is a harness error, not an expected comparison failure.
    let error = Engine::new()
        .run("! cmp left right", &mut state)
        .unwrap_err();
    assert!(error.message.contains("64 KiB"));
    assert!(state.log.is_empty());
    let line = format!("{}\n", "a".repeat(512));
    fs::write(state.work_dir().unwrap().join("matches"), line.repeat(2200)).unwrap();
    let error = Engine::new()
        .run("? grep a matches", &mut state)
        .unwrap_err();
    assert!(error.message.contains("script log exceeds"));
    assert!(state.log.iter().map(String::len).sum::<usize>() <= 1_048_576);
    assert!(state.log.len() <= 4096);
}

#[cfg(unix)]
#[test]
fn fifo_reads_writes_and_materialization_fail_without_opening_a_peer() {
    use std::os::unix::fs::symlink;
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    let directory = fs::File::open(&root).unwrap();
    rustix::fs::mkfifoat(
        &directory,
        "fifo",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    symlink("fifo", root.join("link")).unwrap();
    state.stdout = "must not write to a pipe".into();
    for command in ["cat fifo", "cat link", "cp stdout fifo", "cp stdout link"] {
        assert!(Engine::new().run(command, &mut state).is_err(), "{command}");
    }
    assert!(
        state
            .materialize(&Archive::parse("-- fifo --\ncontent").unwrap())
            .is_err()
    );
    assert!(
        state
            .materialize(&Archive::parse("-- link --\ncontent").unwrap())
            .is_err()
    );
}
