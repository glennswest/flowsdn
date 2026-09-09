#![allow(clippy::unwrap_used)]
#![cfg(unix)]
use flowsdn_scripttest::{Archive, Engine, State};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt, symlink},
};

fn workspace() -> State {
    State::with_workspace(&std::env::temp_dir(), &std::env::temp_dir()).unwrap()
}

#[test]
fn synthetic_archive_executes_modes_links_rename_and_recursive_removal() {
    let mut state = workspace();
    let archive = Archive::parse(
        "exists input\nchmod 0444 input\nexists --readonly input\n! exists --exec input\nchmod 0555 input\nexists --readonly --exec input\nmkdir nested\nsymlink nested/link -> ../input\ncat nested/link\nstdout '^contents$'\nmv input renamed\n! exists nested/link\nrm nested/link\nsymlink nested/link -> ../renamed\ncmp nested/link renamed\nrm nested renamed\n! exists nested\n! exists renamed\n-- input --\ncontents\n"
    ).unwrap();
    Engine::new().run_archive(&archive, &mut state).unwrap();
    assert_eq!(state.stdout, "contents\n");
}

#[test]
fn numeric_modes_reject_symbolic_negative_and_out_of_range_values() {
    let mut state = workspace();
    let path = state.work_dir().unwrap().join("item");
    fs::write(&path, "data").unwrap();
    let engine = Engine::new();
    engine.run("chmod 0640 item", &mut state).unwrap();
    for script in [
        "chmod u+x item",
        "chmod 888 item",
        "chmod -1 item",
        "chmod 10000 item",
        "chmod 755",
        "chmod '' item",
        "exists --unknown item",
    ] {
        assert!(engine.run(script, &mut state).is_err(), "{script}");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }
    engine
        .run(
            "chmod 000 item\nexists --readonly item\nchmod 0600 item",
            &mut state,
        )
        .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn removal_repairs_unreadable_directories_and_never_follows_symlinks() {
    let outside = workspace();
    let sentinel = outside.work_dir().unwrap().join("sentinel");
    fs::write(&sentinel, "keep").unwrap();
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    fs::create_dir_all(root.join("nested/deeper")).unwrap();
    fs::write(root.join("nested/deeper/value"), "remove").unwrap();
    symlink(outside.work_dir().unwrap(), root.join("nested/outside")).unwrap();
    let engine = Engine::new();
    engine
        .run(
            "chmod 000 nested/deeper\nchmod 000 nested\nrm nested\nrm missing",
            &mut state,
        )
        .unwrap();
    assert!(!root.join("nested").exists());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep");
    fs::create_dir(root.join("unreadable")).unwrap();
    fs::write(root.join("unreadable/value"), "cleanup").unwrap();
    engine.run("chmod 000 unreadable", &mut state).unwrap();
    drop(state);
    assert!(
        !root.exists(),
        "owned workspace cleanup repairs directory permissions"
    );
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "keep");
}

#[test]
fn mutations_cannot_touch_datadir_or_the_owned_root() {
    let data = workspace();
    let sentinel = data.work_dir().unwrap().join("sentinel");
    fs::write(&sentinel, "keep").unwrap();
    let mode = fs::metadata(&sentinel).unwrap().permissions().mode();
    let mut state = State::with_workspace(&std::env::temp_dir(), data.work_dir().unwrap()).unwrap();
    fs::write(state.work_dir().unwrap().join("source"), "source").unwrap();
    let engine = Engine::new();
    engine.run("exists $DATADIR/sentinel", &mut state).unwrap();
    engine.run("symlink root-alias -> .", &mut state).unwrap();
    for script in [
        "rm $DATADIR/sentinel",
        "chmod 000 $DATADIR/sentinel",
        "mv $DATADIR/sentinel moved",
        "mv source $DATADIR/sentinel",
        "symlink $DATADIR/link -> sentinel",
        "rm $WORK",
        "mv $WORK moved",
        "chmod 000 $WORK",
        "chmod 000 root-alias",
        "rm ..",
        "rm ../outside",
    ] {
        assert!(engine.run(script, &mut state).is_err(), "{script}");
    }
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep");
    assert_eq!(fs::metadata(&sentinel).unwrap().permissions().mode(), mode);
    assert_eq!(
        fs::read_to_string(state.work_dir().unwrap().join("source")).unwrap(),
        "source"
    );
}

#[test]
fn recursive_removal_rejects_work_root_aliases_before_touching_entries() {
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    fs::write(root.join("sentinel"), "keep").unwrap();
    symlink(".", root.join("root-alias")).unwrap();
    for path in ["root-alias/", "root-alias/."] {
        assert!(
            Engine::new()
                .run(&format!("rm {path}"), &mut state)
                .is_err()
        );
        assert_eq!(fs::read_to_string(root.join("sentinel")).unwrap(), "keep");
        assert!(fs::symlink_metadata(root.join("root-alias")).is_ok());
    }
}

#[test]
fn cleanup_repairs_restricted_trees_beyond_the_command_depth_budget() {
    let state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    let mut path = root.join("deep");
    let mut directories = vec![path.clone()];
    for _ in 0..130 {
        path.push("d");
        directories.push(path.clone());
    }
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("item"), "cleanup").unwrap();
    for directory in directories.iter().rev() {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o0)).unwrap();
    }
    drop(state);
    assert!(
        !root.exists(),
        "cleanup must repair directories past depth 128"
    );
}

#[test]
fn recursive_removal_has_a_depth_budget() {
    let mut state = workspace();
    let mut path = state.work_dir().unwrap().join("deep");
    for _ in 0..130 {
        path.push("d");
    }
    fs::create_dir_all(path).unwrap();
    let error = Engine::new().run("! rm deep", &mut state).unwrap_err();
    assert!(error.message.contains("128 levels"));
}

#[test]
fn relative_symlinks_are_literal_dangling_links_can_be_removed() {
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    let engine = Engine::new();
    engine
        .run(
            "symlink dangling -> not-yet-created\n! exists dangling",
            &mut state,
        )
        .unwrap();
    assert_eq!(
        fs::read_link(root.join("dangling"))
            .unwrap()
            .to_str()
            .unwrap(),
        "not-yet-created"
    );
    engine
        .run("mv dangling renamed-link\nrm renamed-link", &mut state)
        .unwrap();
    assert!(fs::symlink_metadata(root.join("renamed-link")).is_err());
    engine
        .run(
            "symlink escape -> ../../outside\n! exists escape\nrm escape",
            &mut state,
        )
        .unwrap();
    for script in [
        "symlink bad wrong target",
        "symlink bad -> /outside",
        "symlink bad -> ''",
    ] {
        assert!(engine.run(script, &mut state).is_err());
        assert!(fs::symlink_metadata(root.join("bad")).is_err());
    }
}

#[test]
fn fifo_metadata_rename_chmod_and_removal_do_not_open_io_channels() {
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    let directory = fs::File::open(&root).unwrap();
    rustix::fs::mkfifoat(
        &directory,
        "fifo",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    Engine::new()
        .run(
            "exists fifo\nchmod 0400 fifo\nexists --readonly fifo\nmv fifo renamed",
            &mut state,
        )
        .unwrap();
    assert!(
        fs::metadata(root.join("renamed"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    Engine::new()
        .run("rm renamed\n! exists renamed", &mut state)
        .unwrap();
}

#[test]
fn double_dash_paths_and_rename_replacement_follow_filesystem_semantics() {
    let mut state = workspace();
    let root = state.work_dir().unwrap().to_owned();
    fs::write(root.join("-source"), "new").unwrap();
    fs::write(root.join("destination"), "old").unwrap();
    let engine = Engine::new();
    engine.run("exists -- -source\nchmod -- 0444 -source\nexists --readonly -- -source\nmv -- -source destination", &mut state).unwrap();
    assert_eq!(fs::read_to_string(root.join("destination")).unwrap(), "new");
    engine
        .run(
            "symlink -- -link -> destination\nexists -- -link\nrm -- -link destination",
            &mut state,
        )
        .unwrap();
    assert!(!root.join("destination").exists());
}
