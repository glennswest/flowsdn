#![allow(clippy::unwrap_used)]
use flowsdn_scripttest::{Archive, Control, Engine, RunOptions, State};
use flowsdn_table::{Key, Keyed, Table, TableRender};
use std::{fs, sync::Arc, time::Duration};

#[derive(Clone)]
struct Item {
    id: u8,
    name: String,
}
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        vec![self.id]
    }
}
impl TableRender for Item {
    fn headers() -> &'static [&'static str] {
        &["ID", "Name"]
    }
    fn cells(&self) -> Vec<String> {
        vec![self.id.to_string(), self.name.clone()]
    }
}
fn item(id: u8, name: &str) -> Item {
    Item {
        id,
        name: name.into(),
    }
}
fn table() -> Arc<Table<Item>> {
    Arc::new(Table::new(vec![]).unwrap())
}
fn state() -> State {
    State::with_workspace(&std::env::temp_dir(), &std::env::temp_dir()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn show_uses_primary_key_order_and_exact_aligned_headers() {
    let table = table();
    table.insert(item(2, "longer")).await.unwrap();
    table.insert(item(1, "短")).await.unwrap();
    let mut engine = Engine::new();
    engine.register_table("items", table).unwrap();
    let mut state = State::default();
    engine.run("db/show items", &mut state).unwrap();
    assert_eq!(state.stdout, "ID   Name  \n1    短     \n2    longer\n");
    assert_eq!(state.stderr, "");
    engine
        .run("db/show --columns=Name,ID items --format table", &mut state)
        .unwrap();
    assert_eq!(state.stdout, "Name     ID\n短        1 \nlonger   2 \n");
}

#[tokio::test(flavor = "current_thread")]
async fn bindings_are_independent_and_duplicate_registration_never_replaces() {
    let populated = table();
    populated.insert(item(1, "value")).await.unwrap();
    let empty = table();
    let mut first = Engine::new();
    let mut second = Engine::new();
    first.register_table("items", populated).unwrap();
    second.register_table("items", empty.clone()).unwrap();
    assert!(first.register_table("items", empty).is_err());
    assert!(
        first
            .register_command("db/show", false, |_, _| Ok(Control::Continue))
            .is_err()
    );
    assert!(
        first
            .register_command("db/empty", false, |_, _| Ok(Control::Continue))
            .is_err()
    );
    assert!(first.run("db/empty items", &mut State::default()).is_err());
    second.run("db/empty items", &mut State::default()).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn output_file_is_confined_and_invalid_flags_do_not_change_it() {
    let table = table();
    table.insert(item(1, "one")).await.unwrap();
    let mut engine = Engine::new();
    engine.register_table("items", table).unwrap();
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    let archive = Archive::parse("echo retained\ndb/show items -o actual --columns Name\ncmp actual expected\n-- expected --\nName\none \n").unwrap();
    engine.run_archive(&archive, &mut state).unwrap();
    assert_eq!(state.stdout, "retained\n");
    for script in [
        "db/show items -o actual --columns=name",
        "db/show items -o actual --format=json",
        "db/show items -o actual --format=yaml",
        "db/show items -o actual --columns=ID,ID",
        "db/show items -o actual --out=other",
        "db/show items -o",
        "db/show items --unknown",
        "db/show items extra",
    ] {
        assert!(engine.run(script, &mut state).is_err(), "{script}");
        assert_eq!(
            fs::read_to_string(root.join("actual")).unwrap(),
            "Name\none \n"
        );
    }
    assert!(
        engine
            .run("db/show items -o ../outside", &mut state)
            .is_err()
    );
    assert!(
        engine
            .run("db/show items -o $DATADIR/outside", &mut state)
            .is_err()
    );
}

#[test]
fn empty_and_unknown_table_arguments_are_explicit_errors() {
    let mut engine = Engine::new();
    engine.register_table("one", table()).unwrap();
    engine.register_table("two", table()).unwrap();
    engine
        .run("db/empty one two", &mut State::default())
        .unwrap();
    for script in [
        "db/empty",
        "db/empty one missing",
        "db/show missing",
        "db/show",
        "db/show one --columns=",
        "db/empty --unknown",
    ] {
        assert!(
            engine.run(script, &mut State::default()).is_err(),
            "{script}"
        );
    }
    let mut state = State::default();
    engine.run("db/show one", &mut state).unwrap();
    assert_eq!(state.stdout, "ID   Name\n");
}

#[derive(Clone)]
struct Malformed {
    kind: u8,
}
impl Keyed for Malformed {
    fn primary_key(&self) -> Key {
        vec![self.kind]
    }
}
impl TableRender for Malformed {
    fn headers() -> &'static [&'static str] {
        &["A", "B"]
    }
    fn cells(&self) -> Vec<String> {
        match self.kind {
            0 => vec!["missing".into()],
            1 => vec!["tab\tcell".into(), "x".into()],
            2 => vec!["line\ncell".into(), "x".into()],
            _ => vec!["line\rcell".into(), "x".into()],
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn renderer_validates_cell_count_and_unselected_cell_text() {
    for kind in 0..4 {
        let table = Arc::new(Table::new(vec![]).unwrap());
        table.insert(Malformed { kind }).await.unwrap();
        let mut engine = Engine::new();
        engine.register_table("bad", table).unwrap();
        assert!(
            engine
                .run("db/show bad --columns=B", &mut State::default())
                .is_err()
        );
    }
}

#[derive(Clone)]
struct Padded {
    id: u8,
}
impl Keyed for Padded {
    fn primary_key(&self) -> Key {
        vec![self.id]
    }
}
impl TableRender for Padded {
    fn headers() -> &'static [&'static str] {
        &["Value"]
    }
    fn cells(&self) -> Vec<String> {
        vec![if self.id == 0 {
            "x".repeat(131_072)
        } else {
            String::new()
        }]
    }
}
#[tokio::test(flavor = "current_thread")]
async fn padding_amplification_is_bounded_before_publication_or_file_write() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    for id in 0..65 {
        table.insert(Padded { id }).await.unwrap();
    }
    let mut engine = Engine::new();
    engine.register_table("wide", table).unwrap();
    let mut state = state();
    let target = state.work_dir().unwrap().join("actual");
    fs::write(&target, "retained").unwrap();
    let error = engine
        .run("! db/show wide -o actual", &mut state)
        .unwrap_err();
    assert!(error.message.contains("8 MiB"));
    assert_eq!(fs::read_to_string(target).unwrap(), "retained");
}

#[tokio::test(flavor = "current_thread")]
async fn whole_section_retry_refreshes_live_table_snapshots() {
    let table = table();
    table.insert(item(1, "first")).await.unwrap();
    let changed = table.clone();
    let mut engine = Engine::new();
    engine.register_table("items", table).unwrap();
    let mut state = State::default();
    let mut options = RunOptions::with_timeout(Duration::from_secs(3)).unwrap();
    options.retry_interval = Duration::from_millis(10);
    let update = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        changed.delete_all().await.unwrap();
    });
    engine
        .run_async(
            "# current table\ndb/show items\n* db/empty items",
            &mut state,
            &options,
        )
        .await
        .unwrap();
    assert_eq!(state.stdout, "ID   Name\n");
    assert!(state.retry_count > 0);
    update.await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn output_writer_rejects_fifo_and_escaping_symlinks_without_blocking() {
    use std::os::unix::fs::symlink;
    let outside = state();
    let sentinel = outside.work_dir().unwrap().join("sentinel");
    fs::write(&sentinel, "retained").unwrap();
    let mut state = state();
    let root = state.work_dir().unwrap().to_owned();
    symlink(&sentinel, root.join("escape")).unwrap();
    let directory = fs::File::open(&root).unwrap();
    rustix::fs::mkfifoat(
        &directory,
        "fifo",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let mut engine = Engine::new();
    engine.register_table("items", table()).unwrap();
    for name in ["escape", "fifo"] {
        assert!(
            engine
                .run(&format!("db/show items -o {name}"), &mut state)
                .is_err()
        );
    }
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "retained");
}

#[derive(Clone)]
struct InvalidHeaders;
impl Keyed for InvalidHeaders {
    fn primary_key(&self) -> Key {
        Vec::new()
    }
}
impl TableRender for InvalidHeaders {
    fn headers() -> &'static [&'static str] {
        &["Name", "Name"]
    }
    fn cells(&self) -> Vec<String> {
        vec![]
    }
}
#[test]
fn invalid_headers_fail_before_reserving_a_binding_name() {
    let mut engine = Engine::new();
    let invalid = Arc::new(Table::<InvalidHeaders>::new(vec![]).unwrap());
    assert!(engine.register_table("items", invalid).is_err());
    engine.register_table("items", table()).unwrap();
    engine.run("db/empty items", &mut State::default()).unwrap();
}

#[test]
fn malformed_long_column_arguments_have_bounded_diagnostics() {
    let mut engine = Engine::new();
    engine.register_table("items", table()).unwrap();
    let script = format!("db/show items --columns={}", "x".repeat(100_000));
    let error = engine.run(&script, &mut State::default()).unwrap_err();
    assert!(error.message.len() < 1024);
    assert!(error.message.contains("available columns: ID,Name"));
}

#[derive(Clone)]
struct WideEmpty {
    id: u16,
}
impl Keyed for WideEmpty {
    fn primary_key(&self) -> Key {
        self.id.to_be_bytes().to_vec()
    }
}
impl TableRender for WideEmpty {
    fn headers() -> &'static [&'static str] {
        &[
            "C00", "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11",
            "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23",
            "C24", "C25", "C26", "C27", "C28", "C29", "C30", "C31", "C32", "C33", "C34", "C35",
            "C36", "C37", "C38", "C39", "C40", "C41", "C42", "C43", "C44", "C45", "C46", "C47",
            "C48", "C49", "C50", "C51", "C52", "C53", "C54", "C55", "C56", "C57", "C58", "C59",
            "C60", "C61", "C62", "C63",
        ]
    }
    fn cells(&self) -> Vec<String> {
        panic!("cell-count limit must reject before allocating row cells")
    }
}
#[tokio::test(flavor = "current_thread")]
async fn empty_wide_rows_are_bounded_before_allocating_cell_metadata() {
    let table = Arc::new(Table::new(vec![]).unwrap());
    for id in 0..1024 {
        table.insert(WideEmpty { id }).await.unwrap();
    }
    let mut engine = Engine::new();
    engine.register_table("wide", table).unwrap();
    let error = engine
        .run("! db/show wide", &mut State::default())
        .unwrap_err();
    assert!(error.message.contains("65536 cells"));
}

#[tokio::test(flavor = "current_thread")]
async fn binding_retains_its_validated_headers_even_if_the_trait_changes() {
    // This type and its counter are private to this one test, so parallel
    // fixtures cannot affect the changing-header sequence.
    #[derive(Clone)]
    struct Changing {
        extra_cell: bool,
    }
    impl Keyed for Changing {
        fn primary_key(&self) -> Key {
            vec![1]
        }
    }
    impl TableRender for Changing {
        fn headers() -> &'static [&'static str] {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static CALLS: AtomicUsize = AtomicUsize::new(0);
            if CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                &["Name"]
            } else {
                &["unvalidated\nheader"]
            }
        }
        fn cells(&self) -> Vec<String> {
            if self.extra_cell {
                vec!["value".into(), "extra".into()]
            } else {
                vec!["value".into()]
            }
        }
    }
    let table = Arc::new(Table::new(vec![]).unwrap());
    table.insert(Changing { extra_cell: false }).await.unwrap();
    let mut engine = Engine::new();
    engine.register_table("changing", table.clone()).unwrap();
    assert_eq!(Changing::headers(), &["unvalidated\nheader"]);
    let mut state = State::default();
    engine
        .run("db/show changing --columns=Name", &mut state)
        .unwrap();
    assert_eq!(state.stdout, "Name \nvalue\n");
    let error = engine
        .run("db/show changing --columns=missing", &mut state)
        .unwrap_err();
    assert!(error.message.contains("available columns: Name"));
    assert!(!error.message.contains("unvalidated"));
    table.insert(Changing { extra_cell: true }).await.unwrap();
    assert!(
        engine
            .run("db/show changing", &mut state)
            .unwrap_err()
            .message
            .contains("cells/header count mismatch")
    );
}

#[test]
fn diagnostic_dump_is_bounded_utf8_and_does_not_expose_environment() {
    let engine = Engine::new();
    let mut state = State::default();
    state
        .environment
        .insert("TOKEN".into(), "not-for-artifacts".into());
    state.publish("visible", "failure");
    let text = engine.diagnostic_dump(&state);
    assert!(text.contains("visible") && text.contains("failure"));
    assert!(!text.contains("not-for-artifacts"));
    state.stdout = "界".repeat(400_000);
    let text = engine.diagnostic_dump(&state);
    assert!(text.len() <= 1_048_576);
    assert!(text.ends_with("[diagnostic truncated]\n"));
}
