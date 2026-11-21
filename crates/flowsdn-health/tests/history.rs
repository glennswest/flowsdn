//! #456: the health history appends lines and keeps three rotated files.
use flowsdn_health::history::{History, KEPT, read};

fn dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("flowsdn-health-history-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

#[test]
fn appends_rotates_and_reads_back() {
    let dir = dir();
    let path = dir.join("flowsdn-agent-health-history.log");
    // 40 bytes per file: 3 lines of 12 (+ newline) each.
    let mut history = History::open(&path, 40).expect("open");
    for n in 0..12 {
        history
            .append(&format!("{{\"n\":{n:05}}}"))
            .expect("append");
    }
    let files: Vec<_> = std::fs::read_dir(&dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), KEPT, "{files:?}");
    for file in [".log", ".log.1", ".log.2"] {
        let full = dir.join(format!("flowsdn-agent-health-history{file}"));
        let size = std::fs::metadata(&full).expect("rotated file").len();
        assert!(size <= 40, "{file}: {size} bytes");
    }
    // The oldest lines rotated away; the newest are kept, in order.
    let lines = read(&path, 100).expect("read");
    assert_eq!(lines.len(), 9);
    assert_eq!(lines.first().map(String::as_str), Some("{\"n\":00003}"));
    assert_eq!(lines.last().map(String::as_str), Some("{\"n\":00011}"));
    assert_eq!(read(&path, 2).expect("read").len(), 2);
    // Reopening appends to the current file.
    let mut again = History::open(&path, 40).expect("reopen");
    again.append("{\"n\":99999}").expect("append");
    assert_eq!(
        read(&path, 1).expect("read").first().map(String::as_str),
        Some("{\"n\":99999}")
    );
    assert!(
        read(&dir.join("missing.log"), 10)
            .expect("missing")
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
