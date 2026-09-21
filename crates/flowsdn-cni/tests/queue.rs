use flowsdn_cni::{
    CniError,
    delete::DeleteRequest,
    queue::{MAX_ENTRIES, Queue, ReplayRequest},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const WAIT: Duration = Duration::from_secs(3);
// Durable publication serializes fsyncs; allow slow storage without changing
// the explicit timeout assertions or the production deletion-client budget.
const IO_WAIT: Duration = Duration::from_secs(60);

struct Temp {
    path: PathBuf,
}
impl Temp {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "flowsdn-queue-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test directory: {e}"),
            }
        }
    }
    fn queue(&self) -> Queue {
        Queue::open(self.path.join("queue")).expect("open queue")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn request(container_id: &str, ifname: &str) -> DeleteRequest {
    DeleteRequest {
        container_id: container_id.into(),
        ifname: ifname.into(),
        netns: None,
        delegated_ipam: false,
    }
}

#[test]
fn durable_wire_names_modes_deduplication_and_replay() {
    let temp = Temp::new();
    let queue = temp.queue();
    let single = request("container-one", "eth0");
    let batch = request("container-two", "");
    {
        let mut guard = queue.lock_shared(IO_WAIT).expect("shared");
        guard.enqueue(&single).expect("single");
        guard.enqueue(&single).expect("duplicate");
        guard.enqueue(&batch).expect("batch");
    }
    assert_eq!(
        fs::metadata(temp.path.join("queue"))
            .expect("directory")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    for (req, expected) in [
        (&single, b"container-one:eth0".as_slice()),
        (&batch, br#"{"container-id":"container-two"}"#.as_slice()),
    ] {
        assert_eq!(req.queue_contents().expect("wire"), expected);
        let path = temp
            .path
            .join("queue")
            .join(format!("{:x}.delete", Sha256::digest(expected)));
        assert_eq!(fs::read(&path).expect("durable entry"), expected);
        assert_eq!(
            fs::metadata(path).expect("mode").permissions().mode() & 0o777,
            0o644
        );
    }
    drop(queue);
    let queue = temp.queue();
    let mut replay = queue.lock_exclusive(IO_WAIT).expect("exclusive");
    let entries = replay.entries().expect("entries");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|e| e.request
        == Ok(ReplayRequest::Container {
            container_id: "container-two".into()
        })));
    assert!(entries.iter().any(|e| e.request
        == Ok(ReplayRequest::Attachment {
            container_id: "container-one".into(),
            ifname: "eth0".into(),
        })));
    for entry in entries {
        replay.remove(&entry).expect("remove");
        replay.remove(&entry).expect("repeat remove");
    }
    assert!(replay.entries().expect("empty replay").is_empty());
    assert_eq!(
        fs::read_dir(temp.path.join("queue"))
            .expect("directory")
            .count(),
        1
    );
}

#[test]
fn shared_and_exclusive_locks_obey_timeout_and_drop_releases_them() {
    let temp = Temp::new();
    let queue = temp.queue();
    let shared = queue.lock_shared(WAIT).expect("shared");
    let other = queue
        .lock_shared(Duration::ZERO)
        .expect("simultaneous shared");
    let start = Instant::now();
    let copy = queue.clone();
    let result =
        std::thread::spawn(move || copy.lock_exclusive(Duration::from_millis(30)).is_err())
            .join()
            .expect("lock thread");
    assert!(result);
    assert!(start.elapsed() >= Duration::from_millis(30));
    assert!(start.elapsed() < WAIT);
    drop(shared);
    assert!(queue.lock_exclusive(Duration::ZERO).is_err());
    drop(other);
    let exclusive = queue.lock_exclusive(WAIT).expect("released shared locks");
    assert!(queue.lock_shared(Duration::from_millis(10)).is_err());
    assert!(queue.lock_exclusive(Duration::ZERO).is_err());
    drop(exclusive);
    assert!(queue.lock_shared(Duration::ZERO).is_ok());
}

#[test]
fn concurrent_shared_writers_cannot_exceed_the_cap_and_duplicates_still_succeed() {
    let temp = Temp::new();
    let queue = temp.queue();
    {
        let mut guard = queue.lock_shared(IO_WAIT).expect("shared");
        for number in 0..MAX_ENTRIES.saturating_sub(1) {
            guard
                .enqueue(&request(&format!("prefill-{number}"), "eth0"))
                .expect("prefill");
        }
    }
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for number in 0..8 {
        let queue = queue.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let guard = queue.lock_shared(IO_WAIT);
            // Reach the barrier even if acquiring the protocol lock failed.
            barrier.wait();
            guard?.enqueue(&request(&format!("racer-{number}"), "eth0"))
        }));
    }
    // Join every worker before assertions can unwind the temporary directory.
    let results: Vec<_> = threads.into_iter().map(|thread| thread.join()).collect();
    let mut successes = 0_usize;
    for result in results {
        match result.expect("writer") {
            Ok(()) => successes = successes.saturating_add(1),
            Err(error) => assert_eq!(
                error,
                CniError::internal("deletion queue directory has too many entries; aborting"),
                "race loser must report capacity exhaustion, not a lock or I/O failure"
            ),
        }
    }
    assert_eq!(successes, 1);
    // Wait for exclusive access, which cannot succeed until every writer has
    // left its shared guard. Exactly one race winner can publish the last slot.
    let replay = queue.lock_exclusive(IO_WAIT).expect("writers finished");
    assert_eq!(replay.entries().expect("entries").len(), MAX_ENTRIES);
    drop(replay);
    let mut guard = queue.lock_shared(IO_WAIT).expect("shared");
    guard
        .enqueue(&request("prefill-0", "eth0"))
        .expect("dedupe even at capacity");
    assert_eq!(
        guard.enqueue(&request("overflow", "eth0")),
        Err(CniError::internal(
            "deletion queue directory has too many entries; aborting"
        ))
    );
}

#[test]
fn concurrent_duplicate_writers_publish_one_complete_entry() {
    let temp = Temp::new();
    let queue = temp.queue();
    let mut threads = Vec::new();
    for _ in 0..8 {
        let queue = queue.clone();
        threads.push(std::thread::spawn(move || {
            queue
                .lock_shared(IO_WAIT)?
                .enqueue(&request("same", "eth0"))
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|thread| thread.join()).collect();
    for result in results {
        result.expect("writer").expect("dedupe");
    }
    assert_eq!(
        queue
            .lock_exclusive(IO_WAIT)
            .expect("exclusive")
            .entries()
            .expect("entries")
            .len(),
        1
    );
}

#[test]
fn invalid_entries_are_individual_errors_removable_without_following_symlinks() {
    let temp = Temp::new();
    let queue = temp.queue();
    let directory = temp.path.join("queue");
    fs::write(directory.join("bad.delete"), b"not-an-attachment").expect("invalid");
    fs::write(directory.join("json.delete"), br#"{"unrelated":true}"#).expect("invalid JSON shape");
    fs::write(directory.join("utf8.delete"), [255u8]).expect("invalid UTF8");
    fs::write(directory.join(".old-task.tmp"), b"preserve me").expect("old temp");
    let outside = temp.path.join("outside");
    fs::write(&outside, b"outside:eth0").expect("outside");
    symlink(&outside, directory.join("link.delete")).expect("symlink");
    let mut replay = queue.lock_exclusive(IO_WAIT).expect("exclusive");
    let entries = replay.entries().expect("entries including invalid");
    assert_eq!(entries.len(), 4);
    for entry in entries {
        assert!(
            entry.request.is_err(),
            "{}",
            entry.filename().to_string_lossy()
        );
        replay.remove(&entry).expect("remove invalid entry");
    }
    assert_eq!(
        fs::read(outside).expect("outside preserved"),
        b"outside:eth0"
    );
    assert_eq!(
        fs::read(directory.join(".old-task.tmp")).expect("old temp preserved"),
        b"preserve me"
    );
}

#[test]
fn conflicting_contents_and_cross_queue_removal_are_rejected() {
    let first = Temp::new();
    let second = Temp::new();
    let queue = first.queue();
    let req = request("container", "eth0");
    let filename = format!(
        "{:x}.delete",
        Sha256::digest(req.queue_contents().expect("wire"))
    );
    fs::write(first.path.join("queue").join(filename), b"different:eth0").expect("corrupt entry");
    assert!(
        queue
            .lock_shared(IO_WAIT)
            .expect("shared")
            .enqueue(&req)
            .is_err()
    );
    let replay = queue.lock_exclusive(IO_WAIT).expect("exclusive");
    let entry = replay.entries().expect("entries").pop().expect("entry");
    let other = second.queue();
    assert!(
        other
            .lock_exclusive(IO_WAIT)
            .expect("other")
            .remove(&entry)
            .is_err()
    );
    assert_eq!(replay.entries().expect("preserved").len(), 1);
}
