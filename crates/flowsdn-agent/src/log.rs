//! The agent's log lines (#397): each starts with its UTC time, so a boot can be
//! read from the log alone, and dates come without libc (#373).
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The last second RFC 3339 can write, 9999-12-31T23:59:59Z.
pub const LAST_SECOND: u64 = 253_402_300_799;

/// A line on stderr, after its time.
macro_rules! logln {
    ($($arg:tt)*) => {
        eprintln!("{} {}", $crate::log::now(), format_args!($($arg)*))
    };
}
pub(crate) use logln;

/// A line on stderr that is also written to the node's kernel log (#484):
/// the health transitions. A pod's stderr reaches no node log reader; on a
/// stormcos node the log service follows `/dev/kmsg` into syslog. Only rare
/// lines use it, so the kernel's `/dev/kmsg` rate limit is not reached.
macro_rules! noticeln {
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        eprintln!("{} {line}", $crate::log::now());
        $crate::log::KERNEL_LOG.write(&line);
    }};
}
pub(crate) use noticeln;

/// The kernel log device.
pub const KMSG: &str = "/dev/kmsg";
/// The longest message written to it (the kernel's record limit is ~1 KiB).
pub const KMSG_MAX: usize = 900;

/// A writer of kernel log records, opened on first use. When the device
/// cannot be opened (not mounted, not privileged) that is said once on stderr
/// and nothing more is tried.
pub struct Kmsg {
    path: &'static str,
    sink: std::sync::Mutex<Option<Option<std::fs::File>>>,
}
impl Kmsg {
    pub const fn new(path: &'static str) -> Self {
        Self {
            path,
            sink: std::sync::Mutex::new(None),
        }
    }
    /// Write `line` as one record, at user.info (`<14>`), tagged
    /// `flowsdn-agent:`. Errors are not the caller's problem.
    pub fn write(&self, line: &str) {
        use std::io::Write as _;
        let mut sink = self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = sink.get_or_insert_with(|| {
            match std::fs::OpenOptions::new().write(true).open(self.path) {
                Ok(file) => Some(file),
                Err(error) => {
                    eprintln!("{} {}: {error}; health lines not sent to the kernel log", now(), self.path);
                    None
                }
            }
        });
        let failed = file
            .as_mut()
            .is_some_and(|writer| writer.write_all(&record(line)).is_err());
        if failed {
            *file = None;
        }
    }
}

/// The node's kernel log.
pub static KERNEL_LOG: Kmsg = Kmsg::new(KMSG);

/// One `/dev/kmsg` record: `<14>flowsdn-agent: <line>\n`, on one line and
/// at most [`KMSG_MAX`] bytes of message (cut on a character boundary).
pub fn record(line: &str) -> Vec<u8> {
    let flat: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut cut = flat.len().min(KMSG_MAX);
    while !flat.is_char_boundary(cut) {
        cut = cut.saturating_sub(1);
    }
    format!("<14>flowsdn-agent: {}\n", flat.get(..cut).unwrap_or("")).into_bytes()
}

/// `YYYY-MM-DDTHH:MM:SS` of `seconds` after the epoch, at most [`LAST_SECOND`]
/// (civil-from-days, Howard Hinnant's algorithm).
#[allow(clippy::arithmetic_side_effects)] // Bounded by the clamp to LAST_SECOND.
pub fn civil(seconds: u64) -> String {
    let seconds = i64::try_from(seconds.min(LAST_SECOND)).unwrap_or(0);
    let days = seconds / 86400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// A log line's time: UTC with milliseconds.
pub fn stamp(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    format!("{}.{:03}Z", civil(since.as_secs()), since.subsec_millis())
}
pub fn now() -> String {
    stamp(SystemTime::now())
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_milliseconds() {
        assert_eq!(civil(0), "1970-01-01T00:00:00");
        assert_eq!(civil(951_782_400), "2000-02-29T00:00:00");
        assert_eq!(civil(1_791_302_693), "2026-10-06T16:04:53");
        assert_eq!(civil(u64::MAX), "9999-12-31T23:59:59");
        let at = UNIX_EPOCH + Duration::from_millis(1_791_302_693_007);
        assert_eq!(stamp(at), "2026-10-06T16:04:53.007Z");
    }

    #[test]
    fn kernel_log_records_are_one_tagged_bounded_line() {
        assert_eq!(
            record("health agent.api OK: 3 endpoints"),
            b"<14>flowsdn-agent: health agent.api OK: 3 endpoints\n".to_vec()
        );
        assert_eq!(record("a\nb\tc"), b"<14>flowsdn-agent: a b c\n".to_vec());
        let long = "é".repeat(KMSG_MAX);
        let text = String::from_utf8(record(&long)).expect("UTF-8");
        assert!(text.len() <= KMSG_MAX + "<14>flowsdn-agent: \n".len());
        assert!(text.ends_with("é\n"));
    }

    #[test]
    fn the_sink_writes_records_and_tolerates_a_missing_device() {
        let dir = std::env::temp_dir().join(format!("flowsdn-kmsg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path: &'static str = Box::leak(dir.join("kmsg").to_string_lossy().into_owned().into_boxed_str());
        std::fs::write(path, b"").expect("file");
        let sink = Kmsg::new(path);
        sink.write("health agent.api OK: up");
        sink.write("health agent.kubernetes OK: listed");
        assert_eq!(
            std::fs::read_to_string(path).expect("read"),
            "<14>flowsdn-agent: health agent.api OK: up\n<14>flowsdn-agent: health agent.kubernetes OK: listed\n"
        );
        // A device that is not there: said once, then nothing tried.
        let missing = Kmsg::new("/nonexistent/flowsdn/kmsg");
        missing.write("x");
        missing.write("y");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
