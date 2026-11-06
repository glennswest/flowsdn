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
}
