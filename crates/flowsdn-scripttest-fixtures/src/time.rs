//! RFC 3339 times as the harvested scripts write them.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 {
        year.saturating_sub(1)
    } else {
        year
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = month.saturating_add(9).rem_euclid(12);
    let doy = mp
        .saturating_mul(153)
        .saturating_add(2)
        .div_euclid(5)
        .saturating_add(day)
        .saturating_sub(1);
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe.div_euclid(4))
        .saturating_sub(yoe.div_euclid(100))
        .saturating_add(doy);
    era.saturating_mul(146_097)
        .saturating_add(doe)
        .saturating_sub(719_468)
}
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe.div_euclid(1460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096))
        .div_euclid(365);
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.div_euclid(4))
            .saturating_sub(yoe.div_euclid(100)),
    );
    let mp = doy.saturating_mul(5).saturating_add(2).div_euclid(153);
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2).div_euclid(5))
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    (year, month, day)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`. The zero time (year 1)
/// and anything before the epoch read as None.
pub fn parse(text: &str) -> Result<Option<SystemTime>, String> {
    let bad = || format!("not an RFC 3339 time: {text}");
    let text = text.trim();
    let number = |range: std::ops::Range<usize>| -> Result<i64, String> {
        text.get(range)
            .filter(|t| t.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|t| t.parse().ok())
            .ok_or_else(bad)
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let mut rest = text.get(19..).ok_or_else(bad)?;
    let mut nanos = 0u32;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        let (value, tail) = fraction.split_at(digits);
        let padded: String = value
            .chars()
            .chain(std::iter::repeat('0'))
            .take(9)
            .collect();
        nanos = padded.parse().map_err(|_| bad())?;
        rest = tail;
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.get(..1) {
                Some("+") => 1,
                Some("-") => -1,
                _ => return Err(bad()),
            };
            let hours: i64 = rest
                .get(1..3)
                .and_then(|h| h.parse().ok())
                .ok_or_else(bad)?;
            let minutes: i64 = rest
                .get(4..6)
                .and_then(|m| m.parse().ok())
                .ok_or_else(bad)?;
            hours
                .saturating_mul(3600)
                .saturating_add(minutes.saturating_mul(60))
                .saturating_mul(sign)
        }
    };
    if year <= 1 {
        return Ok(None);
    }
    let seconds = days_from_civil(year, month, day)
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second)
        .saturating_sub(offset);
    let Ok(seconds) = u64::try_from(seconds) else {
        return Ok(None);
    };
    Ok(UNIX_EPOCH.checked_add(Duration::new(seconds, nanos)))
}

/// `1970-01-01T00:00:01Z` (UTC, whole seconds).
pub fn format(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let of_day = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day.div_euclid(3600),
        of_day.rem_euclid(3600).div_euclid(60),
        of_day.rem_euclid(60)
    )
}

/// A short age: `2m27s`, `3h0m5s`, `450ms`.
pub fn age(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds == 0 {
        return format!("{}ms", elapsed.as_millis());
    }
    let (h, m, s) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m{s}s"),
        _ => format!("{h}h{m}m{s}s"),
    }
}
