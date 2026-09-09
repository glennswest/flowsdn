//! Deterministic metadata validation shared by the build script and Rust tests.
use std::collections::BTreeMap;

pub const INPUTS: &[&str] = &[
    "FLOWSDN_VERSION",
    "FLOWSDN_REVISION",
    "SOURCE_DATE_EPOCH",
    "FLOWSDN_DIRTY",
    "FLOWSDN_RUSTC",
    "FLOWSDN_BPF_TOOLCHAIN",
    "FLOWSDN_BPF_LINKER",
    "FLOWSDN_BPF_OBJECTS_SHA",
    "FLOWSDN_FEATURES",
];

/// A supplied invalid value is an error, never an absent variable.
pub fn environment_value(name: &str, value: Option<std::ffi::OsString>) -> Result<Option<String>, String> {
    value.map(|value| value.into_string().map_err(|_| format!("{name} must be UTF-8"))).transpose()
}

pub fn clean(value: &str) -> Result<&str, String> {
    if value.chars().any(char::is_control) {
        return Err("metadata must not contain control characters".into());
    }
    Ok(value)
}

/// Gregorian calendar conversion, bounded to Unix timestamps through year 9999.
#[allow(clippy::arithmetic_side_effects)] // Bounds below make all intermediates safe.
pub fn build_date(epoch: &str) -> Result<String, String> {
    if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("SOURCE_DATE_EPOCH must be nonnegative decimal seconds".into());
    }
    let seconds: i64 = epoch.parse().map_err(|_| "SOURCE_DATE_EPOCH overflow")?;
    if seconds > 253_402_300_799 {
        return Err("SOURCE_DATE_EPOCH exceeds year 9999".into());
    }
    let days = seconds / 86400 + 719468;
    let era = days / 146097;
    let day_of_era = days - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    ))
}

pub fn metadata(
    mut values: BTreeMap<String, String>,
    development: bool,
) -> Result<BTreeMap<String, String>, String> {
    for value in values.values() {
        clean(value)?;
    }
    for required in [
        "FLOWSDN_VERSION",
        "FLOWSDN_REVISION",
        "SOURCE_DATE_EPOCH",
        "FLOWSDN_RUSTC",
        "TARGET",
    ] {
        if values.get(required).is_none_or(String::is_empty) {
            return Err(format!("missing build metadata: {required}"));
        }
    }
    let date = build_date(values.get("SOURCE_DATE_EPOCH").expect("required above"))?;
    let dirty = match values.get("FLOWSDN_DIRTY").map(String::as_str) {
        None | Some("false") => development,
        Some("true") => true,
        _ => return Err("FLOWSDN_DIRTY must be true or false".into()),
    };
    values.insert("FLOWSDN_DIRTY".into(), dirty.to_string());
    values.insert("FLOWSDN_BUILD_DATE".into(), date);
    for name in [
        "FLOWSDN_BPF_TOOLCHAIN",
        "FLOWSDN_BPF_LINKER",
        "FLOWSDN_BPF_OBJECTS_SHA",
    ] {
        values
            .entry(name.into())
            .or_insert_with(|| "unavailable".into());
    }
    let features = values
        .get("FLOWSDN_FEATURES")
        .map(String::as_str)
        .unwrap_or("");
    let mut features: Vec<_> = features
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    features.sort_unstable();
    features.dedup();
    values.insert("FLOWSDN_FEATURES".into(), features.join(","));
    Ok(values)
}
