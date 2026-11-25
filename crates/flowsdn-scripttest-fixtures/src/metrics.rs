//! A fixture's own metrics registry and sampler (spec 17 §3.3.3, §12: never a
//! process-global registry) and the `metrics`, `metrics/plot` and
//! `metrics/html` commands.
//!
//! The sampler keeps [`SAMPLES`] samples per series, newest first, one every
//! [`INTERVAL`]; it takes its first sample when the agent instance starts. A
//! histogram is sampled as its 50th, 90th and 99th percentiles, estimated from
//! its buckets by linear interpolation as Prometheus' `histogram_quantile`
//! does. Series of a disabled metric are sampled but not listed.
use crate::{
    doc::{self, Doc},
    fixture::{Component, lock},
};
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const SAMPLES: usize = 24;
pub const INTERVAL: Duration = Duration::from_secs(300);
/// Prometheus' default buckets.
pub const DEFAULT_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

#[derive(Clone, Debug)]
pub enum Value {
    /// A gauge or a counter.
    Scalar(f64),
    /// Upper bounds and the count of observations in each bucket (not
    /// cumulative); observations above the last bound only count.
    Histogram {
        bounds: Vec<f64>,
        counts: Vec<u64>,
        overflow: u64,
    },
}

#[derive(Clone, Debug)]
pub struct Series {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: Value,
    pub enabled: bool,
}
impl Series {
    fn labels_text(&self) -> String {
        self.labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",")
    }
    fn seconds(&self) -> bool {
        self.name.ends_with("_seconds")
    }
}

/// `histogram_quantile(q)` over (non-cumulative) bucket counts.
fn quantile(q: f64, bounds: &[f64], counts: &[u64], overflow: u64) -> f64 {
    let total = counts
        .iter()
        .fold(overflow, |sum, count| sum.saturating_add(*count));
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let rank = q * total as f64;
    let mut below = 0u64;
    let mut lower = 0.0f64;
    for (bound, count) in bounds.iter().zip(counts) {
        let upto = below.saturating_add(*count);
        #[allow(clippy::cast_precision_loss)]
        if upto as f64 >= rank && *count > 0 {
            let into = (rank - below as f64) / *count as f64;
            return lower + (bound - lower) * into;
        }
        below = upto;
        lower = *bound;
    }
    bounds.last().copied().unwrap_or(0.0)
}

/// One sample: a scalar, or a histogram's (p50, p90, p99).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Sample {
    Scalar(f64),
    Percentiles(f64, f64, f64),
}
impl Sample {
    fn of(value: &Value) -> Self {
        match value {
            Value::Scalar(v) => Self::Scalar(*v),
            Value::Histogram {
                bounds,
                counts,
                overflow,
            } => Self::Percentiles(
                quantile(0.5, bounds, counts, *overflow),
                quantile(0.9, bounds, counts, *overflow),
                quantile(0.99, bounds, counts, *overflow),
            ),
        }
    }
    fn zero(&self) -> Self {
        match self {
            Self::Scalar(_) => Self::Scalar(0.0),
            Self::Percentiles(..) => Self::Percentiles(0.0, 0.0, 0.0),
        }
    }
}

/// Go's `time.Duration.String()` for a number of seconds.
pub fn go_duration(seconds: f64) -> String {
    #[allow(clippy::cast_possible_truncation)]
    let nanos = (seconds * 1e9).round() as i128;
    if nanos == 0 {
        return "0s".into();
    }
    let sign = if nanos < 0 { "-" } else { "" };
    let n = nanos.unsigned_abs();
    let trim = |whole: u128, frac: u128, digits: usize| -> String {
        let mut text = format!("{whole}");
        if frac > 0 {
            let fraction = format!("{frac:0digits$}");
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        text
    };
    if n < 1_000 {
        return format!("{sign}{n}ns");
    }
    if n < 1_000_000 {
        return format!("{sign}{}µs", trim(n / 1_000, n % 1_000, 3));
    }
    if n < 1_000_000_000 {
        return format!("{sign}{}ms", trim(n / 1_000_000, n % 1_000_000, 6));
    }
    let total = n / 1_000_000_000;
    let frac = n % 1_000_000_000;
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    let mut out = String::from(sign);
    if hours > 0 {
        let _ = write!(out, "{hours}h");
    }
    if hours > 0 || minutes > 0 {
        let _ = write!(out, "{minutes}m");
    }
    let _ = write!(out, "{}s", trim(seconds, frac, 9));
    out
}

fn shown(series_seconds: bool, value: f64) -> String {
    if series_seconds {
        go_duration(value)
    } else {
        doc_number(value)
    }
}
fn doc_number(value: f64) -> String {
    doc::json(&Doc::Num(value)).trim_end().to_owned()
}
fn percentiles(seconds: bool, (p50, p90, p99): (f64, f64, f64)) -> String {
    format!(
        "{} / {} / {}",
        shown(seconds, p50),
        shown(seconds, p90),
        shown(seconds, p99)
    )
}

/// A sampled series: (name, labels) and (in seconds, samples newest first).
type SampledRow<'a> = (&'a (String, String), &'a (bool, Vec<Sample>));

#[derive(Debug, Default)]
struct Sampled {
    /// (name, labels) -> its samples, newest first.
    series: BTreeMap<(String, String), (bool, Vec<Sample>)>,
    taken: usize,
}

/// The registry and its sampler.
#[derive(Debug, Default)]
pub struct Metrics {
    series: Vec<Series>,
    sampled: Sampled,
}
impl Metrics {
    pub fn add(&mut self, series: Series) {
        self.series.push(series);
    }
    /// Observe `value` in the histogram series `name` with `labels`.
    pub fn observe(&mut self, name: &str, labels: &BTreeMap<String, String>, value: f64) {
        for series in &mut self.series {
            if series.name == name && series.labels == *labels
                && let Value::Histogram {
                    bounds,
                    counts,
                    overflow,
                } = &mut series.value
            {
                match bounds.iter().position(|b| value <= *b) {
                    Some(index) => {
                        if let Some(count) = counts.get_mut(index) {
                            *count = count.saturating_add(1);
                        }
                    }
                    None => *overflow = overflow.saturating_add(1),
                }
            }
        }
    }
    /// Take one sample of every series.
    pub fn sample(&mut self) {
        for series in &self.series {
            let key = (series.name.clone(), series.labels_text());
            let now = Sample::of(&series.value);
            let entry = self
                .sampled
                .series
                .entry(key)
                .or_insert_with(|| (series.seconds(), vec![now.zero(); SAMPLES]));
            entry.1.insert(0, now);
            entry.1.truncate(SAMPLES);
        }
        self.sampled.taken = self.sampled.taken.saturating_add(1).min(SAMPLES);
    }
    fn listed(&self, re: Option<&regex::Regex>) -> Vec<&Series> {
        let mut rows: Vec<&Series> = self
            .series
            .iter()
            .filter(|s| s.enabled && re.is_none_or(|re| re.is_match(&s.name)))
            .collect();
        rows.sort_by(|a, b| (&a.name, a.labels_text()).cmp(&(&b.name, b.labels_text())));
        rows
    }
    fn sampled(&self, re: Option<&regex::Regex>) -> Vec<SampledRow<'_>> {
        self.sampled
            .series
            .iter()
            .filter(|((name, _), _)| re.is_none_or(|re| re.is_match(name)))
            .collect()
    }
}

/// The reference's tab-writer layout (see the `db/show` renderer).
fn columns(rows: &[Vec<String>]) -> String {
    let count = rows.first().map_or(0, Vec::len);
    let mut widths = vec![0usize; count];
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        for (index, (cell, width)) in row.iter().zip(&widths).enumerate() {
            out.push_str(cell);
            if index.saturating_add(1) < count {
                let pad = width
                    .saturating_add(3)
                    .max(5)
                    .saturating_sub(cell.chars().count());
                out.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push('\n');
    }
    out
}

/// The sampled columns: 5m, 30m, 60m, 120m ago (newest-first indexes).
const SAMPLED_COLUMNS: [(&str, usize); 4] = [("5m", 0), ("30m", 5), ("60m", 11), ("120m", 23)];

fn sample_text(seconds: bool, sample: Option<&Sample>) -> String {
    match sample {
        Some(Sample::Scalar(v)) => doc_number(*v),
        Some(Sample::Percentiles(a, b, c)) => percentiles(seconds, (*a, *b, *c)),
        None => String::new(),
    }
}

fn render(metrics: &Metrics, re: Option<&regex::Regex>, sampled: bool, format: &str) -> Result<String, String> {
    if !sampled {
        let rows = metrics.listed(re);
        let value = |s: &Series| match &s.value {
            Value::Scalar(v) => (format!("{v:.6}"), *v),
            Value::Histogram {
                bounds,
                counts,
                overflow,
            } => {
                let p = |q| quantile(q, bounds, counts, *overflow);
                (percentiles(s.seconds(), (p(0.5), p(0.9), p(0.99))), p(0.9))
            }
        };
        return match format {
            "table" => {
                let mut table = vec![vec!["Metric".into(), "Labels".into(), "Value".into()]];
                for s in &rows {
                    table.push(vec![s.name.clone(), s.labels_text(), value(s).0]);
                }
                Ok(columns(&table))
            }
            "json" | "yaml" => {
                let items = rows
                    .iter()
                    .map(|s| {
                        let labels = Doc::map(s.labels.iter().map(|(k, v)| (k.clone(), Doc::str(v))));
                        let mut fields = Vec::new();
                        if format == "yaml" || !s.labels.is_empty() {
                            fields.push(("labels".to_owned(), labels));
                        }
                        fields.push(("name".into(), Doc::str(&s.name)));
                        fields.push(("value".into(), Doc::Num(value(s).1)));
                        Doc::Map(fields)
                    })
                    .collect();
                let list = Doc::Seq(items);
                Ok(if format == "json" { doc::json(&list) } else { doc::yaml(&list) })
            }
            other => Err(format!("unknown format {other}; use table, json or yaml")),
        };
    }
    let rows = metrics.sampled(re);
    match format {
        "table" => {
            let mut table = vec![
                ["Metric", "Labels"]
                    .into_iter()
                    .chain(SAMPLED_COLUMNS.iter().map(|(h, _)| *h))
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ];
            for ((name, labels), (seconds, samples)) in &rows {
                let mut row = vec![name.clone(), labels.clone()];
                for (_, index) in SAMPLED_COLUMNS {
                    row.push(sample_text(*seconds, samples.get(index)));
                }
                table.push(row);
            }
            Ok(columns(&table))
        }
        "json" | "yaml" => {
            let items = rows
                .iter()
                .map(|((name, labels), (seconds, samples))| {
                    let mut fields = vec![("name".to_owned(), Doc::str(name))];
                    if !labels.is_empty() {
                        fields.push(("labels".into(), Doc::str(labels)));
                    }
                    match samples.first() {
                        Some(Sample::Percentiles(..)) => {
                            let column = |pick: fn(&Sample) -> f64| {
                                Doc::Seq(samples.iter().map(|s| Doc::Num(pick(s))).collect())
                            };
                            fields.push((
                                "histogram".into(),
                                Doc::map([
                                    ("p50", column(|s| match s {
                                        Sample::Percentiles(a, _, _) => *a,
                                        Sample::Scalar(v) => *v,
                                    })),
                                    ("p90", column(|s| match s {
                                        Sample::Percentiles(_, b, _) => *b,
                                        Sample::Scalar(v) => *v,
                                    })),
                                    ("p99", column(|s| match s {
                                        Sample::Percentiles(_, _, c) => *c,
                                        Sample::Scalar(v) => *v,
                                    })),
                                ]),
                            ));
                        }
                        _ => {
                            let values = samples
                                .iter()
                                .map(|s| match s {
                                    Sample::Scalar(v) => Doc::Num(*v),
                                    Sample::Percentiles(a, _, _) => Doc::Num(*a),
                                })
                                .collect();
                            fields.push((
                                "gaugeOrCounter".into(),
                                Doc::map([("samples", Doc::Seq(values))]),
                            ));
                        }
                    }
                    fields.push(("latest".into(), Doc::str(sample_text(*seconds, samples.first()))));
                    Doc::Map(fields)
                })
                .collect();
            #[allow(clippy::cast_precision_loss)]
            let top = Doc::map([
                ("nsamples", Doc::Num(SAMPLES as f64)),
                ("interval_seconds", Doc::Num(INTERVAL.as_secs_f64())),
                ("samples", Doc::Seq(items)),
            ]);
            Ok(if format == "json" { doc::json(&top) } else { doc::yaml(&top) })
        }
        other => Err(format!("unknown format {other}; use table, json or yaml")),
    }
}

/// The y-axis label of `value` for a series in seconds (`10.0ms`) or not.
fn axis_label(seconds: bool, value: f64, max: f64) -> String {
    if !seconds {
        return format!("{value:.1}");
    }
    let (scale, unit) = if max >= 1.0 {
        (1.0, "s")
    } else if max >= 1e-3 {
        (1e3, "ms")
    } else {
        (1e6, "µs")
    };
    format!("{:.1}{unit}", value * scale)
}

/// Plot width and height in characters (braille cells: 2×4 dots).
const WIDTH: usize = 68;
const HEIGHT: usize = 7;
/// Plot one sampled series: newest sample at the right edge.
fn plot(title: &str, labels: &str, seconds: bool, samples: &[f64], taken: usize) -> String {
    let center = 45usize;
    let mut out = String::new();
    let centered = |out: &mut String, text: &str| {
        let start = center.saturating_sub(text.chars().count() / 2);
        out.extend(std::iter::repeat_n(' ', start));
        out.push_str(text);
        out.push('\n');
    };
    centered(&mut out, title);
    if !labels.is_empty() {
        centered(&mut out, &format!("[ {labels} ]"));
    }
    let max = samples
        .iter()
        .take(taken)
        .copied()
        .fold(0.0f64, f64::max);
    let mut cells = vec![[0u8; WIDTH]; HEIGHT];
    let (px_w, px_h) = (WIDTH.saturating_mul(2), HEIGHT.saturating_mul(4));
    for (age, value) in samples.iter().take(taken).enumerate() {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let (x, y) = {
            let step = (px_w.saturating_sub(1)) as f64 / (SAMPLES.saturating_sub(1)) as f64;
            let x = (px_w.saturating_sub(1)) as f64 - age as f64 * step;
            let y = if max > 0.0 {
                (1.0 - value / max) * (px_h.saturating_sub(1)) as f64
            } else {
                (px_h.saturating_sub(1)) as f64
            };
            (x.round().max(0.0) as usize, y.round().max(0.0) as usize)
        };
        let bit = match (x % 2, y % 4) {
            (0, 0) => 0x01,
            (0, 1) => 0x02,
            (0, 2) => 0x04,
            (0, _) => 0x40,
            (_, 0) => 0x08,
            (_, 1) => 0x10,
            (_, 2) => 0x20,
            (_, _) => 0x80,
        };
        if let Some(cell) = cells.get_mut(y / 4).and_then(|row| row.get_mut(x / 2)) {
            *cell |= bit;
        }
    }
    out.push_str(&format!("{:10}╭{}╮\n", "", "─".repeat(WIDTH)));
    for (row, line) in cells.iter().enumerate() {
        let label_row = row % 3 == 0;
        if label_row {
            #[allow(clippy::cast_precision_loss)]
            let value = max * (HEIGHT.saturating_sub(1).saturating_sub(row)) as f64
                / (HEIGHT.saturating_sub(1)) as f64;
            out.push_str(&format!("{:>9} ┤", axis_label(seconds, value, max)));
        } else {
            out.push_str(&format!("{:10}│", ""));
        }
        for cell in line {
            out.push(char::from_u32(0x2800 | u32::from(*cell)).unwrap_or(' '));
        }
        out.push_str("│\n");
    }
    // Ticks at 120 and 60 minutes ago and now.
    let ticks = [(3usize, "-120min"), (35, "-60min"), (66, "now")];
    let mut axis: Vec<char> = "─".repeat(WIDTH).chars().collect();
    let mut names = vec![' '; WIDTH.saturating_add(11)];
    for (at, name) in ticks {
        if let Some(c) = axis.get_mut(at) {
            *c = '┬';
        }
        let start = at.saturating_add(11).saturating_sub(name.chars().count() / 2);
        for (offset, ch) in name.chars().enumerate() {
            if let Some(slot) = names.get_mut(start.saturating_add(offset)) {
                *slot = ch;
            }
        }
    }
    out.push_str(&format!("{:10}╰{}╯\n", "", axis.iter().collect::<String>()));
    out.push_str(&names.iter().collect::<String>());
    out.push('\n');
    out
}

/// The fixture's metrics: registry, sampler and the sampler's component.
pub type Shared = Arc<Mutex<Metrics>>;

/// Takes the first sample when the instance starts.
pub struct Sampler(pub Shared);
impl Component for Sampler {
    fn name(&self) -> &str {
        "metrics-sampler"
    }
    fn start(&mut self) -> Result<(), String> {
        lock(&self.0).sample();
        Ok(())
    }
    fn stop(&mut self) -> Result<(), String> {
        Ok(())
    }
}

struct Flags {
    out: Option<String>,
    sampled: bool,
    format: String,
    rate: bool,
    pattern: Option<regex::Regex>,
}
fn flags(args: &[String]) -> Result<Flags, CommandError> {
    let mut parsed = Flags {
        out: None,
        sampled: false,
        format: "table".into(),
        rate: false,
        pattern: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if arg.starts_with('-') => (flag, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| iter.next().cloned())
                .ok_or_else(|| fail(format!("{flag} needs a value")))
        };
        match flag {
            "-o" | "--out" => parsed.out = Some(value()?),
            "-f" | "--format" => parsed.format = value()?,
            "-s" | "--sampled" => parsed.sampled = true,
            "--rate" => parsed.rate = true,
            _ if flag.starts_with('-') && flag.len() > 1 => {
                return Err(fail(format!("unknown flag {flag}")));
            }
            _ => {
                parsed.pattern =
                    Some(regex::Regex::new(arg).map_err(|e| fail(e.to_string()))?);
            }
        }
    }
    Ok(parsed)
}
fn emit(state: &mut State, out: Option<&String>, text: String) -> Result<Control, CommandError> {
    match out {
        Some(file) => state.write_text(file, &text)?,
        None => state.publish(text, ""),
    }
    Ok(Control::Continue)
}

/// Register `metrics`, `metrics/plot` and `metrics/html` for `metrics`.
pub fn register(engine: &mut Engine, metrics: &Shared) -> Result<(), String> {
    let m = Arc::clone(metrics);
    engine.register_command("metrics", true, move |state: &mut State, args: &[String]| {
        let flags = flags(args)?;
        let text = render(&lock(&m), flags.pattern.as_ref(), flags.sampled, &flags.format)
            .map_err(fail)?;
        emit(state, flags.out.as_ref(), text)
    })?;
    let m = Arc::clone(metrics);
    engine.register_command("metrics/plot", true, move |state: &mut State, args: &[String]| {
        let flags = flags(args)?;
        let metrics = lock(&m);
        let mut graphs = Vec::new();
        for ((name, labels), (seconds, samples)) in metrics.sampled(flags.pattern.as_ref()) {
            let mut series: Vec<(String, Vec<f64>)> = Vec::new();
            match samples.first() {
                Some(Sample::Percentiles(..)) => {
                    for (label, pick) in [
                        ("p50", 0usize),
                        ("p90", 1),
                        ("p99", 2),
                    ] {
                        let values = samples
                            .iter()
                            .map(|s| match (s, pick) {
                                (Sample::Percentiles(a, _, _), 0) => *a,
                                (Sample::Percentiles(_, b, _), 1) => *b,
                                (Sample::Percentiles(_, _, c), _) => *c,
                                (Sample::Scalar(v), _) => *v,
                            })
                            .collect();
                        series.push((format!("{name} ({label})"), values));
                    }
                }
                _ => {
                    let mut values: Vec<f64> = samples
                        .iter()
                        .map(|s| match s {
                            Sample::Scalar(v) | Sample::Percentiles(v, _, _) => *v,
                        })
                        .collect();
                    if flags.rate {
                        // Per second between consecutive samples, newest first.
                        let rates: Vec<f64> = values
                            .windows(2)
                            .map(|w| match w {
                                [new, old] => (new - old) / INTERVAL.as_secs_f64(),
                                _ => 0.0,
                            })
                            .collect();
                        values = rates;
                    }
                    series.push((name.clone(), values));
                }
            }
            for (title, values) in series {
                graphs.push(plot(&title, labels, *seconds, &values, metrics.sampled.taken));
            }
        }
        drop(metrics);
        if graphs.is_empty() {
            return Err(fail("no sampled series match"));
        }
        emit(state, flags.out.as_ref(), graphs.join("\n"))
    })?;
    let m = Arc::clone(metrics);
    engine.register_command("metrics/html", false, move |state: &mut State, args: &[String]| {
        let flags = flags(args)?;
        let metrics = lock(&m);
        let mut page = String::from(
            "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Sampled metrics</title></head><body>\n<table>\n<tr><th>Metric</th><th>Labels</th><th>Latest</th></tr>\n",
        );
        for ((name, labels), (seconds, samples)) in metrics.sampled(None) {
            let escape = |t: &str| t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            let _ = writeln!(
                page,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(name),
                escape(labels),
                escape(&sample_text(*seconds, samples.first()))
            );
        }
        page.push_str("</table>\n</body></html>\n");
        drop(metrics);
        emit(state, flags.out.as_ref(), page)
    })?;
    Ok(())
}
