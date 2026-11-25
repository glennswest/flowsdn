//! Typed table adapters and the `db/*` commands (spec 17 §3.3.3, §4.2, §5.2).
//! Bindings belong to one Engine, never a global registry.
use crate::{CommandError, Control, ExpansionMode, State, expand_text_bounded};
use flowsdn_table::{Keyed, Row, Table, TableRender};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const MAX_BYTES: usize = 8_388_608;
const MAX_ROWS: usize = 65_536;
const MAX_COLUMNS: usize = 128;
const MAX_CELLS: usize = 65_536;
/// `db/cmp` and `db/initialized` wait this long unless `--timeout` says otherwise.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
type Result<T> = std::result::Result<T, CommandError>;
type BoxFuture<'a, R> = Pin<Box<dyn Future<Output = R> + Send + 'a>>;

/// A rendering of rows: the `.table` columns, or one exported document per row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Table,
    Json,
    Yaml,
}

/// Exports one row as a complete document (with its trailing newline).
pub type Export<T> = fn(&T, Format) -> std::result::Result<String, String>;
/// Reads the rows of one `db/insert` or `db/delete` file.
pub type Import<T> = fn(&str) -> std::result::Result<Vec<T>, String>;
/// Maps an index as a script names it, and a key's text, to the table's index
/// and key bytes.
pub type QueryKey = fn(&str, &str) -> std::result::Result<(&'static str, Vec<u8>), String>;

/// What a fixture adds to a table beyond its [`TableRender`] columns. Without
/// an export, `-f json|yaml` fails; without an import, `db/insert` and
/// `db/delete` fail; without a key mapping, a key is its UTF-8 bytes on the
/// named index (default `primary`).
pub struct Adapter<T> {
    pub export: Option<Export<T>>,
    pub import: Option<Import<T>>,
    pub key: Option<QueryKey>,
}
impl<T> Default for Adapter<T> {
    fn default() -> Self {
        Self {
            export: None,
            import: None,
            key: None,
        }
    }
}

fn failure(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}
fn diagnostic_name(name: &str) -> String {
    let mut end = name.len().min(256);
    while !name.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let suffix = if end < name.len() { "..." } else { "" };
    format!("{}{suffix}", name.get(..end).expect("UTF-8 boundary"))
}
fn limit() -> CommandError {
    CommandError::LimitExceeded(
        "table rendering exceeds 8 MiB, 65536 rows, 128 columns or 65536 cells",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    Get,
    List,
    Prefix,
    LowerBound,
}

/// One query: the rows, how to render them, and whether to delete them.
pub(crate) struct Query<'a> {
    mode: Mode,
    index: Option<&'a str>,
    key: &'a str,
    columns: Option<&'a str>,
    format: Format,
    delete: bool,
}

pub(crate) trait Binding: Send + Sync {
    fn is_empty(&self) -> bool;
    /// The whole table in `.table` form (diagnostics).
    fn render(&self, columns: Option<&str>) -> Result<String>;
    fn show(&self, columns: Option<&str>, format: Format) -> Result<String>;
    fn headers(&self) -> &'static [&'static str];
    /// Every row's cells, in primary-key order.
    fn cells(&self) -> Result<Vec<Vec<String>>>;
    fn watch(&self) -> watch::Receiver<u64>;
    fn query<'a>(&'a self, query: Query<'a>) -> BoxFuture<'a, Result<String>>;
    /// Insert (or, with `delete`, delete) the rows a file's text describes.
    fn write(&self, text: String, delete: bool) -> BoxFuture<'_, Result<()>>;
    fn initialized(&self) -> bool;
    fn pending(&self) -> Vec<String>;
    fn wait_initialized(&self) -> BoxFuture<'_, ()>;
}
struct Typed<T: Keyed + TableRender> {
    table: Arc<Table<T>>,
    headers: &'static [&'static str],
    adapter: Adapter<T>,
}

pub(crate) fn bind<T: Keyed + TableRender>(
    table: Arc<Table<T>>,
    adapter: Adapter<T>,
) -> std::result::Result<Arc<dyn Binding>, String> {
    let headers = T::headers();
    if headers.is_empty() || headers.len() > MAX_COLUMNS {
        return Err("table must declare between 1 and 128 headers".into());
    }
    let mut names = BTreeSet::new();
    for header in headers {
        if header.is_empty()
            || header.len() > 256
            || header.chars().any(|c| c.is_whitespace() || c.is_control())
            || !names.insert(*header)
        {
            return Err("table headers must be unique nonempty names without whitespace/control characters, at most 256 bytes each".into());
        }
    }
    Ok(Arc::new(Typed {
        table,
        headers,
        adapter,
    }))
}

impl<T: Keyed + TableRender> Typed<T> {
    fn selected(&self, columns: Option<&str>) -> Result<Vec<usize>> {
        let headers = self.headers;
        let Some(columns) = columns else {
            return Ok((0..headers.len()).collect());
        };
        let mut result = Vec::new();
        let mut used = BTreeSet::new();
        for name in columns.split(',') {
            if result.len() >= MAX_COLUMNS {
                return Err(limit());
            }
            let index = headers
                .iter()
                .position(|header| *header == name)
                .ok_or_else(|| {
                    failure(format!(
                        "unknown column {:?}; available columns: {}",
                        diagnostic_name(name),
                        headers.join(",")
                    ))
                })?;
            if !used.insert(index) {
                return Err(failure(format!("duplicate column: {name}")));
            }
            result.push(index);
        }
        Ok(result)
    }
    /// A row's cells, checked against the TableRender contract.
    fn row_cells(&self, row: &T) -> Result<Vec<String>> {
        let cells = row.cells();
        if cells.len() != self.headers.len() {
            return Err(failure("TableRender cells/header count mismatch"));
        }
        let mut row_bytes = 0usize;
        for cell in &cells {
            row_bytes = row_bytes.saturating_add(cell.len());
            if row_bytes > MAX_BYTES {
                return Err(limit());
            }
            if cell.chars().any(|c| matches!(c, '\t' | '\n' | '\r')) {
                return Err(failure(
                    "TableRender cells must not contain tabs or line breaks",
                ));
            }
        }
        Ok(cells)
    }
    fn rows(&self, rows: &[Row<T>], columns: Option<&str>, format: Format) -> Result<String> {
        match format {
            Format::Table => self.table_text(rows, columns),
            Format::Json | Format::Yaml => {
                if columns.is_some() {
                    return Err(failure("--columns applies only to --format=table"));
                }
                let export = self
                    .adapter
                    .export
                    .ok_or_else(|| failure("this table has no json/yaml export"))?;
                let mut documents = Vec::new();
                for (row, _) in rows {
                    documents.push(export(row, format).map_err(failure)?);
                }
                let joined = if format == Format::Yaml {
                    documents.join("---\n")
                } else {
                    documents.concat()
                };
                if joined.len() > MAX_BYTES {
                    return Err(limit());
                }
                Ok(joined)
            }
        }
    }
    /// The reference's tab-writer layout: each column but the last padded to
    /// its widest cell plus three spaces (at least five); the last unpadded.
    fn table_text(&self, rows: &[Row<T>], columns: Option<&str>) -> Result<String> {
        let selected = self.selected(columns)?;
        if rows.len() > MAX_ROWS
            || rows.len().saturating_add(1).saturating_mul(selected.len()) > MAX_CELLS
        {
            return Err(limit());
        }
        let mut lines = Vec::new();
        let mut bytes = 0usize;
        let header: Vec<_> = selected
            .iter()
            .map(|index| {
                self.headers
                    .get(*index)
                    .expect("selected header")
                    .to_string()
            })
            .collect();
        account(&mut bytes, &header)?;
        let mut widths: Vec<_> = header.iter().map(|cell| cell.chars().count()).collect();
        lines.push(header);
        for (row, _) in rows {
            let cells = self.row_cells(row)?;
            let selected_cells: Vec<_> = selected
                .iter()
                .map(|index| cells.get(*index).expect("validated cell count").clone())
                .collect();
            account(&mut bytes, &selected_cells)?;
            for (width, cell) in widths.iter_mut().zip(&selected_cells) {
                *width = (*width).max(cell.chars().count());
            }
            lines.push(selected_cells);
        }
        let last = selected.len().saturating_sub(1);
        let mut output = String::new();
        for line in lines {
            for (index, (cell, width)) in line.iter().zip(&widths).enumerate() {
                append(&mut output, cell)?;
                if index != last {
                    let padding = width
                        .saturating_add(3)
                        .max(5)
                        .saturating_sub(cell.chars().count());
                    if output.len().saturating_add(padding) > MAX_BYTES {
                        return Err(limit());
                    }
                    output.extend(std::iter::repeat_n(' ', padding));
                }
            }
            append(&mut output, "\n")?;
        }
        Ok(output)
    }
    fn import(&self, text: &str) -> Result<Vec<T>> {
        let import = self
            .adapter
            .import
            .ok_or_else(|| failure("this table has no db/insert or db/delete adapter"))?;
        import(text).map_err(failure)
    }
}

impl<T: Keyed + TableRender> Binding for Typed<T> {
    fn is_empty(&self) -> bool {
        self.table.snapshot().is_empty()
    }
    fn render(&self, columns: Option<&str>) -> Result<String> {
        self.show(columns, Format::Table)
    }
    fn show(&self, columns: Option<&str>, format: Format) -> Result<String> {
        let snapshot = self.table.snapshot();
        if snapshot.len() > MAX_ROWS {
            return Err(limit());
        }
        let rows: Vec<_> = snapshot.all().collect();
        self.rows(&rows, columns, format)
    }
    fn headers(&self) -> &'static [&'static str] {
        self.headers
    }
    fn cells(&self) -> Result<Vec<Vec<String>>> {
        let snapshot = self.table.snapshot();
        if snapshot.len() > MAX_ROWS {
            return Err(limit());
        }
        snapshot
            .all()
            .map(|(row, _)| self.row_cells(&row))
            .collect()
    }
    fn watch(&self) -> watch::Receiver<u64> {
        self.table.revisions()
    }
    fn query<'a>(&'a self, query: Query<'a>) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let named = query.index.unwrap_or("primary");
            let (index, key) = match self.adapter.key {
                Some(map) => map(named, query.key).map_err(failure)?,
                None => (named, query.key.as_bytes().to_vec()),
            };
            let snapshot = self.table.snapshot();
            let error = |e: flowsdn_table::TableError| failure(e.to_string());
            let rows: Vec<Row<T>> = match query.mode {
                Mode::Get => snapshot
                    .list(index, &key)
                    .map_err(error)?
                    .into_iter()
                    .take(1)
                    .collect(),
                Mode::List => snapshot.list(index, &key).map_err(error)?,
                Mode::Prefix => snapshot.prefix(index, &key).map_err(error)?,
                Mode::LowerBound => snapshot.lower_bound(index, &key).map_err(error)?,
            };
            if query.mode == Mode::Get && rows.is_empty() {
                return Err(failure(format!(
                    "no row with {named} {}",
                    diagnostic_name(query.key)
                )));
            }
            let text = self.rows(&rows, query.columns, query.format)?;
            if query.delete {
                for (row, _) in &rows {
                    self.table.delete(&row.primary_key()).await.map_err(error)?;
                }
            }
            Ok(text)
        })
    }
    fn write(&self, text: String, delete: bool) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let rows = self.import(&text)?;
            let error = |e: flowsdn_table::TableError| failure(e.to_string());
            for row in rows {
                if delete {
                    self.table.delete(&row.primary_key()).await.map_err(error)?;
                } else {
                    self.table.insert(row).await.map_err(error)?;
                }
            }
            Ok(())
        })
    }
    fn initialized(&self) -> bool {
        self.table.initialized()
    }
    fn pending(&self) -> Vec<String> {
        self.table.pending_initializers()
    }
    fn wait_initialized(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.table.wait_initialized())
    }
}
fn account(total: &mut usize, cells: &[String]) -> Result<()> {
    for cell in cells {
        *total = total.saturating_add(cell.len());
    }
    if *total > MAX_BYTES {
        Err(limit())
    } else {
        Ok(())
    }
}
fn append(output: &mut String, text: &str) -> Result<()> {
    if output.len().saturating_add(text.len()) > MAX_BYTES {
        return Err(limit());
    }
    output.push_str(text);
    Ok(())
}

type Tables = BTreeMap<String, Arc<dyn Binding>>;

fn lookup<'a>(tables: &'a Tables, name: &str) -> Result<&'a Arc<dyn Binding>> {
    tables
        .get(name)
        .ok_or_else(|| failure(format!("unknown table: {}", diagnostic_name(name))))
}

/// Flags (each with a value, inline after `=` or as the next word) and the
/// other words, in order. A flag may come before or after the words.
fn flags<'a>(
    command: &str,
    args: &'a [String],
    allowed: &[&[&str]],
    switches: &[&str],
) -> Result<(BTreeMap<&'static str, &'a str>, Vec<&'a str>)> {
    let mut values = BTreeMap::new();
    let mut words = Vec::new();
    let mut parsing = true;
    let mut iter = args.iter();
    while let Some(word) = iter.next() {
        if parsing && word == "--" {
            parsing = false;
            continue;
        }
        if !(parsing && word.starts_with('-') && word.len() > 1) {
            words.push(word.as_str());
            continue;
        }
        let (flag, inline) = word
            .split_once('=')
            .map(|(flag, value)| (flag, Some(value)))
            .unwrap_or((word, None));
        if let Some(switch) = switches.iter().find(|s| **s == flag) {
            let canonical: &'static str = match *switch {
                "--delete" => "--delete",
                "-q" => "-q",
                _ => return Err(failure(format!("unknown {command} flag: {flag}"))),
            };
            if values.insert(canonical, "true").is_some() {
                return Err(failure(format!("duplicate {command} flag: {flag}")));
            }
            continue;
        }
        let canonical = allowed
            .iter()
            .find(|names| names.contains(&flag))
            .and_then(|names| names.last())
            .ok_or_else(|| failure(format!("unknown {command} flag: {}", diagnostic_name(flag))))?;
        let value = inline
            .or_else(|| iter.next().map(String::as_str))
            .ok_or_else(|| failure(format!("missing value for {flag}")))?;
        // Normalize to the static spelling used for lookups below.
        let key: &'static str = match *canonical {
            "--columns" => "--columns",
            "--out" => "--out",
            "--format" => "--format",
            "--index" => "--index",
            "--timeout" => "--timeout",
            "--grep" => "--grep",
            _ => return Err(failure(format!("unknown {command} flag: {flag}"))),
        };
        if values.insert(key, value).is_some() {
            return Err(failure(format!("duplicate {command} flag: {flag}")));
        }
    }
    Ok((values, words))
}
const COLUMNS: &[&str] = &["--columns"];
const OUT: &[&str] = &["-o", "--out"];
const FORMAT: &[&str] = &["-f", "--format"];
const INDEX: &[&str] = &["-i", "--index"];
const TIMEOUT: &[&str] = &["--timeout"];
const GREP: &[&str] = &["--grep"];

fn format_of(value: Option<&&str>) -> Result<Format> {
    match value.copied() {
        None | Some("table") => Ok(Format::Table),
        Some("json") => Ok(Format::Json),
        Some("yaml") => Ok(Format::Yaml),
        Some(other) => Err(failure(format!(
            "unknown format {}; use table, json or yaml",
            diagnostic_name(other)
        ))),
    }
}

/// `5s`, `100ms`, `1m`, `1.5s`, `2m30s`.
pub(crate) fn duration(text: &str) -> Result<Duration> {
    let bad = || failure(format!("invalid duration: {}", diagnostic_name(text)));
    let mut total = 0f64;
    let mut rest = text;
    if rest.is_empty() {
        return Err(bad());
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or_else(bad)?;
        let (number, tail) = rest.split_at(digits);
        let value: f64 = number.parse().map_err(|_| bad())?;
        let unit_end = tail
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(tail.len());
        let (unit, next) = tail.split_at(unit_end);
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return Err(bad()),
        };
        total = value.mul_add(scale, total);
        rest = next;
    }
    Duration::try_from_secs_f64(total).map_err(|_| bad())
}

fn emit(state: &mut State, out: Option<&&str>, text: String) -> Result<Control> {
    match out {
        Some(path) => state.write_table_output(path, text.as_bytes())?,
        None => state.publish(text, ""),
    }
    Ok(Control::Continue)
}

/// Run `db/<op>`.
pub(crate) async fn dispatch(
    tables: &Tables,
    state: &mut State,
    op: &str,
    args: &[String],
) -> Result<Control> {
    match op {
        "empty" => empty(tables, args),
        "show" => show(tables, state, args),
        "cmp" => compare(tables, state, args).await,
        "insert" | "delete" => {
            let (_, words) = flags(op, args, &[], &[])?;
            let (name, files) = words
                .split_first()
                .ok_or_else(|| failure(format!("db/{op} requires a table and files")))?;
            if files.is_empty() {
                return Err(failure(format!("db/{op} requires files")));
            }
            let binding = lookup(tables, name)?;
            for file in files {
                let text = state.read_text(file)?;
                binding.write(text, op == "delete").await?;
            }
            Ok(Control::Continue)
        }
        "get" | "list" | "prefix" | "lowerbound" => {
            let (values, words) = flags(
                op,
                args,
                &[COLUMNS, OUT, FORMAT, INDEX],
                if op == "get" { &["--delete"] } else { &[] },
            )?;
            let [name, key] = words.as_slice() else {
                return Err(failure(format!("db/{op} requires a table and a key")));
            };
            let mode = match op {
                "get" => Mode::Get,
                "list" => Mode::List,
                "prefix" => Mode::Prefix,
                _ => Mode::LowerBound,
            };
            let binding = lookup(tables, name)?;
            let text = binding
                .query(Query {
                    mode,
                    index: values.get("--index").copied(),
                    key,
                    columns: values.get("--columns").copied(),
                    format: format_of(values.get("--format"))?,
                    delete: values.contains_key("--delete"),
                })
                .await?;
            emit(state, values.get("--out"), text)
        }
        "initialized" => {
            let (values, words) = flags(op, args, &[TIMEOUT], &[])?;
            let timeout = values
                .get("--timeout")
                .map(|t| duration(t))
                .transpose()?
                .unwrap_or(DEFAULT_TIMEOUT);
            let bindings: Vec<(&str, &Arc<dyn Binding>)> = if words.is_empty() {
                tables.iter().map(|(n, b)| (n.as_str(), b)).collect()
            } else {
                words
                    .iter()
                    .map(|n| lookup(tables, n).map(|b| (*n, b)))
                    .collect::<Result<_>>()?
            };
            let pending = |bindings: &[(&str, &Arc<dyn Binding>)]| -> Vec<String> {
                bindings
                    .iter()
                    .filter(|(_, b)| !b.initialized())
                    .map(|(n, b)| format!("{n} ({})", b.pending().join(", ")))
                    .collect()
            };
            if pending(&bindings).is_empty() {
                return Ok(Control::Continue);
            }
            if tokio::runtime::Handle::try_current().is_err() {
                return Err(failure(format!(
                    "not initialized: {}",
                    pending(&bindings).join("; ")
                )));
            }
            let all = async {
                for (_, binding) in &bindings {
                    binding.wait_initialized().await;
                }
            };
            match tokio::time::timeout(timeout, all).await {
                Ok(()) => Ok(Control::Continue),
                Err(_) => Err(failure(format!(
                    "not initialized after {timeout:?}: {}",
                    pending(&bindings).join("; ")
                ))),
            }
        }
        other => Err(failure(format!("unknown command db/{other}"))),
    }
}

pub(crate) fn empty(tables: &Tables, args: &[String]) -> Result<Control> {
    let after_separator = args.first().map(String::as_str) == Some("--");
    let names = if after_separator {
        args.get(1..).unwrap_or_default()
    } else {
        args
    };
    if names.is_empty() {
        return Err(failure("db/empty requires table names"));
    }
    // Resolve every name first, so a misspelling is reported even when an
    // earlier named table is nonempty.
    for name in names {
        if !after_separator && name.starts_with('-') {
            return Err(failure("db/empty does not accept flags"));
        }
        lookup(tables, name)?;
    }
    for name in names {
        if !lookup(tables, name)?.is_empty() {
            return Err(failure(format!("table {name} is not empty")));
        }
    }
    Ok(Control::Continue)
}

pub(crate) fn show(tables: &Tables, state: &mut State, args: &[String]) -> Result<Control> {
    let (values, words) = flags("db/show", args, &[COLUMNS, OUT, FORMAT], &[])?;
    for (flag, value) in &values {
        if value.is_empty() {
            return Err(failure(format!("empty value for {flag}")));
        }
    }
    let [name] = words.as_slice() else {
        return Err(failure(if words.is_empty() {
            "db/show requires a table"
        } else {
            "db/show requires exactly one table"
        }));
    };
    let binding = lookup(tables, name)?;
    let output = binding.show(
        values.get("--columns").copied(),
        format_of(values.get("--format"))?,
    )?;
    emit(state, values.get("--out"), output)
}

/// The `.table` file (spec 17 §4.2): its column names, their offsets in
/// characters (or tab mode) and its expected rows.
struct Expected {
    names: Vec<String>,
    offsets: Vec<usize>,
    tabs: bool,
    rows: Vec<String>,
}
fn expected_table(text: &str) -> Result<Expected> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| failure("the .table file has no header"))?;
    let tabs = header.contains('\t');
    let mut names = Vec::new();
    let mut offsets = Vec::new();
    if tabs {
        names = header.split('\t').map(|n| n.trim().to_owned()).collect();
    } else {
        let mut start = None;
        for (index, c) in header.chars().chain([' ']).enumerate() {
            match (c.is_whitespace(), start) {
                (false, None) => start = Some(index),
                (true, Some(from)) => {
                    names.push(
                        header
                            .chars()
                            .skip(from)
                            .take(index.saturating_sub(from))
                            .collect(),
                    );
                    offsets.push(from);
                    start = None;
                }
                _ => {}
            }
        }
        // The first field starts at the line's start: indentation is shared.
        if let Some(first) = offsets.first_mut() {
            *first = 0;
        }
    }
    Ok(Expected {
        names,
        offsets,
        tabs,
        rows: lines.map(str::to_owned).collect(),
    })
}
fn split_fields(line: &str, offsets: &[usize], tabs: bool) -> Vec<String> {
    if tabs {
        return line.split('\t').map(|f| f.trim().to_owned()).collect();
    }
    let chars: Vec<char> = line.chars().collect();
    offsets
        .iter()
        .enumerate()
        .map(|(k, from)| {
            let from = (*from).min(chars.len());
            let to = offsets
                .get(k.saturating_add(1))
                .copied()
                .unwrap_or(chars.len())
                .clamp(from, chars.len());
            chars
                .get(from..to)
                .unwrap_or_default()
                .iter()
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .collect()
}
fn join_fields(cells: &[String], offsets: &[usize], tabs: bool) -> String {
    if tabs {
        return cells.join("\t");
    }
    let mut line = String::new();
    for (k, cell) in cells.iter().enumerate() {
        if let Some(offset) = offsets.get(k) {
            let at = line.chars().count();
            if k > 0 && at >= *offset {
                line.push(' ');
            } else {
                line.extend(std::iter::repeat_n(' ', offset.saturating_sub(at)));
            }
        }
        line.push_str(cell);
    }
    line
}

/// `db/cmp table file [--timeout=d] [--grep=re]` (spec 17 §5.2): compare
/// until equal, waking on the table's changes, or fail with a row diff.
async fn compare(tables: &Tables, state: &mut State, args: &[String]) -> Result<Control> {
    let (values, words) = flags("db/cmp", args, &[TIMEOUT, GREP], &[])?;
    let [name, file] = words.as_slice() else {
        return Err(failure("db/cmp requires a table and a file"));
    };
    let timeout = values
        .get("--timeout")
        .map(|t| duration(t))
        .transpose()?
        .unwrap_or(DEFAULT_TIMEOUT);
    let grep = values
        .get("--grep")
        .map(|re| regex::Regex::new(re).map_err(|e| failure(e.to_string())))
        .transpose()?;
    let binding = lookup(tables, name)?;
    let text = expand_text_bounded(
        &state.read_text(file)?,
        &state.environment,
        ExpansionMode::Plain,
        1,
        MAX_BYTES,
    )
    .map_err(|e| failure(e.to_string()))?;
    let expected = expected_table(&text)?;
    let headers = binding.headers();
    let mut indexes = Vec::new();
    for name in &expected.names {
        let index = headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                failure(format!(
                    "unknown column {:?}; available columns: {}",
                    diagnostic_name(name),
                    headers.join(",")
                ))
            })?;
        indexes.push(index);
    }
    let mut watch = binding.watch();
    let deadline = tokio::runtime::Handle::try_current()
        .is_ok()
        .then(|| tokio::time::Instant::now().checked_add(timeout))
        .flatten();
    loop {
        watch.borrow_and_update();
        let mut diff = Vec::new();
        let mut equal = true;
        let mut wanted = expected.rows.iter();
        let mut actual_rows = 0usize;
        for row in binding.cells()? {
            let cells: Vec<String> = indexes
                .iter()
                .map(|i| row.get(*i).cloned().unwrap_or_default())
                .collect();
            let line = join_fields(&cells, &expected.offsets, expected.tabs);
            if grep.as_ref().is_some_and(|re| !re.is_match(&line)) {
                continue;
            }
            actual_rows = actual_rows.saturating_add(1);
            match wanted.next() {
                None => {
                    diff.push(format!("- {line}"));
                    equal = false;
                }
                Some(want) => {
                    if split_fields(want, &expected.offsets, expected.tabs) == cells {
                        diff.push(format!("  {line}"));
                    } else {
                        diff.push(format!("- {line}"));
                        diff.push(format!("+ {want}"));
                        equal = false;
                    }
                }
            }
        }
        for rest in wanted {
            diff.push(format!("+ {rest}"));
            equal = false;
        }
        if equal {
            return Ok(Control::Continue);
        }
        let report = || {
            failure(format!(
                "table {name} does not match {file} ({actual_rows} rows, {} expected; - actual, + expected):\n  {}\n{}",
                expected.rows.len(),
                join_fields(&expected.names, &expected.offsets, expected.tabs),
                diff.join("\n")
            ))
        };
        let Some(deadline) = deadline else {
            return Err(report());
        };
        match tokio::time::timeout_at(deadline, watch.changed()).await {
            Ok(Ok(())) => continue,
            Ok(Err(_)) | Err(_) => return Err(report()),
        }
    }
}
