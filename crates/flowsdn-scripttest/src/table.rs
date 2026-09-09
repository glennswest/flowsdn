//! Typed table adapters. Bindings belong to one Engine, never a global registry.
use crate::{CommandError, Control, State};
use flowsdn_table::{Keyed, Table, TableRender};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const MAX_BYTES: usize = 8_388_608;
const MAX_ROWS: usize = 65_536;
const MAX_COLUMNS: usize = 128;
const MAX_CELLS: usize = 65_536;
type Result<T> = std::result::Result<T, CommandError>;

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

pub(crate) trait Binding: Send + Sync {
    fn is_empty(&self) -> bool;
    fn render(&self, columns: Option<&str>) -> Result<String>;
}
struct Typed<T: Keyed + TableRender> {
    table: Arc<Table<T>>,
    headers: &'static [&'static str],
}

pub(crate) fn bind<T: Keyed + TableRender>(
    table: Arc<Table<T>>,
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
    Ok(Arc::new(Typed { table, headers }))
}

impl<T: Keyed + TableRender> Binding for Typed<T> {
    fn is_empty(&self) -> bool {
        self.table.snapshot().is_empty()
    }
    fn render(&self, columns: Option<&str>) -> Result<String> {
        let headers = self.headers;
        let selected: Vec<usize> = match columns {
            None => (0..headers.len()).collect(),
            Some(columns) => {
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
                result
            }
        };
        let snapshot = self.table.snapshot();
        if snapshot.len() > MAX_ROWS
            || snapshot
                .len()
                .saturating_add(1)
                .saturating_mul(selected.len())
                > MAX_CELLS
        {
            return Err(limit());
        }
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let header: Vec<_> = selected
            .iter()
            .map(|index| headers.get(*index).expect("selected header").to_string())
            .collect();
        account(&mut bytes, &header)?;
        let mut widths: Vec<_> = header.iter().map(|cell| cell.chars().count()).collect();
        rows.push(header);
        for (row, _) in snapshot.all() {
            let cells = row.cells();
            if cells.len() != headers.len() {
                return Err(failure("TableRender cells/header count mismatch"));
            }
            // Validate every cell even when only a subset is selected: the row
            // renderer must obey its declared contract, not silently hide errors.
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
            let selected_cells: Vec<_> = selected
                .iter()
                .map(|index| cells.get(*index).expect("validated cell count").clone())
                .collect();
            account(&mut bytes, &selected_cells)?;
            for (width, cell) in widths.iter_mut().zip(&selected_cells) {
                *width = (*width).max(cell.chars().count());
            }
            rows.push(selected_cells);
        }
        let mut output = String::new();
        for row in rows {
            for (index, (cell, width)) in row.iter().zip(&widths).enumerate() {
                if index != 0 {
                    append(&mut output, "   ")?;
                }
                append(&mut output, cell)?;
                let padding = width.saturating_sub(cell.chars().count());
                if output.len().saturating_add(padding) > MAX_BYTES {
                    return Err(limit());
                }
                output.extend(std::iter::repeat_n(' ', padding));
            }
            append(&mut output, "\n")?;
        }
        Ok(output)
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

pub(crate) fn empty(
    tables: &BTreeMap<String, Arc<dyn Binding>>,
    args: &[String],
) -> Result<Control> {
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
        if !tables.contains_key(name) {
            return Err(failure(format!("unknown table: {}", diagnostic_name(name))));
        }
    }
    for name in names {
        if !tables.get(name).expect("validated table name").is_empty() {
            return Err(failure(format!("table {name} is not empty")));
        }
    }
    Ok(Control::Continue)
}

pub(crate) fn show(
    tables: &BTreeMap<String, Arc<dyn Binding>>,
    state: &mut State,
    args: &[String],
) -> Result<Control> {
    let mut table = None;
    let mut columns = None;
    let mut destination = None;
    let mut format = None;
    let mut words = args.iter();
    let mut flags = true;
    while let Some(word) = words.next() {
        if flags && word == "--" {
            flags = false;
            continue;
        }
        if flags && word.starts_with('-') {
            let (flag, inline) = word
                .split_once('=')
                .map(|(flag, value)| (flag, Some(value)))
                .unwrap_or((word, None));
            let slot = match flag {
                "--columns" => &mut columns,
                "-o" | "--out" => &mut destination,
                "-f" | "--format" => &mut format,
                _ => {
                    return Err(failure(format!(
                        "unknown db/show flag: {}",
                        diagnostic_name(flag)
                    )));
                }
            };
            if slot.is_some() {
                return Err(failure(format!("duplicate db/show flag: {flag}")));
            }
            let value = inline
                .or_else(|| words.next().map(String::as_str))
                .ok_or_else(|| failure(format!("missing value for {flag}")))?;
            if value.is_empty() {
                return Err(failure(format!("empty value for {flag}")));
            }
            *slot = Some(value);
        } else if table.replace(word.as_str()).is_some() {
            return Err(failure("db/show requires exactly one table"));
        }
    }
    let name = table.ok_or_else(|| failure("db/show requires a table"))?;
    if format.is_some_and(|format| format != "table") {
        return Err(failure("db/show currently supports only --format=table"));
    }
    let binding = tables
        .get(name)
        .ok_or_else(|| failure(format!("unknown table: {}", diagnostic_name(name))))?;
    let output = binding.render(columns)?;
    if let Some(path) = destination {
        state.write_table_output(path, output.as_bytes())?;
    } else {
        state.publish(output, "");
    }
    Ok(Control::Continue)
}
