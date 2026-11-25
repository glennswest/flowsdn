//! The health registry's commands (spec 17 §3.3.3): `health`, `health/ok`,
//! `health/history`, and the `health` table's `db/insert` adapter.
use crate::time;
use flowsdn_health::{HealthStatus, Level, Registry};
use flowsdn_scripttest::{CommandError, Control, Engine, State, table::Adapter};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

/// The level a row shows: Stopped once stopped, else its reported level.
fn shown(row: &HealthStatus) -> Level {
    if row.stopped.is_some() {
        Level::Stopped
    } else {
        row.level
    }
}

/// One `db/insert health` document: `id: {module: [..], component: [..]}`,
/// `level`, `message`, `error`, `lastok`, `updated`, `stopped`, `final`,
/// `count`. The zero time reads as unset.
fn status(doc: &Value) -> Result<HealthStatus, String> {
    let text = |key: &str| {
        doc.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let path = |key: &str| -> Vec<String> {
        doc.pointer(&format!("/id/{key}"))
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut id = path("module");
    id.extend(path("component"));
    if id.is_empty() {
        return Err("health row has no id".into());
    }
    let level = match text("level").to_ascii_lowercase().as_str() {
        "ok" => Level::Ok,
        "degraded" => Level::Degraded,
        "stopped" => Level::Stopped,
        other => return Err(format!("unknown health level {other:?}")),
    };
    let when = |key: &str| -> Result<Option<SystemTime>, String> {
        match doc.get(key).and_then(Value::as_str) {
            None => Ok(None),
            Some(t) => time::parse(t),
        }
    };
    Ok(HealthStatus {
        id: id.join("."),
        level,
        message: text("message"),
        error: text("error"),
        last_ok: when("lastok")?,
        updated: when("updated")?.unwrap_or(UNIX_EPOCH),
        stopped: when("stopped")?,
        final_message: text("final"),
        count: doc.get("count").and_then(Value::as_u64).unwrap_or(0),
    })
}
fn import(text: &str) -> Result<Vec<HealthStatus>, String> {
    flowsdn_k8s::crd::yaml_documents(text)
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|d| !d.is_null())
        .map(status)
        .collect()
}

/// A tree node: its children by name and the row at this path, if any.
#[derive(Default)]
struct Node<'a> {
    children: BTreeMap<&'a str, Node<'a>>,
    row: Option<&'a HealthStatus>,
}
fn draw(out: &mut String, node: &Node<'_>, prefix: &str, now: SystemTime) {
    let count = node.children.len();
    for (index, (name, child)) in node.children.iter().enumerate() {
        let last = index.saturating_add(1) == count;
        let (branch, carry) = if last {
            ("└── ", "    ")
        } else {
            ("├── ", "│   ")
        };
        out.push_str(prefix);
        out.push_str(branch);
        line(out, name, child, now);
        draw(out, child, &format!("{prefix}{carry}"), now);
    }
}
/// A node's name, and for a row its status, padded as the reference does.
fn line(out: &mut String, name: &str, node: &Node<'_>, now: SystemTime) {
    match node.row {
        None => out.push_str(name),
        Some(row) => {
            let level = shown(row).name().to_ascii_uppercase();
            let age = time::age(now.duration_since(row.updated).unwrap_or_default());
            let separator = if name.chars().count() >= 44 { " " } else { "" };
            out.push_str(&format!(
                "{name:<44}{separator}[{level}] {} ({age}, x{})",
                row.message, row.count
            ));
        }
    }
    out.push('\n');
}

/// `health [--output=f] [--match=re] [--levels=a,b] [module-prefix]`.
fn health(registry: &Registry, state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    let mut output = None;
    let mut matching = None;
    let mut levels: Option<Vec<String>> = None;
    let mut prefix = None;
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
            "-o" | "--output" => output = Some(value()?),
            "-m" | "--match" => {
                matching = Some(regex::Regex::new(&value()?).map_err(|e| fail(e.to_string()))?);
            }
            "-l" | "--levels" => {
                levels = Some(
                    value()?
                        .split(',')
                        .map(|l| l.trim().to_ascii_lowercase())
                        .collect(),
                );
            }
            _ if flag.starts_with('-') => return Err(fail(format!("unknown flag {flag}"))),
            _ => prefix = Some(arg.clone()),
        }
    }
    let snapshot = registry.snapshot();
    let rows: Vec<_> = snapshot
        .all()
        .map(|(row, _)| row)
        .filter(|row| {
            prefix.as_ref().is_none_or(|p| {
                row.id == *p
                    || row
                        .id
                        .strip_prefix(p.as_str())
                        .is_some_and(|rest| rest.starts_with('.'))
            })
        })
        .filter(|row| matching.as_ref().is_none_or(|re| re.is_match(&row.id)))
        .filter(|row| {
            levels.as_ref().is_none_or(|levels| {
                levels.contains(&shown(row).name().to_ascii_lowercase())
            })
        })
        .collect();
    let count = |level: Level| rows.iter().filter(|r| shown(r) == level).count();
    let mut text = format!(
        "Modules Health:\tStopped({}) Degraded({}) OK({})\n",
        count(Level::Stopped),
        count(Level::Degraded),
        count(Level::Ok)
    );
    let mut root = Node::default();
    for row in &rows {
        let mut node = &mut root;
        for part in row.id.split('.') {
            node = node.children.entry(part).or_default();
        }
        node.row = Some(row.as_ref());
    }
    let now = SystemTime::now();
    for (name, node) in &root.children {
        line(&mut text, name, node, now);
        draw(&mut text, node, "", now);
    }
    // The reference ends the tree with an empty line.
    text.push('\n');
    match output {
        Some(file) => state.write_text(&file, &text)?,
        None => state.publish(text, ""),
    }
    Ok(Control::Continue)
}

/// Register the `health` table and the health commands for `registry`.
pub fn register(engine: &mut Engine, registry: &Registry) -> Result<(), String> {
    engine.register_table_with(
        "health",
        registry.table_handle(),
        Adapter {
            import: Some(import),
            ..Adapter::default()
        },
    )?;
    let r = registry.clone();
    engine.register_command("health", false, move |state: &mut State, args: &[String]| {
        health(&r, state, args)
    })?;
    let r = registry.clone();
    engine.register_command("health/ok", false, move |_: &mut State, _: &[String]| {
        let snapshot = r.snapshot();
        let degraded: Vec<String> = snapshot
            .all()
            .filter(|(row, _)| shown(row) == Level::Degraded)
            .map(|(row, _)| format!("{}: {} ({})", row.id, row.message, row.error))
            .collect();
        if degraded.is_empty() {
            Ok(Control::Continue)
        } else {
            Err(fail(format!("degraded: {}", degraded.join("; "))))
        }
    })?;
    let r = registry.clone();
    engine.register_command(
        "health/history",
        false,
        move |state: &mut State, args: &[String]| {
            let output = match args {
                [] => None,
                [flag] => flag
                    .strip_prefix("--output=")
                    .or_else(|| flag.strip_prefix("-o="))
                    .map(str::to_owned),
                [flag, file] if flag == "-o" || flag == "--output" => Some(file.clone()),
                _ => return Err(fail("health/history takes only --output")),
            };
            let mut text = String::new();
            for event in r.events() {
                let detail = if event.error.is_empty() {
                    String::new()
                } else {
                    format!(" | {}", event.error)
                };
                text.push_str(&format!(
                    "{} | {:<16} | {}: {}{detail}\n",
                    time::format(event.time),
                    event.kind,
                    event.id,
                    event.message
                ));
            }
            match output {
                Some(file) => state.write_text(&file, &text)?,
                None => state.publish(text, ""),
            }
            Ok(Control::Continue)
        },
    )?;
    Ok(())
}
