//! Resolve a reviewed container baseline, then audit selected executable traces.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const REQUIRED: [&str; 4] = ["bpf", "mount", "perf_event_open", "setns"];

fn strings(value: &Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or("expected string array")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "expected string".into())
        })
        .collect()
}

fn filter(
    value: Option<&Value>,
    arch: &str,
    caps: &BTreeSet<String>,
    include: bool,
) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(include);
    };
    let obj = value.as_object().ok_or("invalid baseline filter")?;
    if obj.keys().any(|k| k != "arches" && k != "caps") {
        return Err("unsupported baseline filter".into());
    }
    let arches = obj
        .get("arches")
        .map(strings)
        .transpose()?
        .unwrap_or_default();
    let capabilities = obj
        .get("caps")
        .map(strings)
        .transpose()?
        .unwrap_or_default();
    Ok(if include {
        (arches.is_empty() || arches.iter().any(|a| a == arch))
            && capabilities.iter().all(|c| caps.contains(c))
    } else {
        arches.iter().any(|a| a == arch) || capabilities.iter().any(|c| caps.contains(c))
    })
}

fn errno(value: &Value, name: &str, numeric: &str) -> Result<Option<Value>, String> {
    if let Some(symbol) = value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let number = match symbol {
            "EPERM" => 1,
            "ENOSYS" => 38,
            _ => symbol
                .parse::<u32>()
                .map_err(|_| "unsupported symbolic errno")?,
        };
        return Ok(Some(json!(number)));
    }
    match value.get(numeric) {
        None | Some(Value::Null) => Ok(None),
        Some(v) if v.as_u64().is_some_and(|n| u32::try_from(n).is_ok()) => Ok(Some(v.clone())),
        _ => Err("invalid numeric errno".into()),
    }
}

/// Resolve containers/common architecture and capability predicates to OCI JSON.
/// Includes require every listed capability; excludes match any capability.
pub fn profile(baseline: &Value, arch: &str, caps: &BTreeSet<String>) -> Result<Value, String> {
    let architecture = match arch {
        "amd64" => "SCMP_ARCH_X86_64",
        "arm64" => "SCMP_ARCH_AARCH64",
        _ => return Err("arch must be amd64 or arm64".into()),
    };
    if baseline.get("defaultAction").and_then(Value::as_str) != Some("SCMP_ACT_ERRNO") {
        return Err("baseline must default to SCMP_ACT_ERRNO".into());
    }
    let mut architectures = vec![json!(architecture)];
    if baseline.get("archMap").is_some() && baseline.get("architectures").is_some() {
        return Err("ambiguous baseline architectures".into());
    }
    if let Some(map) = baseline.get("archMap") {
        let entries = map.as_array().ok_or("invalid archMap")?;
        let native = entries
            .iter()
            .find(|e| e.get("architecture").and_then(Value::as_str) == Some(architecture))
            .ok_or("native architecture missing from archMap")?;
        for sub in strings(
            native
                .get("subArchitectures")
                .ok_or("missing subArchitectures")?,
        )? {
            architectures.push(json!(sub));
        }
    } else if let Some(list) = baseline.get("architectures") {
        let names = strings(list)?;
        if !names.iter().any(|s| s == architecture) {
            return Err("baseline excludes native architecture".into());
        }
        architectures = names.into_iter().map(Value::String).collect();
    }
    let mut rules = Vec::new();
    for entry in baseline
        .get("syscalls")
        .and_then(Value::as_array)
        .ok_or("missing syscall rules")?
    {
        if !filter(entry.get("includes"), arch, caps, true)?
            || filter(entry.get("excludes"), arch, caps, false)?
        {
            continue;
        }
        let mut names = strings(entry.get("names").ok_or("baseline rule requires names")?)?;
        if entry.get("name").is_some() {
            return Err("singular name not supported".into());
        }
        names.retain(|n| !REQUIRED.contains(&n.as_str()));
        names.sort();
        names.dedup();
        if names.is_empty() {
            continue;
        }
        let action = entry
            .get("action")
            .and_then(Value::as_str)
            .ok_or("missing action")?;
        if ![
            "SCMP_ACT_ALLOW",
            "SCMP_ACT_ERRNO",
            "SCMP_ACT_KILL",
            "SCMP_ACT_KILL_PROCESS",
            "SCMP_ACT_KILL_THREAD",
            "SCMP_ACT_TRAP",
        ]
        .contains(&action)
        {
            return Err("unsupported baseline action".into());
        }
        let mut rule = serde_json::Map::new();
        rule.insert("names".into(), json!(names));
        rule.insert("action".into(), json!(action));
        if let Some(args) = entry.get("args").filter(|v| !v.is_null()) {
            if !args.is_array() {
                return Err("invalid syscall arguments".into());
            }
            rule.insert("args".into(), args.clone());
        }
        if let Some(number) = errno(entry, "errno", "errnoRet")? {
            rule.insert("errnoRet".into(), number);
        }
        rules.push(Value::Object(rule));
    }
    rules.push(json!({"names": REQUIRED, "action": "SCMP_ACT_ALLOW"}));
    let mut result = serde_json::Map::new();
    result.insert("defaultAction".into(), json!("SCMP_ACT_ERRNO"));
    result.insert("architectures".into(), json!(architectures));
    result.insert("syscalls".into(), json!(rules));
    if let Some(number) = errno(baseline, "defaultErrno", "defaultErrnoRet")? {
        result.insert("defaultErrnoRet".into(), number);
    }
    if let Some(flags) = baseline.get("flags") {
        strings(flags)?;
        result.insert("flags".into(), flags.clone());
    }
    if baseline.get("listenerPath").is_some() || baseline.get("listenerMetadata").is_some() {
        return Err("notification listener baseline not supported".into());
    }
    Ok(Value::Object(result))
}

#[derive(Default, Debug)]
pub struct Trace {
    pub counts: BTreeMap<String, u64>,
    pub selected_execs: u64,
    pub unattributed_calls: u64,
}

/// Parse one `strace -ff` PID file. No inheritance is guessed across PID files.
/// Exact executable paths must match successful execve; successful execveat
/// clears attribution because this parser does not resolve directory FDs.
pub fn trace(text: &str, executables: &BTreeSet<String>) -> Trace {
    let mut out = Trace::default();
    let mut active = false;
    for line in text.lines() {
        let line = line.trim_start();
        let line = if line.starts_with(|c: char| c.is_ascii_digit()) {
            line.split_once(char::is_whitespace)
                .map_or(line, |(_, rest)| rest.trim_start())
        } else {
            line
        };
        let Some((name, arguments)) = line.split_once('(') else {
            continue;
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            continue;
        }
        // A split exec cannot safely preserve the old executable identity: its
        // resumed line may describe a successful transition to a helper.
        if (name == "execve" || name == "execveat") && line.contains("<unfinished ...>") {
            active = false;
        }
        if name == "execveat"
            && line
                .rsplit_once(" = ")
                .is_some_and(|(_, result)| result == "0")
        {
            active = false;
        }
        if name == "execve"
            && line
                .rsplit_once(" = ")
                .is_some_and(|(_, result)| result == "0")
        {
            let path = arguments
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .map(|(path, _)| path);
            active = path.is_some_and(|p| !p.contains('\\') && executables.contains(p));
            if active {
                out.selected_execs = out.selected_execs.saturating_add(1);
            }
        }
        if active {
            let count = out.counts.entry(name.into()).or_default();
            *count = count.saturating_add(1);
        } else {
            out.unattributed_calls = out.unattributed_calls.saturating_add(1);
        }
    }
    out
}

/// Name-only observation cannot establish argument-filter coverage.
pub fn coverage(profile: &Value, syscall: &str) -> &'static str {
    let Some(rules) = profile.get("syscalls").and_then(Value::as_array) else {
        return "missing";
    };
    let mut unconditional = false;
    let mut conditional = false;
    let mut denied = false;
    for rule in rules.iter().filter(|r| {
        r.get("names")
            .and_then(Value::as_array)
            .is_some_and(|ns| ns.iter().any(|n| n.as_str() == Some(syscall)))
    }) {
        let args = rule
            .get("args")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        if rule.get("action").and_then(Value::as_str) == Some("SCMP_ACT_ALLOW") {
            conditional |= args;
            unconditional |= !args;
        } else {
            denied = true;
        }
    }
    if unconditional && !denied {
        "allowed"
    } else if unconditional || conditional {
        "conditional"
    } else if denied {
        "denied"
    } else {
        "missing"
    }
}
