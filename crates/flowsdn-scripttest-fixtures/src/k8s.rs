//! The fake Kubernetes client (spec 17 §3.6.1) and its `k8s/*` commands
//! (§3.3.4).
//!
//! Objects are JSON, keyed by resource (`v1.services`, `cilium.io.v2.ciliumnodes`),
//! namespace and name. Every mutation advances one revision counter, written
//! as `metadata.resourceVersion`. UIDs given in a file are kept on add and
//! never changed by an update; one not given is derived from the resource,
//! namespace, name and revision, so it is deterministic and new after a
//! delete and re-add. `k8s/get`/`k8s/list` redact `resourceVersion` and `uid`
//! unless `--show-redacted` names them. Like the reference's typed objects, a
//! Service always shows a `status.loadBalancer`.
use crate::fixture::lock;
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

/// One object's place: (resource, namespace, name).
type Key = (String, String, String);

/// The fake API server's state.
#[derive(Debug, Default)]
pub struct FakeClient {
    revision: u64,
    objects: BTreeMap<Key, Value>,
    /// Resources in the order first seen, for `k8s/summary`.
    resources: Vec<String>,
}

/// The plural of a kind, as the API server names its resource.
fn plural(kind: &str) -> String {
    let lower = kind.to_ascii_lowercase();
    if lower.ends_with("endpoints") {
        lower
    } else if let Some(stem) = lower.strip_suffix('y')
        && !stem.ends_with(['a', 'e', 'i', 'o', 'u'])
    {
        format!("{stem}ies")
    } else if lower.ends_with('s') || lower.ends_with('x') || lower.ends_with("ch") {
        format!("{lower}es")
    } else {
        format!("{lower}s")
    }
}

/// The resource of an object: `<group>.<version>.<plural>`, the core group
/// as `v1.<plural>`.
pub fn resource_of(object: &Value) -> Result<String, String> {
    let api = object
        .get("apiVersion")
        .and_then(Value::as_str)
        .ok_or("object has no apiVersion")?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("object has no kind")?;
    Ok(format!("{}.{}", api.replace('/', "."), plural(kind)))
}

fn meta(object: &Value, field: &str) -> String {
    object
        .pointer(&format!("/metadata/{field}"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
fn key_of(object: &Value) -> Result<Key, String> {
    let name = meta(object, "name");
    if name.is_empty() {
        return Err("object has no metadata.name".into());
    }
    Ok((resource_of(object)?, meta(object, "namespace"), name))
}
fn set_meta(object: &mut Value, field: &str, value: &str) {
    if let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.insert(field.into(), json!(value));
    }
}

/// A UUID-shaped identifier from FNV-1a over `parts` (two seeds, 128 bits).
fn derived_uid(parts: &[&str]) -> String {
    let hash = |seed: u64| {
        let mut h = seed;
        for part in parts {
            for byte in part.bytes().chain([0u8]) {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h
    };
    let (a, b) = (hash(0xcbf2_9ce4_8422_2325), hash(0x8422_2325_cbf2_9ce4));
    let hex = format!("{a:016x}{b:016x}");
    let part = |r: std::ops::Range<usize>| hex.get(r).unwrap_or("0").to_owned();
    format!(
        "{}-{}-{}-{}-{}",
        part(0..8),
        part(8..12),
        part(12..16),
        part(16..20),
        part(20..32)
    )
}

impl FakeClient {
    fn next(&mut self) -> u64 {
        self.revision = self.revision.saturating_add(1);
        self.revision
    }
    fn seen(&mut self, resource: &str) {
        if !self.resources.iter().any(|r| r == resource) {
            self.resources.push(resource.to_owned());
        }
    }
    /// Add (or replace) `object`. A given UID is kept, else one is derived.
    pub fn add(&mut self, mut object: Value) -> Result<(), String> {
        let key = key_of(&object)?;
        let revision = self.next().to_string();
        if meta(&object, "uid").is_empty() {
            let uid = derived_uid(&[&key.0, &key.1, &key.2, &revision]);
            set_meta(&mut object, "uid", &uid);
        }
        set_meta(&mut object, "resourceVersion", &revision);
        self.seen(&key.0);
        self.objects.insert(key, object);
        Ok(())
    }
    /// Update an existing object. `strict`: its `resourceVersion` must be the
    /// stored one. The stored UID is kept.
    pub fn update(&mut self, mut object: Value, strict: bool) -> Result<(), String> {
        let key = key_of(&object)?;
        let stored = self
            .objects
            .get(&key)
            .ok_or_else(|| format!("{} {}/{} not found", key.0, key.1, key.2))?;
        let (stored_version, stored_uid) = (meta(stored, "resourceVersion"), meta(stored, "uid"));
        if strict && meta(&object, "resourceVersion") != stored_version {
            return Err(format!(
                "conflict: {} {}/{} is at resourceVersion {stored_version}, not {:?}",
                key.0,
                key.1,
                key.2,
                meta(&object, "resourceVersion")
            ));
        }
        let revision = self.next().to_string();
        set_meta(&mut object, "uid", &stored_uid);
        set_meta(&mut object, "resourceVersion", &revision);
        self.objects.insert(key, object);
        Ok(())
    }
    /// Replace only `status` (the status subresource).
    pub fn update_status(&mut self, object: &Value) -> Result<(), String> {
        let key = key_of(object)?;
        let revision = self.next().to_string();
        let stored = self
            .objects
            .get_mut(&key)
            .ok_or_else(|| format!("{} {}/{} not found", key.0, key.1, key.2))?;
        let status = object.get("status").cloned().unwrap_or(Value::Null);
        if let Some(map) = stored.as_object_mut() {
            map.insert("status".into(), status);
        }
        set_meta(stored, "resourceVersion", &revision);
        Ok(())
    }
    pub fn delete(&mut self, object: &Value) -> Result<(), String> {
        let key = key_of(object)?;
        self.objects
            .remove(&key)
            .ok_or_else(|| format!("{} {}/{} not found", key.0, key.1, key.2))?;
        self.next();
        Ok(())
    }
    /// `k8s/resync`: drop every object of `resource`, add `objects`, at a new
    /// revision.
    pub fn resync(&mut self, resource: &str, objects: Vec<Value>) -> Result<(), String> {
        self.objects.retain(|key, _| key.0 != resource);
        self.next();
        for object in objects {
            self.add(object)?;
        }
        Ok(())
    }
    /// Resolve a resource as a script names it: `v1.services`, `services`,
    /// `Service`, else the closest known one (noted in `log`).
    pub fn resolve(&self, name: &str, log: &mut Vec<String>) -> Result<String, String> {
        let lower = name.to_ascii_lowercase();
        if self.resources.iter().any(|r| *r == lower) {
            return Ok(lower);
        }
        let plural_name = plural(&lower);
        let found = self.resources.iter().find(|r| {
            r.rsplit('.')
                .next()
                .is_some_and(|p| p == lower || p == plural_name)
        });
        match found {
            Some(resource) => {
                log.push(format!("k8s: resolved {name} to {resource}"));
                Ok(resource.clone())
            }
            None => Err(format!("unknown resource {name}")),
        }
    }
    pub fn get(&self, resource: &str, namespace: &str, name: &str) -> Option<&Value> {
        self.objects
            .get(&(resource.to_owned(), namespace.to_owned(), name.to_owned()))
    }
    pub fn list(&self, resource: &str, namespace: &str) -> Vec<&Value> {
        self.objects
            .iter()
            .filter(|(key, _)| key.0 == resource && (namespace.is_empty() || key.1 == namespace))
            .map(|(_, object)| object)
            .collect()
    }
    /// The list's `resourceVersion`: one past the newest object's.
    pub fn list_version(&self) -> u64 {
        self.revision.saturating_add(1)
    }
    /// `k8s/summary`: object count per resource, in the order first seen.
    pub fn summary(&self) -> String {
        let mut out = String::from("*:\n");
        for resource in &self.resources {
            let count = self.objects.keys().filter(|k| k.0 == *resource).count();
            out.push_str(&format!("- {resource}: {count}\n"));
        }
        out
    }
}

/// How an object is shown: typed defaults (a Service's `status.loadBalancer`)
/// and redaction of what `shown` does not name.
fn render(object: &Value, shown: &[String]) -> Value {
    let mut out = object.clone();
    if object.get("kind").and_then(Value::as_str) == Some("Service")
        && let Some(map) = out.as_object_mut()
    {
        let status = map
            .entry("status")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(status) = status.as_object_mut() {
            status
                .entry("loadBalancer")
                .or_insert_with(|| Value::Object(Map::new()));
        }
    }
    if let Some(metadata) = out.get_mut("metadata").and_then(Value::as_object_mut) {
        for (flag, field) in [("resource-version", "resourceVersion"), ("uid", "uid")] {
            if !shown.iter().any(|s| s == flag) {
                metadata.remove(field);
            }
        }
    }
    out
}

/// Flags (`-o`/`--out`, `--show-redacted`, `--strict`) and the other words.
struct Args {
    words: Vec<String>,
    out: Option<String>,
    shown: Vec<String>,
    strict: bool,
}
fn parse(args: &[String]) -> Result<Args, CommandError> {
    let mut parsed = Args {
        words: Vec::new(),
        out: None,
        shown: Vec::new(),
        strict: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-o" || arg == "--out" {
            parsed.out = Some(
                iter.next()
                    .ok_or_else(|| fail(format!("{arg} needs a file")))?
                    .clone(),
            );
        } else if let Some(file) = arg
            .strip_prefix("--out=")
            .or_else(|| arg.strip_prefix("-o="))
        {
            parsed.out = Some(file.to_owned());
        } else if let Some(fields) = arg.strip_prefix("--show-redacted=") {
            parsed.shown = fields.split(',').map(str::to_owned).collect();
        } else if arg == "--strict" {
            parsed.strict = true;
        } else if arg.starts_with('-') {
            return Err(fail(format!("unknown flag {arg}")));
        } else {
            parsed.words.push(arg.clone());
        }
    }
    Ok(parsed)
}
fn documents(state: &State, file: &str) -> Result<Vec<Value>, CommandError> {
    let text = state.read_text(file)?;
    flowsdn_k8s::crd::yaml_documents(&text)
        .map(|docs| docs.into_iter().filter(|d| !d.is_null()).collect())
        .map_err(|e| fail(format!("{file}: {e}")))
}
fn emit(state: &mut State, out: Option<&String>, value: &Value) -> Result<Control, CommandError> {
    let text = flowsdn_k8s::crd::to_yaml_with(value, go_plain);
    match out {
        Some(file) => state.write_text(file, &text)?,
        None => state.publish(text, ""),
    }
    Ok(Control::Continue)
}
fn ns_name(word: &str) -> (String, String) {
    match word.split_once('/') {
        Some((ns, name)) => (ns.to_owned(), name.to_owned()),
        None => (String::new(), word.to_owned()),
    }
}

/// Register the `k8s/*` commands bound to `client` (spec 17 §3.3.4).
pub fn register(engine: &mut Engine, client: &Arc<Mutex<FakeClient>>) -> Result<(), String> {
    type Op = fn(&mut FakeClient, Value, bool) -> Result<(), String>;
    let ops: [(&str, Op); 3] = [
        ("k8s/add", |c, o, _| c.add(o)),
        ("k8s/update", |c, o, strict| c.update(o, strict)),
        ("k8s/delete", |c, o, _| c.delete(&o)),
    ];
    for (name, op) in ops {
        let c = Arc::clone(client);
        engine.register_command(name, false, move |state: &mut State, args: &[String]| {
            let args = parse(args)?;
            if args.words.is_empty() {
                return Err(fail("needs files"));
            }
            for file in &args.words {
                for object in documents(state, file)? {
                    op(&mut lock(&c), object, args.strict)
                        .map_err(|e| fail(format!("{file}: {e}")))?;
                }
            }
            Ok(Control::Continue)
        })?;
    }
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/get",
        false,
        move |state: &mut State, args: &[String]| {
            let args = parse(args)?;
            let [resource, target] = args.words.as_slice() else {
                return Err(fail("k8s/get needs a resource and namespace/name"));
            };
            let (namespace, name) = ns_name(target);
            let client = lock(&c);
            let resource = client.resolve(resource, &mut state.log).map_err(fail)?;
            let object = client
                .get(&resource, &namespace, &name)
                .ok_or_else(|| fail(format!("{resource} {target} not found")))?;
            let value = render(object, &args.shown);
            drop(client);
            emit(state, args.out.as_ref(), &value)
        },
    )?;
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/list",
        false,
        move |state: &mut State, args: &[String]| {
            let args = parse(args)?;
            let (resource, namespace) = match args.words.as_slice() {
                [resource] => (resource.clone(), String::new()),
                [resource, namespace] => (resource.clone(), namespace.clone()),
                _ => return Err(fail("k8s/list needs a resource and an optional namespace")),
            };
            let client = lock(&c);
            let resource = client.resolve(&resource, &mut state.log).map_err(fail)?;
            let items: Vec<Value> = client
                .list(&resource, &namespace)
                .into_iter()
                .map(|o| render(o, &args.shown))
                .collect();
            let mut metadata = Map::new();
            if args.shown.iter().any(|s| s == "resource-version") {
                metadata.insert(
                    "resourceVersion".into(),
                    json!(client.list_version().to_string()),
                );
            }
            drop(client);
            emit(
                state,
                args.out.as_ref(),
                &json!({"items": items, "metadata": metadata}),
            )
        },
    )?;
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/svc/update-status",
        false,
        move |state: &mut State, args: &[String]| {
            let args = parse(args)?;
            for file in &args.words {
                for object in documents(state, file)? {
                    lock(&c)
                        .update_status(&object)
                        .map_err(|e| fail(format!("{file}: {e}")))?;
                }
            }
            Ok(Control::Continue)
        },
    )?;
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/resync",
        false,
        move |state: &mut State, args: &[String]| {
            let args = parse(args)?;
            let (resource, files) = args
                .words
                .split_first()
                .ok_or_else(|| fail("k8s/resync needs a resource"))?;
            let mut objects = Vec::new();
            for file in files {
                objects.extend(documents(state, file)?);
            }
            let mut client = lock(&c);
            let resource = client.resolve(resource, &mut state.log).map_err(fail)?;
            client.resync(&resource, objects).map_err(fail)?;
            Ok(Control::Continue)
        },
    )?;
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/summary",
        false,
        move |state: &mut State, args: &[String]| {
            let text = lock(&c).summary();
            match args.first() {
                Some(file) => state.write_text(file, &text)?,
                None => state.publish(text, ""),
            }
            Ok(Control::Continue)
        },
    )?;
    let c = Arc::clone(client);
    engine.register_command(
        "k8s/resources",
        false,
        move |state: &mut State, _: &[String]| {
            let text: String = lock(&c)
                .resources
                .iter()
                .map(|r| format!("{r}\n"))
                .collect();
            state.publish(text, "");
            Ok(Control::Continue)
        },
    )?;
    Ok(())
}

/// Whether the reference's encoder (go-yaml v2 behind sigs.k8s.io/yaml) writes
/// `s` plain: unless it is empty, would read back as a bool, null, number or
/// date (YAML 1.1), or holds an indicator, `: `, ` #`, a control character or
/// edge whitespace. Everything else is double-quoted, as there.
pub fn go_plain(s: &str) -> bool {
    const RESOLVED: [&str; 37] = [
        "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "true", "True", "TRUE",
        "false", "False", "FALSE", "on", "On", "ON", "off", "Off", "OFF", "null", "Null",
        "NULL", "~", ".inf", ".Inf", ".INF", "+.inf", "-.inf", "+.Inf", "-.Inf", ".nan",
        ".NaN", ".NAN", "<<",
    ];
    let Some(first) = s.chars().next() else {
        return false;
    };
    let second = s.chars().nth(1);
    let number = || {
        let t: String = s.chars().filter(|c| *c != '_').collect();
        let u = t.strip_prefix(['+', '-']).unwrap_or(&t);
        let radix = |prefix: [&str; 2], radix: u32| {
            prefix
                .iter()
                .find_map(|p| u.strip_prefix(p))
                .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_digit(radix)))
        };
        radix(["0x", "0X"], 16) || radix(["0o", "0O"], 8) || radix(["0b", "0B"], 2) || u.parse::<f64>().is_ok()
    };
    let date = || {
        let b = s.as_bytes();
        b.len() >= 8
            && b.iter().take(4).all(u8::is_ascii_digit)
            && b.get(4) == Some(&b'-')
    };
    !(RESOLVED.contains(&s)
        || s.starts_with(char::is_whitespace)
        || s.ends_with(char::is_whitespace)
        || s.ends_with(':')
        || s.contains(": ")
        || s.contains(" #")
        || s.chars().any(char::is_control)
        || "[]{},#&*!|>'\"%@`".contains(first)
        || ("-?:".contains(first) && second.is_none_or(char::is_whitespace))
        || (first.is_ascii_digit() || "+-.".contains(first)) && (number() || date()))
}
