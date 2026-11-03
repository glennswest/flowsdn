//! The fixture layout (spec 07 §9.1): `tests/cloud/<provider>/<scenario>/`
//! holds `scenario.toml` and the ordered interactions `NNN-<operation>.json`.
//!
//! ```json
//! {
//!   "request": {"method": "POST", "path": "/", "headers": {"content-type": "..."}, "body": "..."},
//!   "response": {"status": 200, "headers": {"content-type": "text/xml"}, "body": "..."}
//! }
//! ```
//!
//! [`load`] scans the directory before it reads any fixture and refuses it on
//! a finding; [`write`] scans what it wrote.
use crate::scan::{self, Finding};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The request target: path and query.
    pub path: String,
    /// Lower-case names.
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interaction {
    /// From the file name: `003-assign-private-ip-addresses.json`.
    pub operation: String,
    pub request: Request,
    pub response: Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Aws,
    Azure,
    Alibaba,
    Gke,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Azure => "azure",
            Provider::Alibaba => "alibaba",
            Provider::Gke => "gke",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Provider::Aws, Provider::Azure, Provider::Alibaba, Provider::Gke]
            .into_iter()
            .find(|p| p.name() == s)
    }
}

/// `scenario.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub provider: Provider,
    pub region: String,
    /// The flowsdn operations the scenario performs.
    pub operations: Vec<String>,
    /// Capture date, `YYYY-MM-DD`.
    pub captured: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    pub meta: Meta,
    pub interactions: Vec<Interaction>,
}

#[derive(Debug)]
pub enum Error {
    Io(PathBuf, std::io::Error),
    Format(PathBuf, String),
    /// The scan found unscrubbed values; nothing was read.
    Scan(Vec<Finding>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Error::Format(p, e) => write!(f, "{}: {e}", p.display()),
            Error::Scan(findings) => {
                write!(f, "{} unscrubbed value(s)", findings.len())?;
                for finding in findings {
                    write!(f, "\n  {finding}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

fn headers_json(h: &BTreeMap<String, String>) -> Value {
    Value::Object(
        h.iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    )
}

impl Interaction {
    pub fn to_json(&self) -> Value {
        json!({
            "request": {
                "method": self.request.method,
                "path": self.request.path,
                "headers": headers_json(&self.request.headers),
                "body": self.request.body,
            },
            "response": {
                "status": self.response.status,
                "headers": headers_json(&self.response.headers),
                "body": self.response.body,
            },
        })
    }

    pub fn from_json(operation: &str, v: &Value) -> Result<Self, String> {
        let obj = |v: &Value, what: &str| -> Result<Map<String, Value>, String> {
            v.as_object().cloned().ok_or_else(|| format!("{what} is not an object"))
        };
        let string = |m: &Map<String, Value>, k: &str| -> Result<String, String> {
            m.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("missing string {k}"))
        };
        let headers = |m: &Map<String, Value>| -> Result<BTreeMap<String, String>, String> {
            let Some(h) = m.get("headers") else {
                return Ok(BTreeMap::new());
            };
            obj(h, "headers")?
                .iter()
                .map(|(k, v)| {
                    v.as_str()
                        .map(|v| (k.to_ascii_lowercase(), v.to_string()))
                        .ok_or_else(|| format!("header {k} is not a string"))
                })
                .collect()
        };
        let top = obj(v, "interaction")?;
        let req = obj(top.get("request").ok_or("missing request")?, "request")?;
        let resp = obj(top.get("response").ok_or("missing response")?, "response")?;
        let status = resp
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|s| u16::try_from(s).ok())
            .filter(|s| (100..=599).contains(s))
            .ok_or("response status is not 100-599")?;
        Ok(Interaction {
            operation: operation.to_string(),
            request: Request {
                method: string(&req, "method")?.to_ascii_uppercase(),
                path: string(&req, "path")?,
                headers: headers(&req)?,
                body: string(&req, "body").unwrap_or_default(),
            },
            response: Response {
                status,
                headers: headers(&resp)?,
                body: string(&resp, "body").unwrap_or_default(),
            },
        })
    }
}

impl Meta {
    pub fn to_toml(&self) -> String {
        let mut t = toml::Table::new();
        t.insert("name".into(), self.name.clone().into());
        t.insert("provider".into(), self.provider.name().into());
        t.insert("region".into(), self.region.clone().into());
        t.insert(
            "operations".into(),
            toml::Value::Array(self.operations.iter().map(|o| o.clone().into()).collect()),
        );
        t.insert("captured".into(), self.captured.clone().into());
        t.to_string()
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let t: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        let s = |k: &str| -> Result<String, String> {
            t.get(k)
                .and_then(toml::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("missing string {k}"))
        };
        if let Some(extra) = t.keys().find(|k| {
            !matches!(
                k.as_str(),
                "name" | "provider" | "region" | "operations" | "captured"
            )
        }) {
            return Err(format!("unknown key {extra}"));
        }
        let name = s("name")?;
        let provider = s("provider")?;
        let captured = s("captured")?;
        let operations = t
            .get("operations")
            .and_then(toml::Value::as_array)
            .ok_or("missing array operations")?
            .iter()
            .map(|o| o.as_str().map(str::to_string).ok_or("operations must be strings"))
            .collect::<Result<Vec<_>, _>>()?;
        if !is_name(&name) {
            return Err(format!("scenario name {name:?} is not [a-z0-9-]+"));
        }
        if !is_date(&captured) {
            return Err(format!("captured {captured:?} is not YYYY-MM-DD"));
        }
        if operations.is_empty() {
            return Err("operations is empty".into());
        }
        Ok(Meta {
            name,
            provider: Provider::parse(&provider)
                .ok_or_else(|| format!("unknown provider {provider:?}"))?,
            region: s("region")?,
            operations,
            captured,
        })
    }
}

/// `NNN-<operation>.json` -> (NNN, operation).
fn interaction_file(name: &str) -> Option<(u32, &str)> {
    let stem = name.strip_suffix(".json")?;
    let (n, op) = stem.split_once('-')?;
    (n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()) && is_name(op))
        .then(|| n.parse().ok().map(|n| (n, op)))
        .flatten()
}

/// Reads one scenario directory after the scan passes on it. The directory
/// must be `<provider>/<name>` as `scenario.toml` says, and hold nothing but
/// `scenario.toml` and `001-...`, `002-...` without gaps.
pub fn load(dir: &Path) -> Result<Scenario, Error> {
    let io = |e| Error::Io(dir.to_path_buf(), e);
    let findings = scan::scan_dir(dir).map_err(io)?;
    if !findings.is_empty() {
        return Err(Error::Scan(findings));
    }
    let format = |p: &Path, e: String| Error::Format(p.to_path_buf(), e);
    let toml_path = dir.join("scenario.toml");
    let meta = Meta::parse(
        &std::fs::read_to_string(&toml_path).map_err(|e| Error::Io(toml_path.clone(), e))?,
    )
    .map_err(|e| format(&toml_path, e))?;
    let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let parent = dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if dir_name != meta.name || parent != meta.provider.name() {
        return Err(format(
            dir,
            format!(
                "directory must be {}/{} as scenario.toml says",
                meta.provider.name(),
                meta.name
            ),
        ));
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        if name == "scenario.toml" {
            continue;
        }
        let (n, op) = interaction_file(&name)
            .ok_or_else(|| format(&path, "not scenario.toml or NNN-<operation>.json".into()))?;
        files.push((n, op.to_string(), path.clone()));
    }
    files.sort();
    let mut interactions = Vec::new();
    for (expected, (n, op, path)) in (1_u32..).zip(files) {
        if n != expected {
            return Err(format(&path, format!("expected {expected:03}-*.json")));
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Error::Io(path.clone(), e))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format(&path, e.to_string()))?;
        interactions.push(Interaction::from_json(&op, &value).map_err(|e| format(&path, e))?);
    }
    if interactions.is_empty() {
        return Err(format(dir, "no interactions".into()));
    }
    Ok(Scenario { meta, interactions })
}

/// Writes a scenario under `root` (`tests/cloud`) as
/// `<provider>/<name>/`, replacing what was there, then scans it. The
/// interactions must already be scrubbed: on a finding the files are removed.
pub fn write(root: &Path, scenario: &Scenario) -> Result<PathBuf, Error> {
    let dir = root
        .join(scenario.meta.provider.name())
        .join(&scenario.meta.name);
    let io = |p: &Path| {
        let p = p.to_path_buf();
        move |e| Error::Io(p, e)
    };
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(io(&dir))?;
    }
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    let toml_path = dir.join("scenario.toml");
    std::fs::write(&toml_path, scenario.meta.to_toml()).map_err(io(&toml_path))?;
    for (n, i) in (1_u32..).zip(&scenario.interactions) {
        if !is_name(&i.operation) {
            return Err(Error::Format(
                dir.clone(),
                format!("operation {:?} is not [a-z0-9-]+", i.operation),
            ));
        }
        let path = dir.join(format!("{n:03}-{}.json", i.operation));
        let mut text = serde_json::to_string_pretty(&i.to_json())
            .map_err(|e| Error::Format(path.clone(), e.to_string()))?;
        text.push('\n');
        std::fs::write(&path, text).map_err(io(&path))?;
    }
    let findings = scan::scan_dir(&dir).map_err(io(&dir))?;
    if !findings.is_empty() {
        std::fs::remove_dir_all(&dir).map_err(io(&dir))?;
        return Err(Error::Scan(findings));
    }
    Ok(dir)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn interaction(op: &str, body: &str, response: &str) -> Interaction {
        let mut headers = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        Interaction {
            operation: op.to_string(),
            request: Request {
                method: "POST".to_string(),
                path: "/".to_string(),
                headers,
                body: body.to_string(),
            },
            response: Response {
                status: 200,
                headers: BTreeMap::new(),
                body: response.to_string(),
            },
        }
    }

    pub(crate) fn scenario() -> Scenario {
        Scenario {
            meta: Meta {
                name: "happy-path".to_string(),
                provider: Provider::Aws,
                region: "us-east-1".to_string(),
                operations: vec!["node bring-up".to_string()],
                captured: "2026-11-03".to_string(),
            },
            interactions: vec![
                interaction(
                    "describe-instances",
                    "Action=DescribeInstances&Version=2016-11-15",
                    "<instanceId>i-5c7b0000000000001</instanceId>",
                ),
                interaction(
                    "create-network-interface",
                    "Action=CreateNetworkInterface&SubnetId=subnet-5c7b0002",
                    "<networkInterfaceId>eni-5c7b0000000000003</networkInterfaceId>",
                ),
            ],
        }
    }

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("flowsdn-fixture-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn round_trip() {
        let root = temp_root("rt");
        let s = scenario();
        let dir = write(&root, &s).expect("write");
        assert_eq!(dir, root.join("aws").join("happy-path"));
        assert!(dir.join("002-create-network-interface.json").exists());
        assert_eq!(load(&dir).expect("load"), s);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn unscrubbed_write_is_removed_and_load_scans_first() {
        let root = temp_root("scan");
        let mut s = scenario();
        if let Some(i) = s.interactions.first_mut() {
            i.response.body = "<publicIp>54.12.0.9</publicIp>".to_string();
        }
        assert!(matches!(write(&root, &s), Err(Error::Scan(_))));
        assert!(!root.join("aws").join("happy-path").exists());
        // A hand-placed unscrubbed file is refused before it is parsed.
        let dir = write(&root, &scenario()).expect("write");
        std::fs::write(dir.join("003-bad.json"), "not json, but 54.12.0.9").expect("write");
        match load(&dir) {
            Err(Error::Scan(f)) => assert_eq!(f.len(), 1),
            other => panic!("expected a scan refusal, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn layout_is_enforced() {
        let root = temp_root("layout");
        let dir = write(&root, &scenario()).expect("write");
        std::fs::rename(
            dir.join("002-create-network-interface.json"),
            dir.join("003-create-network-interface.json"),
        )
        .expect("rename");
        assert!(matches!(load(&dir), Err(Error::Format(..))));
        std::fs::write(dir.join("notes.txt"), "x").expect("write");
        assert!(matches!(load(&dir), Err(Error::Format(..))));
        std::fs::remove_file(dir.join("notes.txt")).expect("rm");
        std::fs::rename(
            dir.join("003-create-network-interface.json"),
            dir.join("002-create-network-interface.json"),
        )
        .expect("rename back");
        assert!(load(&dir).is_ok());
        // Under the wrong provider directory.
        let moved = root.join("azure").join("happy-path");
        std::fs::create_dir_all(root.join("azure")).expect("mkdir");
        std::fs::rename(&dir, &moved).expect("move");
        assert!(matches!(load(&moved), Err(Error::Format(..))));
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn meta_validation() {
        let good = scenario().meta;
        assert_eq!(Meta::parse(&good.to_toml()).expect("parse"), good);
        for bad in [
            "name = \"Happy\"\nprovider = \"aws\"\nregion = \"r\"\noperations = [\"x\"]\ncaptured = \"2026-11-03\"",
            "name = \"h\"\nprovider = \"gcp\"\nregion = \"r\"\noperations = [\"x\"]\ncaptured = \"2026-11-03\"",
            "name = \"h\"\nprovider = \"aws\"\nregion = \"r\"\noperations = []\ncaptured = \"2026-11-03\"",
            "name = \"h\"\nprovider = \"aws\"\nregion = \"r\"\noperations = [\"x\"]\ncaptured = \"03/11/2026\"",
            "name = \"h\"\nprovider = \"aws\"\nregion = \"r\"\noperations = [\"x\"]\ncaptured = \"2026-11-03\"\nextra = 1",
        ] {
            assert!(Meta::parse(bad).is_err(), "{bad}");
        }
    }
}
