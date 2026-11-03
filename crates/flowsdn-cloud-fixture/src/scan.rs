//! The pattern scan over `tests/cloud/**` (ADR-0007 §2, spec 22
//! `cloud-fixture-scan`): it runs before any fixture is read and fails on a
//! credential, a real account identifier or a signature. A finding names the
//! file, line, column and class, never the value.
use crate::rules::{self, Class, IPV4, IPV6, RULES, is_placeholder};
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// One unscrubbed value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub class: Class,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: unscrubbed {}",
            self.path.display(),
            self.line,
            self.column,
            self.class.name()
        )
    }
}

fn position(text: &str, offset: usize) -> (usize, usize) {
    let before = text.get(..offset).unwrap_or(text);
    let line = before.matches('\n').count().saturating_add(1);
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |l| l.chars().count())
        .saturating_add(1);
    (line, column)
}

/// Unscrubbed values in `text`, as (line, column, class), in text order.
pub fn scan_text(text: &str) -> Vec<(usize, usize, Class)> {
    let mut hits = Vec::new();
    for rule in RULES.iter() {
        for caps in rule.re.captures_iter(text) {
            if let Some(value) = caps.get(rule.group)
                && !is_placeholder(rule.form, value.as_str())
            {
                let (line, column) = position(text, value.start());
                hits.push((line, column, rule.class));
            }
        }
    }
    for m in IPV4.find_iter(text) {
        if m.as_str().parse::<Ipv4Addr>().is_ok_and(rules::is_public_v4) {
            let (line, column) = position(text, m.start());
            hits.push((line, column, Class::PublicIp));
        }
    }
    for m in IPV6.find_iter(text) {
        if rules::parse_v6(m.as_str()).is_some_and(rules::is_public_v6) {
            let (line, column) = position(text, m.start());
            hits.push((line, column, Class::PublicIp));
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Scans every file under `root` (recursively, in path order). A missing
/// `root` has no findings.
pub fn scan_dir(root: &Path) -> std::io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    if !root.exists() {
        return Ok(findings);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = std::fs::read_dir(&dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        for path in entries {
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = std::fs::read(&path)?;
            match String::from_utf8(bytes) {
                Ok(text) => findings.extend(scan_text(&text).into_iter().map(
                    |(line, column, class)| Finding {
                        path: path.clone(),
                        line,
                        column,
                        class,
                    },
                )),
                Err(_) => findings.push(Finding {
                    path: path.clone(),
                    line: 0,
                    column: 0,
                    class: Class::NotText,
                }),
            }
        }
    }
    findings.sort();
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_and_no_value_in_the_report() {
        let text = "{\n  \"x\": \"ok\",\n  \"ip\": \"54.12.0.9\"\n}";
        let hits = scan_text(text);
        assert_eq!(hits, vec![(3, 10, Class::PublicIp)]);
        let f = Finding {
            path: PathBuf::from("tests/cloud/aws/s/001-x.json"),
            line: 3,
            column: 10,
            class: Class::PublicIp,
        };
        let shown = f.to_string();
        assert_eq!(shown, "tests/cloud/aws/s/001-x.json:3:10: unscrubbed public IP address");
        assert!(!shown.contains("54.12"));
    }

    #[test]
    fn clean_provider_text_passes() {
        for text in [
            "Action=DescribeSubnets&Version=2016-11-15&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-5c7b0001",
            r#"{"privateIpAddress":"10.0.1.5","cidrBlock":"10.0.0.0/16","region":"us-east-1"}"#,
            "/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-1?api-version=2024-07-01",
            "2026-11-03T10:25:31Z 0a:1b:2c:3d:4e:5f fd00::1 169.254.169.254",
            r#"{"authorization":"scrubbed","token":""}"#,
        ] {
            assert_eq!(scan_text(text), Vec::new(), "{text}");
        }
    }

    #[test]
    fn walks_a_tree_and_refuses_binary() {
        let root = std::env::temp_dir().join(format!("flowsdn-scan-{}", std::process::id()));
        let dir = root.join("aws").join("happy");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("001-a.json"), "{\"ip\": \"10.0.0.1\"}").expect("write");
        std::fs::write(dir.join("002-b.json"), "{\"ip\": \"54.12.0.9\"}").expect("write");
        std::fs::write(dir.join("blob"), [0xff_u8, 0xfe]).expect("write");
        let found = scan_dir(&root).expect("scan");
        let classes: Vec<_> = found.iter().map(|f| (f.line, f.class)).collect();
        assert_eq!(classes, vec![(1, Class::PublicIp), (0, Class::NotText)]);
        assert_eq!(scan_dir(&root.join("absent")).expect("scan"), Vec::new());
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
