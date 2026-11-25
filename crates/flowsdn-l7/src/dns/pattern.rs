//! FQDN selectors and DNS rule names as regexes (spec 16 §3.6.3, §5.5): the
//! same strings the reference makes, since they are what a restore file
//! holds.
use regex::Regex;
use serde_json::Value;

/// The longest name or pattern (`MaxFQDNLength`).
pub const MAX_FQDN_LENGTH: usize = 255;
/// The regex of a pattern of asterisks alone: every name.
pub const ALL: &str = "(^([-a-zA-Z0-9_]+[.])+$)|(^[.]$)";
const SUBDOMAINS: &str = "([-a-zA-Z0-9_]+([.][-a-zA-Z0-9_]+){0,})[.]";
const IN_LABEL: &str = "[-a-zA-Z0-9_]*";

/// Lower-cased and trimmed, with a trailing dot.
pub fn fqdn(name: &str) -> String {
    let mut out = name.trim().to_lowercase();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// Go's `regexp.QuoteMeta`: `\.+*?()|[]{}^$` escaped, nothing else.
pub fn quote_meta(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A `matchName`'s anchored literal regex.
pub fn name_regex(name: &str) -> String {
    format!("^{}$", quote_meta(&fqdn(name)))
}

/// A `matchPattern`'s anchored regex (§5.5), or why it is not valid.
pub fn pattern_regex(pattern: &str) -> Result<String, String> {
    let pattern = pattern.trim().to_lowercase();
    if pattern.len() > MAX_FQDN_LENGTH {
        return Err(format!(
            "matchPattern is longer than {MAX_FQDN_LENGTH} characters"
        ));
    }
    if pattern.is_empty()
        || !pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.*".contains(c))
    {
        return Err(format!("matchPattern {pattern:?} is not [-a-zA-Z0-9_.*]+"));
    }
    let stars = pattern.strip_suffix('.').unwrap_or(&pattern);
    if !stars.is_empty() && stars.chars().all(|c| c == '*') {
        return Ok(ALL.to_owned());
    }
    let dotted = fqdn(&pattern).replace('.', "[.]");
    let leading = dotted.chars().take_while(|c| *c == '*').count();
    let mut rest = dotted.as_str();
    let mut out = String::from("^");
    if leading >= 2
        && let Some(after) = dotted.get(leading..).and_then(|r| r.strip_prefix("[.]"))
    {
        out.push_str(SUBDOMAINS);
        rest = after;
    }
    let mut in_run = false;
    for c in rest.chars() {
        if c == '*' {
            if !in_run {
                out.push_str(IN_LABEL);
            }
            in_run = true;
        } else {
            in_run = false;
            out.push(c);
        }
    }
    out.push('$');
    Ok(out)
}

/// One `toFQDNs` entry or DNS rule (`matchName`, `matchPattern`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Selector {
    pub match_name: Option<String>,
    pub match_pattern: Option<String>,
    /// The regex that decides which names it selects.
    pub regex: String,
}
impl Selector {
    /// From a policy's `{matchName, matchPattern}`.
    pub fn parse(value: &Value) -> Result<Self, String> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let match_name = text("matchName");
        let match_pattern = text("matchPattern");
        if match_name
            .as_ref()
            .is_some_and(|n| n.len() > MAX_FQDN_LENGTH)
        {
            return Err(format!(
                "matchName is longer than {MAX_FQDN_LENGTH} characters"
            ));
        }
        let regex = match (&match_name, &match_pattern) {
            (Some(name), None) => name_regex(name),
            (None, Some(pattern)) => pattern_regex(pattern)?,
            (Some(name), Some(pattern)) => {
                format!("({})|({})", name_regex(name), pattern_regex(pattern)?)
            }
            (None, None) => return Err("neither matchName nor matchPattern".into()),
        };
        Regex::new(&regex).map_err(|e| format!("{regex}: {e}"))?;
        Ok(Self {
            match_name,
            match_pattern,
            regex,
        })
    }
    /// The reference's selector key (spec 06 §4.4): `MatchName: n,
    /// MatchPattern: p`; the label it gives an identity is `fqdn:` and this.
    pub fn key(&self) -> String {
        format!(
            "MatchName: {}, MatchPattern: {}",
            self.match_name.as_deref().unwrap_or(""),
            self.match_pattern.as_deref().unwrap_or("")
        )
    }
    /// The compiled regex (validated by [`Self::parse`]).
    pub fn compiled(&self) -> Option<Regex> {
        Regex::new(&self.regex).ok()
    }
}
