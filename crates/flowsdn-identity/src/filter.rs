//! Identity and node label filters specified in identity specification §4.2.
//! Construction is atomic: invalid configuration returns no partial filter.
use crate::labels::{Label, Labels};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use regex::Regex;
use regex_syntax::ast::{
    self, AssertionKind, Ast, ClassPerl, ClassPerlKind, ClassSetItem, Span, Visitor,
};

// AST spans distinguish real escapes from escaped backslashes and preserve
// bracket context. The visitor uses constant stack space for nested patterns.
fn re2_ascii_classes(pattern: &str) -> Result<String, FilterError> {
    struct Replacements(Vec<(Span, &'static str)>);
    impl Replacements {
        fn perl(&mut self, class: &ClassPerl) {
            let replacement = match (&class.kind, class.negated) {
                (ClassPerlKind::Digit, false) => "[0-9]",
                (ClassPerlKind::Digit, true) => "[^0-9]",
                (ClassPerlKind::Word, false) => "[A-Za-z0-9_]",
                (ClassPerlKind::Word, true) => "[^A-Za-z0-9_]",
                (ClassPerlKind::Space, false) => r"[\t\n\f\r ]",
                (ClassPerlKind::Space, true) => r"[^\t\n\f\r ]",
            };
            self.0.push((class.span, replacement));
        }
    }
    impl Visitor for Replacements {
        type Output = Vec<(Span, &'static str)>;
        type Err = FilterError;
        fn finish(self) -> Result<Self::Output, Self::Err> {
            Ok(self.0)
        }
        fn visit_pre(&mut self, ast: &Ast) -> Result<(), Self::Err> {
            match ast {
                Ast::ClassPerl(class) => self.perl(class),
                Ast::Assertion(assertion) => match assertion.kind {
                    AssertionKind::WordBoundary => self.0.push((assertion.span, r"(?-u:\b)")),
                    AssertionKind::NotWordBoundary => self.0.push((assertion.span, r"(?-u:\B)")),
                    _ => {}
                },
                _ => {}
            }
            Ok(())
        }
        fn visit_class_set_item_pre(&mut self, item: &ClassSetItem) -> Result<(), Self::Err> {
            if let ClassSetItem::Perl(class) = item {
                self.perl(class);
            }
            Ok(())
        }
    }
    let ast = ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|error| FilterError(error.to_string()))?;
    let mut replacements = ast::visit(&ast, Replacements(Vec::new()))?;
    replacements.sort_by_key(|(span, _)| span.start.offset);
    let mut result = String::new();
    let mut previous = 0;
    for (span, replacement) in replacements {
        result.push_str(
            pattern
                .get(previous..span.start.offset)
                .expect("ordered AST spans"),
        );
        result.push_str(replacement);
        previous = span.end.offset;
    }
    result.push_str(
        pattern
            .get(previous..)
            .expect("AST span ends at character boundary"),
    );
    Ok(result)
}

pub const DEFAULT_ENTRIES: [&str; 21] = [
    "reserved:.*",
    r"io\.kubernetes\.pod\.namespace",
    r"io\.cilium\.k8s\.namespace\.labels",
    r"app\.kubernetes\.io",
    r"io\.cilium\.k8s\.policy\.cluster",
    r"io\.cilium\.k8s\.policy\.serviceaccount",
    r"!io\.kubernetes",
    r"!kubernetes\.io",
    r"!statefulset\.kubernetes\.io/pod-name",
    r"!apps\.kubernetes\.io/pod-index",
    r"!batch\.kubernetes\.io/job-completion-index",
    r"!batch\.kubernetes\.io/controller-uid",
    r"!.*beta\.kubernetes\.io",
    r"!k8s\.io",
    "!pod-template-generation",
    "!pod-template-hash",
    "!controller-revision-hash",
    "!controller-uid",
    "!annotation.*",
    "!etcd_node",
    r"!topology\.kubernetes\.io",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterError(String);
impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for FilterError {}

#[derive(Clone, Debug)]
enum Matcher {
    Regex(Regex),
    Literal,
}

#[derive(Clone, Debug)]
pub struct Rule {
    source: String,
    pattern: String,
    exclude: bool,
    matcher: Matcher,
}
impl Rule {
    /// Split the first colon before removing a leading `!` from the pattern.
    /// Use an explicit empty source (`:(?:a|b)`) for patterns containing colons.
    pub fn parse(entry: &str) -> Result<Self, FilterError> {
        let (source, pattern) = entry.split_once(':').unwrap_or(("", entry));
        if pattern.is_empty() {
            return Err(FilterError("label filter pattern is empty".into()));
        }
        let (exclude, pattern) = match pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, pattern),
        };
        // Search then check start, rather than modifying anchors or alternation.
        let matcher = Regex::new(&re2_ascii_classes(pattern)?)
            .map_err(|error| FilterError(error.to_string()))?;
        Ok(Self {
            source: source.into(),
            pattern: pattern.into(),
            exclude,
            matcher: Matcher::Regex(matcher),
        })
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
    pub fn is_exclusion(&self) -> bool {
        self.exclude
    }
    pub fn is_literal(&self) -> bool {
        matches!(self.matcher, Matcher::Literal)
    }
    pub fn match_length(&self, label: &Label) -> Option<usize> {
        if !self.source.is_empty() && self.source != label.source() {
            return None;
        }
        match &self.matcher {
            Matcher::Regex(regex) => regex
                .find(label.key())
                .filter(|found| found.start() == 0)
                .map(|found| found.end()),
            Matcher::Literal => label
                .key()
                .starts_with(&self.pattern)
                .then_some(self.pattern.len()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterDiagnostic {
    /// The caller should log this at error severity; the configuration is accepted.
    MissingReservedRule,
}

#[derive(Clone, Debug)]
pub struct LabelFilter {
    rules: Vec<Rule>,
    whitelist: bool,
    node_only: bool,
    diagnostics: Vec<FilterDiagnostic>,
}
impl LabelFilter {
    /// Default identity rules plus CLI additions. Built-in includes are exceptions
    /// to exclusions, and do not themselves enable whitelist mode.
    pub fn identity(additional: &[&str]) -> Result<Self, FilterError> {
        let mut filter = Self::empty(false);
        for entry in DEFAULT_ENTRIES {
            filter.rules.push(Rule::parse(entry)?);
        }
        filter.append(additional)?;
        Ok(filter)
    }
    /// Node rules have no defaults. Non-node labels pass through unchanged.
    pub fn node(entries: &[&str]) -> Result<Self, FilterError> {
        let mut filter = Self::empty(true);
        filter.append(entries)?;
        Ok(filter)
    }
    fn empty(node_only: bool) -> Self {
        Self {
            rules: Vec::new(),
            whitelist: false,
            node_only,
            diagnostics: Vec::new(),
        }
    }
    fn append(&mut self, entries: &[&str]) -> Result<(), FilterError> {
        for entry in entries.iter().filter(|entry| !entry.is_empty()) {
            let rule = Rule::parse(entry)?;
            self.whitelist |= !rule.exclude;
            self.rules.push(rule);
        }
        Ok(())
    }
    /// Decode caller-supplied JSON bytes; file I/O and log emission belong to the
    /// caller. File rules are literal prefixes, CLI additions remain regexes.
    pub fn identity_from_json(bytes: &[u8], additional: &[&str]) -> Result<Self, FilterError> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| FilterError(error.to_string()))?;
        let object = value
            .as_object()
            .ok_or_else(|| FilterError("prefix file must be an object".into()))?;
        if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(FilterError("prefix file version must be 1".into()));
        }
        let mut filter = Self::empty(false);
        if let Some(prefixes) = object
            .get("valid-prefixes")
            .filter(|value| !value.is_null())
        {
            let prefixes = prefixes
                .as_array()
                .ok_or_else(|| FilterError("valid-prefixes must be an array".into()))?;
            for (index, prefix) in prefixes.iter().enumerate() {
                let source = prefix
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .filter(|source| !source.is_empty())
                    .ok_or_else(|| {
                        FilterError(format!("prefix {index} source must be nonempty"))
                    })?;
                let pattern = prefix
                    .get("prefix")
                    .and_then(serde_json::Value::as_str)
                    .filter(|pattern| !pattern.is_empty())
                    .ok_or_else(|| {
                        FilterError(format!("prefix {index} pattern must be nonempty"))
                    })?;
                let exclude = match prefix.get("invert") {
                    None | Some(serde_json::Value::Null) => false,
                    Some(serde_json::Value::Bool(value)) => *value,
                    _ => {
                        return Err(FilterError(format!(
                            "prefix {index} invert must be boolean"
                        )));
                    }
                };
                filter.whitelist |= !exclude;
                filter.rules.push(Rule {
                    source: source.into(),
                    pattern: pattern.into(),
                    exclude,
                    matcher: Matcher::Literal,
                });
            }
        }
        filter.append(additional)?;
        // Compatibility diagnostic checks pattern/source presence, not order or
        // invert; this diagnostic alone does not prove reserved labels are kept.
        if !filter
            .rules
            .iter()
            .any(|rule| rule.source == "reserved" && rule.pattern == ".*")
        {
            filter
                .diagnostics
                .push(FilterDiagnostic::MissingReservedRule);
        }
        Ok(filter)
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    pub fn diagnostics(&self) -> &[FilterDiagnostic] {
        &self.diagnostics
    }
    pub fn is_whitelist(&self) -> bool {
        self.whitelist
    }
    pub fn retains(&self, label: &Label) -> bool {
        if self.node_only && label.source() != "node" {
            return true;
        }
        // Zero is deliberately the compatibility sentinel, even for a regex
        // that matches an empty string. Rule order matters for zero exclusions.
        let (mut included, mut ignored) = (0, 0);
        for rule in &self.rules {
            if let Some(length) = rule.match_length(label) {
                if rule.exclude {
                    if ignored == 0 || length < ignored {
                        ignored = length;
                    }
                } else {
                    included = included.max(length);
                }
            }
        }
        (!self.whitelist && ignored == 0) || included > ignored
    }
    /// Return retained identity labels and informational labels without changing
    /// source/key/value data or mutating the input set.
    pub fn partition(&self, labels: &Labels) -> (Labels, Labels) {
        let (mut identity, mut information) = (Labels::new(), Labels::new());
        for label in labels.iter() {
            if self.retains(label) {
                identity.insert(label.clone());
            } else {
                information.insert(label.clone());
            }
        }
        (identity, information)
    }
}
