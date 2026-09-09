//! Label parsing and canonical identity keys from identity specification §§3.1,4.1.
//! This is a label data model, not a selector matcher or Kubernetes validator.
use alloc::{collections::BTreeMap, string::String};
use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Label {
    source: String,
    key: String,
    value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelError {
    EmptyKey,
    CidrValue,
}
impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyKey => "a label key must not be empty",
            Self::CidrValue => "a CIDR label must not carry a value",
        })
    }
}
impl core::error::Error for LabelError {}

impl Label {
    /// Construct a label, normalizing an empty source to `unspec`.
    /// CIDR syntax validation and source-specific policy belong to the caller.
    pub fn new(source: &str, key: &str, value: &str) -> Result<Self, LabelError> {
        if key.is_empty() {
            return Err(LabelError::EmptyKey);
        }
        if source == "cidr" && !value.is_empty() {
            return Err(LabelError::CidrValue);
        }
        Ok(Self {
            source: String::from(if source.is_empty() { "unspec" } else { source }),
            key: String::from(key),
            value: String::from(value),
        })
    }

    /// Parse the source first, then split the remaining text at its first `=`.
    /// Unknown sources are retained. No whitespace is trimmed or unescaped.
    pub fn parse(text: &str) -> Result<Self, LabelError> {
        let (source, rest) = if let Some(rest) = text.strip_prefix('$') {
            ("reserved", rest)
        } else {
            text.split_once(':').unwrap_or(("unspec", text))
        };
        let (key, value) = match rest.split_once('=') {
            Some(("", value)) if source == "reserved" => (value, ""),
            Some(parts) => parts,
            None => (rest, ""),
        };
        Self::new(source, key, value)
    }

    /// Parse selector data; both implicit and explicit `unspec` become `any`.
    /// Matching (including CIDR containment) is not performed by this method.
    pub fn parse_selector(text: &str) -> Result<Self, LabelError> {
        let mut label = Self::parse(text)?;
        if label.source == "unspec" {
            label.source = String::from("any");
        }
        Ok(label)
    }

    pub fn source(&self) -> &str { &self.source }
    pub fn key(&self) -> &str { &self.key }
    pub fn value(&self) -> &str { &self.value }
}

/// Identity labels indexed by key only. A later insert replaces all fields of
/// the prior label even when its source differs. Iteration is UTF-8 byte order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Labels {
    by_key: BTreeMap<String, Label>,
}
impl Labels {
    pub fn new() -> Self { Self::default() }
    pub fn insert(&mut self, label: Label) -> Option<Label> {
        self.by_key.insert(label.key.clone(), label)
    }
    pub fn get(&self, key: &str) -> Option<&Label> { self.by_key.get(key) }
    pub fn remove(&mut self, key: &str) -> Option<Label> { self.by_key.remove(key) }
    pub fn len(&self) -> usize { self.by_key.len() }
    pub fn is_empty(&self) -> bool { self.by_key.is_empty() }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Label> { self.by_key.values() }

    /// Canonical identity index key, including `=` and trailing `;` per label.
    /// The specified format does not escape delimiters. Validate externally
    /// supplied label grammars before using this as an allocation key.
    pub fn canonical_key(&self) -> String {
        let mut result = String::new();
        for label in self.iter() {
            result.push_str(label.source());
            result.push(':');
            result.push_str(label.key());
            result.push('=');
            result.push_str(label.value());
            result.push(';');
        }
        result
    }
}
impl FromIterator<Label> for Labels {
    fn from_iter<T: IntoIterator<Item = Label>>(iter: T) -> Self {
        let mut labels = Self::new();
        for label in iter { labels.insert(label); }
        labels
    }
}
