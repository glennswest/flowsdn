use crate::{ParseError, Token};
use std::collections::BTreeMap;

/// How values substituted into an unquoted fragment are represented.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExpansionMode {
    #[default]
    Plain,
    /// Escape substituted values as regex literals. The expression written in
    /// the script, including quoted fragments, remains unchanged.
    Regex,
}

/// Expand `$name` and `${name}` without tokenizing, splitting words, or recursively
/// expanding substituted values. Undefined variables contribute an empty string.
/// Unbraced names contain ASCII letters, digits and underscores; `/` and `:` are
/// also accepted as single-character names for the script's separator variables.
/// Braces allow other environment names, such as `${name-with-dashes}`.
///
/// A dollar without a name is literal. Empty or unterminated braces are rejected
/// with the supplied one-based source line. Backslashes are ordinary characters:
/// script quoting, rather than shell-style backslash escaping, protects a dollar.
/// This function is suitable for archive names and `cmpenv` contents; normal
/// command arguments should use `Token::expand` to preserve quote boundaries.
pub fn expand_text(
    text: &str,
    environment: &BTreeMap<String, String>,
    mode: ExpansionMode,
    line: usize,
) -> Result<String, ParseError> {
    let mut chars = text.chars().peekable();
    let mut result = String::new();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            result.push(ch);
            continue;
        }
        let mut name = String::new();
        if chars.peek() == Some(&'{') {
            chars.next();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => name.push(ch),
                    None => return Err(ParseError::new(line, "unterminated variable expansion")),
                }
            }
            if name.is_empty() {
                return Err(ParseError::new(line, "empty variable name"));
            }
        } else if matches!(chars.peek(), Some('/' | ':')) {
            if let Some(ch) = chars.next() {
                name.push(ch);
            }
        } else {
            while let Some(ch) = chars.peek().copied() {
                if !ch.is_ascii_alphanumeric() && ch != '_' {
                    break;
                }
                chars.next();
                name.push(ch);
            }
            if name.is_empty() {
                result.push('$');
                continue;
            }
        }
        if let Some(value) = environment.get(&name) {
            match mode {
                ExpansionMode::Plain => result.push_str(value),
                ExpansionMode::Regex => result.push_str(&regex::escape(value)),
            }
        }
    }
    Ok(result)
}

impl Token {
    /// Expand unquoted fragments independently and concatenate them with literal
    /// quoted fragments. An empty result remains an argument; expansion never
    /// creates extra words or turns inserted quotes/comments into script syntax.
    /// The caller selects regex mode for the command's declared pattern argument.
    pub fn expand(
        &self,
        environment: &BTreeMap<String, String>,
        mode: ExpansionMode,
        line: usize,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        for fragment in &self.0 {
            if fragment.quoted {
                result.push_str(&fragment.text);
            } else {
                result.push_str(&expand_text(&fragment.text, environment, mode, line)?);
            }
        }
        Ok(result)
    }
}
