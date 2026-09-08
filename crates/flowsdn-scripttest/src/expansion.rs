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
    expand_text_bounded(text, environment, mode, line, usize::MAX)
}

/// As `expand_text`, but refuses each append that would exceed `max_bytes`.
/// A repeated variable cannot allocate the full expanded output before failing.
pub fn expand_text_bounded(
    text: &str,
    environment: &BTreeMap<String, String>,
    mode: ExpansionMode,
    line: usize,
    max_bytes: usize,
) -> Result<String, ParseError> {
    let mut chars = text.chars().peekable();
    let mut result = String::new();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            let mut bytes = [0; 4];
            append(&mut result, ch.encode_utf8(&mut bytes), max_bytes, line)?;
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
                append(&mut result, "$", max_bytes, line)?;
                continue;
            }
        }
        if let Some(value) = environment.get(&name) {
            match mode {
                ExpansionMode::Plain => append(&mut result, value, max_bytes, line)?,
                ExpansionMode::Regex => {
                    // Escape never shortens a value. Check before allocating it;
                    // the intermediate escape buffer is at most twice this bound.
                    if result.len().saturating_add(value.len()) > max_bytes {
                        return Err(ParseError::new(line, "variable expansion exceeds byte limit"));
                    }
                    append(&mut result, &regex::escape(value), max_bytes, line)?;
                }
            }
        }
    }
    Ok(result)
}

fn append(output: &mut String, value: &str, limit: usize, line: usize) -> Result<(), ParseError> {
    if output.len().saturating_add(value.len()) > limit {
        return Err(ParseError::new(line, "variable expansion exceeds byte limit"));
    }
    output.push_str(value);
    Ok(())
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
        self.expand_bounded(environment, mode, line, usize::MAX)
    }

    /// Expand a complete token under an aggregate byte limit, including quoted
    /// fragments. The limit is enforced while producing each fragment.
    pub fn expand_bounded(
        &self,
        environment: &BTreeMap<String, String>,
        mode: ExpansionMode,
        line: usize,
        max_bytes: usize,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        for fragment in &self.0 {
            if fragment.quoted {
                append(&mut result, &fragment.text, max_bytes, line)?;
            } else {
                let expanded = expand_text_bounded(&fragment.text, environment, mode, line, max_bytes.saturating_sub(result.len()))?;
                append(&mut result, &expanded, max_bytes, line)?;
            }
        }
        Ok(result)
    }
}
