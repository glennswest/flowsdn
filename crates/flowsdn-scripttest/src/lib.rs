//! Parsing front end for the harvested scripts (spec 17 §§3.1–3.2).
//!
//! Variable expansion is explicit and preserves the tokenizer's literal fragments.
//! This crate does not execute commands or materialize files.
//! Parsing an archive is not evidence that its networking assertions pass.
mod expansion;
mod script;
mod txtar;

pub use expansion::{ExpansionMode, expand_text};
pub use script::{Command, Condition, Fragment, Line, Status, Token, parse_script, tokenize};
pub use txtar::{Archive, File};

/// A syntax error at a one-based source line.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}
