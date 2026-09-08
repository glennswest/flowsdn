use crate::ParseError;

/// Quoted fragments are literal; unquoted fragments await runtime expansion.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Fragment {
    pub text: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Token(pub Vec<Fragment>);

impl Token {
    pub fn unquoted(&self) -> Option<&str> {
        match self.0.as_slice() {
            [fragment] if !fragment.quoted => Some(&fragment.text),
            _ => None,
        }
    }

    /// Concatenates fragments without interpreting environment variables.
    pub fn literal(&self) -> String {
        self.0.iter().map(|fragment| fragment.text.as_str()).collect()
    }
}

fn flush_fragment(text: &mut String, fragments: &mut Vec<Fragment>) {
    if !text.is_empty() {
        fragments.push(Fragment { text: std::mem::take(text), quoted: false });
    }
}

fn flush_token(fragments: &mut Vec<Fragment>, tokens: &mut Vec<Token>) {
    if !fragments.is_empty() {
        tokens.push(Token(std::mem::take(fragments)));
    }
}

/// Tokenizes one source line, retaining quoted boundaries and empty arguments.
pub fn tokenize(input: &str, line: usize) -> Result<Vec<Token>, ParseError> {
    let mut chars = input.chars().peekable();
    let mut tokens = Vec::new();
    let mut fragments = Vec::new();
    let mut text = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '#' => break,
            ' ' | '\t' | '\r' | '\n' => {
                flush_fragment(&mut text, &mut fragments);
                flush_token(&mut fragments, &mut tokens);
            }
            '\'' => {
                flush_fragment(&mut text, &mut fragments);
                let mut quoted = String::new();
                loop {
                    match chars.next() {
                        Some('\'') if chars.peek() == Some(&'\'') => {
                            chars.next();
                            quoted.push('\'');
                        }
                        Some('\'') => break,
                        Some(ch) => quoted.push(ch),
                        None => return Err(ParseError::new(line, "unterminated single quote")),
                    }
                }
                fragments.push(Fragment { text: quoted, quoted: true });
            }
            _ => text.push(ch),
        }
    }
    flush_fragment(&mut text, &mut fragments);
    flush_token(&mut fragments, &mut tokens);
    Ok(tokens)
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum Status {
    #[default]
    Success,
    Failure,
    SuccessOrFailure,
    SuccessRetry,
    FailureRetry,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Condition {
    pub name: String,
    pub negated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Command {
    pub line: usize,
    pub status: Status,
    pub conditions: Vec<Condition>,
    pub words: Vec<Token>,
    pub background: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Line {
    Section { line: usize, text: String },
    Command(Command),
}

fn parse_command(mut tokens: Vec<Token>, line: usize) -> Result<Command, ParseError> {
    let background = tokens.last().and_then(Token::unquoted) == Some("&");
    if background { tokens.pop(); }
    let mut tokens = tokens.into_iter().peekable();
    let mut status = None;
    let mut conditions = Vec::new();
    while let Some(word) = tokens.peek().and_then(Token::unquoted) {
        let prefix = match word {
            "!" => Some(Status::Failure),
            "?" => Some(Status::SuccessOrFailure),
            "*" => Some(Status::SuccessRetry),
            "!*" => Some(Status::FailureRetry),
            _ => None,
        };
        if let Some(prefix) = prefix {
            if status.replace(prefix).is_some() {
                return Err(ParseError::new(line, "multiple status prefixes"));
            }
        } else if let Some(condition) = word.strip_prefix('[') {
            let condition = condition.strip_suffix(']').ok_or_else(|| ParseError::new(line, "unterminated condition"))?;
            let (negated, name) = condition.strip_prefix('!').map(|name| (true, name)).unwrap_or((false, condition));
            if name.is_empty() {
                return Err(ParseError::new(line, "empty condition"));
            }
            conditions.push(Condition { name: name.to_owned(), negated });
        } else {
            break;
        }
        tokens.next();
    }
    let words: Vec<_> = tokens.collect();
    if words.is_empty() {
        return Err(ParseError::new(line, "missing command"));
    }
    Ok(Command { line, status: status.unwrap_or_default(), conditions, words, background })
}

/// Parses sections and command syntax only. Command/condition registration,
/// async capability checks and variable expansion belong to the future engine.
pub fn parse_script(script: &str) -> Result<Vec<Line>, ParseError> {
    let mut lines = Vec::new();
    for (offset, text) in script.split('\n').enumerate() {
        let line = offset.saturating_add(1);
        if text.starts_with('#') {
            lines.push(Line::Section { line, text: text.to_owned() });
        } else {
            let tokens = tokenize(text, line)?;
            if !tokens.is_empty() {
                lines.push(Line::Command(parse_command(tokens, line)?));
            }
        }
    }
    Ok(lines)
}
