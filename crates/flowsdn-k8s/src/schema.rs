//! Offline validation of custom resources against a CRD's structural schema (#325).
//!
//! This checks what the API server checks on create, so examples and test
//! cases can be accepted or rejected without a cluster: defaults are applied
//! first, then types, `nullable`, required fields, unknown fields (as
//! `kubectl`'s strict field validation reports them), enums, patterns, string,
//! number, list and map bounds, `x-kubernetes-list-type` uniqueness, the
//! formats the API server validates (`cidr`, `ipv4`, `ipv6`, `date-time`,
//! `int32`), `oneOf`/`anyOf`/`allOf`/`not`, and `x-kubernetes-validations`.
//! A null field is pruned, as the server prunes it, so it only counts as
//! missing when required.
//!
//! CEL is a subset: `has()`, field selection on `self`, string/number/bool
//! literals, `== != < <= > >=`, `! && ||` with CEL's error-absorbing
//! `||`/`&&`, and `isIP()`. Transition rules (`oldSelf`) are skipped, as they
//! are on create. A rule outside the subset is reported as a violation, so a
//! new schema rule cannot pass unchecked. `metadata` is ObjectMeta, which the
//! API server validates itself; only its type is checked here.
use regex::Regex;
use serde_json::{Map, Value};
use std::net::IpAddr;

/// Violations of `value` against `schema` (an `openAPIV3Schema`), as
/// `path: message`. Empty means the object would be admitted.
pub fn validate(schema: &Value, value: &Value) -> Vec<String> {
    let mut defaulted = value.clone();
    apply_defaults(schema, &mut defaulted);
    let mut out = Vec::new();
    check(schema, &defaulted, "", true, true, &mut out);
    out
}

/// Fill absent properties from their `default`, recursively, as the API
/// server does before validation.
pub fn apply_defaults(schema: &Value, value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, child) in properties {
                    if !object.contains_key(name)
                        && let Some(default) = child.get("default")
                    {
                        object.insert(name.clone(), default.clone());
                    }
                    if let Some(present) = object.get_mut(name) {
                        apply_defaults(child, present);
                    }
                }
            }
            if let Some(extra) = schema.get("additionalProperties").filter(|s| s.is_object()) {
                for child in object.values_mut() {
                    apply_defaults(extra, child);
                }
            }
        }
        Value::Array(items) => {
            if let Some(item) = schema.get("items") {
                for child in items {
                    apply_defaults(item, child);
                }
            }
        }
        _ => {}
    }
}

fn at(path: &str, child: &str) -> String {
    format!("{path}.{child}")
}

fn check(
    schema: &Value,
    value: &Value,
    path: &str,
    strict: bool,
    root: bool,
    out: &mut Vec<String>,
) {
    let shown = if path.is_empty() { "<root>" } else { path };
    if value.is_null() {
        // The API server prunes null for a non-nullable field (a required one
        // is then reported missing by its parent) and admits it when nullable.
        return;
    }
    if !type_matches(schema, value) {
        out.push(format!("{shown}: expected {}", expected_type(schema)));
        return;
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value)
    {
        out.push(format!(
            "{shown}: {value} is not one of {}",
            Value::Array(choices.clone())
        ));
    }
    match value {
        Value::String(s) => check_string(schema, s, shown, out),
        Value::Number(_) => check_number(schema, value, shown, out),
        Value::Array(items) => check_array(schema, items, path, strict, out),
        Value::Object(object) => check_object(schema, object, path, strict, root, out),
        _ => {}
    }
    for (keyword, all) in [("allOf", true), ("anyOf", false), ("oneOf", false)] {
        let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        let passing = branches
            .iter()
            .filter(|branch| {
                let mut errors = Vec::new();
                check(branch, value, path, false, false, &mut errors);
                errors.is_empty()
            })
            .count();
        let ok = match keyword {
            "oneOf" => passing == 1,
            _ if all => passing == branches.len(),
            _ => passing >= 1,
        };
        if !ok {
            out.push(format!(
                "{shown}: {keyword} matched {passing} of {} branches",
                branches.len()
            ));
        }
    }
    if let Some(not) = schema.get("not") {
        let mut errors = Vec::new();
        check(not, value, path, false, false, &mut errors);
        if errors.is_empty() {
            out.push(format!("{shown}: must not match the `not` schema"));
        }
    }
    for rule in schema
        .get("x-kubernetes-validations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let text = rule.get("rule").and_then(Value::as_str).unwrap_or_default();
        if text.contains("oldSelf") {
            continue;
        }
        match cel::evaluate(text, value) {
            Ok(true) => {}
            Ok(false) | Err(cel::Failure::Error) => {
                let message = rule
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("failed rule");
                out.push(format!("{shown}: {message} ({text})"));
            }
            Err(cel::Failure::Unsupported(why)) => {
                out.push(format!(
                    "{shown}: CEL rule outside the supported subset ({why}): {text}"
                ));
            }
        }
    }
}

fn type_matches(schema: &Value, value: &Value) -> bool {
    if schema.get("x-kubernetes-int-or-string") == Some(&Value::Bool(true)) {
        return value.is_string() || value.is_i64() || value.is_u64();
    }
    match schema.get("type").and_then(Value::as_str) {
        None => true,
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("number") => value.is_number(),
        Some(_) => false,
    }
}

fn expected_type(schema: &Value) -> String {
    if schema.get("x-kubernetes-int-or-string") == Some(&Value::Bool(true)) {
        return "integer or string".into();
    }
    schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("any")
        .to_owned()
}

fn check_string(schema: &Value, s: &str, shown: &str, out: &mut Vec<String>) {
    let length = s.chars().count();
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
        && (length as u64) < min
    {
        out.push(format!("{shown}: shorter than {min}"));
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
        && (length as u64) > max
    {
        out.push(format!("{shown}: longer than {max}"));
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        match Regex::new(pattern) {
            Ok(re) if re.is_match(s) => {}
            Ok(_) => out.push(format!("{shown}: {s:?} does not match {pattern}")),
            Err(e) => out.push(format!("{shown}: invalid pattern {pattern}: {e}")),
        }
    }
    let valid = match schema.get("format").and_then(Value::as_str) {
        Some("cidr") => is_cidr(s),
        Some("ipv4") => s.parse::<std::net::Ipv4Addr>().is_ok(),
        Some("ipv6") => s.parse::<std::net::Ipv6Addr>().is_ok(),
        Some("date-time") => is_date_time(s),
        _ => true,
    };
    if !valid {
        let format = schema
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or_default();
        out.push(format!("{shown}: {s:?} is not a valid {format}"));
    }
}

fn is_cidr(s: &str) -> bool {
    let Some((ip, bits)) = s.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits.parse::<u8>() else {
        return false;
    };
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => bits <= 32,
        Ok(IpAddr::V6(_)) => bits <= 128,
        Err(_) => false,
    }
}

/// RFC 3339 `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
fn is_date_time(s: &str) -> bool {
    Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")
        .is_ok_and(|re| re.is_match(s))
}

fn check_number(schema: &Value, value: &Value, shown: &str, out: &mut Vec<String>) {
    let Some(n) = value.as_f64() else { return };
    let exclusive = |key| schema.get(key) == Some(&Value::Bool(true));
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
        && (n < min || (exclusive("exclusiveMinimum") && n <= min))
    {
        out.push(format!("{shown}: {value} is below the minimum {min}"));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
        && (n > max || (exclusive("exclusiveMaximum") && n >= max))
    {
        out.push(format!("{shown}: {value} is above the maximum {max}"));
    }
    if schema.get("format").and_then(Value::as_str) == Some("int32")
        && value.as_i64().is_none_or(|i| i32::try_from(i).is_err())
    {
        out.push(format!("{shown}: {value} is out of int32 range"));
    }
}

fn check_array(schema: &Value, items: &[Value], path: &str, strict: bool, out: &mut Vec<String>) {
    let shown = if path.is_empty() { "<root>" } else { path };
    let count = items.len() as u64;
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
        && count < min
    {
        out.push(format!("{shown}: fewer than {min} items"));
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
        && count > max
    {
        out.push(format!("{shown}: more than {max} items"));
    }
    let list_type = schema.get("x-kubernetes-list-type").and_then(Value::as_str);
    let keys: Vec<&str> = schema
        .get("x-kubernetes-list-map-keys")
        .and_then(Value::as_array)
        .map(|keys| keys.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let identity = |item: &Value| -> Value {
        if list_type == Some("map") {
            Value::Array(
                keys.iter()
                    .map(|k| item.get(*k).cloned().unwrap_or(Value::Null))
                    .collect(),
            )
        } else {
            item.clone()
        }
    };
    if matches!(list_type, Some("set" | "map"))
        || schema.get("uniqueItems") == Some(&Value::Bool(true))
    {
        let mut seen = Vec::new();
        for item in items {
            let id = identity(item);
            if seen.contains(&id) {
                out.push(format!("{shown}: duplicate entry {id}"));
            } else {
                seen.push(id);
            }
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            check(
                item_schema,
                item,
                &format!("{path}[{index}]"),
                strict,
                false,
                out,
            );
        }
    }
}

fn check_object(
    schema: &Value,
    object: &Map<String, Value>,
    path: &str,
    strict: bool,
    root: bool,
    out: &mut Vec<String>,
) {
    let shown = if path.is_empty() { "<root>" } else { path };
    let properties = schema.get("properties").and_then(Value::as_object);
    let count = object.len() as u64;
    if let Some(min) = schema.get("minProperties").and_then(Value::as_u64)
        && count < min
    {
        out.push(format!("{shown}: fewer than {min} properties"));
    }
    if let Some(max) = schema.get("maxProperties").and_then(Value::as_u64)
        && count > max
    {
        out.push(format!("{shown}: more than {max} properties"));
    }
    for name in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let nullable = properties
            .and_then(|p| p.get(name))
            .and_then(|p| p.get("nullable"))
            == Some(&Value::Bool(true));
        match object.get(name) {
            None => out.push(format!("{}: required", at(path, name))),
            Some(Value::Null) if !nullable => out.push(format!("{}: required", at(path, name))),
            _ => {}
        }
    }
    let preserve = schema.get("x-kubernetes-preserve-unknown-fields") == Some(&Value::Bool(true));
    let additional = schema.get("additionalProperties");
    for (name, child) in object {
        let child_path = at(path, name);
        if root && name == "metadata" {
            if !child.is_object() {
                out.push(format!("{child_path}: expected object"));
            }
            continue;
        }
        if let Some(child_schema) = properties.and_then(|p| p.get(name)) {
            check(child_schema, child, &child_path, strict, false, out);
        } else if let Some(extra) = additional.filter(|a| a.is_object()) {
            check(extra, child, &child_path, strict, false, out);
        } else if additional == Some(&Value::Bool(false))
            || (strict && !preserve && additional.is_none())
        {
            out.push(format!("{child_path}: unknown field"));
        }
    }
}

/// The CEL subset `x-kubernetes-validations` rules are evaluated with.
pub mod cel {
    use serde_json::Value;
    use std::net::IpAddr;

    #[derive(Debug, PartialEq)]
    pub enum Failure {
        /// A runtime error (no such field, mismatched types): the rule fails.
        Error,
        /// Syntax the subset does not implement.
        Unsupported(String),
    }

    #[derive(Clone, Debug, PartialEq)]
    enum Token {
        Ident(String),
        Str(String),
        Num(f64),
        Op(&'static str),
    }

    fn tokens(text: &str) -> Result<Vec<Token>, Failure> {
        let mut out = Vec::new();
        let mut chars = text.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else if c.is_ascii_alphabetic() || c == '_' {
                let mut ident = String::new();
                while let Some(&c) = chars
                    .peek()
                    .filter(|c| c.is_ascii_alphanumeric() || **c == '_')
                {
                    ident.push(c);
                    chars.next();
                }
                out.push(Token::Ident(ident));
            } else if c.is_ascii_digit() {
                let mut number = String::new();
                while let Some(&c) = chars.peek().filter(|c| c.is_ascii_digit() || **c == '.') {
                    number.push(c);
                    chars.next();
                }
                let n = number
                    .parse()
                    .map_err(|_| Failure::Unsupported(format!("number {number}")))?;
                out.push(Token::Num(n));
            } else if c == '\'' || c == '"' {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        Some(q) if q == c => break,
                        Some('\\') => return Err(Failure::Unsupported("string escapes".into())),
                        Some(ch) => s.push(ch),
                        None => return Err(Failure::Unsupported("unterminated string".into())),
                    }
                }
                out.push(Token::Str(s));
            } else {
                chars.next();
                let two = chars.peek().map(|n| format!("{c}{n}"));
                let op = match two.as_deref() {
                    Some(op @ ("==" | "!=" | "<=" | ">=" | "&&" | "||")) => {
                        chars.next();
                        match op {
                            "==" => "==",
                            "!=" => "!=",
                            "<=" => "<=",
                            ">=" => ">=",
                            "&&" => "&&",
                            _ => "||",
                        }
                    }
                    _ => match c {
                        '<' => "<",
                        '>' => ">",
                        '!' => "!",
                        '(' => "(",
                        ')' => ")",
                        '.' => ".",
                        ',' => ",",
                        other => return Err(Failure::Unsupported(format!("character {other:?}"))),
                    },
                };
                out.push(Token::Op(op));
            }
        }
        Ok(out)
    }

    /// A value under evaluation; `Err` is a CEL runtime error.
    type Eval = Result<Value, ()>;

    struct Parser<'a> {
        tokens: &'a [Token],
        position: usize,
        this: &'a Value,
    }

    impl Parser<'_> {
        fn peek(&self) -> Option<&Token> {
            self.tokens.get(self.position)
        }
        fn bump(&mut self) -> Option<Token> {
            let token = self.peek().cloned();
            self.position = self.position.saturating_add(1);
            token
        }
        fn expect(&mut self, op: &str) -> Result<(), Failure> {
            match self.bump() {
                Some(Token::Op(found)) if found == op => Ok(()),
                other => Err(Failure::Unsupported(format!(
                    "expected {op}, found {other:?}"
                ))),
            }
        }
        fn eat(&mut self, op: &str) -> bool {
            if self.peek()
                == Some(&Token::Op(match op {
                    "||" => "||",
                    "&&" => "&&",
                    _ => "!",
                }))
            {
                self.position = self.position.saturating_add(1);
                true
            } else {
                false
            }
        }
        fn or(&mut self) -> Result<Eval, Failure> {
            let mut left = self.and()?;
            while self.eat("||") {
                let right = self.and()?;
                left = match (left, right) {
                    (Ok(Value::Bool(true)), _) | (_, Ok(Value::Bool(true))) => {
                        Ok(Value::Bool(true))
                    }
                    (Ok(Value::Bool(false)), Ok(Value::Bool(false))) => Ok(Value::Bool(false)),
                    _ => Err(()),
                };
            }
            Ok(left)
        }
        fn and(&mut self) -> Result<Eval, Failure> {
            let mut left = self.unary()?;
            while self.eat("&&") {
                let right = self.unary()?;
                left = match (left, right) {
                    (Ok(Value::Bool(false)), _) | (_, Ok(Value::Bool(false))) => {
                        Ok(Value::Bool(false))
                    }
                    (Ok(Value::Bool(true)), Ok(Value::Bool(true))) => Ok(Value::Bool(true)),
                    _ => Err(()),
                };
            }
            Ok(left)
        }
        fn unary(&mut self) -> Result<Eval, Failure> {
            if self.eat("!") {
                return Ok(match self.unary()? {
                    Ok(Value::Bool(b)) => Ok(Value::Bool(!b)),
                    _ => Err(()),
                });
            }
            self.comparison()
        }
        fn comparison(&mut self) -> Result<Eval, Failure> {
            let left = self.primary()?;
            let op = match self.peek() {
                Some(Token::Op(op @ ("==" | "!=" | "<" | "<=" | ">" | ">="))) => *op,
                _ => return Ok(left),
            };
            self.bump();
            let right = self.primary()?;
            let (Ok(left), Ok(right)) = (left, right) else {
                return Ok(Err(()));
            };
            Ok(match op {
                "==" => Ok(Value::Bool(left == right)),
                "!=" => Ok(Value::Bool(left != right)),
                _ => match (left.as_f64(), right.as_f64()) {
                    (Some(l), Some(r)) => Ok(Value::Bool(match op {
                        "<" => l < r,
                        "<=" => l <= r,
                        ">" => l > r,
                        _ => l >= r,
                    })),
                    _ => Err(()),
                },
            })
        }
        /// `self.a.b` as a selection, or None when a step is absent.
        fn select(&mut self) -> Result<Option<Value>, Failure> {
            match self.bump() {
                Some(Token::Ident(name)) if name == "self" => {}
                other => return Err(Failure::Unsupported(format!("operand {other:?}"))),
            }
            let mut current = Some(self.this.clone());
            while self.peek() == Some(&Token::Op(".")) {
                self.bump();
                let Some(Token::Ident(field)) = self.bump() else {
                    return Err(Failure::Unsupported("field selection".into()));
                };
                current = current.and_then(|v| v.get(&field).cloned());
            }
            Ok(current)
        }
        fn primary(&mut self) -> Result<Eval, Failure> {
            match self.peek().cloned() {
                Some(Token::Op("(")) => {
                    self.bump();
                    let inner = self.or()?;
                    self.expect(")")?;
                    Ok(inner)
                }
                Some(Token::Str(s)) => {
                    self.bump();
                    Ok(Ok(Value::String(s)))
                }
                Some(Token::Num(n)) => {
                    self.bump();
                    Ok(Ok(Value::from(n)))
                }
                Some(Token::Ident(name)) if name == "true" || name == "false" => {
                    self.bump();
                    Ok(Ok(Value::Bool(name == "true")))
                }
                Some(Token::Ident(name)) if name == "has" => {
                    self.bump();
                    self.expect("(")?;
                    let present = self.select()?.is_some();
                    self.expect(")")?;
                    Ok(Ok(Value::Bool(present)))
                }
                Some(Token::Ident(name)) if name == "isIP" => {
                    self.bump();
                    self.expect("(")?;
                    let value = self.select()?;
                    self.expect(")")?;
                    Ok(match value {
                        Some(Value::String(s)) => Ok(Value::Bool(s.parse::<IpAddr>().is_ok())),
                        _ => Err(()),
                    })
                }
                Some(Token::Ident(name)) if name == "self" => {
                    // A missing field is a CEL "no such key" error.
                    Ok(self.select()?.map(normalize).ok_or(()))
                }
                other => Err(Failure::Unsupported(format!("expression {other:?}"))),
            }
        }
    }

    /// Integers compare equal to the same float literal, as CEL's
    /// heterogeneous numeric equality does.
    fn normalize(value: Value) -> Value {
        match value.as_f64() {
            Some(n) if value.is_number() => Value::from(n),
            _ => value,
        }
    }

    /// Evaluate `rule` with `self` bound to `this`.
    pub fn evaluate(rule: &str, this: &Value) -> Result<bool, Failure> {
        let tokens = tokens(rule)?;
        let mut parser = Parser {
            tokens: &tokens,
            position: 0,
            this,
        };
        let result = parser.or()?;
        if parser.position != tokens.len() {
            return Err(Failure::Unsupported("trailing tokens".into()));
        }
        match result {
            Ok(Value::Bool(b)) => Ok(b),
            _ => Err(Failure::Error),
        }
    }
}
