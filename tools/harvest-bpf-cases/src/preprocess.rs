use regex::Regex;
use std::collections::BTreeMap;

type Defines = BTreeMap<String, String>;

/// Deliberately limited expression evaluator for inventory extraction, not a C
/// compiler. Unknown expressions select the branch conservatively, matching the
/// original harvester. No host-language eval or external preprocessor is used.
pub fn truthy(expression: &str, defines: &Defines) -> bool {
    let expression = expression.split("/*").next().unwrap_or("").trim();
    fn evaluate(expression: &str, defines: &Defines) -> Option<bool> {
        let defined = Regex::new(r"\bdefined\s*(?:\(\s*(\w+)\s*\)|(\w+))").ok()?;
        let expanded = defined.replace_all(expression, |captures: &regex::Captures<'_>| {
            let name = captures
                .get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            if defines.contains_key(name) { "1" } else { "0" }
        });
        let ident = Regex::new(r"[A-Za-z_]\w*").ok()?;
        let expanded = ident.replace_all(&expanded, |captures: &regex::Captures<'_>| {
            let name = captures.get(0).map(|m| m.as_str()).unwrap_or("");
            defines
                .get(name)
                .and_then(|value| value.split("/*").next())
                .and_then(|value| value.trim().parse::<i64>().ok())
                .unwrap_or(0)
                .to_string()
        });
        let mut parser = Expr {
            rest: expanded.trim(),
        };
        let value = parser.or()?;
        parser.space();
        parser.rest.is_empty().then_some(value != 0)
    }
    evaluate(expression, defines).unwrap_or(true)
}

struct Expr<'a> {
    rest: &'a str,
}
impl Expr<'_> {
    fn space(&mut self) {
        self.rest = self.rest.trim_start();
    }
    fn take(&mut self, text: &str) -> bool {
        self.space();
        if let Some(rest) = self.rest.strip_prefix(text) {
            self.rest = rest;
            true
        } else {
            false
        }
    }
    fn or(&mut self) -> Option<i64> {
        let mut value = self.and()?;
        while self.take("||") {
            let right = self.and()?;
            value = i64::from(value != 0 || right != 0);
        }
        Some(value)
    }
    fn and(&mut self) -> Option<i64> {
        let mut value = self.compare()?;
        while self.take("&&") {
            let right = self.compare()?;
            value = i64::from(value != 0 && right != 0);
        }
        Some(value)
    }
    fn compare(&mut self) -> Option<i64> {
        let left = self.atom()?;
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            if self.take(op) {
                // Legacy parser conservatively selected expressions containing !=.
                if op == "!=" {
                    return None;
                }
                let right = self.atom()?;
                return Some(i64::from(match op {
                    "==" => left == right,
                    ">=" => left >= right,
                    "<=" => left <= right,
                    ">" => left > right,
                    _ => left < right,
                }));
            }
        }
        Some(left)
    }
    fn atom(&mut self) -> Option<i64> {
        if self.take("!") {
            return Some(i64::from(self.atom()? == 0));
        }
        if self.take("(") {
            let value = self.or()?;
            return self.take(")").then_some(value);
        }
        self.space();
        let length = self
            .rest
            .char_indices()
            .take_while(|(i, ch)| ch.is_ascii_digit() || (*i == 0 && *ch == '-'))
            .map(|(i, ch)| i.saturating_add(ch.len_utf8()))
            .last()?;
        let (number, rest) = self.rest.split_at(length);
        self.rest = rest;
        number.parse().ok()
    }
}

#[derive(Clone, Debug)]
pub struct Section {
    pub kind: String,
    pub program: String,
    pub name: String,
    pub body: Vec<String>,
    pub file: String,
}

pub struct Patterns {
    pub define: Regex,
    pub undef: Regex,
    pub include: Regex,
    pub ifdef: Regex,
    pub ifndef: Regex,
    pub if_expr: Regex,
    pub elif: Regex,
    pub else_expr: Regex,
    pub endif: Regex,
    pub section: Regex,
    pub config: Regex,
}
impl Patterns {
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            define: Regex::new(r"^\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)$")?,
            undef: Regex::new(r"^\s*#\s*undef\s+([A-Za-z_]\w*)")?,
            include: Regex::new(r#"^\s*#\s*include\s+["<]([^">]+)[">]"#)?,
            ifdef: Regex::new(r"^\s*#\s*ifdef\s+([A-Za-z_]\w*)")?,
            ifndef: Regex::new(r"^\s*#\s*ifndef\s+([A-Za-z_]\w*)")?,
            if_expr: Regex::new(r"^\s*#\s*if\s+(.*)$")?,
            elif: Regex::new(r"^\s*#\s*elif\s+(.*)$")?,
            else_expr: Regex::new(r"^\s*#\s*else")?,
            endif: Regex::new(r"^\s*#\s*endif")?,
            section: Regex::new(
                r#"^\s*(PKTGEN|SETUP|CHECK)\s*\(\s*("[^"]*"|[A-Za-z_]\w*)\s*,\s*"([^"]*)"\s*\)"#,
            )?,
            config: Regex::new(r"^\s*ASSIGN_CONFIG\s*\(\s*[^,]+,\s*(\w+)\s*,")?,
        })
    }
}
fn capture(c: &regex::Captures<'_>, index: usize) -> String {
    c.get(index).map(|m| m.as_str()).unwrap_or("").to_owned()
}

#[derive(Default)]
pub struct Walk {
    pub defines: Defines,
    pub sections: Vec<Section>,
    pub configs: Vec<String>,
    pub includes: Vec<String>,
    body: Option<Section>,
}
impl Walk {
    fn flush(&mut self) {
        if let Some(body) = self.body.take() {
            self.sections.push(body);
        }
    }
    pub fn run(
        &mut self,
        file: &str,
        files: &BTreeMap<String, Vec<String>>,
        patterns: &Patterns,
        depth: usize,
    ) {
        let Some(lines) = files.get(file) else {
            return;
        };
        if depth > 12 {
            return;
        }
        let mut stack: Vec<(bool, bool)> = Vec::new();
        for line in lines {
            let active = stack.iter().all(|(active, _)| *active);
            if let Some(c) = patterns.ifdef.captures(line) {
                let value = self.defines.contains_key(&capture(&c, 1));
                stack.push((value, value));
                continue;
            }
            if let Some(c) = patterns.ifndef.captures(line) {
                let value = !self.defines.contains_key(&capture(&c, 1));
                stack.push((value, value));
                continue;
            }
            if let Some(c) = patterns.if_expr.captures(line) {
                let value = truthy(&capture(&c, 1), &self.defines);
                stack.push((value, value));
                continue;
            }
            if let Some(c) = patterns.elif.captures(line)
                && let Some((active, taken)) = stack.last_mut()
            {
                *active = !*taken && truthy(&capture(&c, 1), &self.defines);
                *taken |= *active;
                continue;
            }
            if patterns.else_expr.is_match(line)
                && let Some((active, taken)) = stack.last_mut()
            {
                *active = !*taken;
                *taken = true;
                continue;
            }
            if patterns.endif.is_match(line) {
                stack.pop();
                continue;
            }
            if !active {
                continue;
            }
            if let Some(c) = patterns.define.captures(line) {
                self.flush();
                self.defines
                    .insert(capture(&c, 1), capture(&c, 3).trim().to_owned());
                continue;
            }
            if let Some(c) = patterns.undef.captures(line) {
                self.defines.remove(&capture(&c, 1));
                continue;
            }
            if let Some(c) = patterns.include.captures(line) {
                self.flush();
                let include = capture(&c, 1);
                self.includes.push(include.clone());
                let base = include.rsplit('/').next().unwrap_or(&include);
                let candidate = if files.contains_key(&include) {
                    include.as_str()
                } else {
                    base
                };
                if candidate.ends_with(".h") && !["common.h", "pktgen.h"].contains(&candidate) {
                    self.run(candidate, files, patterns, depth.saturating_add(1));
                }
                continue;
            }
            if let Some(c) = patterns.config.captures(line) {
                self.configs.push(capture(&c, 1));
                continue;
            }
            if let Some(c) = patterns.section.captures(line) {
                self.flush();
                let program = capture(&c, 2);
                let program = if program.starts_with('"') {
                    program.as_str()
                } else {
                    self.defines
                        .get(&program)
                        .map(String::as_str)
                        .unwrap_or(&program)
                };
                self.body = Some(Section {
                    kind: capture(&c, 1),
                    program: program.trim().trim_matches('"').to_owned(),
                    name: capture(&c, 3),
                    body: Vec::new(),
                    file: file.to_owned(),
                });
                continue;
            }
            if let Some(body) = &mut self.body {
                body.body.push(line.clone());
            }
        }
        self.flush();
    }
}
