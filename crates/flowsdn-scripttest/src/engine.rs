//! Synchronous execution slice from spec 17 §§3.2–3.3. Handlers must return
//! promptly: this core cannot interrupt a blocking custom callback. Retry and
//! background syntax are rejected until the asynchronous engine is available.
use crate::{Command, ExpansionMode, Line, Status, parse_script};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    /// The fixture supplies WORK, PWD, TMPDIR and DATADIR. This engine does not
    /// create directories or inspect the process environment.
    pub environment: BTreeMap<String, String>,
    pub stdout: String,
    pub stderr: String,
    pub log: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            environment: BTreeMap::from([
                ("/".into(), std::path::MAIN_SEPARATOR.to_string()),
                (":".into(), if cfg!(windows) { ";" } else { ":" }.into()),
            ]),
            stdout: String::new(), stderr: String::new(), log: Vec::new(),
        }
    }
}

impl State {
    pub fn new(mut environment: BTreeMap<String, String>) -> Self {
        environment.insert("/".into(), std::path::MAIN_SEPARATOR.to_string());
        environment.insert(":".into(), if cfg!(windows) { ";" } else { ":" }.into());
        Self { environment, ..Self::default() }
    }

    /// Output publication replaces both buffers. A handler that does not call
    /// this method leaves the previous output intact, including on failure.
    pub fn publish(&mut self, stdout: impl Into<String>, stderr: impl Into<String>) {
        self.stdout = stdout.into();
        self.stderr = stderr.into();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Continue,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    Failure(String),
    Cancelled,
    Deadline,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(message) => f.write_str(message),
            Self::Cancelled => f.write_str("command cancelled"),
            Self::Deadline => f.write_str("command deadline exceeded"),
        }
    }
}

impl std::error::Error for CommandError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunError {
    pub line: usize,
    pub command: String,
    pub message: String,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}: {}", self.line, self.command, self.message)
    }
}

impl std::error::Error for RunError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Execution {
    pub commands_run: usize,
    pub commands_skipped: usize,
    pub stopped: bool,
}

type Handler = dyn Fn(&mut State, &[String]) -> Result<Control, CommandError> + Send + Sync;
type Predicate = dyn Fn(&State, &str) -> Result<bool, String> + Send + Sync;

struct RegisteredCommand {
    pattern_argument: bool,
    handler: Box<Handler>,
}

struct RegisteredCondition {
    prefix: bool,
    predicate: Box<Predicate>,
}

/// A command registry with a finite command-count budget. Unknown commands and
/// conditions, unsupported execution syntax, and expansion errors are harness
/// failures: `!` and `?` cannot hide them. Ordinary command failures can satisfy
/// those prefixes. A stop result always ends the script successfully.
pub struct Engine {
    commands: BTreeMap<String, RegisteredCommand>,
    conditions: BTreeMap<String, RegisteredCondition>,
    max_commands: usize,
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

impl Engine {
    /// Registers echo, env, stdout, stderr and stop. OS/architecture conditions
    /// are built in; privilege, kernel, short/verbose and fixture conditions
    /// must be supplied by the caller. No privilege is inferred from an env var.
    pub fn new() -> Self {
        let mut engine = Self {
            commands: BTreeMap::new(),
            conditions: BTreeMap::new(),
            max_commands: 100_000,
        };
        for (name, pattern_argument, handler) in [
            ("echo", false, echo as fn(&mut State, &[String]) -> _),
            ("env", false, env_command),
            ("stdout", true, stdout),
            ("stderr", true, stderr),
            ("stop", false, stop),
        ] {
            engine.commands.insert(name.into(), RegisteredCommand { pattern_argument, handler: Box::new(handler) });
        }
        for (name, value) in [
            ("linux", cfg!(target_os = "linux")),
            ("darwin", cfg!(target_os = "macos")),
            ("amd64", cfg!(target_arch = "x86_64")),
            ("arm64", cfg!(target_arch = "aarch64")),
        ] {
            engine.conditions.insert(name.into(), RegisteredCondition {
                prefix: false, predicate: Box::new(move |_, _| Ok(value)),
            });
        }
        engine.conditions.insert("os".into(), RegisteredCondition {
            prefix: true,
            predicate: Box::new(|_, name| Ok(name == if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS })),
        });
        engine.conditions.insert("arch".into(), RegisteredCondition {
            prefix: true,
            predicate: Box::new(|_, name| Ok(name == match std::env::consts::ARCH { "x86_64" => "amd64", "aarch64" => "arm64", other => other })),
        });
        engine
    }

    pub fn set_max_commands(&mut self, max_commands: usize) { self.max_commands = max_commands; }

    /// Pattern commands regex-escape substitutions in their first non-option
    /// argument (or the argument following `--`). Argument indices exclude the
    /// command name. Flags themselves are parsed by the registered handler.
    pub fn register_command(
        &mut self,
        name: &str,
        pattern_argument: bool,
        handler: impl Fn(&mut State, &[String]) -> Result<Control, CommandError> + Send + Sync + 'static,
    ) -> Result<(), String> {
        if !valid_name(name) || self.commands.contains_key(name) {
            return Err(format!("invalid or duplicate command name: {name}"));
        }
        self.commands.insert(name.into(), RegisteredCommand { pattern_argument, handler: Box::new(handler) });
        Ok(())
    }

    /// Prefix predicates receive the suffix after the first colon. Boolean
    /// predicates receive an empty string. The caller owns caching for any
    /// process-global capability probes; no such probes run in this core.
    pub fn register_condition(
        &mut self,
        name: &str,
        prefix: bool,
        predicate: impl Fn(&State, &str) -> Result<bool, String> + Send + Sync + 'static,
    ) -> Result<(), String> {
        if !valid_name(name) || name.contains(':') || self.conditions.contains_key(name) {
            return Err(format!("invalid or duplicate condition name: {name}"));
        }
        self.conditions.insert(name.into(), RegisteredCondition { prefix, predicate: Box::new(predicate) });
        Ok(())
    }

    /// Parse and execute a script body, for example `archive.script()`. Archive
    /// flags and fixture files are the caller's responsibility. Section headers
    /// enter the log, but retry prefixes are explicitly unsupported.
    pub fn run(&self, script: &str, state: &mut State) -> Result<Execution, RunError> {
        let lines = parse_script(script).map_err(|error| RunError { line: error.line, command: String::new(), message: error.message })?;
        let mut execution = Execution::default();
        for line in lines {
            let command = match line {
                Line::Section { text, .. } => { state.log.push(text); continue; }
                Line::Command(command) => command,
            };
            let error = |message: String| RunError {
                line: command.line,
                command: command.words.first().map(|word| word.literal()).unwrap_or_default(),
                message,
            };
            if command.background { return Err(error("background commands are not implemented".into())); }
            if matches!(command.status, Status::SuccessRetry | Status::FailureRetry) {
                return Err(error("section retries are not implemented".into()));
            }
            let name = command.words.first().ok_or_else(|| error("missing command".into()))?
                .expand(&state.environment, ExpansionMode::Plain, command.line).map_err(|e| error(e.message))?;
            let registered = self.commands.get(&name).ok_or_else(|| error(format!("unknown command: {name}")))?;
            if !self.selected(&command, state).map_err(error)? {
                execution.commands_skipped = execution.commands_skipped.saturating_add(1);
                continue;
            }
            if execution.commands_run >= self.max_commands {
                return Err(error("command execution limit exceeded".into()));
            }
            let mut args = Vec::new();
            let mut pattern_found = false;
            let mut after_separator = false;
            for token in command.words.iter().skip(1) {
                let plain = token.expand(&state.environment, ExpansionMode::Plain, command.line).map_err(|e| error(e.message))?;
                let argument = if registered.pattern_argument && !pattern_found {
                    if !after_separator && plain == "--" {
                        after_separator = true;
                        plain
                    } else if after_separator || !plain.starts_with('-') {
                        pattern_found = true;
                        token.expand(&state.environment, ExpansionMode::Regex, command.line).map_err(|e| error(e.message))?
                    } else { plain }
                } else { plain };
                args.push(argument);
            }
            execution.commands_run = execution.commands_run.saturating_add(1);
            match (registered.handler)(state, &args) {
                Ok(Control::Stop) => { execution.stopped = true; return Ok(execution); }
                Ok(Control::Continue) if command.status == Status::Failure => return Err(error("unexpected success".into())),
                Ok(Control::Continue) => {},
                Err(CommandError::Failure(message)) if matches!(command.status, Status::Failure | Status::SuccessOrFailure) => {
                    state.log.push(format!("line {}: expected failure: {message}", command.line));
                }
                Err(failure) => return Err(error(failure.to_string())),
            }
        }
        Ok(execution)
    }

    fn selected(&self, command: &Command, state: &State) -> Result<bool, String> {
        let mut selected = true;
        // Validate every condition even when another predicate is false.
        for condition in &command.conditions {
            let (name, suffix) = condition.name.split_once(':').map(|(name, suffix)| (name, Some(suffix))).unwrap_or((&condition.name, None));
            let registered = self.conditions.get(name).ok_or_else(|| format!("unknown condition: {name}"))?;
            if registered.prefix != suffix.is_some() || suffix == Some("") {
                return Err(format!("invalid condition suffix: {}", condition.name));
            }
            let value = (registered.predicate)(state, suffix.unwrap_or(""))?;
            selected &= value != condition.negated;
        }
        Ok(selected)
    }
}

fn valid_name(name: &str) -> bool { !name.is_empty() && !name.chars().any(char::is_whitespace) }
fn fail(message: &str) -> CommandError { CommandError::Failure(message.into()) }

fn echo(state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    state.publish(format!("{}\n", args.join(" ")), "");
    Ok(Control::Continue)
}

fn env_command(state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    if args.is_empty() {
        let output: String = state.environment.iter().map(|(key, value)| format!("{key}={value}\n")).collect();
        state.publish(output, "");
        return Ok(Control::Continue);
    }
    if args.first().map(String::as_str) == Some("--from-stdout") {
        if args.len() < 2 || args.iter().skip(1).any(|key| !valid_environment_key(key)) {
            return Err(fail("env --from-stdout requires variable names"));
        }
        let value = state.stdout.trim().to_owned();
        for key in args.iter().skip(1) { state.environment.insert(key.clone(), value.clone()); }
        return Ok(Control::Continue);
    }
    let mut output = String::new();
    let mut printed = false;
    for arg in args {
        let (key, value) = arg.split_once('=').map(|(key, value)| (key, Some(value))).unwrap_or((arg, None));
        if !valid_environment_key(key) { return Err(fail("invalid env variable name")); }
        if let Some(value) = value {
            state.environment.insert(key.into(), value.into());
        } else {
            printed = true;
            output.push_str(&format!("{key}={}\n", state.environment.get(key).map(String::as_str).unwrap_or("")));
        }
    }
    if printed { state.publish(output, ""); }
    Ok(Control::Continue)
}

fn valid_environment_key(key: &str) -> bool {
    !key.is_empty() && !key.starts_with('-') && !key.contains(['=', '\0']) && !key.chars().any(char::is_whitespace)
}

fn stop(state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    if args.len() > 1 { return Err(fail("stop accepts at most one message")); }
    if let Some(message) = args.first() { state.log.push(message.clone()); }
    Ok(Control::Stop)
}

fn stdout(state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    match_output(&state.stdout, args, &mut state.log)
}

fn stderr(state: &mut State, args: &[String]) -> Result<Control, CommandError> {
    match_output(&state.stderr, args, &mut state.log)
}

fn match_output(text: &str, args: &[String], log: &mut Vec<String>) -> Result<Control, CommandError> {
    let mut pattern = None;
    let mut count = None;
    let mut quiet = false;
    let mut flags = true;
    for arg in args {
        if flags && arg == "--" { flags = false; continue; }
        if flags && arg == "-q" { quiet = true; continue; }
        if flags && let Some(value) = arg.strip_prefix("--count=") {
            count = Some(value.parse::<usize>().map_err(|_| fail("invalid match count"))?);
            continue;
        }
        if flags && arg.starts_with('-') { return Err(fail("unknown output assertion flag")); }
        if pattern.replace(arg).is_some() { return Err(fail("output assertion requires one pattern")); }
    }
    let pattern = pattern.ok_or_else(|| fail("output assertion requires a pattern"))?;
    let regex = regex::RegexBuilder::new(pattern).multi_line(true).build().map_err(|_| fail("invalid output assertion pattern"))?;
    let found = regex.find_iter(text).count();
    if !quiet {
        for line in text.lines().filter(|line| regex.is_match(line)) { log.push((*line).into()); }
    }
    if count.map(|count| found == count).unwrap_or(found > 0) { Ok(Control::Continue) }
    else { Err(fail("output did not match expected pattern count")) }
}
