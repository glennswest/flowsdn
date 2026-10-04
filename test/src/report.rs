//! Results as stormcentral reads them (docs/test-standard.md): one JSON object
//! per test on stdout, a final summary line, and exit 0 (passed), 1 (a test
//! failed) or 2 (the test could not run).
use serde_json::{Value, json};
use std::{
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Report {
    pass: u64,
    fail: u64,
    skip: u64,
    infrastructure: Option<String>,
}

pub fn ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

impl Report {
    fn line(&mut self, test: &str, status: &str, elapsed: Duration, detail: &str) {
        emit(&json!({"test": test, "status": status, "ms": ms(elapsed), "detail": detail}));
    }
    pub fn pass(&mut self, test: &str, elapsed: Duration, detail: &str) {
        self.pass = self.pass.saturating_add(1);
        self.line(test, "pass", elapsed, detail);
    }
    pub fn fail(&mut self, test: &str, elapsed: Duration, detail: &str) {
        self.fail = self.fail.saturating_add(1);
        self.line(test, "fail", elapsed, detail);
    }
    pub fn skip(&mut self, test: &str, detail: &str) {
        self.skip = self.skip.saturating_add(1);
        self.line(test, "skip", Duration::ZERO, detail);
    }
    /// Run one check, timing it; an error is the test's failure detail.
    pub fn check<T>(
        &mut self,
        test: &str,
        f: impl FnOnce() -> Result<(T, String), String>,
    ) -> Option<T> {
        let start = Instant::now();
        match f() {
            Ok((value, detail)) => {
                self.pass(test, start.elapsed(), &detail);
                Some(value)
            }
            Err(detail) => {
                self.fail(test, start.elapsed(), &detail);
                None
            }
        }
    }
    /// The run cannot proceed for a reason outside flowsdn: exit 2.
    pub fn infrastructure(&mut self, test: &str, detail: &str) {
        self.fail = self.fail.saturating_add(1);
        self.line(test, "fail", Duration::ZERO, detail);
        self.infrastructure = Some(detail.to_owned());
    }
    pub fn finish(self) -> ExitCode {
        emit(&json!({"summary": {"pass": self.pass, "fail": self.fail, "skip": self.skip}}));
        if self.infrastructure.is_some() {
            ExitCode::from(2)
        } else if self.fail > 0 {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

pub fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}
