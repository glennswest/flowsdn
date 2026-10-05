//! Results in stormcentral's test-line format (docs/test-standard.md), each
//! carrying the flavor, the node and its numbers, so runs on a Cilium and a
//! flowsdn machine line up metric by metric:
//! `{"test","status","ms","detail","flavor","node","metrics":{…}}`, then a
//! `summary` line. Exit 0 all passed, 1 a probe failed, 2 could not run.
use serde_json::{Value, json};
use std::{
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};

pub struct Report {
    pub flavor: String,
    pub node: String,
    pass: u64,
    fail: u64,
    skip: u64,
    infrastructure: bool,
}

fn ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

impl Report {
    pub fn new(flavor: &str, node: &str) -> Self {
        Self {
            flavor: flavor.into(),
            node: node.into(),
            pass: 0,
            fail: 0,
            skip: 0,
            infrastructure: false,
        }
    }
    fn line(&self, test: &str, status: &str, elapsed: Duration, detail: &str, metrics: &Value) {
        emit(&json!({"test": test, "status": status, "ms": ms(elapsed), "detail": detail,
            "flavor": self.flavor, "node": self.node, "metrics": metrics}));
    }
    pub fn pass(&mut self, test: &str, elapsed: Duration, detail: &str, metrics: Value) {
        self.pass = self.pass.saturating_add(1);
        self.line(test, "pass", elapsed, detail, &metrics);
    }
    pub fn fail(&mut self, test: &str, elapsed: Duration, detail: &str) {
        self.fail = self.fail.saturating_add(1);
        self.line(test, "fail", elapsed, detail, &json!({}));
    }
    pub fn skip(&mut self, test: &str, detail: &str) {
        self.skip = self.skip.saturating_add(1);
        self.line(test, "skip", Duration::ZERO, detail, &json!({}));
    }
    /// Run one measurement: Ok((detail, metrics)) passes, Err(detail) fails.
    pub fn measure(&mut self, test: &str, f: impl FnOnce() -> Result<(String, Value), String>) -> bool {
        let start = Instant::now();
        match f() {
            Ok((detail, metrics)) => {
                self.pass(test, start.elapsed(), &detail, metrics);
                true
            }
            Err(detail) => {
                self.fail(test, start.elapsed(), &detail);
                false
            }
        }
    }
    pub fn infrastructure(&mut self, test: &str, detail: &str) {
        self.fail = self.fail.saturating_add(1);
        self.infrastructure = true;
        self.line(test, "fail", Duration::ZERO, detail, &json!({}));
    }
    pub fn finish(self) -> ExitCode {
        emit(&json!({"summary": {"pass": self.pass, "fail": self.fail, "skip": self.skip},
            "flavor": self.flavor, "node": self.node}));
        if self.infrastructure {
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
