//! How long the steps of a CNI ADD take (#396): the plugin reports its own
//! after each ADD, the agent adds those of its `PUT /v1/endpoint`, and
//! `GET /v1/cni/timing` gives each step's percentiles over its last samples.
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, VecDeque};

/// The steps the plugin may report, in the order of an ADD. Only these are
/// kept, so what a client posts cannot grow the agent's memory.
pub const PLUGIN_STEPS: [&str; 8] = [
    "config",
    "lookup",
    "allocate",
    "link",
    "configure",
    "endpoint",
    "finalize",
    "total",
];
/// Samples kept per step.
const KEPT: usize = 256;

#[derive(Default)]
pub struct Timing {
    steps: BTreeMap<&'static str, VecDeque<u64>>,
}
impl Timing {
    /// One sample of a step, in microseconds.
    pub fn record(&mut self, step: &'static str, micros: u64) {
        let samples = self.steps.entry(step).or_default();
        if samples.len() == KEPT {
            samples.pop_front();
        }
        samples.push_back(micros);
    }
    /// A plugin's report: `{"steps":{"<step>":<microseconds>,…}}`. Unknown
    /// steps are ignored.
    pub fn record_plugin(&mut self, report: &Value) {
        let Some(steps) = report.get("steps").and_then(Value::as_object) else {
            return;
        };
        for name in PLUGIN_STEPS {
            if let Some(micros) = steps.get(name).and_then(Value::as_u64) {
                self.record(name, micros);
            }
        }
    }
    /// `{"<step>":{"samples","p50-us","p99-us","max-us"},…}`.
    pub fn json(&self) -> Value {
        let mut out = Map::new();
        for (step, samples) in &self.steps {
            let mut sorted: Vec<u64> = samples.iter().copied().collect();
            sorted.sort_unstable();
            let at = |percent: usize| {
                let last = sorted.len().saturating_sub(1);
                let index = last.saturating_mul(percent).checked_div(100).unwrap_or(0);
                sorted.get(index).copied().unwrap_or(0)
            };
            out.insert(
                (*step).to_owned(),
                json!({"samples":sorted.len(),"p50-us":at(50),"p99-us":at(99),"max-us":at(100)}),
            );
        }
        Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_by_step_over_the_last_samples() {
        let mut timing = Timing::default();
        for micros in 1..=300 {
            timing.record("agent-put", micros);
        }
        let row = timing.json();
        let row = row.get("agent-put").expect("step");
        assert_eq!(row.get("samples"), Some(&json!(256)));
        assert_eq!(row.get("max-us"), Some(&json!(300)));
        assert_eq!(row.get("p50-us"), Some(&json!(172)));
    }

    #[test]
    fn a_report_keeps_only_known_steps() {
        let mut timing = Timing::default();
        timing.record_plugin(&json!({"steps":{"link":5,"made-up":7,"total":"x"}}));
        timing.record_plugin(&json!({"not":"a report"}));
        let out = timing.json();
        assert_eq!(out.as_object().map(Map::len), Some(1));
        assert_eq!(out.pointer("/link/p50-us"), Some(&json!(5)));
    }
}
