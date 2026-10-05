//! Latency summaries: nearest-rank percentiles over nanosecond samples.
use serde_json::{Value, json};
use std::time::Duration;

/// Samples in nanoseconds, kept sorted once [`Samples::finish`] runs.
#[derive(Clone, Debug, Default)]
pub struct Samples {
    nanos: Vec<u64>,
    sorted: bool,
}
impl Samples {
    pub fn push(&mut self, elapsed: Duration) {
        self.nanos
            .push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        self.sorted = false;
    }
    pub fn len(&self) -> usize {
        self.nanos.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nanos.is_empty()
    }
    fn finish(&mut self) {
        if !self.sorted {
            self.nanos.sort_unstable();
            self.sorted = true;
        }
    }
    /// Nearest-rank percentile `q` in 0..=1, in microseconds.
    pub fn percentile_us(&mut self, q: f64) -> Option<f64> {
        self.finish();
        let last = self.nanos.len().checked_sub(1)?;
        let rank = (last as f64 * q.clamp(0.0, 1.0)).round() as usize;
        self.nanos.get(rank.min(last)).map(|n| *n as f64 / 1000.0)
    }
    pub fn mean_us(&self) -> Option<f64> {
        if self.nanos.is_empty() {
            return None;
        }
        let total: f64 = self.nanos.iter().map(|n| *n as f64).sum();
        Some(total / self.nanos.len() as f64 / 1000.0)
    }
    /// `{p50_us, p90_us, p99_us, max_us, mean_us, samples}`, rounded to 0.1 us.
    pub fn summary(&mut self) -> Value {
        let round = |v: Option<f64>| v.map(|v| (v * 10.0).round() / 10.0);
        json!({
            "p50_us": round(self.percentile_us(0.50)),
            "p90_us": round(self.percentile_us(0.90)),
            "p99_us": round(self.percentile_us(0.99)),
            "max_us": round(self.percentile_us(1.0)),
            "mean_us": round(self.mean_us()),
            "samples": self.nanos.len(),
        })
    }
}

/// Bits per second for `bytes` over `elapsed`, as Gbit/s rounded to 0.001.
pub fn gbps(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    (bytes as f64 * 8.0 / seconds / 1e9 * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let mut samples = Samples::default();
        assert_eq!(samples.percentile_us(0.5), None);
        for us in (1..=100).rev() {
            samples.push(Duration::from_micros(us));
        }
        assert_eq!(samples.percentile_us(0.0), Some(1.0));
        assert_eq!(samples.percentile_us(0.5), Some(51.0));
        assert_eq!(samples.percentile_us(0.99), Some(99.0));
        assert_eq!(samples.percentile_us(1.0), Some(100.0));
        assert_eq!(samples.mean_us(), Some(50.5));
        let summary = samples.summary();
        assert_eq!(summary.get("samples"), Some(&json!(100)));
        assert_eq!(summary.get("p99_us"), Some(&json!(99.0)));
    }

    #[test]
    fn throughput_in_gbps() {
        assert_eq!(gbps(1_250_000_000, Duration::from_secs(1)), 10.0);
        assert_eq!(gbps(0, Duration::from_secs(1)), 0.0);
        assert_eq!(gbps(10, Duration::ZERO), 0.0);
    }
}
