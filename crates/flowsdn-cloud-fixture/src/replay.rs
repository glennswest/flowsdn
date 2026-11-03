//! In-order replay (spec 07 §9.1): each request must match the next recorded
//! interaction by method, canonical target and canonical body. An unmatched
//! request is reported beside the closest remaining recorded one; strict mode
//! also fails on recorded interactions never used. Replay never reaches a
//! provider: a request with nothing left to match is a failure.
use crate::canon;
use crate::fixture::{Interaction, Request, Response};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    method: String,
    target: String,
    body: String,
}

fn key(r: &Request) -> Key {
    Key {
        method: r.method.to_ascii_uppercase(),
        target: canon::target(&r.path),
        body: canon::body(r.headers.get("content-type").map(String::as_str), &r.body),
    }
}

fn path_only(target: &str) -> &str {
    target.split_once('?').map_or(target, |(p, _)| p)
}

fn shown(k: &Key) -> String {
    const LIMIT: usize = 2000;
    let body = match k.body.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}...", k.body.get(..cut).unwrap_or_default()),
        None => k.body.clone(),
    };
    format!("{} {}\n      body: {body}", k.method, k.target)
}

pub struct Replayer {
    interactions: Vec<(Interaction, Key)>,
    next: usize,
    served: usize,
    failures: Vec<String>,
}

impl Replayer {
    pub fn new(interactions: Vec<Interaction>) -> Self {
        Self {
            interactions: interactions
                .into_iter()
                .map(|i| {
                    let k = key(&i.request);
                    (i, k)
                })
                .collect(),
            next: 0,
            served: 0,
            failures: Vec::new(),
        }
    }

    /// The recorded response to `request`, or the mismatch report (also kept
    /// for [`Replayer::finish`]).
    pub fn respond(&mut self, request: &Request) -> Result<Response, String> {
        self.served = self.served.saturating_add(1);
        let k = key(request);
        if let Some((i, recorded)) = self.interactions.get(self.next)
            && *recorded == k
        {
            self.next = self.next.saturating_add(1);
            return Ok(i.response.clone());
        }
        let remaining = self.interactions.get(self.next..).unwrap_or_default();
        // Closest: same method and path, then same method, else the next one.
        let score = |r: &Key| {
            u8::from(r.method == k.method)
                .saturating_add(u8::from(path_only(&r.target) == path_only(&k.target)))
        };
        let closest = remaining
            .iter()
            .enumerate()
            .max_by_key(|(n, (_, r))| (score(r), std::cmp::Reverse(*n)));
        let mut report = format!(
            "request {} matches no recorded interaction\n    sent: {}",
            self.served,
            shown(&k)
        );
        match closest {
            Some((n, (i, r))) => report.push_str(&format!(
                "\n    closest: {:03}-{}: {}",
                self.next.saturating_add(n).saturating_add(1),
                i.operation,
                shown(r)
            )),
            None => report.push_str("\n    closest: none, every recorded interaction was used"),
        }
        self.failures.push(report.clone());
        Err(report)
    }

    /// Records a failure found outside matching (an unreadable request).
    pub fn note_failure(&mut self, report: String) {
        self.failures.push(report);
    }

    /// Ok when every request matched and, in strict mode, every recorded
    /// interaction was used.
    pub fn finish(&self, strict: bool) -> Result<(), String> {
        let mut problems = self.failures.clone();
        if strict && self.next < self.interactions.len() {
            let unused = self
                .interactions
                .get(self.next..)
                .unwrap_or_default()
                .iter()
                .zip(self.next.saturating_add(1)..)
                .map(|((i, _), n)| format!("{n:03}-{}", i.operation))
                .collect::<Vec<_>>()
                .join(", ");
            problems.push(format!("recorded interactions never used: {unused}"));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("\n"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::tests::scenario;

    fn request(body: &str) -> Request {
        let mut r = scenario()
            .interactions
            .first()
            .map(|i| i.request.clone())
            .expect("an interaction");
        r.body = body.to_string();
        r
    }

    #[test]
    fn in_order_with_canonical_bodies() {
        let mut r = Replayer::new(scenario().interactions);
        let first = r
            .respond(&request(
                "Version=2016-11-15&Action=DescribeInstances&Signature=fresh",
            ))
            .expect("first matches");
        assert!(first.body.contains("i-5c7b"));
        let second = r
            .respond(&request(
                "SubnetId=subnet-5c7b0002&Action=CreateNetworkInterface",
            ))
            .expect("second matches");
        assert!(second.body.contains("eni-5c7b"));
        assert_eq!(r.finish(true), Ok(()));
    }

    #[test]
    fn out_of_order_reports_the_closest() {
        let mut r = Replayer::new(scenario().interactions);
        let err = r
            .respond(&request(
                "Action=CreateNetworkInterface&SubnetId=subnet-5c7b0002",
            ))
            .expect_err("second sent first");
        assert!(
            err.contains("request 1 matches no recorded interaction"),
            "{err}"
        );
        assert!(err.contains("closest: 001-describe-instances"), "{err}");
        let finish = r.finish(false).expect_err("a failure was recorded");
        assert!(finish.contains("request 1"), "{finish}");
    }

    #[test]
    fn strict_fails_on_unused_and_nothing_left_fails() {
        let mut r = Replayer::new(scenario().interactions);
        r.respond(&request("Action=DescribeInstances&Version=2016-11-15"))
            .expect("first");
        assert_eq!(r.finish(false), Ok(()));
        let strict = r.finish(true).expect_err("strict");
        assert!(
            strict.contains("never used: 002-create-network-interface"),
            "{strict}"
        );
        r.respond(&request(
            "Action=CreateNetworkInterface&SubnetId=subnet-5c7b0002",
        ))
        .expect("second");
        let err = r
            .respond(&request("Action=DescribeInstances&Version=2016-11-15"))
            .expect_err("nothing left");
        assert!(err.contains("every recorded interaction was used"), "{err}");
    }
}
