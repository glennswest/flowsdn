//! `short` (< 2 min): flowsdn does its main job, giving pods a network. The
//! commit's agent starts, its CNI gives two sandboxes dual-stack addresses,
//! BPF delivers traffic between them both ways, and CNI DEL returns every
//! endpoint, address, pin and link it made.
use crate::{
    env::Env,
    lab::{Endpoint, Lab, exchange},
    report::Report,
};

pub fn run(report: &mut Report, env: &Env) {
    let Some(lab) = report.check("agent-start", || {
        let lab = Lab::start(env, "short")?;
        Ok((lab, "agent healthy on a private bpffs".into()))
    }) else {
        for test in ["endpoint-add", "pod-traffic-ipv4", "pod-traffic-ipv6", "endpoint-del"] {
            report.skip(test, "agent did not start");
        }
        return;
    };
    let baseline = lab.residue();
    let Some(mut endpoints) = report.check("endpoint-add", || {
        let mut endpoints = Vec::new();
        let mut addresses = Vec::new();
        for id in 1..=2 {
            let mut endpoint = Endpoint::new(id)?;
            let result = lab.add(&mut endpoint)?;
            addresses.push(result.get("ips").cloned().unwrap_or_default().to_string());
            endpoints.push(endpoint);
        }
        let listed = lab.endpoints()?;
        if listed.len() != 2 {
            return Err(format!("agent lists {} endpoints, expected 2", listed.len()));
        }
        Ok((endpoints, format!("2 sandboxes: {}", addresses.join(" "))))
    }) else {
        for test in ["pod-traffic-ipv4", "pod-traffic-ipv6", "endpoint-del"] {
            report.skip(test, "no endpoints");
        }
        return;
    };
    for (test, v6) in [("pod-traffic-ipv4", false), ("pod-traffic-ipv6", true)] {
        report.check(test, || {
            let [a, b] = endpoints.as_mut_slice() else {
                return Err("expected two endpoints".into());
            };
            exchange(a, b, v6)?;
            exchange(b, a, v6)?;
            Ok(((), "UDP both ways through BPF; kernel forwarding refused".into()))
        });
    }
    report.check("endpoint-del", || {
        for endpoint in &endpoints {
            lab.del(endpoint)?;
        }
        drop(std::mem::take(&mut endpoints));
        let after = lab.residue()?;
        let before = baseline.clone()?;
        // The agent's own fds and memory are not objects; long tracks them.
        let leaked: Vec<String> = before
            .objects()
            .iter()
            .zip(after.objects())
            .filter(|(b, a)| b.1 != a.1)
            .map(|(b, a)| format!("{} {} -> {}", b.0, b.1, a.1))
            .collect();
        if leaked.is_empty() {
            Ok(((), format!("drained: {}", after.json())))
        } else {
            Err(format!("left behind: {}", leaked.join(", ")))
        }
    });
}
