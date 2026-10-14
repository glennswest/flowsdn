//! `cargo xtask chart-check` (#294, #375): the Helm chart's lint, renders,
//! version match, guards and names, in Rust (it replaced
//! `install/kubernetes/check.sh`). Needs `helm` on PATH. Renders with an
//! example image (no image is published) and fails on a chart version that
//! differs from the workspace, a render that names Cilium, a missing kind, a
//! CRD count other than 22, or a guard that does not refuse what it should.
use std::{error::Error, fs, path::Path, process::Command};

const CHART: &str = "install/kubernetes/flowsdn";
const IMAGE: &str = "image.repository=registry.example/flowsdn-agent";
const CRDS: usize = 22;
const KINDS: [&str; 5] = [
    "ServiceAccount",
    "ClusterRole",
    "ClusterRoleBinding",
    "ConfigMap",
    "DaemonSet",
];

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// `version` of `[workspace.package]` in the root Cargo.toml.
pub fn workspace_version(cargo_toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[workspace.package]";
            continue;
        }
        if in_package
            && let Some(value) = line.strip_prefix("version = ")
        {
            return Some(value.trim_matches('"').to_owned());
        }
    }
    None
}

/// Chart.yaml must carry `version: V` and `appVersion: "V"` as whole lines.
pub fn chart_versions(chart_yaml: &str, version: &str) -> std::result::Result<(), String> {
    let has = |wanted: String| chart_yaml.lines().any(|line| line == wanted);
    if !has(format!("version: {version}")) {
        return Err(format!("Chart.yaml version is not {version}"));
    }
    if !has(format!("appVersion: \"{version}\"")) {
        return Err(format!("Chart.yaml appVersion is not {version}"));
    }
    Ok(())
}

/// The lines (1-based number, text) of `render` that name Cilium, any case.
pub fn cilium_lines(render: &str) -> Vec<(usize, &str)> {
    render
        .lines()
        .enumerate()
        .filter(|(_, line)| line.to_ascii_lowercase().contains("cilium"))
        .map(|(at, line)| (at.saturating_add(1), line))
        .collect()
}

/// The full render: 22 CRDs and every kind the chart must produce.
pub fn check_render(render: &str) -> std::result::Result<(), String> {
    let crds = render
        .lines()
        .filter(|line| *line == "kind: CustomResourceDefinition")
        .count();
    if crds != CRDS {
        return Err(format!("{crds} CRDs rendered, not {CRDS}"));
    }
    for kind in KINDS {
        let line = format!("kind: {kind}");
        if !render.lines().any(|l| l == line) {
            return Err(format!("no {kind} rendered"));
        }
    }
    Ok(())
}

/// The first `error…` text in helm's output, for a refusal's report.
pub fn first_error(output: &str) -> &str {
    output
        .lines()
        .find_map(|line| line.find("error").and_then(|at| line.get(at..)))
        .unwrap_or("")
}

fn helm(args: &[&str]) -> Result<std::process::Output> {
    Command::new("helm")
        .args(args)
        .output()
        .map_err(|e| format!("helm {}: {e}", args.first().unwrap_or(&"")).into())
}

fn helm_ok(args: &[&str]) -> Result<String> {
    let output = helm(args)?;
    if !output.status.success() {
        return Err(format!(
            "helm {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Run every check from the workspace root.
pub fn run(root: &Path) -> Result<()> {
    let version = workspace_version(&fs::read_to_string(root.join("Cargo.toml"))?)
        .ok_or("no [workspace.package] version in Cargo.toml")?;
    let chart = root.join(CHART);
    chart_versions(&fs::read_to_string(chart.join("Chart.yaml"))?, &version)?;
    let chart = chart.to_str().ok_or("chart path is not UTF-8")?;
    print!("{}", helm_ok(&["lint", "--strict", chart, "--set", IMAGE])?);
    let template = ["template", "flowsdn", chart, "--namespace", "kube-system"];
    let mut full = template.to_vec();
    full.extend(["--include-crds", "--set", IMAGE]);
    let render = helm_ok(&full)?;
    let mut fixed = template.to_vec();
    fixed.extend([
        "--set",
        IMAGE,
        "--set",
        "agent.ipv4Pool=10.244.0.0/16",
        "--set",
        "agent.ipv4Gateway=10.244.0.1",
        "--set",
        "agent.ipv6Pool=fd00:10::/64",
        "--set",
        "agent.ipv6Gateway=fd00:10::1",
        "--set",
        "agent.bpfPinRoot=/sys/fs/bpf/flowsdn",
        "--set",
        "agent.httpListen=",
    ]);
    let fixed_render = helm_ok(&fixed)?;
    for (name, text) in [("render", &render), ("fixed-pool render", &fixed_render)] {
        let named = cilium_lines(text);
        if !named.is_empty() {
            for (line, content) in named.iter().take(10) {
                eprintln!("{name}:{line}: {content}");
            }
            return Err(format!("the {name} of the chart names Cilium").into());
        }
    }
    check_render(&render)?;
    let guards: [(&str, &[&str]); 4] = [
        ("no image.repository", &[]),
        (
            "fixed pool without gateway",
            &["--set", IMAGE, "--set", "agent.ipv4Pool=10.244.0.0/16"],
        ),
        ("no pool", &["--set", IMAGE, "--set", "agent.ipv4Pool="]),
        ("bad egress", &["--set", IMAGE, "--set", "agent.egress=tunnel"]),
    ];
    for (why, extra) in guards {
        let mut args = vec!["template", "flowsdn", chart];
        args.extend_from_slice(extra);
        let output = helm(&args)?;
        if output.status.success() {
            return Err(format!("rendered although {why}").into());
        }
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("refused ({why}): {}", first_error(&text));
    }
    println!("chart flowsdn {version}: lint, render ({CRDS} CRDs), guards and names pass");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_version_reads_only_the_workspace_package() {
        let toml = "[package]\nversion = \"9.9.9\"\n[workspace.package]\nedition = \"2024\"\nversion = \"0.14.0\"\n[workspace.dependencies]\nversion = \"1\"\n";
        assert_eq!(workspace_version(toml).as_deref(), Some("0.14.0"));
        assert_eq!(workspace_version("[package]\nversion = \"1\"\n"), None);
    }

    #[test]
    fn chart_versions_need_both_whole_lines() {
        let good = "apiVersion: v2\nname: flowsdn\nversion: 0.14.0\nappVersion: \"0.14.0\"\n";
        assert_eq!(chart_versions(good, "0.14.0"), Ok(()));
        assert!(chart_versions(good, "0.15.0").is_err());
        let unquoted = "version: 0.14.0\nappVersion: 0.14.0\n";
        assert_eq!(
            chart_versions(unquoted, "0.14.0"),
            Err("Chart.yaml appVersion is not 0.14.0".into())
        );
    }

    #[test]
    fn cilium_is_found_in_any_case_with_line_numbers() {
        let render = "kind: ConfigMap\n  name: flowsdn\n  image: quay.io/Cilium/x\n";
        assert_eq!(
            cilium_lines(render),
            vec![(3, "  image: quay.io/Cilium/x")]
        );
        assert!(cilium_lines("kind: DaemonSet\n").is_empty());
    }

    #[test]
    fn render_needs_22_crds_and_every_kind() {
        let mut render = "kind: CustomResourceDefinition\n---\n".repeat(CRDS);
        for kind in KINDS {
            render.push_str(&format!("---\nkind: {kind}\n"));
        }
        assert_eq!(check_render(&render), Ok(()));
        let short = render.replacen("kind: CustomResourceDefinition\n", "", 1);
        assert_eq!(
            check_render(&short),
            Err("21 CRDs rendered, not 22".into())
        );
        let no_daemonset = render.replace("kind: DaemonSet\n", "");
        assert_eq!(
            check_render(&no_daemonset),
            Err("no DaemonSet rendered".into())
        );
    }

    #[test]
    fn first_error_takes_helms_error_text() {
        let output = "walk.go:75: found symbolic link\nError: execution error at (flowsdn/templates/x.yaml:3:4): image.repository is required\n";
        assert_eq!(
            first_error(output),
            "error at (flowsdn/templates/x.yaml:3:4): image.repository is required"
        );
        assert_eq!(first_error("nothing"), "");
    }
}
