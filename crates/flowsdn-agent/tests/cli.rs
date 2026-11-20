//! Public CLI probes must work without a config file, privileges or live daemon.
use std::process::{Command, Output};
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_flowsdn-agent"))
        .args(args)
        .output()
        .expect("run agent CLI")
}
#[test]
fn help_succeeds_without_initializing_the_daemon() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(text.contains("Usage: flowsdn-agent --config PATH"));
        assert!(text.contains("--version"));
        assert!(text.contains("Unix socket"));
        assert!(text.contains("GET /v1/healthz"));
        assert!(text.contains("does not report complete pod-network readiness"));
    }
}
#[test]
fn version_reports_the_built_package_without_configuration() {
    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).expect("version"),
            format!("flowsdn-agent {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
#[test]
fn malformed_invocations_remain_errors_instead_of_starting_the_daemon() {
    for args in [
        vec![],
        vec!["--config"],
        vec!["--unknown"],
        vec!["--help", "extra"],
        vec!["--version", "extra"],
        vec!["--config", "file", "extra"],
    ] {
        let output = run(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .expect("error")
                .contains("usage: flowsdn-agent --config PATH")
        );
    }
}
#[cfg(unix)]
#[test]
fn non_utf8_unknown_argument_produces_usage_not_a_panic() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let output = Command::new(env!("CARGO_BIN_EXE_flowsdn-agent"))
        .arg(OsString::from_vec(vec![255]))
        .output()
        .expect("run");
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).expect("error");
    assert!(error.contains("usage:"));
    assert!(!error.contains("panicked"));
}

/// `operator` exists only in a Kubernetes build (#337); a bad argument
/// fails before anything connects.
#[test]
fn operator_mode_is_a_kubernetes_build_command() {
    let help = run(&["operator", "--help"]);
    let bogus = run(&["operator", "--bogus"]);
    assert!(!bogus.status.success());
    if cfg!(feature = "kubernetes") {
        assert!(help.status.success(), "{help:?}");
        let text = String::from_utf8(help.stdout).expect("UTF-8");
        assert!(text.contains("--skip-crd-creation") && text.contains("flowsdn-operator"));
        let main = String::from_utf8(run(&["--help"]).stdout).expect("UTF-8");
        assert!(main.contains("flowsdn-agent operator --help"));
    } else {
        assert!(!help.status.success());
        let main = String::from_utf8(run(&["--help"]).stdout).expect("UTF-8");
        assert!(!main.contains("operator"));
    }
}
