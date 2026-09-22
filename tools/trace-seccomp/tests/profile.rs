use flowsdn_trace_seccomp::{coverage, profile, trace, REQUIRED};
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn selected_execs_only_and_unfinished_calls_count_once() {
    let input = "execve(\"/test/helper\", [], []) = 0\nread(0, 0, 0) = 0\n12.000 execve(\"/bin/flowsdn-agent\", [], []) = 0\n12.001 bpf(1, 0, 0) = 3\nfutex(1 <unfinished ...>\n<... futex resumed>) = 0\nexecve(\"/bad\", [], []) = -1 ENOENT\nwrite(1, 0, 0) = 0\nexecve(\"/test/helper\", [], []) = 0\nmount(0, 0, 0) = 0";
    let result = trace(input, &BTreeSet::from(["/bin/flowsdn-agent".into()]));
    assert_eq!(result.selected_execs, 1);
    assert_eq!(result.counts.get("futex"), Some(&1));
    assert_eq!(result.counts.get("execve"), Some(&2));
    assert_eq!(result.counts.get("bpf"), Some(&1));
    assert_eq!(result.counts.get("write"), Some(&1));
    assert!(!result.counts.contains_key("read"));
    assert!(!result.counts.contains_key("mount"));
    assert!(trace("read(0, 0, 0) = 0", &BTreeSet::new()).counts.is_empty());
}

#[test]
fn capability_arch_filters_and_argument_rules_are_preserved() {
    let baseline = json!({"defaultAction":"SCMP_ACT_ERRNO", "defaultErrno":"ENOSYS", "archMap":[{"architecture":"SCMP_ARCH_X86_64","subArchitectures":["SCMP_ARCH_X86"]}], "syscalls":[
        {"names":["read"],"action":"SCMP_ACT_ALLOW"},
        {"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["amd64"]}},
        {"names":["cacheflush"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["arm64"]}},
        {"names":["ptrace"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_PTRACE","CAP_SYS_ADMIN"]}},
        {"names":["bpf","setns","perf_event_open","mount","other"],"action":"SCMP_ACT_ERRNO","errno":"EPERM","excludes":{"caps":["CAP_BPF","CAP_SYS_ADMIN"]}},
        {"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]}
    ]});
    let result = profile(&baseline, "amd64", &BTreeSet::from(["CAP_SYS_PTRACE".into()])).expect("profile");
    for name in REQUIRED { assert_eq!(coverage(&result, name), "allowed"); }
    assert_eq!(coverage(&result, "ptrace"), "missing");
    assert_eq!(coverage(&result, "other"), "denied");
    assert_eq!(coverage(&result, "personality"), "conditional");
    assert_eq!(coverage(&result, "arch_prctl"), "allowed");
    assert_eq!(coverage(&result, "cacheflush"), "missing");
    assert_eq!(result.get("defaultErrnoRet"), Some(&json!(38)));
    let result = profile(&baseline, "amd64", &BTreeSet::from(["CAP_SYS_PTRACE".into(), "CAP_SYS_ADMIN".into()])).expect("profile");
    assert_eq!(coverage(&result, "ptrace"), "allowed");
    assert_eq!(coverage(&result, "other"), "missing");
}

#[test]
fn unsupported_conditions_and_allow_default_fail_closed() {
    for baseline in [json!({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}), json!({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"4.0"}}]})] {
        assert!(profile(&baseline, "amd64", &BTreeSet::new()).is_err());
    }
}

#[test]
fn successful_execveat_stops_attribution_and_basename_is_not_identity() {
    let executables = BTreeSet::from(["/bin/flowsdn-cni".into()]);
    let input = "execve(\"/tmp/flowsdn-cni\", [], []) = 0\nbpf(0) = 0\nexecve(\"/bin/flowsdn-cni\", [], []) = 0\nsetns(0) = 0\nexecveat(4, \"helper\", [], [], 0) = 0\nmount(0) = 0";
    let parsed = trace(input, &executables);
    assert!(!parsed.counts.contains_key("bpf"));
    assert!(!parsed.counts.contains_key("mount"));
    assert_eq!(parsed.counts.get("setns"), Some(&1));
}

#[test]
fn split_exec_transition_cannot_attribute_a_helper_to_agent() {
    let parsed = trace("execve(\"/bin/flowsdn-agent\", [], []) = 0\nexecve(\"/bin/helper\", [] <unfinished ...>\n<... execve resumed>) = 0\nmount(0) = 0", &BTreeSet::from(["/bin/flowsdn-agent".into()]));
    assert!(!parsed.counts.contains_key("mount"));
    assert_eq!(parsed.counts.get("execve"), Some(&1));
}

#[test]
fn arm64_filters_and_mixed_allow_deny_are_not_reported_as_proven() {
    let baseline = json!({"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_AARCH64"],"syscalls":[
        {"names":["cacheflush"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["arm64"]}},
        {"names":["socket"],"action":"SCMP_ACT_ALLOW"},
        {"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":16,"op":"SCMP_CMP_EQ"}]}
    ]});
    let generated = profile(&baseline, "arm64", &BTreeSet::new()).expect("profile");
    assert_eq!(coverage(&generated, "cacheflush"), "allowed");
    assert_eq!(coverage(&generated, "socket"), "conditional");
    assert!(profile(&baseline, "amd64", &BTreeSet::new()).is_err());
    assert_eq!(generated, profile(&baseline, "arm64", &BTreeSet::new()).expect("deterministic"));
}
