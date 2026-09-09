//! Explicit resolutions recorded in spec 18 §4.3.1 after reference ambiguity reads.
//! These check syntactic evidence for known cases, not arbitrary control flow.
//! CLI use additionally requires the exact pinned commit and clean reference.
use regex::Regex;

// Evidence must occur in C code, not in comments or diagnostic strings.
fn code_only(input: &str) -> String {
    let mut chars = input.chars().peekable();
    let mut output = String::with_capacity(input.len());
    while let Some(ch) = chars.next() {
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            output.push(' ');
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            output.push(' ');
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
                if next == '\n' {
                    output.push('\n');
                }
            }
        } else if ch == '"' || ch == '\'' {
            output.push(' ');
            while let Some(next) = chars.next() {
                if next == '\\' {
                    chars.next();
                } else if next == ch {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    output
}

pub(crate) fn entrypoint(
    file: &str,
    case: &str,
    setup: &str,
    check: &str,
    corpus: &str,
    objects: &[String],
) -> Result<Option<&'static str>, String> {
    if !matches!(
        file,
        "icmp_error_revnat.c"
            | "ipv6_test.c"
            | "l7_lb_local_backend_host.c"
            | "l7_lb_local_backend_pod.c"
            | "tc_nodeport_l3_dev.c"
            | "tc_nodeport_l3_wireguard.c"
    ) {
        return Ok(None);
    }
    let setup = code_only(setup);
    let check = code_only(check);
    let corpus = code_only(corpus);
    let setup = setup.as_str();
    let check = check.as_str();
    let corpus = corpus.as_str();
    let matches = |pattern: &str, text: &str| -> bool {
        Regex::new(pattern).is_ok_and(|pattern| pattern.is_match(text))
    };
    let require = |valid: bool| -> Result<(), String> {
        if valid {
            Ok(())
        } else {
            Err(format!(
                "audited entrypoint evidence changed for {file}:{case}; review spec 18 §4.3.1 before reclassifying"
            ))
        }
    };
    match (file, case) {
        ("icmp_error_revnat.c", "nat4_icmp_error_tcp_snat_revnat") => {
            require(
                objects.is_empty()
                    && matches(r"\bret\s*=\s*snat_v4_rev_nat\s*\(", setup)
                    && matches(r"\breturn\s+TEST_PASS\s*;", setup),
            )?;
            Ok(Some("direct"))
        }
        ("ipv6_test.c", "ipv6_without_extension_header" | "ipv6_with_auth_hop_tcp") => {
            let sentinel = if case == "ipv6_without_extension_header" {
                "123"
            } else {
                "1234"
            };
            require(
                objects.is_empty()
                    && matches(&format!(r"\{{\s*return\s+{sentinel}\s*;\s*\}}"), setup)
                    && matches(r"\bipv6_hdrlen\s*\(", check),
            )?;
            Ok(Some("direct"))
        }
        (
            "l7_lb_local_backend_host.c" | "l7_lb_local_backend_pod.c",
            "l7_lb_local_backend_v4" | "l7_lb_local_backend_v6",
        ) => {
            require(
                objects == ["lxc"]
                    && matches(
                        r"\breturn\s+tail_call_egress_policy\s*\(\s*ctx\s*,\s*CLIENT_EP_ID\s*\)",
                        setup,
                    )
                    && matches(
                        r"\[\s*CLIENT_EP_ID\s*\]\s*=\s*&cil_lxc_policy_egress\b",
                        corpus,
                    )
                    && matches(
                        r"\btail_call\s*\(\s*ctx\s*,\s*&mock_cilium_egresscall_policy\s*,\s*slot\s*\)",
                        corpus,
                    ),
            )?;
            Ok(Some("lxc_policy_egress"))
        }
        ("tc_nodeport_l3_dev.c" | "tc_nodeport_l3_wireguard.c", _)
            if matches(
                r"^(ingress|egress)_ipv[46]_l3_to_l2_fast_redirect_(pod|host)$",
                case,
            ) =>
        {
            let call = Regex::new(r"\breturn\s+l3_to_l2_fast_redirect_setup\s*\(\s*ctx\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*\)").map_err(|error| error.to_string())?;
            let captures = call
                .captures(setup)
                .ok_or_else(|| format!("audited setup arguments changed for {file}:{case}"))?;
            let flag = |index| {
                captures
                    .get(index)
                    .is_some_and(|value| value.as_str() == "true")
            };
            let ingress = flag(1);
            require(
                ingress == case.starts_with("ingress_")
                    && flag(2) == case.contains("_ipv4_")
                    && flag(3) == case.ends_with("_host"),
            )?;
            require(matches(
                r"\btail_call_static\s*\(\s*ctx\s*,\s*entry_call_map\s*,\s*is_ingress\s*\?\s*0\s*:\s*1\s*\)",
                corpus,
            ))?;
            let wireguard = file == "tc_nodeport_l3_wireguard.c";
            let object = if wireguard { "wireguard" } else { "host" };
            let (incoming, outgoing) = if wireguard {
                ("from_wireguard", "to_wireguard")
            } else {
                ("from_netdev", "to_netdev")
            };
            require(
                objects == [object]
                    && matches(&format!(r"\[\s*0\s*\]\s*=\s*&cil_{incoming}\b"), corpus)
                    && matches(&format!(r"\[\s*1\s*\]\s*=\s*&cil_{outgoing}\b"), corpus),
            )?;
            Ok(Some(if ingress { incoming } else { outgoing }))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn l3_direction_is_selected_from_setup_arguments_and_object() {
        let corpus = "tail_call_static(ctx, entry_call_map, is_ingress ? 0 : 1); [0] = &cil_from_netdev; [1] = &cil_to_netdev; [0] = &cil_from_wireguard; [1] = &cil_to_wireguard;";
        for (file, object, incoming, outgoing) in [
            ("tc_nodeport_l3_dev.c", "host", "from_netdev", "to_netdev"),
            (
                "tc_nodeport_l3_wireguard.c",
                "wireguard",
                "from_wireguard",
                "to_wireguard",
            ),
        ] {
            for (direction, ingress) in [("ingress", true), ("egress", false)] {
                for (family, ipv4) in [("ipv4", true), ("ipv6", false)] {
                    for (destination, host) in [("host", true), ("pod", false)] {
                        let case =
                            format!("{direction}_{family}_l3_to_l2_fast_redirect_{destination}");
                        let setup = format!(
                            "return l3_to_l2_fast_redirect_setup(ctx, {ingress}, {ipv4}, {host});"
                        );
                        assert_eq!(
                            entrypoint(file, &case, &setup, "", corpus, &[object.into()]).unwrap(),
                            Some(if ingress { incoming } else { outgoing })
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn l3_changed_arguments_slot_dispatch_and_object_fail_closed() {
        let case = "ingress_ipv4_l3_to_l2_fast_redirect_pod";
        let setup = "return l3_to_l2_fast_redirect_setup(ctx, true, true, false);";
        let corpus = "tail_call_static(ctx, entry_call_map, is_ingress ? 0 : 1); [0] = &cil_from_netdev; [1] = &cil_to_netdev;";
        for (setup, corpus, objects) in [
            (
                setup.replace("true, true", "false, true"),
                corpus.to_owned(),
                vec!["host".to_owned()],
            ),
            (
                setup.to_owned(),
                corpus.replace("? 0 : 1", "? 1 : 0"),
                vec!["host".to_owned()],
            ),
            (
                setup.to_owned(),
                corpus.to_owned(),
                vec!["wireguard".to_owned()],
            ),
            (
                setup.to_owned(),
                corpus.to_owned(),
                vec!["host".to_owned(), "wireguard".to_owned()],
            ),
            (
                setup.to_owned(),
                format!("/* {corpus} */"),
                vec!["host".to_owned()],
            ),
            (
                setup.to_owned(),
                format!("log(\"{corpus}\");"),
                vec!["host".to_owned()],
            ),
            (
                setup.to_owned(),
                corpus.replace("&cil_from_netdev", "&different_program"),
                vec!["host".to_owned()],
            ),
        ] {
            assert!(
                entrypoint("tc_nodeport_l3_dev.c", case, &setup, "", &corpus, &objects).is_err()
            );
        }
    }
    #[test]
    fn l7_variants_enter_egress_policy_not_the_simulated_caller() {
        let setup = "return tail_call_egress_policy(ctx, CLIENT_EP_ID);";
        let corpus = "[CLIENT_EP_ID] = &cil_lxc_policy_egress; tail_call(ctx, &mock_cilium_egresscall_policy, slot);";
        for file in ["l7_lb_local_backend_host.c", "l7_lb_local_backend_pod.c"] {
            for case in ["l7_lb_local_backend_v4", "l7_lb_local_backend_v6"] {
                assert_eq!(
                    entrypoint(file, case, setup, "", corpus, &["lxc".into()]).unwrap(),
                    Some("lxc_policy_egress")
                );
                assert!(
                    entrypoint(
                        file,
                        case,
                        setup,
                        "",
                        &corpus.replace("cil_lxc_policy_egress", "cil_from_host"),
                        &["lxc".into()]
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn direct_cases_require_positive_library_evidence() {
        assert_eq!(
            entrypoint(
                "icmp_error_revnat.c",
                "nat4_icmp_error_tcp_snat_revnat",
                "ret = snat_v4_rev_nat(ctx, &target, &trace, 0); return TEST_PASS;",
                "",
                "",
                &[]
            )
            .unwrap(),
            Some("direct")
        );
        for (case, sentinel) in [
            ("ipv6_without_extension_header", 123),
            ("ipv6_with_auth_hop_tcp", 1234),
        ] {
            let setup = format!("int setup(void *ctx) {{ return {sentinel}; }}");
            assert_eq!(
                entrypoint(
                    "ipv6_test.c",
                    case,
                    &setup,
                    "ipv6_hdrlen(ctx, &next)",
                    "",
                    &[]
                )
                .unwrap(),
                Some("direct")
            );
            assert!(
                entrypoint(
                    "ipv6_test.c",
                    case,
                    &setup,
                    "different_operation(ctx)",
                    "",
                    &[]
                )
                .is_err()
            );
        }
        assert_eq!(
            entrypoint("unknown.c", "unknown", "return 123;", "", "", &[]).unwrap(),
            None
        );
    }
}
