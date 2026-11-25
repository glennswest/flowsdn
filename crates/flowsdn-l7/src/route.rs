//! The routing a proxy redirect needs (spec 16 §3.3.3): packets carrying the
//! proxy mark are looked up in a table whose only route is local, so the
//! stack delivers them to the proxy's transparent sockets even though their
//! destination is not one of this node's addresses.
use flowsdn_bpf_abi::policy::proxy_mark;

/// One rule the agent keeps, IPv4 and IPv6 alike:
/// `ip rule add pref 9 fwmark 0x200/0xf00 lookup 2004`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    pub priority: u32,
    pub mark: u32,
    pub mask: u32,
    pub table: u32,
}
/// The rule (one per family).
pub const RULE: Rule = Rule {
    priority: proxy_mark::RULE_PRIORITY,
    mark: proxy_mark::TO_PROXY,
    mask: proxy_mark::MASK,
    table: proxy_mark::TABLE,
};

/// The `ip` arguments that install the rule and the local route for one
/// family (`-4` or `-6`): what an operator or a test runs, and what the
/// agent's netlink code mirrors.
pub fn ip_commands(family: &str) -> [Vec<String>; 2] {
    let default = if family == "-6" { "::/0" } else { "0.0.0.0/0" };
    [
        vec![
            family.into(),
            "rule".into(),
            "add".into(),
            "pref".into(),
            RULE.priority.to_string(),
            "fwmark".into(),
            format!("{:#x}/{:#x}", RULE.mark, RULE.mask),
            "lookup".into(),
            RULE.table.to_string(),
        ],
        vec![
            family.into(),
            "route".into(),
            "add".into(),
            "local".into(),
            default.into(),
            "dev".into(),
            "lo".into(),
            "table".into(),
            RULE.table.to_string(),
        ],
    ]
}
