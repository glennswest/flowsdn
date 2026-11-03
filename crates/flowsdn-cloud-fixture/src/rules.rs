//! What a committed fixture must not contain (ADR-0007 §2, spec 07 §9.1), as
//! one table used by both the scrubber and the scan: scrubbed text never
//! matches the scan, and scrubbing scrubbed text changes nothing.
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// A kind of value the scrubber replaces and the scan refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    PrivateKey,
    Jwt,
    BearerToken,
    AwsAccessKeyId,
    Credential,
    Signature,
    Arn,
    DnsName,
    ResourceGroup,
    ScaleSet,
    Guid,
    AccountId,
    AlibabaResourceId,
    AwsResourceId,
    PublicIp,
    /// Not UTF-8: a fixture is text, so the scan cannot vouch for it.
    NotText,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::PrivateKey => "private key",
            Class::Jwt => "JWT",
            Class::BearerToken => "bearer token",
            Class::AwsAccessKeyId => "AWS access key id",
            Class::Credential => "credential value",
            Class::Signature => "request signature or signing parameter",
            Class::Arn => "ARN",
            Class::DnsName => "instance DNS name",
            Class::ResourceGroup => "resource group name",
            Class::ScaleSet => "VMSS name",
            Class::Guid => "subscription/tenant/object GUID",
            Class::AccountId => "account or UID",
            Class::AlibabaResourceId => "Alibaba resource id",
            Class::AwsResourceId => "AWS resource id",
            Class::PublicIp => "public IP address",
            Class::NotText => "non-UTF-8 file",
        }
    }
}

/// How a matched value is replaced, and how a replacement is recognised.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Form {
    /// The constant `scrubbed` (secrets: never mapped, never revealable).
    Scrubbed,
    /// Same length, `5c7b` then the counter in hex (AWS ids).
    Hex5c7b,
    /// Same length, `5c7b` then the counter in decimal (Alibaba ids).
    Dec5c7b,
    /// Same length, the counter zero-padded (account ids, UIDs).
    Digits,
    /// `00000000-0000-4000-8000-<counter, 12 digits>`.
    Guid,
    /// A prefix and the counter (`rg-3`, `vmss-1`).
    Named(&'static str),
    /// `host-<n>.scrubbed.invalid`, replacing the whole match.
    Dns,
    /// `arn:scrubbed:<n>`, replacing the whole match.
    Arn,
}

pub(crate) struct Rule {
    pub class: Class,
    pub re: Regex,
    /// The capture group holding the value (0: the whole match).
    pub group: usize,
    pub form: Form,
}

/// Header names whose values are credentials or signatures.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-amz-security-token",
    "x-acs-signature",
    "x-acs-accesskey-id",
    "x-acs-security-token",
    "x-identity-header",
    "x-ms-authorization-auxiliary",
    "cookie",
    "set-cookie",
];

/// JSON keys whose values are credentials (IMDS role credentials, MSI and
/// OAuth token responses) or, in a fixture file, credential headers.
const CREDENTIAL_KEYS: &[&str] = &[
    "accesskeyid",
    "secretaccesskey",
    "accesskeysecret",
    "token",
    "sessiontoken",
    "securitytoken",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
];

/// Query and form parameters that sign a request (SigV4 presigning, Alibaba
/// RPC signatures). Their values are scrubbed and ignored when matching.
pub const SIGNING_PARAMS: &[&str] = &[
    "signature",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "accesskeyid",
    "securitytoken",
    "signaturenonce",
];

fn rule(class: Class, re: &str, group: usize, form: Form) -> Rule {
    Rule {
        class,
        re: Regex::new(re).expect("rule regex"),
        group,
        form,
    }
}

/// In scrub order: secrets first, then identifiers, broad shapes (GUIDs, bare
/// ids) last so a narrower rule names the value.
pub(crate) static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let json_keys = CREDENTIAL_KEYS
        .iter()
        .chain(CREDENTIAL_HEADERS)
        .copied()
        .collect::<Vec<_>>()
        .join("|");
    let xml_keys = CREDENTIAL_KEYS.join("|");
    let params = SIGNING_PARAMS.join("|");
    vec![
        rule(
            Class::PrivateKey,
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            0,
            Form::Scrubbed,
        ),
        rule(
            Class::Jwt,
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
            0,
            Form::Scrubbed,
        ),
        rule(
            Class::BearerToken,
            r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]+)",
            1,
            Form::Scrubbed,
        ),
        rule(
            Class::AwsAccessKeyId,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            0,
            Form::Scrubbed,
        ),
        rule(
            Class::Credential,
            &format!(r#"(?i)"({json_keys})"\s*:\s*"([^"\\]*)""#),
            2,
            Form::Scrubbed,
        ),
        rule(
            Class::Credential,
            &format!(r"(?i)<({xml_keys})>([^<]*)</"),
            2,
            Form::Scrubbed,
        ),
        rule(
            Class::Signature,
            &format!(r#"(?i)(?:^|[?&"])({params})=([^&\s"]*)"#),
            2,
            Form::Scrubbed,
        ),
        rule(Class::Arn, r#"\barn:aws[a-z-]*:[^\s"'<>&,]+"#, 0, Form::Arn),
        rule(
            Class::DnsName,
            r"(?i)\b[a-z0-9][a-z0-9.-]*\.(?:compute(?:-1)?\.amazonaws\.com|ec2\.internal|compute\.internal|cloudapp\.azure\.com|internal\.cloudapp\.net|cloudapp\.net)\b",
            0,
            Form::Dns,
        ),
        rule(
            Class::ResourceGroup,
            r#"(?i)/resourcegroups/([^/?&"\s]+)"#,
            1,
            Form::Named("rg-"),
        ),
        rule(
            Class::ResourceGroup,
            r#"(?i)"resourcegroup"\s*:\s*"([^"]+)""#,
            1,
            Form::Named("rg-"),
        ),
        rule(
            Class::ScaleSet,
            r#"(?i)/virtualmachinescalesets/([^/?&"\s]+)"#,
            1,
            Form::Named("vmss-"),
        ),
        rule(
            Class::Guid,
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            0,
            Form::Guid,
        ),
        rule(
            Class::AccountId,
            r#"(?i)(owner-?id|account-?id|requester-?id|uid)(["']?\s*[:=>]\s*["']?)(\d{12}|\d{16})\b"#,
            3,
            Form::Digits,
        ),
        rule(
            Class::AlibabaResourceId,
            r"\b(?:eni|vsw|vpc|sg|i|eip|lb)-([a-z0-9]{20,})\b",
            1,
            Form::Dec5c7b,
        ),
        rule(
            Class::AwsResourceId,
            r"\b(?:eni-attach|eipalloc|eipassoc|subnet|vpc|eni|sg|igw|rtb|acl|ami|vol|snap|i|r)-([0-9a-f]{17}|[0-9a-f]{8})\b",
            1,
            Form::Hex5c7b,
        ),
    ]
});

pub(crate) static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("ipv4 regex")
});
pub(crate) static IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9A-Fa-f:]{2,39}").expect("ipv6 regex"));

pub(crate) const GUID_PREFIX: &str = "00000000-0000-4000-8000-";

/// Whether `value` is already a replacement of this form.
pub(crate) fn is_placeholder(form: Form, value: &str) -> bool {
    match form {
        Form::Scrubbed => value.is_empty() || value == "scrubbed",
        Form::Hex5c7b | Form::Dec5c7b => value.starts_with("5c7b"),
        Form::Digits => value.starts_with("0000000"),
        Form::Guid => value.to_ascii_lowercase().starts_with(GUID_PREFIX),
        Form::Named(prefix) => value
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())),
        // These rules never match their own replacements.
        Form::Dns | Form::Arn => false,
    }
}

/// The `n`th (from 1) replacement of this form for `original`, or `None` when
/// the counter no longer fits the original's length.
pub(crate) fn placeholder(form: Form, original: &str, n: u32) -> Option<String> {
    let fixed = |digits: String, width: usize| (digits.len() <= width).then_some(digits);
    match form {
        Form::Scrubbed => Some("scrubbed".to_string()),
        Form::Hex5c7b => {
            let width = original.len().checked_sub(4)?;
            fixed(format!("{n:0width$x}"), width).map(|d| format!("5c7b{d}"))
        }
        Form::Dec5c7b => {
            let width = original.len().checked_sub(4)?;
            fixed(format!("{n:0width$}"), width).map(|d| format!("5c7b{d}"))
        }
        Form::Digits => fixed(format!("{n:0width$}", width = original.len()), original.len()),
        Form::Guid => fixed(format!("{n:012}"), 12).map(|d| format!("{GUID_PREFIX}{d}")),
        Form::Named(prefix) => Some(format!("{prefix}{n}")),
        Form::Dns => Some(format!("host-{n}.scrubbed.invalid")),
        Form::Arn => Some(format!("arn:scrubbed:{n}")),
    }
}

/// Documentation ranges (RFC 5737): where public IPv4 addresses are mapped.
pub(crate) const DOC_V4: [[u8; 3]; 3] = [[203, 0, 113], [198, 51, 100], [192, 0, 2]];

fn is_doc_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    DOC_V4.contains(&[a, b, c])
}

/// A globally routable IPv4 address outside the documentation ranges.
pub(crate) fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    let special = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 198 && (b & 0xfe) == 18);
    !special && !is_doc_v4(ip)
}

/// Documentation prefixes (RFC 3849 2001:db8::/32, RFC 9637 3fff::/20).
pub(crate) fn is_doc_v6(ip: Ipv6Addr) -> bool {
    let [s0, s1, ..] = ip.segments();
    (s0 == 0x2001 && s1 == 0x0db8) || (s0 == 0x3fff && s1 < 0x1000)
}

/// A global unicast IPv6 address (2000::/3) outside the documentation prefixes.
pub(crate) fn is_public_v6(ip: Ipv6Addr) -> bool {
    let [s0, ..] = ip.segments();
    (s0 & 0xe000) == 0x2000 && !is_doc_v6(ip)
}

/// An IPv6 candidate token: at least two colons and a valid address.
pub(crate) fn parse_v6(token: &str) -> Option<Ipv6Addr> {
    if token.matches(':').count() < 2 {
        return None;
    }
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_recognised_and_keep_length() {
        let id = "0123456789abcdef0";
        let p = placeholder(Form::Hex5c7b, id, 1).expect("fits");
        assert_eq!(p, "5c7b0000000000001");
        assert_eq!(p.len(), id.len());
        assert!(is_placeholder(Form::Hex5c7b, &p));
        assert_eq!(placeholder(Form::Hex5c7b, "0123abcd", 0x1_0000), None);
        let acct = placeholder(Form::Digits, "123456789012", 3).expect("fits");
        assert_eq!(acct, "000000000003");
        assert!(is_placeholder(Form::Digits, &acct));
        let guid = placeholder(Form::Guid, "", 7).expect("fits");
        assert!(is_placeholder(Form::Guid, &guid.to_ascii_uppercase()));
        assert!(is_placeholder(Form::Named("rg-"), "rg-12"));
        assert!(!is_placeholder(Form::Named("rg-"), "rg-prod"));
    }

    #[test]
    fn address_classes() {
        for (ip, public) in [
            ("54.12.0.9", true),
            ("10.0.3.4", false),
            ("169.254.169.254", false),
            ("100.64.1.1", false),
            ("203.0.113.5", false),
            ("198.18.0.1", false),
        ] {
            assert_eq!(is_public_v4(ip.parse().expect("ip")), public, "{ip}");
        }
        for (ip, public) in [
            ("2600:1f18:abc::5", true),
            ("2001:db8::1", false),
            ("3fff:1::1", false),
            ("fd00::1", false),
            ("fe80::1", false),
        ] {
            assert_eq!(is_public_v6(ip.parse().expect("ip")), public, "{ip}");
        }
        assert_eq!(parse_v6("10:25:31"), None);
        assert_eq!(parse_v6("0a:1b:2c:3d:4e:5f"), None);
    }
}
