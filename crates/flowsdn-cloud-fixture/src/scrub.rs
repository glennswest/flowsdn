//! The capture-side scrubber (ADR-0007 §2): replaces identifiers
//! deterministically within one scenario, so a value seen in a response and
//! sent back in a later request gets the same placeholder in both, and drops
//! credentials and signatures outright. Private addresses and CIDRs are kept.
use crate::fixture::{Interaction, Request, Response};
use crate::rules::{
    self, CREDENTIAL_HEADERS, Class, DOC_V4, Form, IPV4, IPV6, RULES, Rule, is_placeholder,
    placeholder,
};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// One scenario's mapping. Keep one `Scrubber` per scenario capture; the
/// real values it holds stay in memory and are never written.
#[derive(Default)]
pub struct Scrubber {
    forward: BTreeMap<(Class, String), String>,
    reverse: BTreeMap<String, String>,
    counters: BTreeMap<Class, u32>,
    v4: BTreeMap<Ipv4Addr, Ipv4Addr>,
    v6: BTreeMap<(u16, u16), (u16, u16)>,
}

fn key(form: Form, value: &str) -> String {
    match form {
        // ARM ids and GUIDs are case-insensitive.
        Form::Guid | Form::Named(_) => value.to_ascii_lowercase(),
        _ => value.to_string(),
    }
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    /// The real value behind a placeholder this scrubber issued (capture
    /// only: a later live request must carry the real id). Secrets are
    /// never kept, so they cannot be revealed.
    pub fn reveal(&self, placeholder: &str) -> Option<&str> {
        self.reverse.get(placeholder).map(String::as_str)
    }

    fn next(&mut self, class: Class) -> Result<u32, String> {
        let counter = self.counters.entry(class).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| format!("too many {} values", class.name()))?;
        Ok(*counter)
    }

    fn map(&mut self, rule: &Rule, value: &str) -> Result<String, String> {
        if matches!(rule.form, Form::Scrubbed) {
            return Ok("scrubbed".to_string());
        }
        let k = (rule.class, key(rule.form, value));
        if let Some(p) = self.forward.get(&k) {
            return Ok(p.clone());
        }
        let n = self.next(rule.class)?;
        let p = placeholder(rule.form, value, n)
            .ok_or_else(|| format!("too many {} values for their length", rule.class.name()))?;
        self.forward.insert(k, p.clone());
        self.reverse.insert(p.clone(), value.to_string());
        Ok(p)
    }

    fn apply(&mut self, rule: &Rule, text: &str) -> Result<String, String> {
        let mut err = None;
        let out = rule.re.replace_all(text, |caps: &regex::Captures<'_>| {
            let (Some(whole), Some(value)) = (caps.get(0), caps.get(rule.group)) else {
                return caps.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
            };
            if is_placeholder(rule.form, value.as_str()) {
                return whole.as_str().to_string();
            }
            match self.map(rule, value.as_str()) {
                Ok(new) => {
                    let pre = text.get(whole.start()..value.start()).unwrap_or_default();
                    let post = text.get(value.end()..whole.end()).unwrap_or_default();
                    format!("{pre}{new}{post}")
                }
                Err(e) => {
                    err.get_or_insert(e);
                    whole.as_str().to_string()
                }
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(out.into_owned()),
        }
    }

    fn map_v4(&mut self, ip: Ipv4Addr) -> Result<Ipv4Addr, String> {
        if let Some(p) = self.v4.get(&ip) {
            return Ok(*p);
        }
        let n = u32::try_from(self.v4.len()).map_err(|e| e.to_string())?;
        let exhausted = || "more than 762 public IPv4 addresses in one scenario".to_string();
        let pool = n.checked_div(254).ok_or_else(exhausted)?;
        let host = n
            .checked_rem(254)
            .and_then(|h| h.checked_add(1))
            .and_then(|h| u8::try_from(h).ok())
            .ok_or_else(exhausted)?;
        let [a, b, c] = *usize::try_from(pool)
            .ok()
            .and_then(|i| DOC_V4.get(i))
            .ok_or_else(exhausted)?;
        let p = Ipv4Addr::new(a, b, c, host);
        self.v4.insert(ip, p);
        Ok(p)
    }

    /// Public IPv6 addresses keep their low 96 bits, so prefixes and the
    /// addresses inside them stay related; each distinct /32 maps to a
    /// documentation /32 (2001:db8, then 3fff:0001...).
    fn map_v6(&mut self, ip: Ipv6Addr) -> Result<Ipv6Addr, String> {
        let [s0, s1, s2, s3, s4, s5, s6, s7] = ip.segments();
        let top = match self.v6.get(&(s0, s1)) {
            Some(t) => *t,
            None => {
                let t = match u16::try_from(self.v6.len()) {
                    Ok(0) => (0x2001, 0x0db8),
                    Ok(n) if n < 0x1000 => (0x3fff, n),
                    _ => return Err("too many public IPv6 /32s in one scenario".to_string()),
                };
                self.v6.insert((s0, s1), t);
                t
            }
        };
        Ok(Ipv6Addr::new(top.0, top.1, s2, s3, s4, s5, s6, s7))
    }

    fn ips(&mut self, text: &str) -> Result<String, String> {
        let mut err = None;
        let v4 = IPV4.replace_all(text, |caps: &regex::Captures<'_>| {
            let token = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            match token.parse::<Ipv4Addr>() {
                Ok(ip) if rules::is_public_v4(ip) => match self.map_v4(ip) {
                    Ok(p) => p.to_string(),
                    Err(e) => {
                        err.get_or_insert(e);
                        token.to_string()
                    }
                },
                _ => token.to_string(),
            }
        });
        let v4 = v4.into_owned();
        let v6 = IPV6.replace_all(&v4, |caps: &regex::Captures<'_>| {
            let token = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            match rules::parse_v6(token) {
                Some(ip) if rules::is_public_v6(ip) => match self.map_v6(ip) {
                    Ok(p) => p.to_string(),
                    Err(e) => {
                        err.get_or_insert(e);
                        token.to_string()
                    }
                },
                _ => token.to_string(),
            }
        });
        let v6 = v6.into_owned();
        match err {
            Some(e) => Err(e),
            None => Ok(v6),
        }
    }

    /// Scrubs free text: a body, a path with its query, a header value.
    pub fn text(&mut self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for rule in RULES.iter() {
            out = self.apply(rule, &out)?;
        }
        self.ips(&out)
    }

    fn headers(
        &mut self,
        headers: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, String> {
        headers
            .iter()
            .map(|(name, value)| {
                let name = name.to_ascii_lowercase();
                let value = if CREDENTIAL_HEADERS.contains(&name.as_str()) {
                    "scrubbed".to_string()
                } else {
                    self.text(value)?
                };
                Ok((name, value))
            })
            .collect()
    }

    /// Scrubs one recorded request/response pair.
    pub fn interaction(&mut self, i: &Interaction) -> Result<Interaction, String> {
        Ok(Interaction {
            operation: i.operation.clone(),
            request: Request {
                method: i.request.method.clone(),
                path: self.text(&i.request.path)?,
                headers: self.headers(&i.request.headers)?,
                body: self.text(&i.request.body)?,
            },
            response: Response {
                status: i.response.status,
                headers: self.headers(&i.response.headers)?,
                body: self.text(&i.response.body)?,
            },
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan;

    /// Synthetic provider traffic with one value of each class. Secret-shaped
    /// strings are assembled at run time so the source holds none.
    pub(crate) fn raw_samples() -> Vec<(&'static str, String)> {
        let key_id = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let jwt = format!("eyJ{}.eyJzdWIiOiIxMjM0.c2lnbmF0dXJl", "hbGciOiJSUzI1NiJ9");
        let pem = format!(
            "-----BEGIN {k}-----\\nMIIEvQIBADAN\\n-----END {k}-----",
            k = "PRIVATE KEY"
        );
        vec![
            ("private key", format!(r#"{{"key": "{pem}"}}"#)),
            ("JWT", format!(r#"{{"note": "{jwt}"}}"#)),
            ("bearer token", "Bearer abcdefghijklmnop".to_string()),
            ("AWS access key id", format!("credential {key_id}")),
            (
                "credential value",
                format!(
                    r#"{{"Code":"Success","SecretAccessKey":"wJalrXUtnFEMI{}"}}"#,
                    "bPxRfiCYEXAMPLEKEY"
                ),
            ),
            (
                "credential value",
                "<SessionToken>FwoGZXIvYXdzEXAMPLE</SessionToken>".to_string(),
            ),
            (
                "request signing parameter",
                "/?Action=DescribeInstances&Signature=Zm9vYmFy&AccessKeyId=LTAI5tEXAMPLE".to_string(),
            ),
            ("ARN", "arn:aws:iam::123456789012:role/node".to_string()),
            ("instance DNS name", "ec2-54-1-2-3.compute-1.amazonaws.com".to_string()),
            (
                "resource group name",
                "/subscriptions/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/resourceGroups/prod-west/providers".to_string(),
            ),
            (
                "VMSS name",
                "/providers/Microsoft.Compute/virtualMachineScaleSets/workers".to_string(),
            ),
            ("GUID", r#"{"tenantId":"9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d"}"#.to_string()),
            ("account id", "<ownerId>123456789012</ownerId>".to_string()),
            ("Alibaba uid", r#"{"OwnerId": 1234567890123456}"#.to_string()),
            ("Alibaba id", "vsw-bp1a2b3c4d5e6f7g8h9i0j".to_string()),
            ("AWS id", "<networkInterfaceId>eni-0a1b2c3d4e5f60718</networkInterfaceId>".to_string()),
            ("public IPv4", "<publicIp>54.12.0.9</publicIp>".to_string()),
            ("public IPv6", "<ipv6Address>2600:1f18:abc:de00::5</ipv6Address>".to_string()),
        ]
    }

    #[test]
    fn every_sample_is_found_raw_and_clean_after_scrubbing() {
        for (what, raw) in raw_samples() {
            assert!(!scan::scan_text(&raw).is_empty(), "scan misses raw {what}: {raw}");
            let scrubbed = Scrubber::new().text(&raw).expect("scrub");
            assert_ne!(scrubbed, raw, "{what} not scrubbed");
            let left = scan::scan_text(&scrubbed);
            assert!(left.is_empty(), "{what} after scrubbing: {scrubbed} -> {left:?}");
            let again = Scrubber::new().text(&scrubbed).expect("rescrub");
            assert_eq!(again, scrubbed, "{what}: scrubbing is not idempotent");
        }
    }

    #[test]
    fn consistent_within_a_scenario_and_revealable() {
        let mut s = Scrubber::new();
        let a = s.text("eni-0a1b2c3d4e5f60718 in subnet-0123abcd").expect("scrub");
        let b = s.text(r#"{"NetworkInterfaceId":"eni-0a1b2c3d4e5f60718"}"#).expect("scrub");
        // One counter per class: the subnet is the second AWS id.
        assert_eq!(a, "eni-5c7b0000000000001 in subnet-5c7b0002");
        assert_eq!(b, r#"{"NetworkInterfaceId":"eni-5c7b0000000000001"}"#);
        assert_eq!(s.reveal("5c7b0000000000001"), Some("0a1b2c3d4e5f60718"));
        // Case-insensitive ARM names map to one placeholder.
        let p = s
            .text("/resourceGroups/Prod-West/x /resourcegroups/prod-west/y")
            .expect("scrub");
        assert_eq!(p, "/resourceGroups/rg-1/x /resourcegroups/rg-1/y");
        // Secrets are never kept.
        let _ = s.text("Bearer abcdefghijklmnop").expect("scrub");
        assert_eq!(s.reveal("scrubbed"), None);
    }

    #[test]
    fn private_addresses_kept_public_mapped() {
        let mut s = Scrubber::new();
        let out = s
            .text("10.0.1.5 172.31.0.0/16 169.254.169.254 54.12.0.9 54.12.0.10 54.12.0.9")
            .expect("scrub");
        assert_eq!(
            out,
            "10.0.1.5 172.31.0.0/16 169.254.169.254 203.0.113.1 203.0.113.2 203.0.113.1"
        );
        let v6 = s
            .text("2600:1f18:abc:de00::/56 2600:1f18:abc:de00::5 2a05:d014::1 fd00::1")
            .expect("scrub");
        assert_eq!(v6, "2001:db8:abc:de00::/56 2001:db8:abc:de00::5 3fff:1::1 fd00::1");
    }

    #[test]
    fn credential_headers_scrubbed_others_kept() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_string(),
            "AWS4-HMAC-SHA256 Credential=x/20261103/us-east-1/ec2/aws4_request, Signature=ab".to_string(),
        );
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
        let i = Interaction {
            operation: "describe-instances".to_string(),
            request: Request {
                method: "POST".to_string(),
                path: "/".to_string(),
                headers,
                body: "Action=DescribeInstances&Version=2016-11-15".to_string(),
            },
            response: Response {
                status: 200,
                headers: BTreeMap::new(),
                body: "<instanceId>i-0123456789abcdef0</instanceId>".to_string(),
            },
        };
        let out = Scrubber::new().interaction(&i).expect("scrub");
        assert_eq!(out.request.headers.get("authorization").map(String::as_str), Some("scrubbed"));
        assert_eq!(
            out.request.headers.get("content-type").map(String::as_str),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(out.request.body, i.request.body);
        assert_eq!(out.response.body, "<instanceId>i-5c7b0000000000001</instanceId>");
    }
}
