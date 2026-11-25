//! DNS messages as the proxy needs them (RFC 1035 §4), read with bounds: the
//! question of a query, the address answers of a response and their names
//! (the question's and its CNAME chain's), and the short replies the proxy
//! makes itself (a refusal, SERVFAIL). Responses are forwarded as upstream
//! sent them, byte for byte (spec 16 §3.6.6), so nothing here writes one.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The fixed header's length.
pub const HEADER: usize = 12;
/// Response codes the proxy uses.
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const REFUSED: u8 = 5;
}
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
/// The longest name kept, in text: a wire name is at most 255 octets, and
/// escaping can at most quadruple a label byte.
const MAX_NAME_TEXT: usize = 1024;
/// Compression pointers followed in one name before it is refused.
const MAX_JUMPS: u8 = 64;
/// Records read from one response.
const MAX_RECORDS: u16 = 512;

/// A query's question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// Lower-cased, with the trailing dot (`example.com.`).
    pub name: String,
    pub qtype: u16,
    /// Where the question section ends.
    pub end: usize,
}

/// What a response says about addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answers {
    pub id: u16,
    pub rcode: u8,
    /// The question's name and each name its CNAME chain reaches.
    pub names: Vec<String>,
    /// The A and AAAA answers for those names.
    pub ips: Vec<IpAddr>,
    /// The smallest TTL of the records used (0 without any).
    pub ttl: u32,
}

fn u16_at(message: &[u8], at: usize) -> Option<u16> {
    let bytes = message.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}
fn u32_at(message: &[u8], at: usize) -> Option<u32> {
    let bytes = message.get(at..at.checked_add(4)?)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Some(u32::from_be_bytes(out))
}

/// The name at `at`: its text (lower-cased, trailing dot; a byte outside
/// `!`..`~`, or a dot inside a label, escaped as `\DDD` or `\.`) and where
/// the name ends in place (after the first pointer, if any).
pub fn name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut at = start;
    let mut end = None;
    let mut jumps = 0u8;
    loop {
        let length = *message.get(at)?;
        match length & 0xc0 {
            0x00 if length == 0 => {
                if out.is_empty() {
                    out.push('.');
                }
                let next = at.checked_add(1)?;
                return Some((out, end.unwrap_or(next)));
            }
            0x00 => {
                let from = at.checked_add(1)?;
                let to = from.checked_add(usize::from(length))?;
                for byte in message.get(from..to)? {
                    let byte = byte.to_ascii_lowercase();
                    match byte {
                        b'.' | b'\\' => {
                            out.push('\\');
                            out.push(char::from(byte));
                        }
                        b'!'..=b'~' => out.push(char::from(byte)),
                        _ => out.push_str(&format!("\\{byte:03}")),
                    }
                }
                out.push('.');
                if out.len() > MAX_NAME_TEXT {
                    return None;
                }
                at = to;
            }
            0xc0 => {
                let low = *message.get(at.checked_add(1)?)?;
                if end.is_none() {
                    end = Some(at.checked_add(2)?);
                }
                jumps = jumps.checked_add(1)?;
                if jumps > MAX_JUMPS {
                    return None;
                }
                at = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            }
            _ => return None,
        }
    }
}

/// The question of a query: one question, QR clear.
pub fn question(message: &[u8]) -> Option<Question> {
    let id = u16_at(message, 0)?;
    let flags = u16_at(message, 2)?;
    if flags & 0x8000 != 0 || u16_at(message, 4)? != 1 {
        return None;
    }
    let (name, at) = name(message, HEADER)?;
    let qtype = u16_at(message, at)?;
    u16_at(message, at.checked_add(2)?)?;
    Some(Question {
        id,
        name,
        qtype,
        end: at.checked_add(4)?,
    })
}

/// The address answers of a response to `question`; `None` for a message
/// that is not one (QR clear, another ID, cut short).
pub fn answers(message: &[u8], question: &Question) -> Option<Answers> {
    let id = u16_at(message, 0)?;
    let flags = u16_at(message, 2)?;
    if flags & 0x8000 == 0 || id != question.id {
        return None;
    }
    let questions = u16_at(message, 4)?;
    let count = u16_at(message, 6)?.min(MAX_RECORDS);
    let mut at = HEADER;
    for _ in 0..questions {
        let (_, next) = name(message, at)?;
        at = next.checked_add(4)?;
    }
    // (owner, type, ttl, rdata start, rdata length)
    let mut records = Vec::new();
    for _ in 0..count {
        let (owner, next) = name(message, at)?;
        let kind = u16_at(message, next)?;
        let ttl = u32_at(message, next.checked_add(4)?)?;
        let length = usize::from(u16_at(message, next.checked_add(8)?)?);
        let data = next.checked_add(10)?;
        message.get(data..data.checked_add(length)?)?;
        records.push((owner, kind, ttl, data, length));
        at = data.checked_add(length)?;
    }
    let mut out = Answers {
        id,
        rcode: (flags & 0x000f) as u8,
        names: vec![question.name.clone()],
        ..Answers::default()
    };
    let mut ttl: Option<u32> = None;
    // Follow the CNAME chain from the question's name (any order).
    let mut grew = true;
    while grew {
        grew = false;
        for (owner, kind, record_ttl, data, _) in &records {
            if *kind != TYPE_CNAME || !out.names.contains(owner) {
                continue;
            }
            let Some((target, _)) = name(message, *data) else {
                continue;
            };
            if !out.names.contains(&target) {
                out.names.push(target);
                ttl = Some(ttl.map_or(*record_ttl, |t| t.min(*record_ttl)));
                grew = true;
            }
        }
    }
    for (owner, kind, record_ttl, data, length) in &records {
        if !out.names.contains(owner) {
            continue;
        }
        let bytes = message.get(*data..data.checked_add(*length)?)?;
        let ip = match (*kind, bytes.len()) {
            (TYPE_A, 4) => {
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                IpAddr::V4(Ipv4Addr::from(a))
            }
            (TYPE_AAAA, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from(a))
            }
            _ => continue,
        };
        if !out.ips.contains(&ip) {
            out.ips.push(ip);
        }
        ttl = Some(ttl.map_or(*record_ttl, |t| t.min(*record_ttl)));
    }
    out.ttl = ttl.unwrap_or(0);
    Some(out)
}

/// The proxy's own answer to a query: its header (ID, opcode and RD kept,
/// QR and RA set, `code`) and its question, nothing else.
pub fn reply(message: &[u8], question: &Question, code: u8) -> Option<Vec<u8>> {
    let flags = u16_at(message, 2)?;
    let flags = 0x8000 | (flags & 0x7900) | 0x0080 | u16::from(code & 0x0f);
    let mut out = Vec::with_capacity(question.end);
    out.extend_from_slice(&question.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(message.get(HEADER..question.end)?);
    Some(out)
}

/// SERVFAIL for a message whose question cannot be read: its ID and a bare
/// header; `None` without even an ID.
pub fn servfail_header(message: &[u8]) -> Option<Vec<u8>> {
    let id = u16_at(message, 0)?;
    let mut out = Vec::with_capacity(HEADER);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8080u16 | u16::from(rcode::SERVFAIL)).to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    Some(out)
}

/// A query for `name` (test and fixture use): ID, RD set, one question.
pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    push_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

/// A response to `query` with `answers` (owner name, TTL, address), each an
/// A or AAAA record (test and fixture use).
pub fn response(query: &[u8], answers: &[(&str, u32, IpAddr)]) -> Option<Vec<u8>> {
    let question = question(query)?;
    let mut out = reply(query, &question, rcode::NOERROR)?;
    let count = u16::try_from(answers.len()).ok()?;
    let [high, low] = count.to_be_bytes();
    *out.get_mut(6)? = high;
    *out.get_mut(7)? = low;
    for (owner, ttl, ip) in answers {
        push_name(&mut out, owner);
        let (kind, data): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&data);
    }
    Some(out)
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        let bytes = label.as_bytes();
        let length = u8::try_from(bytes.len().min(63)).unwrap_or(63);
        out.push(length);
        out.extend(bytes.iter().take(usize::from(length)));
    }
    out.push(0);
}
