//! Bounded BGP wire and configuration primitives from specification 15.
//! Includes a deterministic session core, but no sockets, RIB or working speaker.
pub mod capabilities;
pub mod encode_update;
pub mod messages;
pub mod session;
pub mod open;
pub mod planning;
pub mod update;
use std::fmt;
pub const HEADER_LENGTH: usize = 19;
pub const MAX_MESSAGE_LENGTH: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorScope {
    Framing,
    AttributeStructure,
    UpdateContent,
    Open,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub code: u8,
    pub subcode: u8,
    pub scope: ErrorScope,
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BGP notification {}/{} ({:?})",
            self.code, self.subcode, self.scope
        )
    }
}
impl std::error::Error for ProtocolError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    NeedMore,
    Protocol(ProtocolError),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub body: &'a [u8],
}
fn framing(subcode: u8) -> ProtocolError {
    ProtocolError {
        code: 1,
        subcode,
        scope: ErrorScope::Framing,
    }
}
/// Returns one frame and its byte count; trailing bytes belong to the next
/// frame. Marker content is accepted per the pinned compatibility specification.
pub fn decode(bytes: &[u8]) -> Result<(Frame<'_>, usize), DecodeError> {
    let header = bytes.get(..HEADER_LENGTH).ok_or(DecodeError::NeedMore)?;
    let length = usize::from(u16::from_be_bytes([
        *header.get(16).expect("header"),
        *header.get(17).expect("header"),
    ]));
    if !(HEADER_LENGTH..=MAX_MESSAGE_LENGTH).contains(&length) {
        return Err(DecodeError::Protocol(framing(2)));
    }
    let kind = match header.get(18) {
        Some(1) => Kind::Open,
        Some(2) => Kind::Update,
        Some(3) => Kind::Notification,
        Some(4) => Kind::Keepalive,
        Some(5) => Kind::RouteRefresh,
        _ => return Err(DecodeError::Protocol(framing(3))),
    };
    let valid = match kind {
        Kind::Open => length >= 29,
        Kind::Update => length >= 23,
        Kind::Notification => length >= 21,
        Kind::Keepalive => length == 19,
        Kind::RouteRefresh => length == 23,
    };
    if !valid {
        return Err(DecodeError::Protocol(framing(2)));
    }
    let body = bytes
        .get(HEADER_LENGTH..length)
        .ok_or(DecodeError::NeedMore)?;
    Ok((Frame { kind, body }, length))
}
pub fn encode(kind: Kind, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let length = HEADER_LENGTH
        .checked_add(body.len())
        .filter(|n| *n <= MAX_MESSAGE_LENGTH)
        .ok_or_else(|| framing(2))?;
    let length = u16::try_from(length).map_err(|_| framing(2))?;
    let mut bytes = vec![0xff; 16];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.push(kind as u8);
    bytes.extend_from_slice(body);
    decode(&bytes).map_err(|error| match error {
        DecodeError::Protocol(error) => error,
        DecodeError::NeedMore => framing(2),
    })?;
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorAction {
    NotifyAndClose,
    CountLogAndDiscard,
}
/// Session survival is safe only for this export-only, non-installing receive
/// path. Never use the lenient policy for imported/forwarding routes.
pub const fn error_action(error: ProtocolError, strict_update_errors: bool) -> ErrorAction {
    if matches!(error.scope, ErrorScope::UpdateContent) && !strict_update_errors {
        ErrorAction::CountLogAndDiscard
    } else {
        ErrorAction::NotifyAndClose
    }
}

pub mod rib;
pub mod collision;
