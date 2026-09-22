//! Checked little-endian drop headers, specification 01 §4.6 and 11 §4.4.
use std::fmt;
use flowsdn_bpf_abi::notify::MESSAGE_TYPE_DROP;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError { Truncated, WrongType, UnknownVersion, UnknownExtension, InvalidCaptureLength }
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "invalid monitor drop sample: {self:?}") }
}
impl std::error::Error for DecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface { pub index: u32, pub name: String }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropNotification<'a> {
    pub reason: u8,
    pub source: u16,
    pub original_length: u32,
    pub version: u8,
    pub ifindex: u32,
    pub flags: u8,
    pub ip_trace_id: u64,
    pub packet: &'a [u8],
}
fn read<const N: usize>(sample: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    sample.get(offset..offset.checked_add(N).ok_or(DecodeError::Truncated)?)
        .ok_or(DecodeError::Truncated)?.try_into().map_err(|_| DecodeError::Truncated)
}
impl<'a> DropNotification<'a> {
    pub fn decode(sample: &'a [u8]) -> Result<Self, DecodeError> {
        let kind = sample.first().ok_or(DecodeError::Truncated)?;
        if *kind != MESSAGE_TYPE_DROP { return Err(DecodeError::WrongType); }
        let version = *sample.get(14).ok_or(DecodeError::Truncated)?;
        let offset: usize = match version { 0 | 1 => 36, 2 => 40, 3 => 48, _ => return Err(DecodeError::UnknownVersion) };
        if *sample.get(15).ok_or(DecodeError::Truncated)? != 0 { return Err(DecodeError::UnknownExtension); }
        sample.get(..offset).ok_or(DecodeError::Truncated)?;
        let length = u16::from_le_bytes(read(sample, 12)?);
        let original_length = u32::from_le_bytes(read(sample, 8)?);
        if u32::from(length) > original_length { return Err(DecodeError::InvalidCaptureLength); }
        let end = offset.checked_add(usize::from(length)).ok_or(DecodeError::Truncated)?;
        Ok(Self {
            reason: *sample.get(1).ok_or(DecodeError::Truncated)?,
            source: u16::from_le_bytes(read(sample, 2)?),
            original_length, version,
            ifindex: u32::from_le_bytes(read(sample, 32)?),
            flags: if version >= 2 { *sample.get(36).ok_or(DecodeError::Truncated)? } else { 0 },
            ip_trace_id: if version >= 3 { u64::from_le_bytes(read(sample, 40)?) } else { 0 },
            packet: sample.get(offset..end).ok_or(DecodeError::Truncated)?,
        })
    }
    /// Preserve reference projection: raw drop ifindex is not Flow.interface.
    pub const fn flow_interface(&self) -> Option<Interface> { None }
}
