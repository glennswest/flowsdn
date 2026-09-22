//! Binary access-log message reader. Protocol decoding and Hubble emission are
//! caller responsibilities. A warning callback is invoked for every dropped
//! truncated message; callers may rate-limit their logging implementation.
use nix::sys::socket::{getsockname, getsockopt, recvmsg, sockopt, MsgFlags, SockType};
use std::{io::{self, IoSliceMut}, os::fd::{AsRawFd, OwnedFd}};
pub const DEFAULT_BUFFER_SIZE: usize = 16_384;
pub const MAX_BUFFER_SIZE: usize = 1_048_576;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Truncation { pub buffer_size: usize, pub dropped_total: u64 }
#[derive(Debug, Eq, PartialEq)]
pub enum Read { Record(Vec<u8>), Truncated(Truncation), EmptyOrClosed }
/// Owns one bound datagram socket or accepted seqpacket connection. The caller
/// owns listener permissions, accept/reconnect, cancellation and scheduling.
pub struct Reader { socket: OwnedFd, buffer: Vec<u8>, dropped: u64, seqpacket: bool }
impl Reader {
    pub fn new(socket: OwnedFd) -> io::Result<Self> { Self::with_capacity(socket, DEFAULT_BUFFER_SIZE) }
    pub fn with_capacity(socket: OwnedFd, capacity: usize) -> io::Result<Self> {
        if !(1..=MAX_BUFFER_SIZE).contains(&capacity) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "envoy-access-log-buffer-size must be in 1..=1048576"));
        }
        getsockname::<nix::sys::socket::UnixAddr>(socket.as_raw_fd()).map_err(io::Error::from)?;
        let kind = getsockopt(&socket, sockopt::SockType).map_err(io::Error::from)?;
        if !matches!(kind, SockType::Datagram | SockType::SeqPacket) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "access logs require a message socket"));
        }
        Ok(Self { socket, buffer: vec![0; capacity], dropped: 0, seqpacket: kind == SockType::SeqPacket })
    }
    pub fn dropped(&self) -> u64 { self.dropped }
    /// Reads exactly one message. EINTR retries; WouldBlock is returned unchanged.
    /// A zero-byte seqpacket result is EmptyOrClosed: recvmsg alone cannot
    /// distinguish an empty packet from orderly peer shutdown.
    /// A truncated prefix is never returned as a Record, even when binary data
    /// happens to parse. Exact-buffer-size complete messages remain valid.
    pub fn receive(&mut self, mut warn: impl FnMut(Truncation)) -> io::Result<Read> {
        let (length, flags) = loop {
            let mut buffers = [IoSliceMut::new(&mut self.buffer)];
            match recvmsg::<()>(self.socket.as_raw_fd(), &mut buffers, None, MsgFlags::empty()) {
                Ok(message) => break (message.bytes, message.flags),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            }
        };
        if flags.contains(MsgFlags::MSG_TRUNC) {
            self.dropped = self.dropped.saturating_add(1);
            let warning = Truncation { buffer_size: self.buffer.len(), dropped_total: self.dropped };
            warn(warning);
            return Ok(Read::Truncated(warning));
        }
        if length == 0 && self.seqpacket { return Ok(Read::EmptyOrClosed); }
        let bytes = self.buffer.get(..length).ok_or_else(|| io::Error::other("invalid access-log receive length"))?;
        Ok(Read::Record(bytes.to_vec()))
    }
}
