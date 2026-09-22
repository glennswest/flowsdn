use flowsdn_proxy::accesslog::{DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE, Read, Reader};
use std::os::{
    fd::OwnedFd,
    unix::net::{UnixDatagram, UnixStream},
};
#[test]
fn header_heavy_binary_records_and_exact_boundary_survive() {
    let (sender, receiver) = UnixDatagram::pair().expect("pair");
    let mut reader = Reader::new(OwnedFd::from(receiver)).expect("reader");
    for size in [0, 8192, DEFAULT_BUFFER_SIZE] {
        let data = vec![0xff; size];
        sender.send(&data).expect("send");
        assert_eq!(
            reader
                .receive(|_| panic!("unexpected truncation"))
                .expect("read"),
            Read::Record(data)
        );
    }
    assert_eq!(reader.dropped(), 0);
}
#[test]
fn oversize_is_dropped_once_then_next_datagram_remains_intact() {
    let (sender, receiver) = UnixDatagram::pair().expect("pair");
    let mut reader = Reader::new(receiver.into()).expect("reader");
    sender.send(&vec![b'x'; 20_000]).expect("large message");
    sender.send(b"\0\xffnext").expect("next");
    let mut warnings = Vec::new();
    let result = reader
        .receive(|warning| warnings.push(warning))
        .expect("receive");
    assert!(matches!(result, Read::Truncated(_)));
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings.first().expect("warning").buffer_size, 16_384);
    assert_eq!(reader.dropped(), 1);
    assert_eq!(
        reader
            .receive(|_| panic!("unexpected truncation"))
            .expect("next"),
        Read::Record(b"\0\xffnext".to_vec())
    );
}
#[test]
fn legacy_buffer_truncates_header_heavy_record_and_bounds_reject() {
    let (sender, receiver) = UnixDatagram::pair().expect("pair");
    let mut reader = Reader::with_capacity(receiver.into(), 4096).expect("reader");
    sender.send(&vec![b'h'; 8192]).expect("send");
    assert!(matches!(
        reader.receive(|_| {}).expect("receive"),
        Read::Truncated(_)
    ));
    for capacity in [0, MAX_BUFFER_SIZE.saturating_add(1)] {
        let (_, receiver) = UnixDatagram::pair().expect("pair");
        assert!(Reader::with_capacity(receiver.into(), capacity).is_err());
    }
    let (_, receiver) = UnixStream::pair().expect("stream");
    assert!(Reader::new(receiver.into()).is_err());
}
#[cfg(target_os = "linux")]
#[test]
fn seqpacket_truncation_and_peer_close() {
    use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, send, socketpair};
    use std::os::fd::AsRawFd;
    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .expect("seqpacket");
    let mut reader = Reader::new(receiver).expect("reader");
    send(sender.as_raw_fd(), &vec![42; 20_000], MsgFlags::empty()).expect("send");
    assert!(matches!(
        reader.receive(|_| {}).expect("read"),
        Read::Truncated(_)
    ));
    send(sender.as_raw_fd(), b"record", MsgFlags::empty()).expect("send");
    assert_eq!(
        reader.receive(|_| {}).expect("read"),
        Read::Record(b"record".to_vec())
    );
    drop(sender);
    assert_eq!(reader.receive(|_| {}).expect("close"), Read::EmptyOrClosed);
}
