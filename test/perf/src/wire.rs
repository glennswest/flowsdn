//! The measurement protocols, server and client, over plain sockets:
//!
//! - `RR_PORT` TCP and UDP: request/response echo of one byte (netperf
//!   TCP_RR/UDP_RR's default size); the client times each transaction.
//! - `STREAM_PORT` TCP: the client writes for a fixed time and half-closes;
//!   the server counts what it read and answers with that count (8 bytes, big
//!   endian), so throughput is what arrived, not what was buffered.
//! - `ACCEPT_PORT` TCP: accept and close; the client times `connect`.
use crate::stats::Samples;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};

pub const RR_PORT: u16 = 5201;
pub const STREAM_PORT: u16 = 5202;
pub const ACCEPT_PORT: u16 = 5203;
/// One write in a stream test.
const CHUNK: usize = 128 * 1024;
/// Most samples one RR or connect run keeps (about 8 MiB).
const MAX_SAMPLES: usize = 1_000_000;

/// Serve all three protocols on every address until the process ends.
pub fn serve() -> io::Result<()> {
    let rr = TcpListener::bind(("::", RR_PORT)).or_else(|_| TcpListener::bind(("0.0.0.0", RR_PORT)))?;
    let udp = UdpSocket::bind(("::", RR_PORT)).or_else(|_| UdpSocket::bind(("0.0.0.0", RR_PORT)))?;
    let stream = TcpListener::bind(("::", STREAM_PORT))
        .or_else(|_| TcpListener::bind(("0.0.0.0", STREAM_PORT)))?;
    let accept = TcpListener::bind(("::", ACCEPT_PORT))
        .or_else(|_| TcpListener::bind(("0.0.0.0", ACCEPT_PORT)))?;
    thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        loop {
            if let Ok((n, from)) = udp.recv_from(&mut buffer) {
                let _ = udp.send_to(buffer.get(..n).unwrap_or_default(), from);
            }
        }
    });
    thread::spawn(move || {
        for connection in stream.incoming().flatten() {
            thread::spawn(move || {
                let _ = sink(connection);
            });
        }
    });
    thread::spawn(move || {
        for connection in accept.incoming() {
            drop(connection);
        }
    });
    for connection in rr.incoming().flatten() {
        thread::spawn(move || {
            let _ = echo(connection);
        });
    }
    Ok(())
}
fn echo(mut connection: TcpStream) -> io::Result<()> {
    connection.set_nodelay(true)?;
    let mut byte = [0u8; 1];
    loop {
        if connection.read(&mut byte)? == 0 {
            return Ok(());
        }
        connection.write_all(&byte)?;
    }
}
fn sink(mut connection: TcpStream) -> io::Result<()> {
    let mut buffer = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = connection.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(n).unwrap_or(0));
    }
    connection.write_all(&total.to_be_bytes())
}

/// Whether `address` accepts a TCP connection within `timeout`.
pub fn reachable(address: SocketAddr, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&address, timeout).is_ok()
}

/// The result of a request/response run.
#[derive(Debug)]
pub struct RrResult {
    pub samples: Samples,
    pub elapsed: Duration,
    /// UDP requests without a reply within a second.
    pub lost: u64,
}
impl RrResult {
    pub fn per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds <= 0.0 {
            0.0
        } else {
            (self.samples.len() as f64 / seconds).round()
        }
    }
}

pub fn tcp_rr(address: SocketAddr, duration: Duration) -> io::Result<RrResult> {
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    connection.set_nodelay(true)?;
    connection.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut samples = Samples::default();
    let mut byte = [7u8; 1];
    let start = Instant::now();
    while start.elapsed() < duration && samples.len() < MAX_SAMPLES {
        let sent = Instant::now();
        connection.write_all(&byte)?;
        connection.read_exact(&mut byte)?;
        samples.push(sent.elapsed());
    }
    Ok(RrResult {
        samples,
        elapsed: start.elapsed(),
        lost: 0,
    })
}

pub fn udp_rr(address: SocketAddr, duration: Duration) -> io::Result<RrResult> {
    let local: SocketAddr = if address.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut samples = Samples::default();
    let mut lost: u64 = 0;
    let mut buffer = [0u8; 16];
    let start = Instant::now();
    let mut sequence: u8 = 0;
    while start.elapsed() < duration && samples.len() < MAX_SAMPLES {
        sequence = sequence.wrapping_add(1);
        let sent = Instant::now();
        socket.send(&[sequence])?;
        loop {
            match socket.recv(&mut buffer) {
                // A late reply to an earlier (lost) request is skipped.
                Ok(n) if n == 1 && buffer.first() == Some(&sequence) => {
                    samples.push(sent.elapsed());
                    break;
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    lost = lost.saturating_add(1);
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        if lost > 100 && samples.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no UDP reply to 100 requests",
            ));
        }
    }
    Ok(RrResult {
        samples,
        elapsed: start.elapsed(),
        lost,
    })
}

/// `streams` parallel TCP streams for `duration`; returns bytes the server
/// received and the time from the first connect to the last count.
pub fn tcp_stream(
    address: SocketAddr,
    streams: usize,
    duration: Duration,
) -> io::Result<(u64, Duration)> {
    let start = Instant::now();
    let workers: Vec<_> = (0..streams.max(1))
        .map(|_| {
            thread::spawn(move || -> io::Result<u64> {
                let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                connection.set_write_timeout(Some(Duration::from_secs(10)))?;
                connection.set_read_timeout(Some(Duration::from_secs(30)))?;
                let chunk = vec![0x5au8; CHUNK];
                let begun = Instant::now();
                while begun.elapsed() < duration {
                    connection.write_all(&chunk)?;
                }
                connection.shutdown(Shutdown::Write)?;
                let mut count = [0u8; 8];
                connection.read_exact(&mut count)?;
                Ok(u64::from_be_bytes(count))
            })
        })
        .collect();
    let mut total: u64 = 0;
    for worker in workers {
        let bytes = worker
            .join()
            .map_err(|_| io::Error::other("stream worker panicked"))??;
        total = total.saturating_add(bytes);
    }
    Ok((total, start.elapsed()))
}

/// Connect-and-close in a loop for `duration`; times each `connect`.
/// Returns the samples and the number of failed connects.
pub fn connect_rate(address: SocketAddr, duration: Duration) -> (RrResult, u64) {
    let mut samples = Samples::default();
    let mut failed: u64 = 0;
    let start = Instant::now();
    while start.elapsed() < duration && samples.len() < MAX_SAMPLES {
        let begun = Instant::now();
        match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
            Ok(connection) => {
                samples.push(begun.elapsed());
                // RST instead of TIME_WAIT keeps the client's ports free.
                let _ = socket_linger_zero(&connection);
                drop(connection);
            }
            Err(_) => failed = failed.saturating_add(1),
        }
    }
    (
        RrResult {
            samples,
            elapsed: start.elapsed(),
            lost: 0,
        },
        failed,
    )
}

#[allow(unsafe_code)]
fn socket_linger_zero(connection: &TcpStream) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let size = libc::socklen_t::try_from(std::mem::size_of::<libc::linger>())
        .map_err(|_| io::Error::other("linger size"))?;
    // SAFETY: a valid socket fd and a pointer to a live linger of `size` bytes.
    let rc = unsafe {
        libc::setsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn protocols_against_a_loopback_server() {
        // Ports are fixed; a second test process on the box would collide,
        // so the server is shared by this one test.
        thread::spawn(|| serve());
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .expect("deadline");
        while !reachable(local(RR_PORT), Duration::from_millis(100)) {
            assert!(Instant::now() < deadline, "server did not start");
            thread::sleep(Duration::from_millis(20));
        }
        let mut tcp = tcp_rr(local(RR_PORT), Duration::from_millis(200)).expect("tcp rr");
        assert!(tcp.samples.len() > 10, "{}", tcp.samples.len());
        assert!(tcp.samples.percentile_us(0.5).expect("p50") > 0.0);
        let udp = udp_rr(local(RR_PORT), Duration::from_millis(200)).expect("udp rr");
        assert!(udp.samples.len() > 10);
        assert_eq!(udp.lost, 0);
        let (bytes, elapsed) =
            tcp_stream(local(STREAM_PORT), 2, Duration::from_millis(200)).expect("stream");
        assert!(bytes >= 2 * CHUNK as u64, "{bytes}");
        assert!(elapsed >= Duration::from_millis(200));
        let (rate, failed) = connect_rate(local(ACCEPT_PORT), Duration::from_millis(200));
        assert!(rate.samples.len() > 10);
        assert_eq!(failed, 0);
        assert!(!reachable(local(1), Duration::from_millis(100)));
    }
}
