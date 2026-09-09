use crate::{Error, Limits, Response, Result, remaining};
use std::{
    io::{self, Read},
    os::unix::net::UnixStream,
    time::Instant,
};

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

struct Reader {
    stream: UnixStream,
    deadline: Option<Instant>,
    limits: Limits,
    buffer: [u8; 4096],
    cursor: usize,
    filled: usize,
    received: usize,
}
impl Reader {
    fn fill(&mut self) -> Result<bool> {
        if self.cursor < self.filled {
            return Ok(true);
        }
        loop {
            self.stream
                .set_read_timeout(self.deadline.map(remaining).transpose()?)?;
            // One extra byte distinguishes EOF exactly at the wire limit from
            // a response which actually exceeds it.
            let available = self
                .limits
                .wire_bytes
                .saturating_sub(self.received)
                .saturating_add(1)
                .min(self.buffer.len());
            let buffer = self
                .buffer
                .get_mut(..available)
                .ok_or_else(|| protocol("invalid read bound"))?;
            match self.stream.read(buffer) {
                Ok(count) => {
                    self.received = self
                        .received
                        .checked_add(count)
                        .ok_or(Error::Limit("wire bytes"))?;
                    if self.received > self.limits.wire_bytes {
                        return Err(Error::Limit("wire bytes"));
                    }
                    self.cursor = 0;
                    self.filled = count;
                    return Ok(count != 0);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn byte(&mut self) -> Result<Option<u8>> {
        if !self.fill()? {
            return Ok(None);
        }
        let byte = *self
            .buffer
            .get(self.cursor)
            .ok_or_else(|| protocol("invalid read position"))?;
        self.cursor = self.cursor.saturating_add(1);
        Ok(Some(byte))
    }

    fn line(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let byte = self
                .byte()?
                .ok_or_else(|| protocol("truncated HTTP line"))?;
            if line.len() >= limit {
                return Err(Error::Limit("header bytes"));
            }
            line.push(byte);
            if byte == b'\n' {
                if !line.ends_with(b"\r\n") {
                    return Err(protocol("HTTP lines require CRLF"));
                }
                return Ok(line);
            }
        }
    }

    fn exact(&mut self, output: &mut Vec<u8>, count: usize) -> Result<()> {
        let target = output
            .len()
            .checked_add(count)
            .ok_or(Error::Limit("body bytes"))?;
        if target > self.limits.body_bytes {
            return Err(Error::Limit("body bytes"));
        }
        while output.len() < target {
            if !self.fill()? {
                return Err(protocol("truncated HTTP body"));
            }
            let count = target
                .saturating_sub(output.len())
                .min(self.filled.saturating_sub(self.cursor));
            let end = self.cursor.saturating_add(count);
            output.extend_from_slice(
                self.buffer
                    .get(self.cursor..end)
                    .ok_or_else(|| protocol("invalid read bounds"))?,
            );
            self.cursor = end;
        }
        Ok(())
    }
}

pub(crate) fn response(
    stream: UnixStream,
    deadline: Option<Instant>,
    limits: Limits,
) -> Result<Response> {
    let mut reader = Reader {
        stream,
        deadline,
        limits,
        buffer: [0; 4096],
        cursor: 0,
        filled: 0,
        received: 0,
    };
    let mut header_budget = limits.header_bytes;
    let mut interim = 0u8;
    let (status, length, chunked) = loop {
        let mut bytes = Vec::new();
        loop {
            let line = reader.line(header_budget)?;
            header_budget = header_budget
                .checked_sub(line.len())
                .ok_or(Error::Limit("header bytes"))?;
            let end = line == b"\r\n";
            bytes.extend_from_slice(&line);
            if end {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(&bytes).map_err(|e| protocol(e.to_string()))? {
            httparse::Status::Complete(consumed) if consumed == bytes.len() => {}
            _ => return Err(protocol("incomplete response headers")),
        }
        let status = parsed.code.ok_or_else(|| protocol("missing HTTP status"))?;
        let mut length = None;
        let mut chunked = false;
        for header in parsed.headers.iter() {
            if header.name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err(protocol("duplicate Content-Length"));
                }
                let text = std::str::from_utf8(header.value)
                    .map_err(|e| protocol(e.to_string()))?
                    .trim();
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(protocol("invalid Content-Length"));
                }
                length = Some(
                    text.parse::<usize>()
                        .map_err(|_| protocol("Content-Length overflow"))?,
                );
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(protocol("unsupported or duplicate Transfer-Encoding"));
                }
                chunked = true;
            }
        }
        if chunked && length.is_some() {
            return Err(protocol("ambiguous response framing"));
        }
        if (100..200).contains(&status) {
            if status == 101 || chunked || length.is_some_and(|n| n != 0) {
                return Err(protocol("unsupported informational response"));
            }
            interim = interim.saturating_add(1);
            if interim > 8 {
                return Err(protocol("too many informational responses"));
            }
            continue;
        }
        if !(200..600).contains(&status) {
            return Err(protocol("invalid HTTP status"));
        }
        break (status, length, chunked);
    };
    let mut body = Vec::new();
    if matches!(status, 204 | 304) {
        if status == 204 && (chunked || length.is_some_and(|n| n != 0)) {
            return Err(protocol("204 response carries body framing"));
        }
    } else if chunked {
        loop {
            let line = reader.line(limits.header_bytes)?;
            let size =
                match httparse::parse_chunk_size(&line).map_err(|e| protocol(e.to_string()))? {
                    httparse::Status::Complete((consumed, size)) if consumed == line.len() => size,
                    _ => return Err(protocol("invalid chunk size")),
                };
            let size = usize::try_from(size).map_err(|_| Error::Limit("body bytes"))?;
            if size == 0 {
                let mut trailer_bytes = Vec::new();
                loop {
                    let line = reader.line(header_budget)?;
                    header_budget = header_budget
                        .checked_sub(line.len())
                        .ok_or(Error::Limit("header bytes"))?;
                    let end = line == b"\r\n";
                    trailer_bytes.extend_from_slice(&line);
                    if end {
                        break;
                    }
                }
                let mut trailers = [httparse::EMPTY_HEADER; 64];
                match httparse::parse_headers(&trailer_bytes, &mut trailers)
                    .map_err(|e| protocol(e.to_string()))?
                {
                    httparse::Status::Complete((consumed, headers))
                        if consumed == trailer_bytes.len() =>
                    {
                        if headers.iter().any(|h| {
                            h.name.eq_ignore_ascii_case("content-length")
                                || h.name.eq_ignore_ascii_case("transfer-encoding")
                        }) {
                            return Err(protocol("framing header in trailer"));
                        }
                    }
                    _ => return Err(protocol("invalid chunk trailers")),
                }
                break;
            }
            reader.exact(&mut body, size)?;
            if reader.byte()? != Some(b'\r') || reader.byte()? != Some(b'\n') {
                return Err(protocol("missing chunk terminator"));
            }
        }
    } else if let Some(length) = length {
        reader.exact(&mut body, length)?;
    } else {
        while reader.fill()? {
            let count = reader.filled.saturating_sub(reader.cursor);
            reader.exact(&mut body, count)?;
        }
    }
    if let Some(deadline) = deadline {
        remaining(deadline)?;
    }
    let json = serde_json::from_slice(&body).ok();
    if let Some(deadline) = deadline {
        remaining(deadline)?;
    }
    Ok(Response { status, json, body })
}
