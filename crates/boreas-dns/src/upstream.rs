//! Blocking, plaintext DNS-over-TCP forwarding to a trusted configured address.
//!
//! One exchange opens one OS TCP connection, sends one query, reads one frame,
//! then closes the connection. There is no listener, cache, retry, pooling,
//! system resolver, UDP (including fallback), or DoH. DNS payloads, including
//! IDs, EDNS options and response TTLs, are passed through unchanged. This is
//! not DNSSEC validation or authentication of a plaintext upstream.
//!
//! Before calling, the consumer must authenticate and authorize the client,
//! classify the query as public (private names must fail closed), and enforce
//! per-identity/global concurrency, query and byte budgets. The endpoint must
//! come from trusted configuration, never from a client packet or a peer
//! advertisement. This primitive only bounds one exchange, not aggregate load.

use crate::{
    CLASS_IN, DnsError, MAX_RESPONSE_BYTES, Question, TYPE_OPT, decode_name, parse_query, u16_at,
    valid_edns_options,
};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MIN_MESSAGE_BYTES: usize = 17; // DNS header + root name + QTYPE + QCLASS.
/// Hard ceiling for the configured end-to-end timeout of one exchange.
pub const MAX_TCP_TIMEOUT: Duration = Duration::from_secs(30);

/// Failure to complete one upstream exchange. DNS rcodes (including REFUSED,
/// NXDOMAIN and SERVFAIL) are not transport errors if the reply validates.
#[derive(Debug)]
pub enum UpstreamError {
    InvalidQuery(DnsError),
    UnsupportedQueryType,
    DeadlineExceeded,
    Io(io::Error),
    InvalidResponse(DnsError),
    ResponseMismatch,
    TruncatedResponse,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuery(reason) => write!(f, "invalid upstream DNS query: {reason:?}"),
            Self::UnsupportedQueryType => f.write_str("unsupported upstream DNS query type"),
            Self::DeadlineExceeded => f.write_str("upstream DNS deadline exceeded"),
            Self::Io(error) => write!(f, "upstream DNS TCP I/O: {error}"),
            Self::InvalidResponse(reason) => write!(f, "invalid upstream DNS response: {reason:?}"),
            Self::ResponseMismatch => f.write_str("upstream DNS response does not match query"),
            Self::TruncatedResponse => f.write_str("upstream DNS response set TC over TCP"),
        }
    }
}

impl std::error::Error for UpstreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// One explicitly allowed numeric TCP destination and its per-exchange limits.
#[derive(Debug)]
pub struct TcpUpstream {
    endpoint: SocketAddr,
    timeout: Duration,
    max_response_bytes: usize,
}

impl TcpUpstream {
    /// Configure a destination without opening a socket. The response cap is
    /// `17..=MAX_RESPONSE_BYTES`; `timeout` must be positive and at most
    /// [`MAX_TCP_TIMEOUT`]. The query ceiling is always `MAX_QUERY_BYTES`.
    /// Explicit unicast loopback/private addresses are allowed (e.g. a local
    /// recursive resolver); no request can supply or override the address.
    pub fn new(
        endpoint: SocketAddr,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, DnsError> {
        let ip = match endpoint.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        if endpoint.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
            || timeout.is_zero()
            || timeout > MAX_TCP_TIMEOUT
            || !(MIN_MESSAGE_BYTES..=MAX_RESPONSE_BYTES).contains(&max_response_bytes)
        {
            return Err(DnsError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            timeout,
            max_response_bytes,
        })
    }

    /// Exchange a prefix-free DNS query for a prefix-free response, with the
    /// configured timeout. See [`Self::exchange_until`] for accepted messages.
    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        self.exchange_until(query, Instant::now() + self.timeout)
    }

    /// Like [`Self::exchange`], but can take a shorter caller deadline. One
    /// monotonic deadline covers query validation, connect, all writes, all
    /// reads and response validation. Partial progress does not reset it.
    ///
    /// Accepts the crate's single-question IN query format. Transfers and
    /// transaction/control QTYPEs are unsupported. The reply must have QR set,
    /// match ID, opcode and the complete question (ASCII case-insensitive name,
    /// exact type and class), and fit one complete frame with TC clear. Record
    /// owners and section/RDLENGTH boundaries are checked; except for OPT
    /// framing, RDATA is opaque, not semantically validated.
    pub fn exchange_until(
        &self,
        query: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, UpstreamError> {
        let deadline = deadline.min(Instant::now() + self.timeout);
        remaining(deadline)?;
        let question = parse_query(query).map_err(UpstreamError::InvalidQuery)?;
        self.exchange_parsed_until(query, &question, deadline)
    }

    // Only for callers passing the result of parsing these exact bytes.
    pub(super) fn exchange_parsed_until(
        &self,
        query: &[u8],
        question: &Question,
        deadline: Instant,
    ) -> Result<Vec<u8>, UpstreamError> {
        let deadline = deadline.min(Instant::now() + self.timeout);
        remaining(deadline)?;
        if matches!(question.qtype, 0 | TYPE_OPT | 249..=254) {
            return Err(UpstreamError::UnsupportedQueryType);
        }
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        let connected = TcpStream::connect_timeout(&self.endpoint, remaining(deadline)?);
        remaining(deadline)?;
        let mut tcp = connected.map_err(socket_error)?;
        let mut bytes = framed.as_slice();
        while !bytes.is_empty() {
            let sent = io_until(deadline, |left| {
                tcp.set_write_timeout(Some(left))?;
                tcp.write(bytes)
            })?;
            if sent == 0 {
                return Err(UpstreamError::Io(io::ErrorKind::WriteZero.into()));
            }
            bytes = &bytes[sent..];
        }

        let mut prefix = [0; 2];
        read_exact_until(&mut tcp, &mut prefix, deadline)?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len > self.max_response_bytes {
            return Err(UpstreamError::InvalidResponse(DnsError::MessageTooLarge));
        }
        if len < MIN_MESSAGE_BYTES {
            return Err(UpstreamError::InvalidResponse(DnsError::Truncated));
        }
        let mut response = vec![0; len];
        read_exact_until(&mut tcp, &mut response, deadline)?;
        let validation = validate_response(&response, question);
        remaining(deadline)?;
        validation?;
        Ok(response)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, UpstreamError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(UpstreamError::DeadlineExceeded)
    } else {
        Ok(left)
    }
}

fn io_until<T>(
    deadline: Instant,
    mut operation: impl FnMut(Duration) -> io::Result<T>,
) -> Result<T, UpstreamError> {
    loop {
        let result = operation(remaining(deadline)?);
        remaining(deadline)?;
        match result {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(socket_error(error)),
        }
    }
}

fn socket_error(error: io::Error) -> UpstreamError {
    // Unix may use WouldBlock for SO_RCVTIMEO/SO_SNDTIMEO expiry.
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => UpstreamError::DeadlineExceeded,
        _ => UpstreamError::Io(error),
    }
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), UpstreamError> {
    while !bytes.is_empty() {
        let got = io_until(deadline, |left| {
            stream.set_read_timeout(Some(left))?;
            stream.read(bytes)
        })?;
        if got == 0 {
            return Err(UpstreamError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        bytes = &mut bytes[got..];
    }
    Ok(())
}

fn validate_response(msg: &[u8], query: &Question) -> Result<(), UpstreamError> {
    use UpstreamError::{InvalidResponse, ResponseMismatch, TruncatedResponse};

    let word = |offset| u16_at(msg, offset).map_err(InvalidResponse);
    let flags = word(2)?;
    if word(0)? != query.id || flags & 0x7800 != query.flags & 0x7800 {
        return Err(ResponseMismatch);
    }
    if flags & 0x8000 == 0 || flags & 0x0040 != 0 || word(4)? != 1 {
        return Err(InvalidResponse(DnsError::InvalidHeader));
    }
    let (name, end) = decode_name(msg, 12).map_err(InvalidResponse)?;
    if name != query.name || word(end)? != query.qtype || word(end + 2)? != CLASS_IN {
        return Err(ResponseMismatch);
    }
    if flags & 0x0200 != 0 {
        return Err(TruncatedResponse);
    }

    let mut pos = end + 4;
    let counts = [word(6)?, word(8)?, word(10)?];
    // Even an empty RR takes at least eleven bytes (root + fixed RR header).
    if counts.iter().map(|&n| usize::from(n)).sum::<usize>() > (msg.len() - pos) / 11 {
        return Err(InvalidResponse(DnsError::Truncated));
    }
    let mut seen_opt = false;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let owner = pos;
            let header = skip_owner(msg, owner).map_err(InvalidResponse)?;
            let rrtype = word(header)?;
            let rdlen = usize::from(word(header + 8)?);
            let data_start = header + 10;
            pos = data_start + rdlen;
            let rdata = msg
                .get(data_start..pos)
                .ok_or(InvalidResponse(DnsError::Truncated))?;
            if rrtype == TYPE_OPT {
                if section != 2
                    || seen_opt
                    || query.edns_size.is_none()
                    || msg[owner] != 0
                    || !valid_edns_options(rdata)
                {
                    return Err(InvalidResponse(DnsError::InvalidEdns));
                }
                seen_opt = true;
            }
        }
    }
    if pos != msg.len() {
        return Err(InvalidResponse(DnsError::InvalidHeader));
    }
    Ok(())
}

// Owners may compress against the question or earlier records (including
// names in opaque RDATA). Follow only backward pointers; each jump narrows
// the readable range, preventing loops and reading through the pointer that
// led there. This checks the encoded name's structure, not whether a target
// is semantically a name field within a particular RDATA type.
fn skip_owner(msg: &[u8], start: usize) -> Result<usize, DnsError> {
    const MAX_POINTERS: usize = 128;
    let mut pos = start;
    let mut limit = msg.len();
    let mut encoded_end = None;
    let mut expanded = 1; // Include the terminating root label.
    let mut pointers = 0;
    while pos < limit {
        let first = msg[pos];
        if first == 0 {
            return Ok(encoded_end.unwrap_or(pos + 1));
        }
        match first & 0xc0 {
            0 => {
                let label = usize::from(first) + 1;
                if pos + label > limit {
                    return Err(DnsError::Truncated);
                }
                expanded += label;
                if expanded > 255 {
                    return Err(DnsError::InvalidName);
                }
                pos += label;
            }
            0xc0 => {
                if pos + 2 > limit {
                    return Err(DnsError::Truncated);
                }
                let target = (usize::from(first & 0x3f) << 8) | usize::from(msg[pos + 1]);
                pointers += 1;
                if target < 12 || target >= pos || pointers > MAX_POINTERS {
                    return Err(DnsError::InvalidName);
                }
                encoded_end.get_or_insert(pos + 2);
                limit = pos;
                pos = target;
            }
            _ => return Err(DnsError::InvalidName),
        }
    }
    Err(DnsError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_QUERY_BYTES;
    use std::net::{Shutdown, TcpListener};
    use std::thread::{self, JoinHandle};

    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
    const QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x00\x00\x01\x00\x01";
    const OPT: &[u8] = &[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0];

    fn reply(rcode: u8) -> Vec<u8> {
        let mut response = QUERY.to_vec();
        response[2..4].copy_from_slice(&[0x81, 0x80 | rcode]);
        response
    }

    fn server(serve: impl FnOnce(TcpStream) + Send + 'static) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + FIXTURE_TIMEOUT;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "test client did not connect");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
            serve(stream);
        });
        (endpoint, worker)
    }

    fn expect_query(stream: &mut TcpStream) {
        let mut actual = vec![0; 2 + QUERY.len()];
        stream.read_exact(&mut actual).unwrap();
        assert_eq!(&actual[..2], &(QUERY.len() as u16).to_be_bytes());
        assert_eq!(&actual[2..], QUERY);
    }

    #[test]
    fn tcp_roundtrip_with_split_prefix_and_coalesced_frames() {
        let mut response = reply(0);
        response[13] = b'W'; // DNS question names compare case-insensitively.
        response[7] = 1;
        // A owner compressed to the question; TTL 300, RDLENGTH 4.
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
        let expected = response.clone();
        let (endpoint, worker) = server(move |mut stream| {
            expect_query(&mut stream);
            let prefix = (response.len() as u16).to_be_bytes();
            stream.write_all(&prefix[..1]).unwrap();
            let mut frames = vec![prefix[1]];
            frames.extend_from_slice(&response);
            frames.extend_from_slice(&prefix);
            frames.extend_from_slice(&response);
            stream.write_all(&frames).unwrap();
        });
        let upstream = TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, expected.len()).unwrap();
        let result = upstream.exchange(QUERY);
        worker.join().unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn rejects_bad_configuration_and_queries_before_connecting() {
        for address in ["127.0.0.1:0", "0.0.0.0:53", "[::ffff:224.0.0.1]:53"] {
            assert!(TcpUpstream::new(address.parse().unwrap(), FIXTURE_TIMEOUT, 512).is_err());
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        assert!(TcpUpstream::new(endpoint, Duration::ZERO, 512).is_err());
        assert!(TcpUpstream::new(endpoint, MAX_TCP_TIMEOUT + Duration::from_secs(1), 512).is_err());
        assert!(TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, 16).is_err());
        assert!(TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, MAX_RESPONSE_BYTES + 1).is_err());
        let upstream = TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, 512).unwrap();
        assert!(matches!(
            upstream.exchange(&[]),
            Err(UpstreamError::InvalidQuery(_))
        ));
        assert!(matches!(
            upstream.exchange(&vec![0; MAX_QUERY_BYTES + 1]),
            Err(UpstreamError::InvalidQuery(DnsError::MessageTooLarge))
        ));
        let mut query = QUERY.to_vec();
        let end = query.len();
        query[end - 4..end - 2].copy_from_slice(&252u16.to_be_bytes());
        assert!(matches!(
            upstream.exchange(&query),
            Err(UpstreamError::UnsupportedQueryType)
        ));
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn correlation_checks_header_and_complete_question() {
        let q = parse_query(QUERY).unwrap();
        let response = reply(0);
        for (offset, bit) in [
            (0, 1),
            (2, 8),
            (13, 1),
            (QUERY.len() - 3, 1),
            (QUERY.len() - 1, 1),
        ] {
            let mut bad = response.clone();
            bad[offset] ^= bit;
            assert!(matches!(
                validate_response(&bad, &q),
                Err(UpstreamError::ResponseMismatch)
            ));
        }
        for (offset, bit) in [(2, 0x80), (3, 0x40), (5, 1)] {
            let mut bad = response.clone();
            bad[offset] ^= bit;
            assert!(matches!(
                validate_response(&bad, &q),
                Err(UpstreamError::InvalidResponse(DnsError::InvalidHeader))
            ));
        }
        let mut bad = response;
        bad[2] |= 2;
        assert!(matches!(
            validate_response(&bad, &q),
            Err(UpstreamError::TruncatedResponse)
        ));
    }

    #[test]
    fn validates_sections_and_opt_and_preserves_dns_rcodes() {
        let plain = parse_query(QUERY).unwrap();
        for code in [0, 2, 3, 5] {
            validate_response(&reply(code), &plain).unwrap();
        }
        let mut bad = reply(0);
        bad.push(0);
        assert!(validate_response(&bad, &plain).is_err());
        bad[7] = 1;
        assert!(validate_response(&bad, &plain).is_err());
        let mut bad = reply(0);
        bad[7] = 1;
        // A record advertises four bytes, but none follow.
        bad.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
        assert!(validate_response(&bad, &plain).is_err());
        bad.extend_from_slice(&[192, 0, 2, 1]);
        validate_response(&bad, &plain).unwrap();
        bad[QUERY.len() + 1] = QUERY.len() as u8; // Owner pointer to itself.
        assert!(validate_response(&bad, &plain).is_err());

        let mut with_edns = QUERY.to_vec();
        with_edns[11] = 1;
        with_edns.extend_from_slice(OPT);
        let edns = parse_query(&with_edns).unwrap();
        let mut response = reply(0);
        response[11] = 1;
        response.extend_from_slice(OPT);
        validate_response(&response, &edns).unwrap();
        assert!(validate_response(&response, &plain).is_err());
        response[11] = 2;
        response.extend_from_slice(OPT);
        assert!(validate_response(&response, &edns).is_err());
    }

    #[test]
    fn rejects_oversize_short_and_incomplete_tcp_frames() {
        for length in [0u16, 513, u16::MAX] {
            let (endpoint, worker) = server(move |mut stream| {
                expect_query(&mut stream);
                stream.write_all(&length.to_be_bytes()).unwrap();
                // Do not send a body or half-close: the prefix alone must
                // cause rejection, without first waiting for the body.
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            });
            let upstream = TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, 512).unwrap();
            let expected = if length == 0 {
                DnsError::Truncated
            } else {
                DnsError::MessageTooLarge
            };
            let result = upstream.exchange(QUERY);
            worker.join().unwrap();
            assert!(
                matches!(result, Err(UpstreamError::InvalidResponse(reason)) if reason == expected)
            );
        }
        let (endpoint, worker) = server(|mut stream| {
            expect_query(&mut stream);
            stream.write_all(&[0, QUERY.len() as u8, 0x12]).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let upstream = TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, 512).unwrap();
        let result = upstream.exchange(QUERY);
        worker.join().unwrap();
        assert!(
            matches!(result, Err(UpstreamError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn caller_deadline_bounds_partial_response_and_already_expired_skips_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let upstream =
            TcpUpstream::new(listener.local_addr().unwrap(), FIXTURE_TIMEOUT, 512).unwrap();
        assert!(matches!(
            upstream.exchange_until(QUERY, Instant::now()),
            Err(UpstreamError::DeadlineExceeded)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let (endpoint, worker) = server(|mut stream| {
            expect_query(&mut stream);
            stream.write_all(&[0, QUERY.len() as u8, 0x12]).unwrap();
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        });
        let upstream = TcpUpstream::new(endpoint, FIXTURE_TIMEOUT, 512).unwrap();
        let result = upstream.exchange_until(QUERY, Instant::now() + Duration::from_millis(500));
        worker.join().unwrap();
        assert!(matches!(result, Err(UpstreamError::DeadlineExceeded)));
    }

    #[test]
    fn io_never_accepts_progress_past_the_original_deadline() {
        let deadline = Instant::now() + Duration::from_millis(50);
        let result = io_until(deadline, |_| {
            thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Ok(1)
        });
        assert!(matches!(result, Err(UpstreamError::DeadlineExceeded)));
    }
}
