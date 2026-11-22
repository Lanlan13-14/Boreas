//! Explicit DNS over authenticated TCP: HTTPS/1.1 POST (DoH) or TLS with
//! RFC 7858 length framing. No plaintext mode, bootstrap lookup, or retry.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use openssl::{
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder, verify::X509CheckFlags},
};

use crate::{
    MAX_RESPONSE_BYTES, Question,
    upstream::{MIN_MESSAGE_BYTES, UpstreamError, TcpUpstream, validate_response},
};

const MAX_HEADERS: usize = 8192;
const MAX_HEADER_FIELDS: usize = 64;
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_CA_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum SecureTransport {
    /// The fixed origin-form path; never taken from a query or redirect.
    Https { path: String },
    /// DNS length framing inside TLS (not ordinary port-53 plaintext).
    TlsTcp,
}

pub struct SecureUpstream {
    endpoint: SocketAddr,
    name: String,
    request_header: Option<String>,
    tls: SslContext,
}

impl SecureUpstream {
    /// Only the supplied PEM authorities are trusted. `name` is an ASCII DNS
    /// name for SNI and certificate SAN matching, not a bootstrap hostname.
    pub fn new(
        endpoint: SocketAddr,
        name: String,
        ca_pem: &[u8],
        transport: SecureTransport,
    ) -> Result<Self, &'static str> {
        TcpUpstream::new(endpoint, EXCHANGE_TIMEOUT, MAX_RESPONSE_BYTES)
            .map_err(|_| "invalid numeric DNS upstream endpoint")?;
        if name.len() > 253
            || !name.contains('.')
            || name.parse::<std::net::IpAddr>().is_ok()
            || !name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("invalid DNS upstream certificate name");
        }
        let request_header = match transport {
            SecureTransport::TlsTcp => None,
            SecureTransport::Https { path } => {
                // An intentionally narrow origin-form endpoint, no parameters,
                // URI escaping, credentials, authority or fragment.
                if path.len() > 512
                    || !path.starts_with('/')
                    || path.starts_with("//")
                    || !path.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~')
                    })
                {
                    return Err("invalid DoH origin path");
                }
                Some(format!(
                    "POST {path} HTTP/1.1\r\nHost: {name}:{}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nConnection: close\r\nContent-Length: ",
                    endpoint.port()
                ))
            }
        };
        if ca_pem.is_empty() || ca_pem.len() > MAX_CA_BYTES {
            return Err("invalid DNS upstream CA bundle size");
        }
        let certs = X509::stack_from_pem(ca_pem).map_err(|_| "invalid DNS upstream CA PEM")?;
        if !(1..=16).contains(&certs.len()) {
            return Err("DNS upstream CA bundle must have 1–16 certificates");
        }
        let context_error = |_| "cannot configure authenticated DNS upstream TLS";
        let mut store = X509StoreBuilder::new().map_err(context_error)?;
        for cert in certs {
            store.add_cert(cert).map_err(context_error)?;
        }
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).map_err(context_error)?;
        builder.set_cert_store(store.build());
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_verify_depth(4);
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(context_error)?;
        if request_header.is_some() {
            builder.set_alpn_protos(b"\x08http/1.1").map_err(context_error)?;
        }
        Ok(Self { endpoint, name, request_header, tls: builder.build() })
    }

    pub(crate) fn exchange(
        &self,
        query: &[u8],
        question: &Question,
        deadline: Instant,
        current: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, UpstreamError> {
        let result = self.exchange_io(query, deadline, current);
        time_left(deadline, current).map_err(UpstreamError::Io)?;
        let reply = result.map_err(UpstreamError::Io)?;
        validate_response(&reply, question)?;
        time_left(deadline, current).map_err(UpstreamError::Io)?;
        Ok(reply)
    }

    fn exchange_io(
        &self,
        query: &[u8],
        deadline: Instant,
        current: &dyn Fn() -> bool,
    ) -> io::Result<Vec<u8>> {
        let socket = TcpStream::connect_timeout(&self.endpoint, time_left(deadline, current)?)?;
        let socket = DeadlineStream { socket, deadline, current };
        let mut ssl = Ssl::new(&self.tls).map_err(io::Error::other)?;
        ssl.set_hostname(&self.name).map_err(io::Error::other)?;
        ssl.param_mut().set_hostflags(
            X509CheckFlags::NO_PARTIAL_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT,
        );
        ssl.param_mut().set_host(&self.name).map_err(io::Error::other)?;
        // No application bytes (including DNS) before authentication completes.
        let mut tls = ssl.connect(socket).map_err(|_| invalid("upstream TLS handshake rejected"))?;
        time_left(deadline, current)?;
        if let Some(header) = &self.request_header {
            if tls.ssl().selected_alpn_protocol().is_some_and(|p| p != b"http/1.1") {
                return Err(invalid("unsupported upstream ALPN"));
            }
            write!(tls, "{header}{}\r\n\r\n", query.len())?;
            tls.write_all(query)?;
            read_http(BufReader::with_capacity(2048, tls))
        } else {
            tls.write_all(&(query.len() as u16).to_be_bytes())?;
            tls.write_all(query)?;
            let mut prefix = [0; 2];
            tls.read_exact(&mut prefix)?;
            read_body(tls, usize::from(u16::from_be_bytes(prefix)))
        }
    }
}

fn time_left(deadline: Instant, current: &dyn Fn() -> bool) -> io::Result<Duration> {
    if !current() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { Err(io::ErrorKind::TimedOut.into()) } else { Ok(left) }
}

struct DeadlineStream<'a> {
    socket: TcpStream,
    deadline: Instant,
    current: &'a dyn Fn() -> bool,
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(time_left(self.deadline, self.current)?))?;
        self.socket.read(buf)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(time_left(self.deadline, self.current)?))?;
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        time_left(self.deadline, self.current)?;
        self.socket.flush()
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn read_body(mut reader: impl Read, length: usize) -> io::Result<Vec<u8>> {
    if !(MIN_MESSAGE_BYTES..=MAX_RESPONSE_BYTES).contains(&length) {
        return Err(invalid("invalid upstream DNS body length"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

fn read_http(mut reader: impl BufRead) -> io::Result<Vec<u8>> {
    let mut line = String::new();
    let mut remaining = MAX_HEADERS;
    let mut next_line = |reader: &mut _, line: &mut String| -> io::Result<()> {
        line.clear();
        let count = Read::take(reader, remaining as u64).read_line(line)?;
        remaining -= count;
        if !line.ends_with("\r\n") {
            return Err(invalid("invalid or oversized DoH header"));
        }
        line.truncate(line.len() - 2);
        if !line.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b)) {
            return Err(invalid("invalid DoH header characters"));
        }
        Ok(())
    };
    next_line(&mut reader, &mut line)?;
    if !line.starts_with("HTTP/1.1 200 ") && line != "HTTP/1.1 200" {
        return Err(invalid("DoH did not return HTTP/1.1 200"));
    }
    let mut length = None;
    let mut dns_media = false;
    for _ in 0..=MAX_HEADER_FIELDS {
        next_line(&mut reader, &mut line)?;
        if line.is_empty() {
            if !dns_media {
                return Err(invalid("missing DoH media type"));
            }
            return read_body(reader, length.ok_or_else(|| invalid("missing DoH length"))?);
        }
        let (key, value) = line.split_once(':').ok_or_else(|| invalid("invalid DoH header"))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(invalid("invalid DoH field name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if key.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("ambiguous DoH length"));
            }
            length = Some(value.parse().map_err(|_| invalid("invalid DoH length"))?);
        } else if key.eq_ignore_ascii_case("Content-Type") {
            if dns_media || !value.eq_ignore_ascii_case("application/dns-message") {
                return Err(invalid("invalid DoH media type"));
            }
            dns_media = true;
        } else if key.eq_ignore_ascii_case("Transfer-Encoding")
            || key.eq_ignore_ascii_case("Content-Encoding")
        {
            return Err(invalid("unsupported DoH encoding"));
        }
    }
    Err(invalid("too many DoH header fields"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_rejects_noncanonical_framing_without_retry() {
        let body = [0; MIN_MESSAGE_BYTES];
        let valid = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n";
        let read = |headers: &str| read_http([headers.as_bytes(), &body].concat().as_slice());
        assert_eq!(read(&format!("{valid}\r\n")).unwrap(), body);
        for header in ["Content-Length: 17", "Transfer-Encoding: chunked", "Content-Encoding: gzip", "Content-Type: application/dns-message", " Bad: field"] {
            assert!(read(&format!("{valid}{header}\r\n\r\n")).is_err());
        }
        for code in [204, 301, 400, 503] {
            assert!(read(&format!("HTTP/1.1 {code} bad\r\n\r\n")).is_err());
        }
        assert!(read(&format!("{valid}X: {}\r\n\r\n", "a".repeat(MAX_HEADERS))).is_err());
        assert!(read_http(format!("{valid}\r\n").as_bytes()).is_err());
    }
}
