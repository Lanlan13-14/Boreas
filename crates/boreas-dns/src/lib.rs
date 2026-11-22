//! Bounded authoritative DNS wire handling and explicit TCP upstream transport.
//!
//! The authoritative packet path has three layers and uses no OS sockets:
//!
//! * [`packet`] parses complete IPv4/IPv6 UDP packets and builds replies for the
//!   existing authoritative resolver;
//! * [`tcp`] is a real smoltcp TCP DNS server driven by the caller's
//!   `Interface`/`SocketSet`;
//! * [`packet_runtime`] owns one bounded medium-IP `Device`, an `Interface`, a
//!   `SocketSet`, and that TCP server, accepting complete input IP packets and
//!   producing complete output IP packets through bounded queues. DNS VIPs are
//!   interface addresses only; no OS socket is bound.
//!
//! `packet_runtime` is a packet model, not an authentication authority. Its
//! [`packet_runtime::AuthenticatedSourceMap`] must be implemented by the trusted
//! Tunnel/Overlay consumer after peer authentication; a source IP field or a
//! caller-supplied boolean is never accepted as identity.
//!
//! Negative answers omit SOA authority records, so negative-cache TTL behavior
//! is not implemented. [`SourceAuthorization`] alone is an address allowlist, not
//! peer authentication. A response that would exceed the caller byte cap is
//! [`DnsError::TruncatedWouldExceed`]. [`AuthoritativeDns::respond_udp`] and
//! [`AuthoritativeDns::respond_tcp`] never set TC and never return a partial
//! RRset. The private UDP dispatcher can explicitly emit TC with an empty
//! answer section. RD is echoed and is not recursion: RA stays clear. QCLASS
//! other than IN is [`DnsError::InvalidQuestion`] (FORMERR); no REFUSED
//! message is built.
//! [`Zone::refuse_name`] is an exact-match REFUSED list and wins over addresses.
//!
//! [`dispatch`] composes the authority with an optional blocking plaintext
//! DNS-over-TCP [`upstream`]. The private packet path uses only the private
//! branch; it cannot invoke that upstream.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod dispatch;
pub mod packet;
pub mod packet_runtime;
pub mod tcp;
pub mod upstream;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Hard limit applied before parsing any incoming DNS payload.
pub const MAX_QUERY_BYTES: usize = 4096;
/// Hard limit for any response, independent of EDNS advertisements.
pub const MAX_RESPONSE_BYTES: usize = 4096;
/// This implementation accepts one question only; multiple-query DNS messages
/// are rejected rather than partially answered.
pub const MAX_QUESTIONS: usize = 1;
const MAX_NAME_LABELS: usize = 127;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const OPT_HEADER_BYTES: usize = 11;
const CLASS_IN: u16 = 1;

/// Reason a bounded DNS message could not be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    MessageTooLarge,
    Truncated,
    /// The only honest response would exceed the caller byte cap. No partial
    /// answer is returned. UDP TC, when wanted, must be requested explicitly
    /// via [`AuthoritativeDns::udp_truncate`].
    TruncatedWouldExceed,
    InvalidHeader,
    UnsupportedOpcode,
    /// FORMERR: QCLASS was not IN, the question was cut short, or bytes
    /// trailed a single question. No response message is produced. This is not
    /// REFUSED (rcode 5), which is reserved for names outside the zone and for
    /// names listed by [`Zone::refuse_name`].
    InvalidQuestion,
    InvalidName,
    InvalidEdns,
    InvalidConfiguration,
}

/// A configured authoritative zone name and its records.
///
/// Names use ASCII DNS presentation form, with an optional trailing dot. All
/// lookups are case-insensitive. Non-ASCII/IDNA conversion is deliberately the
/// caller's responsibility.
#[derive(Clone, Debug)]
pub struct Zone {
    origin: String,
    records: BTreeMap<String, Vec<IpAddr>>,
    /// Exact-match names that are answered REFUSED even though they are inside
    /// the zone. This is not a policy engine and does not match wildcards.
    refused: BTreeSet<String>,
}

impl Zone {
    /// Create a zone. `origin` must be a valid DNS name (root is not supported).
    pub fn new(origin: &str) -> Result<Self, DnsError> {
        let origin = normalize_name(origin).ok_or(DnsError::InvalidConfiguration)?;
        if origin.is_empty() {
            return Err(DnsError::InvalidConfiguration);
        }
        Ok(Self {
            origin,
            records: BTreeMap::new(),
            refused: BTreeSet::new(),
        })
    }

    /// Refuse this exact owner on every QTYPE. The name must be inside the zone.
    /// Addresses already stored for it are ignored while it remains refused.
    pub fn refuse_name(&mut self, owner: &str) -> Result<(), DnsError> {
        let name = normalize_name(owner).ok_or(DnsError::InvalidConfiguration)?;
        if !is_in_zone(&name, &self.origin) {
            return Err(DnsError::InvalidConfiguration);
        }
        self.refused.insert(name);
        Ok(())
    }

    /// Add an address to an owner name within this zone. Duplicate addresses
    /// are ignored; names outside the configured zone are rejected.
    pub fn add_address(&mut self, owner: &str, address: IpAddr) -> Result<(), DnsError> {
        let name = normalize_name(owner).ok_or(DnsError::InvalidConfiguration)?;
        if !is_in_zone(&name, &self.origin) {
            return Err(DnsError::InvalidConfiguration);
        }
        let values = self.records.entry(name).or_default();
        if !values.contains(&address) {
            values.push(address);
        }
        Ok(())
    }

    /// Configured origin in canonical lowercase form without a trailing dot.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Explicit source-policy input. A packet source must exactly match one of
/// these configured addresses before any response is synthesized. This is only
/// an address allowlist, not cryptographic identity authentication: the caller
/// must bind addresses to authenticated Overlay peers and enforce packet-source
/// integrity before invoking this API.
#[derive(Clone, Debug, Default)]
pub struct SourceAuthorization {
    authorized: Vec<IpAddr>,
}

impl SourceAuthorization {
    pub fn new<I: IntoIterator<Item = IpAddr>>(sources: I) -> Self {
        let mut authorized = Vec::new();
        for source in sources {
            if !authorized.contains(&source) {
                authorized.push(source);
            }
        }
        Self { authorized }
    }

    pub fn permits(&self, source: IpAddr) -> bool {
        self.authorized.contains(&source)
    }
}

/// Immutable resolver configuration.
#[derive(Clone, Debug)]
pub struct AuthoritativeDns {
    zone: Zone,
    sources: SourceAuthorization,
    max_response_bytes: usize,
}

impl AuthoritativeDns {
    /// Construct a non-recursive authority with an explicit source allowlist.
    /// The response ceiling must fit a DNS header and question and is capped at
    /// the crate hard maximum.
    pub fn new(
        zone: Zone,
        sources: SourceAuthorization,
        max_response_bytes: usize,
    ) -> Result<Self, DnsError> {
        if !(12..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(DnsError::InvalidConfiguration);
        }
        Ok(Self {
            zone,
            sources,
            max_response_bytes,
        })
    }

    fn name_exists(&self, name: &str) -> bool {
        name == self.zone.origin
            || self.zone.records.contains_key(name)
            || self.zone.records.keys().any(|owner| {
                owner
                    .strip_suffix(name)
                    .is_some_and(|prefix| prefix.ends_with('.'))
            })
    }

    /// Handle one length-prefix-stripped TCP DNS query. TCP has no UDP datagram
    /// payload ceiling, so its response may use the configured DNS message cap
    /// (at most 4096 bytes) rather than inheriting UDP's 512-byte default or
    /// EDNS datagram size. Authorization and wire parsing remain shared.
    pub fn respond_tcp(&self, source: IpAddr, query: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        self.respond(source, query, false)
    }

    /// Handle one DNS-over-UDP payload from an authorized source address.
    /// Unauthorized sources receive `Ok(None)`. If the whole answer does not
    /// fit, the response is an error; this method does not insert TC itself.
    pub fn respond_udp(&self, source: IpAddr, query: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        self.respond(source, query, true)
    }

    fn respond(
        &self,
        source: IpAddr,
        query: &[u8],
        datagram: bool,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        if !self.sources.permits(source) {
            return Ok(None);
        }
        let question = parse_query(query)?;
        self.respond_parsed(query, &question, datagram, MAX_RESPONSE_BYTES)
            .map(Some)
    }

    // Only for callers that already checked sources and parsed this query.
    fn respond_parsed(
        &self,
        query: &[u8],
        question: &Question,
        datagram: bool,
        ceiling: usize,
    ) -> Result<Vec<u8>, DnsError> {
        let limit = if datagram {
            self.udp_limit(question, ceiling)
        } else {
            self.max_response_bytes.min(ceiling)
        };
        let authoritative = is_in_zone(&question.name, &self.zone.origin);
        let refused = self.zone.refused.contains(&question.name);
        let (rcode, addresses) = if !authoritative || refused {
            // REFUSED: outside the zone, or an exact refused-name hit.
            (5, &[][..])
        } else if let Some(addresses) = self.zone.records.get(&question.name) {
            (0, addresses.as_slice())
        } else if self.name_exists(&question.name) {
            // Existing apex or empty non-terminal with no RRset: NODATA.
            (0, &[][..])
        } else {
            (3, &[][..]) // NXDOMAIN
        };
        build_response(
            query,
            question,
            rcode,
            addresses,
            limit,
            question.edns_size.is_some(),
            authoritative && !refused,
        )
    }

    fn udp_limit(&self, question: &Question, ceiling: usize) -> usize {
        let advertised = question
            .edns_size
            .unwrap_or(512)
            .clamp(512, MAX_RESPONSE_BYTES);
        self.max_response_bytes.min(ceiling).min(advertised)
    }

    /// UDP TC indication only. Copies the query id, echoes RD (never sets RA),
    /// keeps the whole question, sets TC, and leaves the answer section empty.
    /// This does not invent a shortened RRset. If the header plus question
    /// cannot fit in `max`, returns [`DnsError::TruncatedWouldExceed`] instead
    /// of dropping the question. `max` must be between 12 and 4096.
    pub fn udp_truncate(&self, query: &[u8], max: usize) -> Result<Vec<u8>, DnsError> {
        if !(12..=MAX_RESPONSE_BYTES).contains(&max) {
            return Err(DnsError::InvalidConfiguration);
        }
        truncate_parsed(query, &parse_query(query)?, max, false)
    }
}

fn truncate_parsed(
    query: &[u8],
    question: &Question,
    max: usize,
    include_opt: bool,
) -> Result<Vec<u8>, DnsError> {
    let required = question.end + if include_opt { OPT_HEADER_BYTES } else { 0 };
    if required > max {
        return Err(DnsError::TruncatedWouldExceed);
    }
    let mut out = Vec::with_capacity(required);
    out.extend_from_slice(&question.id.to_be_bytes());
    // QR | TC | echoed RD. AA and RA stay clear: this is not an answer.
    let flags = 0x8200 | (question.flags & 0x0100);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(include_opt).to_be_bytes());
    out.extend_from_slice(&query[12..question.end]);
    if include_opt {
        write_opt(&mut out, max);
    }
    Ok(out)
}

#[derive(Debug)]
struct Question {
    id: u16,
    flags: u16,
    name: String,
    qtype: u16,
    end: usize,
    edns_size: Option<usize>,
}

/// Matching key for a private DNS request and the question echoed in its reply.
/// This does not validate or authenticate answer RRs; the transport must bind
/// the authenticated responder and the application must still match replies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateQuestion {
    id: u16,
    name: String,
    qtype: u16,
}

impl PrivateQuestion {
    /// Apply the responder's query parser and exact label-boundary rule.
    pub fn query(message: &[u8], origin: &str) -> Option<Self> {
        let Question {
            id, name, qtype, ..
        } = parse_query(message).ok()?;
        is_in_zone(&name, origin).then_some(Self { id, name, qtype })
    }

    /// Require one IN question in a private-only DNS response.
    pub fn response(message: &[u8], origin: &str) -> Option<Self> {
        if message.len() > MAX_RESPONSE_BYTES
            || u16_at(message, 2).map(|flags| flags & 0xf8c0) != Ok(0x8000)
            || u16_at(message, 4) != Ok(1)
        {
            return None;
        }
        let (name, end) = decode_name(message, 12).ok()?;
        if !is_in_zone(&name, origin) || u16_at(message, end + 2) != Ok(CLASS_IN) {
            return None;
        }
        Some(Self {
            id: u16_at(message, 0).ok()?,
            name,
            qtype: u16_at(message, end).ok()?,
        })
    }
}

fn parse_query(msg: &[u8]) -> Result<Question, DnsError> {
    if msg.len() > MAX_QUERY_BYTES {
        return Err(DnsError::MessageTooLarge);
    }
    if msg.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16_at(msg, 0)?;
    let flags = u16_at(msg, 2)?;
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)?;
    let ns = u16_at(msg, 8)?;
    let ar = u16_at(msg, 10)?;
    // Accept only RD and CD request bits. Requests must not carry response-only
    // flags, a nonzero opcode, or any reserved/Z bits.
    if flags & !0x0110 != 0 || qd != MAX_QUESTIONS as u16 || an != 0 || ns != 0 || ar > 1 {
        return Err(DnsError::InvalidHeader);
    }
    let (name, after_name) = decode_name(msg, 12)?;
    let qtype = u16_at(msg, after_name)?;
    let qclass = u16_at(msg, after_name + 2)?;
    if qclass != CLASS_IN {
        return Err(DnsError::InvalidQuestion);
    }
    let end = after_name + 4;
    let edns_size = if ar == 1 {
        if end + OPT_HEADER_BYTES > msg.len() {
            return Err(DnsError::Truncated);
        }
        if msg[end] != 0 || u16_at(msg, end + 1)? != TYPE_OPT {
            return Err(DnsError::InvalidEdns);
        }
        let payload = usize::from(u16_at(msg, end + 3)?);
        let ttl = u32_at(msg, end + 5)?;
        let rdlen = usize::from(u16_at(msg, end + 9)?);
        let rstart = end + OPT_HEADER_BYTES;
        let rend = rstart.checked_add(rdlen).ok_or(DnsError::InvalidEdns)?;
        // Extended RCODE and EDNS version must be zero. Only the DO bit is
        // meaningful in the low flags word; reserved bits fail closed.
        if rend != msg.len()
            || ttl >> 24 != 0
            || ttl & 0x00ff_7fff != 0
            || !valid_edns_options(&msg[rstart..rend])
        {
            return Err(DnsError::InvalidEdns);
        }
        Some(payload)
    } else {
        if end != msg.len() {
            return Err(DnsError::InvalidQuestion);
        }
        None
    };
    Ok(Question {
        id,
        flags,
        name,
        qtype,
        end,
        edns_size,
    })
}

fn valid_edns_options(mut data: &[u8]) -> bool {
    let mut count = 0usize;
    while !data.is_empty() {
        if data.len() < 4 || count >= 64 {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        if len > data.len() - 4 {
            return false;
        }
        data = &data[4 + len..];
        count += 1;
    }
    true
}

fn decode_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut expanded = 1usize;
    loop {
        let first = *msg.get(pos).ok_or(DnsError::Truncated)?;
        if first & 0xc0 == 0xc0 {
            // In the accepted one-question format there is no earlier owner
            // name a query-name pointer could validly reference. Rejecting
            // pointers here safely narrows compression support rather than
            // interpreting arbitrary header/question bytes as labels.
            return Err(DnsError::InvalidName);
        }
        if first & 0xc0 != 0 {
            return Err(DnsError::InvalidName);
        }
        pos += 1;
        if first == 0 {
            break;
        }
        let len = usize::from(first);
        if len > 63
            || pos
                .checked_add(len)
                .filter(|end| *end <= msg.len())
                .is_none()
        {
            return Err(DnsError::Truncated);
        }
        if labels.len() >= MAX_NAME_LABELS {
            return Err(DnsError::InvalidName);
        }
        expanded = expanded.checked_add(len + 1).ok_or(DnsError::InvalidName)?;
        if expanded > 255 {
            return Err(DnsError::InvalidName);
        }
        let raw = &msg[pos..pos + len];
        if !raw.is_ascii()
            || raw
                .iter()
                .any(|b| *b <= 0x20 || *b >= 0x7f || *b == b'.' || *b == b'\\')
        {
            return Err(DnsError::InvalidName);
        }
        let label = std::str::from_utf8(raw).map_err(|_| DnsError::InvalidName)?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }
    Ok((labels.join("."), pos))
}

fn build_response(
    query: &[u8],
    q: &Question,
    rcode: u16,
    addresses: &[IpAddr],
    limit: usize,
    include_opt: bool,
    authoritative: bool,
) -> Result<Vec<u8>, DnsError> {
    let base_len = q.end + if include_opt { OPT_HEADER_BYTES } else { 0 };
    let budget = limit
        .checked_sub(base_len)
        .ok_or(DnsError::TruncatedWouldExceed)?;
    let rdata_len: u16 = if q.qtype == TYPE_AAAA { 16 } else { 4 };
    let rr_len = 12 + usize::from(rdata_len);
    let max_answers = budget / rr_len;
    let answers = || {
        addresses.iter().filter(|ip| match q.qtype {
            TYPE_A => ip.is_ipv4(),
            TYPE_AAAA => ip.is_ipv6(),
            _ => false,
        })
    };
    let count = answers().take(max_answers + 1).count();
    if count > max_answers {
        return Err(DnsError::TruncatedWouldExceed);
    }
    let mut out = Vec::with_capacity(base_len + count * rr_len);
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR, optional AA, echo RD/CD; RA stays clear.
    let flags = 0x8000 | (if authoritative { 0x0400 } else { 0 }) | (q.flags & 0x0110) | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(count as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(include_opt).to_be_bytes());
    out.extend_from_slice(&query[12..q.end]);
    for address in answers() {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&rdata_len.to_be_bytes());
        match address {
            IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
        }
    }
    if include_opt {
        write_opt(&mut out, limit);
    }
    Ok(out)
}

fn write_opt(out: &mut Vec<u8>, limit: usize) {
    out.extend_from_slice(&[0, 0, TYPE_OPT as u8]);
    // Advertise the effective response budget; ext-RCODE, version and flags are zero.
    out.extend_from_slice(&(limit as u16).to_be_bytes());
    out.extend_from_slice(&[0; 6]);
}

fn normalize_name(name: &str) -> Option<String> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Some(String::new());
    }
    if trimmed.len() > 253 || !trimmed.is_ascii() {
        return None;
    }
    let mut total = 1usize;
    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label
                .bytes()
                .any(|b| b <= 0x20 || b >= 0x7f || b == b'/' || b == b'\\')
        {
            return None;
        }
        total = total.checked_add(label.len() + 1)?;
    }
    if total > 255 {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn is_in_zone(name: &str, origin: &str) -> bool {
    name == origin
        || name
            .strip_suffix(origin)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
fn u16_at(data: &[u8], at: usize) -> Result<u16, DnsError> {
    let bytes = data.get(at..at + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn u32_at(data: &[u8], at: usize) -> Result<u32, DnsError> {
    let bytes = data.get(at..at + 4).ok_or(DnsError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// TCP DNS is intentionally not implemented. Do not interpret TCP segments as DNS messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDnsSupport {
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    fn base_query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }
    fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
        let mut n = Vec::new();
        for l in labels {
            n.push(l.len() as u8);
            n.extend_from_slice(l);
        }
        n.push(0);
        n
    }
    fn fixture() -> AuthoritativeDns {
        let mut z = Zone::new("corp.example.").unwrap();
        z.add_address(
            "Host.Corp.Example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        )
        .unwrap();
        z.add_address(
            "host.corp.example",
            IpAddr::V6("2001:db8::10".parse().unwrap()),
        )
        .unwrap();
        AuthoritativeDns::new(z, SourceAuthorization::new([CLIENT]), 1232).unwrap()
    }
    fn response(query: &[u8]) -> Vec<u8> {
        fixture().respond_udp(CLIENT, query).unwrap().unwrap()
    }
    fn rcode(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[2], r[3]]) & 15
    }

    #[test]
    fn a_and_aaaa_records_are_authoritative() {
        let a = response(&base_query(&wire_name(&[b"HOST", b"corp", b"example"]), 1));
        assert_eq!(rcode(&a), 0);
        assert_eq!(u16_at(&a, 6).unwrap(), 1);
        assert_eq!(&a[a.len() - 4..], &[192, 0, 2, 10]);
        assert_ne!(a[2] & 4, 0);
        let aaaa = response(&base_query(&wire_name(&[b"host", b"corp", b"example"]), 28));
        assert_eq!(rcode(&aaaa), 0);
        assert_eq!(u16_at(&aaaa, 6).unwrap(), 1);
        assert_eq!(
            &aaaa[aaaa.len() - 16..],
            &"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets()
        );
    }
    #[test]
    fn absent_family_and_unknown_type_are_nodata() {
        let mut z = Zone::new("corp.example").unwrap();
        z.add_address("v4.corp.example", CLIENT).unwrap();
        let svc = AuthoritativeDns::new(z, SourceAuthorization::new([CLIENT]), 1232).unwrap();
        for qtype in [28, 65280] {
            let r = svc
                .respond_udp(
                    CLIENT,
                    &base_query(&wire_name(&[b"v4", b"corp", b"example"]), qtype),
                )
                .unwrap()
                .unwrap();
            assert_eq!(rcode(&r), 0);
            assert_eq!(u16_at(&r, 6).unwrap(), 0);
        }
    }
    #[test]
    fn zone_apex_and_empty_nonterminal_are_nodata_not_nxdomain() {
        let svc = fixture();
        let apex = svc
            .respond_udp(CLIENT, &base_query(&wire_name(&[b"corp", b"example"]), 28))
            .unwrap()
            .unwrap();
        assert_eq!(rcode(&apex), 0);
        assert_eq!(u16_at(&apex, 6).unwrap(), 0);
        let mut zone = svc.zone.clone();
        zone.add_address("leaf.branch.corp.example", CLIENT)
            .unwrap();
        let svc = AuthoritativeDns::new(zone, SourceAuthorization::new([CLIENT]), 1232).unwrap();
        let ent = svc
            .respond_udp(
                CLIENT,
                &base_query(&wire_name(&[b"branch", b"corp", b"example"]), 1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(rcode(&ent), 0);
        assert_eq!(u16_at(&ent, 6).unwrap(), 0);
    }
    #[test]
    fn missing_name_is_nxdomain_and_external_is_refused() {
        let missing = response(&base_query(
            &wire_name(&[b"missing", b"corp", b"example"]),
            1,
        ));
        assert_eq!(rcode(&missing), 3);
        let external = response(&base_query(&wire_name(&[b"example", b"net"]), 1));
        assert_eq!(rcode(&external), 5);
        assert_eq!(external[2] & 4, 0);
    }
    #[test]
    fn unauthorized_source_gets_no_response_even_for_malformed_packet() {
        assert_eq!(
            fixture()
                .respond_udp("192.0.2.200".parse().unwrap(), &[0; 1])
                .unwrap(),
            None
        );
    }
    #[test]
    fn rejects_short_headers_counts_and_response_packets() {
        for q in [&[][..], &[0; 11][..]] {
            assert_eq!(fixture().respond_udp(CLIENT, q), Err(DnsError::Truncated));
        }
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        q[5] = 0;
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidHeader)
        );
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        q[2] = 0x80;
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidHeader)
        );
        assert_eq!(
            fixture().respond_udp(CLIENT, &vec![0; MAX_QUERY_BYTES + 1]),
            Err(DnsError::MessageTooLarge)
        );
    }
    #[test]
    fn validates_labels_pointers_and_bounds() {
        let mut q = base_query(&[0x40, 0], 1);
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidName)
        );
        q = base_query(&[0xc0, 0x0c], 1);
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidName)
        );
        q = base_query(&[0xc0, 0xff], 1);
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidName)
        );
        q = base_query(&[1, b'\\', 0], 1);
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidName)
        );
        q = base_query(&[0x03, b'a', b'b'], 1);
        assert!(fixture().respond_udp(CLIENT, &q).is_err());
        let long = [b'a'; 63];
        let mut labels = Vec::new();
        for _ in 0..4 {
            labels.push(&long[..]);
        }
        assert!(
            fixture()
                .respond_udp(CLIENT, &base_query(&wire_name(&labels), 1))
                .is_err()
        );
    }
    #[test]
    fn rejects_multiple_questions_non_in_and_trailing_garbage() {
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        q[5] = 2;
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidHeader)
        );
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        let last = q.len() - 1;
        q[last] = 3;
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidQuestion)
        );
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        q.push(0);
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidQuestion)
        );
    }
    #[test]
    fn edns_clamped_and_malformed_edns_rejected() {
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0xff, 0xff, 0, 0, 0, 0, 0, 0]);
        let r = fixture().respond_udp(CLIENT, &q).unwrap().unwrap();
        assert!(r.len() <= 1232);
        assert_eq!(u16_at(&r, 6).unwrap(), 1);
        let last = q.len() - 1;
        q[last] = 2;
        assert_eq!(
            fixture().respond_udp(CLIENT, &q),
            Err(DnsError::InvalidEdns)
        );
    }
    #[test]
    fn truncates_whole_answer_to_advertised_and_configured_caps() {
        let mut q = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        let small = AuthoritativeDns::new(
            fixture().zone.clone(),
            SourceAuthorization::new([CLIENT]),
            32,
        )
        .unwrap();
        assert_eq!(
            small.respond_udp(CLIENT, &q),
            Err(DnsError::TruncatedWouldExceed)
        );
        // 32 cannot hold this question, so truncation must fail closed
        // instead of emitting a header that drops the question.
        assert_eq!(
            small.udp_truncate(&q, 32),
            Err(DnsError::TruncatedWouldExceed)
        );
        let tc = small.udp_truncate(&q, q.len()).unwrap();
        assert_eq!(tc.len(), q.len());
        assert_eq!(u16_at(&tc, 6).unwrap(), 0);
        assert_ne!(tc[2] & 2, 0);
        assert_eq!(tc[3] & 0x80, 0);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0]);
        let r = fixture().respond_udp(CLIENT, &q).unwrap().unwrap();
        assert!(r.len() <= 512);
        assert_eq!(r[2] & 2, 0);
    }
    #[test]
    fn tcp_response_uses_configured_cap_without_udp_datagram_clamp() {
        let mut zone = Zone::new("corp.example").unwrap();
        zone.add_address(
            "host.corp.example",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        )
        .unwrap();
        let dns = AuthoritativeDns::new(zone, SourceAuthorization::new([CLIENT]), 1500).unwrap();
        let query = base_query(&wire_name(&[b"host", b"corp", b"example"]), 1);
        let udp = dns.respond_udp(CLIENT, &query).unwrap().unwrap();
        let tcp = dns.respond_tcp(CLIENT, &query).unwrap().unwrap();
        assert_eq!(udp.len(), tcp.len());
        assert_eq!(u16_at(&tcp, 6).unwrap(), 1);
        assert_eq!(u16_at(&udp, 6).unwrap(), 1);
        assert!(tcp.len() <= 1500);
    }

    #[test]
    fn configuration_and_zone_boundaries() {
        assert!(Zone::new("bad..example").is_err());
        assert!(Zone::new(&"a".repeat(64)).is_err());
        let mut z = Zone::new("example.com").unwrap();
        assert!(z.add_address("notexample.com", CLIENT).is_err());
        assert!(AuthoritativeDns::new(z.clone(), SourceAuthorization::default(), 11).is_err());
        assert!(
            AuthoritativeDns::new(z, SourceAuthorization::default(), MAX_RESPONSE_BYTES + 1)
                .is_err()
        );
        assert!(is_in_zone("a.example.com", "example.com"));
        assert!(!is_in_zone("notexample.com", "example.com"));
    }
}
