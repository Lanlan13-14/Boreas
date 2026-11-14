//! Strictly bounded, non-recursive authoritative DNS wire handling.
//!
//! This crate only builds DNS-over-UDP wire responses. It does not parse or
//! synthesize IP/UDP packets, provide a socket, or implement TCP DNS. TCP DNS is
//! explicitly unsupported until a maintained user-space TCP endpoint is chosen.
//! Negative answers omit SOA authority records, so negative-cache TTL behavior
//! is not implemented. Caller must provide an authenticated source-IP mapping;
//! [`SourceAuthorization`] alone is an allowlist, not peer authentication.

#![forbid(unsafe_code)]

pub mod packet;

use std::collections::BTreeMap;
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
const CLASS_IN: u16 = 1;

/// Reason a bounded DNS message could not be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    MessageTooLarge,
    Truncated,
    InvalidHeader,
    UnsupportedOpcode,
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
        })
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

    /// Handle one DNS-over-UDP message payload from an IPv4/IPv6 source address.
    /// Unauthorized sources get no response (`Ok(None)`), preventing accidental
    /// synthetic responses. Exactly one question and at most one EDNS OPT are
    /// accepted. No recursion, forwarding, or TCP behavior is provided.
    fn name_exists(&self, name: &str) -> bool {
        name == self.zone.origin
            || self.zone.records.contains_key(name)
            || self.zone.records.keys().any(|owner| {
                owner
                    .strip_suffix(name)
                    .is_some_and(|prefix| prefix.ends_with('.'))
            })
    }

    pub fn respond_udp(&self, source: IpAddr, query: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
        if !self.sources.permits(source) {
            return Ok(None);
        }
        if query.len() > MAX_QUERY_BYTES {
            return Err(DnsError::MessageTooLarge);
        }
        let question = parse_query(query)?;
        let mut limit = self.max_response_bytes;
        if let Some(edns_limit) = question.edns_size {
            limit = limit.min(edns_limit.clamp(512, MAX_RESPONSE_BYTES));
        } else {
            limit = limit.min(512);
        }
        let mut answer = None;
        let authoritative = is_in_zone(&question.name, &self.zone.origin);
        let exists = authoritative && self.name_exists(&question.name);
        let rcode;
        if !authoritative {
            rcode = 5; // REFUSED
        } else if exists {
            rcode = 0; // Existing owner/empty non-terminal with no requested RRset is NODATA.
            if let Some(addresses) = self.zone.records.get(&question.name) {
                answer = addresses.iter().find_map(|ip| match (question.qtype, ip) {
                    (TYPE_A, IpAddr::V4(v4)) => Some((1u16, v4.octets().to_vec())),
                    (TYPE_AAAA, IpAddr::V6(v6)) => Some((28u16, v6.octets().to_vec())),
                    _ => None,
                });
            }
        } else {
            rcode = 3; // NXDOMAIN
        }
        Ok(Some(build_response(
            query,
            &question,
            rcode,
            answer,
            limit,
            question.edns_size.is_some(),
            authoritative,
        )?))
    }
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

fn parse_query(msg: &[u8]) -> Result<Question, DnsError> {
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
    if flags & 0xfee0 != 0 || qd != MAX_QUESTIONS as u16 || an != 0 || ns != 0 || ar > 1 {
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
        if end + 11 > msg.len() {
            return Err(DnsError::Truncated);
        }
        if msg[end] != 0 || u16_at(msg, end + 1)? != TYPE_OPT {
            return Err(DnsError::InvalidEdns);
        }
        let payload = usize::from(u16_at(msg, end + 3)?);
        let ttl = u32_at(msg, end + 5)?;
        let rdlen = usize::from(u16_at(msg, end + 9)?);
        let rstart = end + 11;
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
    answer: Option<(u16, Vec<u8>)>,
    limit: usize,
    include_opt: bool,
    authoritative: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(q.end + 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    let mut flags = 0x8000 | (if authoritative { 0x0400 } else { 0 }) | (q.flags & 0x0100) | rcode; // QR, conditional AA, echo RD; RA stays clear.
    if q.flags & 0x0010 != 0 {
        flags |= 0x0010;
    } // CD
    out.extend_from_slice(&flags.to_be_bytes());
    // If the question itself cannot fit, return a bounded TC header rather
    // than exceeding the caller's advertised response ceiling.
    let question_fits = q.end <= limit;
    out.extend_from_slice(&(if question_fits { 1u16 } else { 0u16 }).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    if question_fits {
        out.extend_from_slice(&query[12..q.end]);
    }
    if !question_fits {
        let flags = u16::from_be_bytes([out[2], out[3]]) | 0x0200;
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        return Ok(out);
    }
    let opt_size = if include_opt { 11 } else { 0 };
    if include_opt
        && out
            .len()
            .checked_add(opt_size)
            .filter(|size| *size <= limit)
            .is_none()
    {
        let flags = u16::from_be_bytes([out[2], out[3]]) | 0x0200;
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        return Ok(out);
    }
    if let Some((rrtype, bytes)) = answer {
        let required = 2 + 2 + 2 + 4 + 2 + bytes.len();
        if out
            .len()
            .checked_add(required)
            .and_then(|size| size.checked_add(opt_size))
            .filter(|size| *size <= limit)
            .is_some()
        {
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&rrtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&bytes);
            out[6..8].copy_from_slice(&1u16.to_be_bytes());
        } else {
            let flags = u16::from_be_bytes([out[2], out[3]]) | 0x0200;
            out[2..4].copy_from_slice(&flags.to_be_bytes());
        }
    }
    if include_opt {
        out.extend_from_slice(&[0, 0, TYPE_OPT.to_be_bytes()[0], TYPE_OPT.to_be_bytes()[1]]);
        // Advertise the effective response budget; ext-RCODE, version and flags are zero.
        out.extend_from_slice(&(limit as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        out[10..12].copy_from_slice(&1u16.to_be_bytes());
    }
    if out.len() > limit {
        return Err(DnsError::InvalidConfiguration);
    }
    Ok(out)
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
        let long = vec![63u8; 1];
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
        let r = small.respond_udp(CLIENT, &q).unwrap().unwrap();
        assert!(r.len() <= 32);
        assert_eq!(u16_at(&r, 6).unwrap(), 0);
        assert_ne!(r[2] & 2, 0);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0]);
        let r = fixture().respond_udp(CLIENT, &q).unwrap().unwrap();
        assert!(r.len() <= 512);
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
