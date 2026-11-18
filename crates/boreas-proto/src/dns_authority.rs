//! Isolated DNS authority candidate bytes.
//!
//! Two objects are defined, and neither extends `objects::ObjectType` nor the
//! management-object profile:
//!
//! * [`DnsSignerGrant`] — a NetworkRoot dual-signed authorization of one
//!   separate DNS signer key pair. Its `purpose` byte and `signer_key_id` are
//!   fixed, so an identity-authority or route-authority grant cannot be replayed
//!   as a DNS issuer.
//! * [`DnsAuthority`] — a DnsSigner dual-signed zone/VIP/record authority. It is
//!   bound to one exact verified NetworkPolicy TBS digest, one zone origin, one
//!   permanent VIP claim per node id, and one record set whose addresses must be
//!   claimed by that same object.
//!
//! The wire format below is IPv4-first. `DnsVipClaim::ipv6` and `AAAA` records
//! are parsed for forward compatibility, but the current `NetworkPolicy` has no
//! ULA field; `boreas-pki` therefore refuses to mint a verified authority that
//! carries either, and the runtime does not advertise IPv6 in this slice.
//!
//! An authority body also does not carry `signer_generation` or the signer grant
//! digest. `boreas-pki` therefore accepts only `signer_generation == 1` and
//! disables rotation; a real rotation profile must bind the grant digest into
//! this signed object or its signature domain and add new fixed vectors.
//!
//! Both use the same canonical CBOR subset and domain-separated signature input
//! as `network_policy`: definite lengths, shortest integer forms, sequential
//! envelope keys, and exact trailing-byte rejection. Reachability is bounded
//! before decoding, so a caller cannot make this module allocate from an
//! attacker-declared length.

use crate::objects::SIGNATURE_DOMAIN;

/// Hard cap applied before parsing any candidate; identical to the sibling
/// candidate profile so one bound covers every management-plane object.
pub const MAX_TBS_LEN: usize = 16 * 1024;
pub const SCHEMA_VERSION: u64 = 1;
/// Candidate object types for the domain-separated signature input. These are
/// deliberately *not* `objects::ObjectType` discriminants.
pub const SIGNER_GRANT_OBJECT_TYPE: u8 = 8;
pub const AUTHORITY_OBJECT_TYPE: u8 = 9;
/// Only purpose `1` means "DNS authority". Identity, route, status and
/// core-operational grants use other values in their own profiles.
pub const DNS_SIGNER_PURPOSE: u64 = 1;
/// The signer key id this profile accepts. It is distinct from
/// `network-policy`'s `network-root-v1` and from any identity issuer key id.
pub const DNS_SIGNER_KEY_ID: &[u8] = b"dns-authority-v1";
/// ML-DSA-65 is the only parameter set the reviewed backend verifies here.
pub const MLDSA_PARAMETER_SET_65: u64 = 65;
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const MAX_ZONE_LEN: usize = 253;
pub const MAX_LABEL_LEN: usize = 63;
pub const MAX_ED25519_KEY_DER: usize = 256;
pub const MAX_MLDSA_KEY_DER: usize = 2048;
pub const MAX_VIP_CLAIMS: usize = 64;
pub const MAX_RECORDS: usize = 128;
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    Invalid(&'static str),
}

/// NetworkRoot-authorized DNS signer key binding. Untrusted until the pki layer
/// verifies both root signatures over [`DnsSignerGrant::signature_input`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSignerGrant {
    pub net_id: [u8; 16],
    pub policy_digest: [u8; 32],
    pub signer_generation: u64,
    pub sequence: u64,
    pub not_before: u64,
    pub expires: u64,
    pub ed25519_public_key_der: Vec<u8>,
    pub mldsa_parameter_set: u64,
    pub mldsa_public_key_der: Vec<u8>,
}

/// One permanent VIP claim. `ipv6` is all-zero when the node has no IPv6 claim;
/// a present address must be in the RFC 4193 `fd00::/8` space. That is only a
/// format check, not proof that the address belongs to this network: the signed
/// `NetworkPolicy` has one IPv4 overlay prefix and no ULA field, so `boreas-pki`
/// refuses every nonzero IPv6 claim and every `AAAA` record instead of
/// advertising an address the policy never authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsVipClaim {
    pub node_id: u16,
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
}

/// One authoritative record. `owner` is a lowercase ASCII presentation name
/// without a trailing dot and must be inside the object's zone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecordEntry {
    pub owner: Vec<u8>,
    pub record_type: u16,
    pub address: Vec<u8>,
}

/// DnsSigner-authorized zone/VIP/record authority. Untrusted until the pki layer
/// verifies both signer signatures over [`DnsAuthority::signature_input`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAuthority {
    pub net_id: [u8; 16],
    pub policy_digest: [u8; 32],
    pub sequence: u64,
    pub issued_at: u64,
    pub expires: u64,
    pub zone: Vec<u8>,
    pub vips: Vec<DnsVipClaim>,
    pub records: Vec<DnsRecordEntry>,
}

impl DnsSignerGrant {
    pub fn validate(&self) -> Result<(), Error> {
        if self.net_id == [0; 16] {
            return Err(Error::Invalid("net_id"));
        }
        if self.policy_digest == [0; 32] {
            return Err(Error::Invalid("policy digest"));
        }
        if self.signer_generation == 0 {
            return Err(Error::Invalid("signer generation"));
        }
        if self.sequence == 0 {
            return Err(Error::Invalid("sequence"));
        }
        if self.not_before >= self.expires {
            return Err(Error::Invalid("time window"));
        }
        if self.ed25519_public_key_der.is_empty()
            || self.ed25519_public_key_der.len() > MAX_ED25519_KEY_DER
        {
            return Err(Error::Invalid("ed25519 key"));
        }
        if self.mldsa_parameter_set != MLDSA_PARAMETER_SET_65 {
            return Err(Error::Invalid("mldsa parameter set"));
        }
        if self.mldsa_public_key_der.is_empty()
            || self.mldsa_public_key_der.len() > MAX_MLDSA_KEY_DER
        {
            return Err(Error::Invalid("mldsa key"));
        }
        Ok(())
    }

    /// Canonical TBS bytes. The caller keeps and verifies these exact bytes.
    pub fn encode_tbs(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        map(&mut out, 10);
        uint(&mut out, 0);
        bytes(&mut out, &self.net_id);
        uint(&mut out, 1);
        bytes(&mut out, &self.policy_digest);
        uint(&mut out, 2);
        uint(&mut out, SCHEMA_VERSION);
        uint(&mut out, 3);
        uint(&mut out, DNS_SIGNER_PURPOSE);
        uint(&mut out, 4);
        bytes(&mut out, DNS_SIGNER_KEY_ID);
        uint(&mut out, 5);
        uint(&mut out, self.signer_generation);
        uint(&mut out, 6);
        uint(&mut out, self.sequence);
        uint(&mut out, 7);
        uint(&mut out, self.not_before);
        uint(&mut out, 8);
        uint(&mut out, self.expires);
        uint(&mut out, 9);
        map(&mut out, 3);
        uint(&mut out, 0);
        bytes(&mut out, &self.ed25519_public_key_der);
        uint(&mut out, 1);
        uint(&mut out, self.mldsa_parameter_set);
        uint(&mut out, 2);
        bytes(&mut out, &self.mldsa_public_key_der);
        if out.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Parse the complete canonical TBS. Re-encoding equality is checked by the
    /// caller through the fixed envelope, so no alternate signed form is usable.
    pub fn decode_tbs(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { b: raw, i: 0 };
        r.container(5, 10)?;
        r.key(0)?;
        let net_id = r.fixed::<16>()?;
        r.key(1)?;
        let policy_digest = r.fixed::<32>()?;
        r.key(2)?;
        if r.uint()? != SCHEMA_VERSION {
            return Err(Error::Invalid("schema version"));
        }
        r.key(3)?;
        if r.uint()? != DNS_SIGNER_PURPOSE {
            return Err(Error::Invalid("purpose"));
        }
        r.key(4)?;
        if r.blob(MAX_ED25519_KEY_DER + DNS_SIGNER_KEY_ID.len())? != DNS_SIGNER_KEY_ID {
            return Err(Error::Invalid("signer key id"));
        }
        r.key(5)?;
        let signer_generation = r.uint()?;
        r.key(6)?;
        let sequence = r.uint()?;
        r.key(7)?;
        let not_before = r.uint()?;
        r.key(8)?;
        let expires = r.uint()?;
        r.key(9)?;
        r.container(5, 3)?;
        r.key(0)?;
        let ed25519_public_key_der = r.blob(MAX_ED25519_KEY_DER)?.to_vec();
        r.key(1)?;
        let mldsa_parameter_set = r.uint()?;
        r.key(2)?;
        let mldsa_public_key_der = r.blob(MAX_MLDSA_KEY_DER)?.to_vec();
        if r.i != raw.len() {
            return Err(Error::Invalid("trailing bytes"));
        }
        let value = Self {
            net_id,
            policy_digest,
            signer_generation,
            sequence,
            not_before,
            expires,
            ed25519_public_key_der,
            mldsa_parameter_set,
            mldsa_public_key_der,
        };
        value.validate()?;
        Ok(value)
    }

    /// Domain-separated bytes for the NetworkRoot Ed25519 + ML-DSA AND check.
    pub fn signature_input(raw_tbs: &[u8]) -> Result<Vec<u8>, Error> {
        signature_input(raw_tbs, SIGNER_GRANT_OBJECT_TYPE)
    }
}

impl DnsAuthority {
    pub fn validate(&self) -> Result<(), Error> {
        if self.net_id == [0; 16] {
            return Err(Error::Invalid("net_id"));
        }
        if self.policy_digest == [0; 32] {
            return Err(Error::Invalid("policy digest"));
        }
        if self.sequence == 0 {
            return Err(Error::Invalid("sequence"));
        }
        if self.issued_at >= self.expires {
            return Err(Error::Invalid("time window"));
        }
        if !valid_name(&self.zone) {
            return Err(Error::Invalid("zone"));
        }
        if self.vips.len() > MAX_VIP_CLAIMS {
            return Err(Error::Invalid("vip claim count"));
        }
        if self.records.len() > MAX_RECORDS {
            return Err(Error::Invalid("record count"));
        }
        // Duplicate node ids or duplicate addresses would let two owners claim
        // one permanent slot, so both are rejected rather than resolved.
        for (index, claim) in self.vips.iter().enumerate() {
            if claim.node_id == 0 {
                return Err(Error::Invalid("vip node id"));
            }
            if !unicast(&claim.ipv4) {
                return Err(Error::Invalid("vip address"));
            }
            if claim.ipv6 != [0; 16] && !ula_v6(&claim.ipv6) {
                return Err(Error::Invalid("vip ipv6"));
            }
            for other in &self.vips[..index] {
                if other.node_id == claim.node_id
                    || other.ipv4 == claim.ipv4
                    || (claim.ipv6 != [0; 16] && other.ipv6 == claim.ipv6)
                {
                    return Err(Error::Invalid("duplicate vip claim"));
                }
            }
        }
        for (index, record) in self.records.iter().enumerate() {
            if !valid_name(&record.owner) || !in_zone(&record.owner, &self.zone) {
                return Err(Error::Invalid("record owner"));
            }
            match record.record_type {
                TYPE_A => {
                    if record.address.len() != IPV4_LEN {
                        return Err(Error::Invalid("A address length"));
                    }
                    let octets: [u8; 4] = record
                        .address
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Invalid("A address length"))?;
                    if !unicast(&octets) {
                        return Err(Error::Invalid("A address"));
                    }
                    if !self.vips.iter().any(|claim| claim.ipv4 == octets) {
                        return Err(Error::Invalid("A address not claimed"));
                    }
                }
                TYPE_AAAA => {
                    if record.address.len() != IPV6_LEN {
                        return Err(Error::Invalid("AAAA address length"));
                    }
                    let octets: [u8; 16] = record
                        .address
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Invalid("AAAA address length"))?;
                    if !ula_v6(&octets) {
                        return Err(Error::Invalid("AAAA address"));
                    }
                    if !self.vips.iter().any(|claim| claim.ipv6 == octets) {
                        return Err(Error::Invalid("AAAA address not claimed"));
                    }
                }
                _ => return Err(Error::Invalid("record type")),
            }
            for other in &self.records[..index] {
                if other.owner == record.owner
                    && other.record_type == record.record_type
                    && other.address == record.address
                {
                    return Err(Error::Invalid("duplicate record"));
                }
            }
        }
        Ok(())
    }

    /// Canonical TBS bytes. The caller keeps and verifies these exact bytes.
    pub fn encode_tbs(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        map(&mut out, 10);
        uint(&mut out, 0);
        bytes(&mut out, &self.net_id);
        uint(&mut out, 1);
        bytes(&mut out, &self.policy_digest);
        uint(&mut out, 2);
        uint(&mut out, SCHEMA_VERSION);
        uint(&mut out, 3);
        bytes(&mut out, &self.zone);
        uint(&mut out, 4);
        uint(&mut out, self.sequence);
        uint(&mut out, 5);
        uint(&mut out, self.issued_at);
        uint(&mut out, 6);
        uint(&mut out, self.expires);
        uint(&mut out, 7);
        bytes(&mut out, DNS_SIGNER_KEY_ID);
        uint(&mut out, 8);
        array(&mut out, self.vips.len() as u64);
        for claim in &self.vips {
            map(&mut out, 3);
            uint(&mut out, 0);
            uint(&mut out, u64::from(claim.node_id));
            uint(&mut out, 1);
            bytes(&mut out, &claim.ipv4);
            uint(&mut out, 2);
            bytes(&mut out, &claim.ipv6);
        }
        uint(&mut out, 9);
        array(&mut out, self.records.len() as u64);
        for record in &self.records {
            map(&mut out, 3);
            uint(&mut out, 0);
            bytes(&mut out, &record.owner);
            uint(&mut out, 1);
            uint(&mut out, u64::from(record.record_type));
            uint(&mut out, 2);
            bytes(&mut out, &record.address);
        }
        if out.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Parse the complete canonical TBS. Every field is bounded before it is
    /// copied, and trailing bytes are rejected.
    pub fn decode_tbs(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { b: raw, i: 0 };
        r.container(5, 10)?;
        r.key(0)?;
        let net_id = r.fixed::<16>()?;
        r.key(1)?;
        let policy_digest = r.fixed::<32>()?;
        r.key(2)?;
        if r.uint()? != SCHEMA_VERSION {
            return Err(Error::Invalid("schema version"));
        }
        r.key(3)?;
        let zone = r.blob(MAX_ZONE_LEN)?.to_vec();
        r.key(4)?;
        let sequence = r.uint()?;
        r.key(5)?;
        let issued_at = r.uint()?;
        r.key(6)?;
        let expires = r.uint()?;
        r.key(7)?;
        if r.blob(MAX_ED25519_KEY_DER)? != DNS_SIGNER_KEY_ID {
            return Err(Error::Invalid("signer key id"));
        }
        r.key(8)?;
        let vip_count = r.array_len(MAX_VIP_CLAIMS)?;
        let mut vips = Vec::with_capacity(vip_count);
        for _ in 0..vip_count {
            r.container(5, 3)?;
            r.key(0)?;
            let node_id = u16::try_from(r.uint()?).map_err(|_| Error::Invalid("vip node id"))?;
            r.key(1)?;
            let ipv4 = r.fixed::<4>()?;
            r.key(2)?;
            let ipv6 = r.fixed::<16>()?;
            vips.push(DnsVipClaim {
                node_id,
                ipv4,
                ipv6,
            });
        }
        r.key(9)?;
        let record_count = r.array_len(MAX_RECORDS)?;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            r.container(5, 3)?;
            r.key(0)?;
            let owner = r.blob(MAX_ZONE_LEN)?.to_vec();
            r.key(1)?;
            let record_type = u16::try_from(r.uint()?).map_err(|_| Error::Invalid("record type"))?;
            r.key(2)?;
            let address = r.blob(IPV6_LEN)?.to_vec();
            records.push(DnsRecordEntry {
                owner,
                record_type,
                address,
            });
        }
        if r.i != raw.len() {
            return Err(Error::Invalid("trailing bytes"));
        }
        let value = Self {
            net_id,
            policy_digest,
            sequence,
            issued_at,
            expires,
            zone,
            vips,
            records,
        };
        value.validate()?;
        Ok(value)
    }

    /// Domain-separated bytes for the DnsSigner Ed25519 + ML-DSA AND check.
    pub fn signature_input(raw_tbs: &[u8]) -> Result<Vec<u8>, Error> {
        signature_input(raw_tbs, AUTHORITY_OBJECT_TYPE)
    }
}

fn signature_input(raw_tbs: &[u8], object_type: u8) -> Result<Vec<u8>, Error> {
    if raw_tbs.len() > MAX_TBS_LEN {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 11 + raw_tbs.len());
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(object_type);
    out.extend_from_slice(&(raw_tbs.len() as u64).to_be_bytes());
    out.extend_from_slice(raw_tbs);
    Ok(out)
}

/// Lowercase ASCII presentation name without a trailing dot: at least one label,
/// each 1..=63 bytes, total at most 253 bytes, no control characters, spaces,
/// dots inside labels or backslashes.
fn valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_ZONE_LEN || !name.is_ascii() {
        return false;
    }
    let mut labels = 0usize;
    for label in name.split(|b| *b == b'.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return false;
        }
        if label
            .iter()
            .any(|b| *b <= 0x20 || *b >= 0x7f || *b == b'\\' || b.is_ascii_uppercase())
        {
            return false;
        }
        labels += 1;
    }
    labels > 0
}

fn in_zone(name: &[u8], zone: &[u8]) -> bool {
    name == zone
        || (name.len() > zone.len()
            && name.ends_with(zone)
            && name[name.len() - zone.len() - 1] == b'.')
}

fn unicast(address: &[u8; 4]) -> bool {
    let first = address[0];
    let last = address[3];
    first != 0 && first < 224 && last != 0 && last != 255
}

fn ula_v6(address: &[u8; 16]) -> bool {
    // RFC 4193 prefix only. There is no signed network ULA in this profile, so
    // the pki layer refuses every nonzero IPv6 claim rather than treating this
    // byte check as authorization.
    address[0] == 0xfd
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push(major << 5 | n as u8);
    } else if n <= 255 {
        out.extend([major << 5 | 24, n as u8]);
    } else if n <= 65535 {
        out.push(major << 5 | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(major << 5 | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major << 5 | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}
fn uint(out: &mut Vec<u8>, n: u64) {
    head(out, 0, n);
}
fn map(out: &mut Vec<u8>, n: u64) {
    head(out, 5, n);
}
fn array(out: &mut Vec<u8>, n: u64) {
    head(out, 4, n);
}
fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let value = *self.b.get(self.i).ok_or(Error::Invalid("truncated"))?;
        self.i += 1;
        Ok(value)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .i
            .checked_add(n)
            .ok_or(Error::Invalid("length overflow"))?;
        let bytes = self.b.get(self.i..end).ok_or(Error::Invalid("truncated"))?;
        self.i = end;
        Ok(bytes)
    }
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        let (value, width) = match ai {
            0..=23 => (u64::from(ai), 0),
            24 => (u64::from(self.byte()?), 1),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 2)
            }
            26 => {
                let b = self.take(4)?;
                (u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])), 4)
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0; 8];
                a.copy_from_slice(b);
                (u64::from_be_bytes(a), 8)
            }
            _ => return Err(Error::Invalid("indefinite/reserved")),
        };
        if (width == 1 && value < 24)
            || (width == 2 && value <= 255)
            || (width == 4 && value <= 65535)
            || (width == 8 && value <= u32::MAX as u64)
        {
            return Err(Error::Invalid("noncanonical integer/length"));
        }
        Ok(value)
    }
    fn item(&mut self, major: u8) -> Result<u64, Error> {
        let h = self.byte()?;
        if h >> 5 != major {
            return Err(Error::Invalid("wrong CBOR type"));
        }
        self.arg(h & 31)
    }
    fn uint(&mut self) -> Result<u64, Error> {
        self.item(0)
    }
    /// Read a container header and require the declared count to be `expected`.
    fn container(&mut self, major: u8, expected: u64) -> Result<u64, Error> {
        let count = self.item(major)?;
        if count != expected {
            return Err(Error::Invalid(
                "map/array size; nonempty extension rejected",
            ));
        }
        Ok(count)
    }
    fn key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(Error::Invalid("field order/unknown/duplicate key"))
        }
    }
    /// Read an array header and bound its declared element count *before*
    /// `Vec::with_capacity`. The header is consumed exactly once; an earlier
    /// draft read it twice in one expression, which also failed to borrow.
    fn array_len(&mut self, max: usize) -> Result<usize, Error> {
        let count = usize::try_from(self.item(4)?).map_err(|_| Error::TooLarge)?;
        if count > max {
            return Err(Error::Invalid("array count"));
        }
        Ok(count)
    }

    fn blob(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.item(2)?).map_err(|_| Error::TooLarge)?;
        if n > max {
            return Err(Error::Invalid("blob length"));
        }
        self.take(n)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.blob(N)?;
        let mut out = [0; N];
        out.copy_from_slice(b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|v| u8::from_str_radix(v, 16).expect("hex vector"))
            .collect()
    }

    fn authority_sample() -> DnsAuthority {
        DnsAuthority {
            net_id: [1; 16],
            policy_digest: [2; 32],
            sequence: 1,
            issued_at: 10,
            expires: 20,
            zone: b"b.example".to_vec(),
            vips: vec![DnsVipClaim {
                node_id: 0x0301,
                ipv4: [10, 20, 3, 1],
                ipv6: [0; 16],
            }],
            records: vec![DnsRecordEntry {
                owner: b"a.b.example".to_vec(),
                record_type: TYPE_A,
                address: vec![10, 20, 3, 1],
            }],
        }
    }

    /// Independent fixed vector: map(10), net_id, policy digest, schema, zone,
    /// sequence, issued, expires, signer key id, one VIP claim, one A record.
    const POSITIVE_AUTHORITY_TBS: &str = concat!(
        "aa 00 50 ",
        "01 01 01 01 01 01 01 01 ",
        "01 01 01 01 01 01 01 01 ",
        "01 58 20 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "02 01 03 49 62 2e 65 78 61 6d 70 6c 65 04 01 05 0a 06 14 ",
        "07 50 64 6e 73 2d 61 75 74 68 6f 72 69 74 79 2d 76 31 ",
        "08 81 a3 00 19 03 01 01 44 0a 14 03 01 02 50 ",
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ",
        "09 81 a3 00 4b 61 2e 62 2e 65 78 61 6d 70 6c 65 01 01 02 44 0a 14 03 01",
    );

    #[test]
    fn independent_fixed_authority_vector_and_signature_input() {
        let raw = hex(POSITIVE_AUTHORITY_TBS);
        // map(10) envelope with one 16-byte key id: 146 bytes, not 145.
        assert_eq!(raw.len(), 146);
        assert_eq!(DnsAuthority::decode_tbs(&raw).unwrap(), authority_sample());
        assert_eq!(authority_sample().encode_tbs().unwrap(), raw);
        let mut expected = b"BOREAS-MGMT-OBJECT\0\x00\x01\x09\0\0\0\0\0\0\0\x92".to_vec();
        expected.extend_from_slice(&raw);
        assert_eq!(
            DnsAuthority::signature_input(&raw).unwrap(),
            expected,
            "authority signature input is domain separated with type 9 and the exact length"
        );
    }

    #[test]
    fn signer_grant_round_trips_and_uses_its_own_object_type() {
        let grant = DnsSignerGrant {
            net_id: [4; 16],
            policy_digest: [5; 32],
            signer_generation: 2,
            sequence: 3,
            not_before: 10,
            expires: 20,
            ed25519_public_key_der: vec![0xaa; 44],
            mldsa_parameter_set: MLDSA_PARAMETER_SET_65,
            mldsa_public_key_der: vec![0xbb; 1975],
        };
        let raw = grant.encode_tbs().unwrap();
        assert_eq!(DnsSignerGrant::decode_tbs(&raw).unwrap(), grant);
        assert_eq!(grant.encode_tbs().unwrap(), raw);
        // Purpose byte (1) and key id are fixed by the profile, not caller data.
        // Domain is 19 bytes, then a 2-byte version, then the object type.
        assert_eq!(DnsSignerGrant::signature_input(&raw).unwrap()[21], 8);
        assert_ne!(
            DnsSignerGrant::signature_input(&raw).unwrap(),
            DnsAuthority::signature_input(&raw).unwrap()
        );
        // An identity issuer key id is not a DNS signer key id.
        let mut identity = grant.clone();
        identity.ed25519_public_key_der = vec![0xaa; 44];
        assert_eq!(identity.encode_tbs().unwrap(), raw);
        let mut wrong_param = grant.clone();
        wrong_param.mldsa_parameter_set = 87;
        assert_eq!(
            wrong_param.encode_tbs(),
            Err(Error::Invalid("mldsa parameter set"))
        );
        let mut empty_key = grant;
        empty_key.ed25519_public_key_der.clear();
        assert_eq!(empty_key.encode_tbs(), Err(Error::Invalid("ed25519 key")));
    }

    #[test]
    fn rejects_noncanonical_and_truncated_encodings() {
        let raw = hex(POSITIVE_AUTHORITY_TBS);
        // Every strict prefix is truncated, never "vacuously one item".
        for n in 0..raw.len() {
            assert!(
                DnsAuthority::decode_tbs(&raw[..n]).is_err(),
                "prefix of {n} bytes must reject"
            );
        }
        // Wrong envelope size, duplicate/out-of-order key, trailing bytes.
        let mut short_map = raw.clone();
        short_map[0] = 0xa9;
        assert!(DnsAuthority::decode_tbs(&short_map).is_err());
        // Envelope layout: aa | 00 50 <16 net> | 01 58 20 <32 digest> | ...
        // Byte 19 is the second envelope key; byte 18 is still net_id.
        let mut duplicate = raw.clone();
        assert_eq!(duplicate[19], 0x01); // envelope key 1
        duplicate[19] = 0x00; // repeats key 0
        assert!(DnsAuthority::decode_tbs(&duplicate).is_err());
        // A noncanonical integer is rejected by the reader itself rather than by
        // a shifted decode. `0x18 0x01` is "1" in a longer form.
        let noncanonical = [0x18u8, 0x01];
        let mut r = Reader {
            b: &noncanonical,
            i: 0,
        };
        assert_eq!(r.uint(), Err(Error::Invalid("noncanonical integer/length")));
        // A well-formed noncanonical text head is not a uint at all.
        let text = [0x61u8, b'a'];
        let mut r = Reader { b: &text, i: 0 };
        assert_eq!(r.uint(), Err(Error::Invalid("wrong CBOR type")));
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(DnsAuthority::decode_tbs(&trailing).is_err());
        // A declared blob longer than the field cap must not allocate. Byte 57
        // is the zone byte-string head in this vector.
        let mut overlong = raw.clone();
        assert_eq!(overlong[57], 0x49);
        overlong[57] = 0x58; // zone becomes a 2-byte length head
        overlong[58] = 0xff; // 255 > MAX_ZONE_LEN, before any copy
        assert!(DnsAuthority::decode_tbs(&overlong).is_err());
        assert_eq!(
            DnsAuthority::decode_tbs(&vec![0; MAX_TBS_LEN + 1]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn arrays_decode_once_and_bound_their_declared_count() {
        let raw = authority_sample().encode_tbs().unwrap();
        // The one-element VIP array is `08 81`; a declared count above
        // MAX_VIP_CLAIMS must be refused before `Vec::with_capacity`.
        let at = raw
            .windows(2)
            .position(|w| w[0] == 0x08 && w[1] == 0x81)
            .expect("one-element vip array");
        let mut over = raw[..=at].to_vec();
        over.extend_from_slice(&[0x98, 0x41]); // array(65)
        over.extend_from_slice(&raw[at + 2..]);
        assert_eq!(
            DnsAuthority::decode_tbs(&over),
            Err(Error::Invalid("array count"))
        );
    }

    #[test]
    fn multi_entry_and_empty_arrays_round_trip() {
        let mut authority = authority_sample();
        let v6 = [
            0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        authority.vips.push(DnsVipClaim {
            node_id: 0x0302,
            ipv4: [10, 20, 3, 2],
            ipv6: v6,
        });
        authority.records.push(DnsRecordEntry {
            owner: b"b.b.example".to_vec(),
            record_type: TYPE_AAAA,
            address: v6.to_vec(),
        });
        authority.records.push(DnsRecordEntry {
            owner: b"b.example".to_vec(),
            record_type: TYPE_A,
            address: vec![10, 20, 3, 2],
        });
        let raw = authority.encode_tbs().unwrap();
        assert_eq!(DnsAuthority::decode_tbs(&raw).unwrap(), authority);
        assert_eq!(authority.encode_tbs().unwrap(), raw);

        let mut empty = authority;
        empty.vips.clear();
        empty.records.clear();
        let raw = empty.encode_tbs().unwrap();
        assert_eq!(DnsAuthority::decode_tbs(&raw).unwrap(), empty);
    }

    #[test]
    fn reader_rejects_every_truncated_array_item() {
        // Every prefix that cuts inside the VIP array must fail closed rather
        // than consume the next envelope key as an array item.
        let raw = authority_sample().encode_tbs().unwrap();
        let at = raw
            .windows(2)
            .position(|w| w[0] == 0x08 && w[1] == 0x81)
            .expect("one-element vip array");
        for cut in at + 2..raw.len() {
            assert!(DnsAuthority::decode_tbs(&raw[..cut]).is_err(), "{cut}");
        }
    }

    #[test]
    fn rejects_values_outside_the_strict_authority_scope() {
        let base = authority_sample();
        let cases: [(&'static str, DnsAuthority); 13] = [
            ("zero net", {
                let mut x = base.clone();
                x.net_id = [0; 16];
                x
            }),
            ("zero digest", {
                let mut x = base.clone();
                x.policy_digest = [0; 32];
                x
            }),
            ("zero sequence", {
                let mut x = base.clone();
                x.sequence = 0;
                x
            }),
            ("empty time window", {
                let mut x = base.clone();
                x.expires = x.issued_at;
                x
            }),
            ("uppercase zone", {
                let mut x = base.clone();
                x.zone = b"B.example".to_vec();
                x
            }),
            ("empty label", {
                let mut x = base.clone();
                x.zone = b"b..example".to_vec();
                x
            }),
            ("record outside zone", {
                let mut x = base.clone();
                x.records[0].owner = b"a.other".to_vec();
                x
            }),
            ("unclaimed address", {
                let mut x = base.clone();
                x.records[0].address = vec![10, 20, 3, 9];
                x
            }),
            ("duplicate vip", {
                let mut x = base.clone();
                x.vips.push(DnsVipClaim {
                    node_id: 0x0302,
                    ipv4: [10, 20, 3, 1],
                    ipv6: [0; 16],
                });
                x
            }),
            ("unknown record type", {
                let mut x = base.clone();
                x.records[0].record_type = 16;
                x
            }),
            ("AAAA length", {
                let mut x = base.clone();
                x.records[0].record_type = TYPE_AAAA;
                x
            }),
            ("vip ipv6 outside ula", {
                let mut x = base.clone();
                x.vips[0].ipv6 = [0x20; 16];
                x
            }),
            ("AAAA outside ula", {
                let mut x = base.clone();
                x.vips[0].ipv6 = [
                    0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ];
                x.records[0].record_type = TYPE_AAAA;
                x.records[0].address = vec![0x20; 16];
                x
            }),
        ];
        for (label, value) in cases {
            assert!(value.encode_tbs().is_err(), "{label} must be rejected");
        }
        let mut too_many = base;
        too_many.vips = (1..=u16::try_from(MAX_VIP_CLAIMS).unwrap() + 1)
            .map(|node| DnsVipClaim {
                node_id: node,
                ipv4: [10, 20, 3, u8::try_from(node % 200 + 1).unwrap()],
                ipv6: [0; 16],
            })
            .collect();
        assert!(too_many.encode_tbs().is_err());
    }

    #[test]
    fn name_and_zone_helpers_are_strict() {
        assert!(valid_name(b"a.b.example"));
        assert!(!valid_name(b""));
        assert!(!valid_name(b".a"));
        assert!(!valid_name(b"a."));
        assert!(!valid_name(&[b'a'; 64]));
        assert!(!valid_name(b"a b"));
        assert!(!valid_name(b"a\\b"));
        assert!(in_zone(b"a.b.example", b"b.example"));
        assert!(in_zone(b"b.example", b"b.example"));
        assert!(!in_zone(b"xb.example", b"b.example"));
        assert!(!in_zone(b"example", b"b.example"));
    }
}
