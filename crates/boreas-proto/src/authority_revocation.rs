//! Authority-specific revocation candidate bytes (independent domain).
//!
//! This module deliberately does not extend `objects::ObjectType`, does not reuse
//! `StatusSnapshot.revocations` and does not define a new `ManagementObject`
//! body. A revocation here is its own canonical CBOR object, signed by the
//! authority named in the schema:
//!
//! * `Identity` — `IdentityAuthority`
//! * `Core` — `NetworkRoot`
//! * `Route` — `RouteAuthority`, exactly one route prefix
//! * `Direct` — the `CoreOperationalKey` of the Core that issued the grant; the
//!   subject's home Core is not used to infer the DirectGrant issuer.
//!
//! The pki verifier is intentionally narrower than this schema: v1 fully enables
//! only `Identity`. `Core`, `Route` and `Direct` are parsed and structurally
//! validated so future authority-specific work cannot drift the wire shape, but
//! `boreas_pki::authority_revocation::AuthorityRevocationTrust::verify` returns
//! `UnsupportedClass` for them until their exact scope evidence is implemented.
//!
//! Wire shape (canonical deterministic CBOR, unsigned integer keys, ascending):
//!
//! ```text
//! object = {0: version(1),
//!           1: net_id(16),
//!           2: class,                 ; 1 Identity | 2 Core | 3 Route | 4 Direct
//!           3: subject_node_id,
//!           4: identity_generation,   ; >= 1
//!           5: issuer_key_id,         ; <= 64 bytes
//!           6: issuer_generation,     ; >= 1
//!           7: scope,                 ; {0: prefix, 1: prefix_len, 2: core_id}
//!           8: seq,                   ; >= 1
//!           9: issued_at,
//!           10: next_update}          ; issued_at < next_update
//! ```
//!
//! Class/scope rules:
//!
//! * `Identity` and `Core` use an empty scope (`prefix = b""`, `prefix_len = 0`,
//!   `core_id = 0`). A `Core` subject must be a Core slot.
//! * `Route` carries exactly one canonical prefix in `scope.prefix` /
//!   `scope.prefix_len` and `core_id = 0`. The prefix is IPv4 or IPv6 with host
//!   bits zero.
//! * `Direct` uses `scope.core_id` as the issuing Core's id and an empty prefix.
//!   The object's `issuer_key_id` is the CoreOperationalKey; no `home_core_id`
//!   inference is allowed.
//!
//! The signature input is domain-separated from `objects`, `network_policy` and
//! `dns_authority` by [`SIGNATURE_DOMAIN`], a profile version and
//! [`AUTHORITY_REVOCATION_OBJECT_TYPE`]. Signatures cover the exact TBS bytes;
//! the pki layer rejects a re-encoded substitute.

/// Hard cap applied before parsing any object.
pub const MAX_TBS_LEN: usize = 16 * 1024;
/// Exact signed carrier shared by local publication and Core–Core delivery.
pub const IDENTITY_REVOCATION_MAGIC: &[u8; 8] = b"BRIR\0\0\0\x01";
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;
pub const SIGNED_CARRIER_HEADER_LEN: usize =
    IDENTITY_REVOCATION_MAGIC.len() + ED25519_SIGNATURE_LEN + MLDSA65_SIGNATURE_LEN;
pub const MAX_IDENTITY_REVOCATION_BYTES: usize = SIGNED_CARRIER_HEADER_LEN + MAX_TBS_LEN;
pub const MAX_IDENTITY_REVOCATIONS: usize = 16;
/// Schema version carried in field 0.
pub const SCHEMA_VERSION: u64 = 1;
/// Object type inside the independent signature domain. This is deliberately not
/// an `objects::ObjectType` discriminant.
pub const AUTHORITY_REVOCATION_OBJECT_TYPE: u8 = 1;
/// Domain separator for both Ed25519 and ML-DSA signatures.
pub const SIGNATURE_DOMAIN: &[u8] = b"BOREAS-AUTHORITY-REVOCATION\0";
/// Maximum issuer key id length, matching the management profile.
pub const MAX_ISSUER_ID_LEN: usize = 64;
/// Maximum prefix byte length accepted in a `Route` scope.
pub const MAX_PREFIX_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    Invalid(&'static str),
}

/// Authority class named by one revocation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RevocationClass {
    Identity = 1,
    Core = 2,
    Route = 3,
    Direct = 4,
}

impl RevocationClass {
    pub fn from_code(code: u64) -> Result<Self, Error> {
        Ok(match code {
            1 => Self::Identity,
            2 => Self::Core,
            3 => Self::Route,
            4 => Self::Direct,
            _ => return Err(Error::Invalid("revocation class")),
        })
    }

    pub const fn code(self) -> u64 {
        self as u64
    }
}

/// Class-specific scope. All three fields are always encoded; unused fields must
/// be zero/empty, which keeps one canonical shape for every class.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationScope {
    /// Empty except for `Route`.
    pub prefix: Vec<u8>,
    /// Zero except for `Route`.
    pub prefix_len: u8,
    /// Zero except for `Direct`, where it names the issuing Core.
    pub core_id: u8,
}

/// Untrusted authority revocation object. Only the pki verifier may turn this
/// into a `VerifiedAuthorityRevocation` token; this struct is not evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocation {
    pub net_id: [u8; 16],
    pub class: RevocationClass,
    /// Permanent overlay node slot of the revoked subject.
    pub subject_node_id: u16,
    pub identity_generation: u64,
    pub issuer_key_id: Vec<u8>,
    pub issuer_generation: u64,
    pub scope: RevocationScope,
    pub seq: u64,
    pub issued_at: u64,
    pub next_update: u64,
}

impl AuthorityRevocation {
    /// Structural validation only. This does not authenticate the issuer.
    pub fn validate(&self) -> Result<(), Error> {
        if self.net_id == [0; 16] {
            return Err(Error::Invalid("net_id"));
        }
        if self.issuer_key_id.is_empty() || self.issuer_key_id.len() > MAX_ISSUER_ID_LEN {
            return Err(Error::Invalid("issuer key id"));
        }
        if self.issuer_generation == 0 {
            return Err(Error::Invalid("issuer generation"));
        }
        if self.identity_generation == 0 {
            return Err(Error::Invalid("identity generation"));
        }
        if self.seq == 0 {
            return Err(Error::Invalid("sequence"));
        }
        if self.issued_at >= self.next_update {
            return Err(Error::Invalid("time window"));
        }
        let (_home_core, octet) = node_slot(self.subject_node_id)?;
        match self.class {
            RevocationClass::Identity => {
                if self.scope != RevocationScope::default() {
                    return Err(Error::Invalid("identity scope"));
                }
            }
            RevocationClass::Core => {
                if octet != 1 || self.scope != RevocationScope::default() {
                    return Err(Error::Invalid("core scope/subject"));
                }
            }
            RevocationClass::Route => {
                if self.scope.core_id != 0
                    || !valid_prefix(&self.scope.prefix, self.scope.prefix_len)
                {
                    return Err(Error::Invalid("route scope"));
                }
            }
            RevocationClass::Direct => {
                if !self.scope.prefix.is_empty()
                    || self.scope.prefix_len != 0
                    || !(1..=16).contains(&self.scope.core_id)
                {
                    return Err(Error::Invalid("direct scope"));
                }
            }
        }
        Ok(())
    }

    /// Canonical TBS bytes. The caller must sign these exact bytes.
    pub fn encode_tbs(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        map(&mut out, 11);
        uint(&mut out, 0);
        uint(&mut out, SCHEMA_VERSION);
        uint(&mut out, 1);
        bytes(&mut out, &self.net_id);
        uint(&mut out, 2);
        uint(&mut out, self.class.code());
        uint(&mut out, 3);
        uint(&mut out, u64::from(self.subject_node_id));
        uint(&mut out, 4);
        uint(&mut out, self.identity_generation);
        uint(&mut out, 5);
        bytes(&mut out, &self.issuer_key_id);
        uint(&mut out, 6);
        uint(&mut out, self.issuer_generation);
        uint(&mut out, 7);
        map(&mut out, 3);
        uint(&mut out, 0);
        bytes(&mut out, &self.scope.prefix);
        uint(&mut out, 1);
        uint(&mut out, u64::from(self.scope.prefix_len));
        uint(&mut out, 2);
        uint(&mut out, u64::from(self.scope.core_id));
        uint(&mut out, 8);
        uint(&mut out, self.seq);
        uint(&mut out, 9);
        uint(&mut out, self.issued_at);
        uint(&mut out, 10);
        uint(&mut out, self.next_update);
        if out.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Strict canonical decode. Re-encoding equality is required.
    pub fn decode_tbs(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { b: raw, i: 0 };
        r.container(5, 11)?;
        r.key(0)?;
        if r.uint()? != SCHEMA_VERSION {
            return Err(Error::Invalid("schema version"));
        }
        r.key(1)?;
        let net_id = r.fixed::<16>()?;
        r.key(2)?;
        let class = RevocationClass::from_code(r.uint()?)?;
        r.key(3)?;
        let subject_node_id = u16::try_from(r.uint()?).map_err(|_| Error::Invalid("node id"))?;
        r.key(4)?;
        let identity_generation = r.uint()?;
        r.key(5)?;
        let issuer_key_id = r.blob(MAX_ISSUER_ID_LEN)?.to_vec();
        r.key(6)?;
        let issuer_generation = r.uint()?;
        r.key(7)?;
        r.container(5, 3)?;
        r.key(0)?;
        let prefix = r.blob(MAX_PREFIX_BYTES)?.to_vec();
        r.key(1)?;
        let prefix_len = u8::try_from(r.uint()?).map_err(|_| Error::Invalid("prefix length"))?;
        r.key(2)?;
        let core_id = u8::try_from(r.uint()?).map_err(|_| Error::Invalid("core id"))?;
        r.key(8)?;
        let seq = r.uint()?;
        r.key(9)?;
        let issued_at = r.uint()?;
        r.key(10)?;
        let next_update = r.uint()?;
        if r.i != raw.len() {
            return Err(Error::Invalid("trailing bytes"));
        }
        let value = Self {
            net_id,
            class,
            subject_node_id,
            identity_generation,
            issuer_key_id,
            issuer_generation,
            scope: RevocationScope {
                prefix,
                prefix_len,
                core_id,
            },
            seq,
            issued_at,
            next_update,
        };
        value.validate()?;
        if value.encode_tbs()?.as_slice() != raw {
            return Err(Error::Invalid("noncanonical object"));
        }
        Ok(value)
    }

    /// Domain-separated bytes for the authority Ed25519 + ML-DSA AND check.
    pub fn signature_input(raw_tbs: &[u8]) -> Result<Vec<u8>, Error> {
        if raw_tbs.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 11 + raw_tbs.len());
        out.extend_from_slice(SIGNATURE_DOMAIN);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(AUTHORITY_REVOCATION_OBJECT_TYPE);
        out.extend_from_slice(&(raw_tbs.len() as u64).to_be_bytes());
        out.extend_from_slice(raw_tbs);
        Ok(out)
    }
}

/// Permanent overlay node slot: home Core 1..=16, host octet 1 or 2..=251.
fn node_slot(node_id: u16) -> Result<(u8, u8), Error> {
    let home_core = (node_id >> 8) + 1;
    if !(1..=16).contains(&home_core) {
        return Err(Error::Invalid("node id"));
    }
    let octet = (node_id & 0xff) as u8;
    if octet == 1 || (2..=251).contains(&octet) {
        Ok((
            u8::try_from(home_core).map_err(|_| Error::Invalid("node id"))?,
            octet,
        ))
    } else {
        Err(Error::Invalid("node id"))
    }
}

/// IPv4 /8..=/32 or IPv6 /48..=/128, with all host bits zero.
fn valid_prefix(prefix: &[u8], prefix_len: u8) -> bool {
    if !matches!(prefix.len(), 4 | 16) {
        return false;
    }
    let bits = prefix.len() * 8;
    let minimum = if prefix.len() == 4 { 8 } else { 48 };
    if usize::from(prefix_len) < minimum || usize::from(prefix_len) > bits {
        return false;
    }
    let full = usize::from(prefix_len) / 8;
    let rem = usize::from(prefix_len) % 8;
    if rem == 0 {
        if prefix[full..].iter().any(|b| *b != 0) {
            return false;
        }
    } else {
        if prefix[full] & (0xff >> rem) != 0 {
            return false;
        }
        if prefix[full + 1..].iter().any(|b| *b != 0) {
            return false;
        }
    }
    true
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
    fn container(&mut self, major: u8, expected: u64) -> Result<u64, Error> {
        let count = self.item(major)?;
        if count != expected {
            return Err(Error::Invalid("map/array size"));
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

    fn identity_sample() -> AuthorityRevocation {
        AuthorityRevocation {
            net_id: [7; 16],
            class: RevocationClass::Identity,
            subject_node_id: 0x0207,
            identity_generation: 2,
            issuer_key_id: b"identity-authority-v1".to_vec(),
            issuer_generation: 1,
            scope: RevocationScope::default(),
            seq: 3,
            issued_at: 1_000,
            next_update: 2_000,
        }
    }

    #[test]
    fn identity_round_trips_and_separates_its_domain() {
        let sample = identity_sample();
        let raw = sample.encode_tbs().unwrap();
        assert_eq!(AuthorityRevocation::decode_tbs(&raw).unwrap(), sample);
        let input = AuthorityRevocation::signature_input(&raw).unwrap();
        assert!(input.starts_with(SIGNATURE_DOMAIN));
        assert_eq!(
            input[SIGNATURE_DOMAIN.len() + 2],
            AUTHORITY_REVOCATION_OBJECT_TYPE
        );
        assert_eq!(&input[input.len() - raw.len()..], raw.as_slice());
    }

    #[test]
    fn class_scope_rules_are_structural_only() {
        let mut route = identity_sample();
        route.class = RevocationClass::Route;
        route.scope = RevocationScope {
            prefix: vec![10, 20, 0, 0],
            prefix_len: 16,
            core_id: 0,
        };
        assert!(route.validate().is_ok());
        route.scope.prefix_len = 7;
        assert!(route.validate().is_err());

        let mut direct = identity_sample();
        direct.class = RevocationClass::Direct;
        direct.scope.core_id = 3;
        assert!(direct.validate().is_ok());
        direct.scope.prefix = vec![10, 20, 0, 0];
        assert!(direct.validate().is_err());

        let mut core = identity_sample();
        core.class = RevocationClass::Core;
        core.subject_node_id = 0x0202;
        assert!(core.validate().is_err(), "Core subject must be a Core slot");
    }

    #[test]
    fn rejects_noncanonical_truncated_and_trailing_bytes() {
        let raw = identity_sample().encode_tbs().unwrap();
        for n in 0..raw.len() {
            assert!(
                AuthorityRevocation::decode_tbs(&raw[..n]).is_err(),
                "prefix {n} must reject"
            );
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(AuthorityRevocation::decode_tbs(&trailing).is_err());
    }
}
