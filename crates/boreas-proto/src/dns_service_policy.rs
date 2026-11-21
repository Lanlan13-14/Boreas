//! Isolated V1 DNS service entitlement snapshot; not a control message or zone authority.
use crate::dns_authority::{self, Reader, array, bytes, map, uint};
use crate::objects::valid_node_id;

pub use crate::dns_authority::Error;

pub const SCHEMA_VERSION: u64 = 1;
/// Signature discriminator only; not an `ObjectType` or control registry entry.
pub const CANDIDATE_OBJECT_TYPE: u8 = 10;
pub const MAX_TBS_LEN: usize = 4 * 1024;
pub const MAX_GRANTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsSubject {
    pub node_id: u16,
    pub identity_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Capability {
    Advertise = 1,
    PublicForward = 2,
    Replica = 4,
    /// Request registration, not write records or choose another node's name.
    Register = 8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capabilities(u8);

impl Capabilities {
    const CORE_ONLY: u8 =
        Capability::Advertise as u8 | Capability::PublicForward as u8 | Capability::Replica as u8;
    const KNOWN: u8 = Self::CORE_ONLY | Capability::Register as u8;

    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability as u8)
    }

    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability as u8 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsServiceGrant {
    pub subject: DnsSubject,
    pub capabilities: Capabilities,
}

/// Untrusted typed TBS. The type represents V1 only; the version is explicit on wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServicePolicy {
    pub net_id: [u8; 16],
    /// SHA-256 of the exact NetworkPolicy TBS, not its sequence or prefix.
    pub policy_digest: [u8; 32],
    pub sequence: u64,
    /// UTC Unix microseconds, as in NetworkPolicy.
    pub issued_at: u64,
    pub expires: u64,
    /// Strictly ascending NodeID, at most one explicit generation per slot.
    pub grants: Vec<DnsServiceGrant>,
}

impl DnsServicePolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.net_id == [0; 16] || self.policy_digest == [0; 32] {
            return Err(Error::Invalid("network/policy binding"));
        }
        if self.sequence == 0 || self.issued_at >= self.expires {
            return Err(Error::Invalid("sequence/time window"));
        }
        if self.grants.len() > MAX_GRANTS {
            return Err(Error::TooLarge);
        }
        let mut previous = 0;
        for grant in &self.grants {
            let DnsSubject {
                node_id,
                identity_generation,
            } = grant.subject;
            if !valid_node_id(node_id) || identity_generation == 0 {
                return Err(Error::Invalid("node slot/generation"));
            }
            if previous >= node_id {
                return Err(Error::Invalid("grant order/duplicate node"));
            }
            previous = node_id;
            let bits = grant.capabilities.0;
            if bits == 0 || bits & !Capabilities::KNOWN != 0 {
                return Err(Error::Invalid("capability mask"));
            }
            if bits & Capabilities::CORE_ONLY != 0 && node_id & 0xff != 1 {
                return Err(Error::Invalid("service capability requires Core slot"));
            }
        }
        Ok(())
    }

    pub fn encode_tbs(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        map(&mut out, 7);
        uint(&mut out, 0);
        uint(&mut out, SCHEMA_VERSION);
        uint(&mut out, 1);
        bytes(&mut out, &self.net_id);
        uint(&mut out, 2);
        bytes(&mut out, &self.policy_digest);
        uint(&mut out, 3);
        uint(&mut out, self.sequence);
        uint(&mut out, 4);
        uint(&mut out, self.issued_at);
        uint(&mut out, 5);
        uint(&mut out, self.expires);
        uint(&mut out, 6);
        array(&mut out, self.grants.len() as u64);
        for grant in &self.grants {
            array(&mut out, 3);
            uint(&mut out, u64::from(grant.subject.node_id));
            uint(&mut out, grant.subject.identity_generation);
            uint(&mut out, u64::from(grant.capabilities.0));
        }
        if out.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Decode one complete canonical TBS; verifiers must sign/verify the exact raw bytes.
    pub fn decode_tbs(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { b: raw, i: 0 };
        r.container(5, 7)?;
        r.key(0)?;
        if r.uint()? != SCHEMA_VERSION {
            return Err(Error::Invalid("schema version"));
        }
        r.key(1)?;
        let net_id = r.fixed::<16>()?;
        r.key(2)?;
        let policy_digest = r.fixed::<32>()?;
        r.key(3)?;
        let sequence = r.uint()?;
        r.key(4)?;
        let issued_at = r.uint()?;
        r.key(5)?;
        let expires = r.uint()?;
        r.key(6)?;
        let count = r.array_len(MAX_GRANTS)?;
        let mut grants = Vec::with_capacity(count);
        for _ in 0..count {
            r.container(4, 3)?;
            let node_id = u16::try_from(r.uint()?).map_err(|_| Error::Invalid("node id"))?;
            let identity_generation = r.uint()?;
            let bits = u8::try_from(r.uint()?).map_err(|_| Error::Invalid("capability mask"))?;
            grants.push(DnsServiceGrant {
                subject: DnsSubject {
                    node_id,
                    identity_generation,
                },
                capabilities: Capabilities(bits),
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
            grants,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn signature_input(raw_tbs: &[u8]) -> Result<Vec<u8>, Error> {
        if raw_tbs.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        dns_authority::signature_input(raw_tbs, CANDIDATE_OBJECT_TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> Vec<u8> {
        concat!(
            "a7 00 01 01 50 ",
            "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ",
            "02 58 20 ",
            "02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 ",
            "02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 ",
            "03 01 04 0a 05 14 06 82 83 01 01 05 83 02 03 08",
        )
        .split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
    }

    #[test]
    fn fixed_canonical_and_signature_vector() {
        let raw = vector();
        let policy = DnsServicePolicy::decode_tbs(&raw).unwrap();
        assert_eq!(
            policy.grants[0].capabilities,
            Capabilities::default()
                .with(Capability::Advertise)
                .with(Capability::Replica)
        );
        assert_eq!(policy.grants[1].subject.identity_generation, 3);
        assert_eq!(policy.encode_tbs().unwrap(), raw);
        let mut message = b"BOREAS-MGMT-OBJECT\0\x00\x01\x0a\0\0\0\0\0\0\0\x48".to_vec();
        message.extend_from_slice(&raw);
        assert_eq!(DnsServicePolicy::signature_input(&raw).unwrap(), message);
    }

    #[test]
    fn rejects_noncanonical_ambiguous_or_unbounded_objects() {
        let raw = vector();
        for (offset, value) in [
            (2, 2),     // unknown schema
            (21, 1),    // duplicate map key
            (63, 0x9f), // indefinite grants
            (66, 0),    // zero generation
            (67, 16),   // unknown capability
            (69, 1),    // duplicate NodeID, even with another generation
            (69, 0),    // reserved NodeID
            (71, 2),    // non-Core slot with public-forward capability
            (71, 0),    // empty grant
        ] {
            let mut bad = raw.clone();
            bad[offset] = value;
            assert!(
                DnsServicePolicy::decode_tbs(&bad).is_err(),
                "offset {offset}"
            );
        }
        let mut bad = raw.clone();
        bad.splice(64..72, [0x83, 2, 3, 8, 0x83, 1, 1, 5]);
        assert!(DnsServicePolicy::decode_tbs(&bad).is_err());
        for (range, replacement) in [(2..3, [0x18, 1]), (63..64, [0x98, 129])] {
            let mut bad = raw.clone();
            bad.splice(range, replacement);
            assert!(DnsServicePolicy::decode_tbs(&bad).is_err());
        }
        for end in 0..raw.len() {
            assert!(DnsServicePolicy::decode_tbs(&raw[..end]).is_err());
        }
        let mut trailing = raw;
        trailing.push(0);
        assert!(DnsServicePolicy::decode_tbs(&trailing).is_err());
        let oversized = vec![0; MAX_TBS_LEN + 1];
        assert_eq!(
            DnsServicePolicy::decode_tbs(&oversized),
            Err(Error::TooLarge)
        );
        assert_eq!(
            DnsServicePolicy::signature_input(&oversized),
            Err(Error::TooLarge)
        );
    }
}
