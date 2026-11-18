//! Bounded, **test-only model** of revocation entries carried in
//! `StatusSnapshot.revocations` (candidate v1).
//!
//! This module is schema only: no clock, no cryptography and no decision about which
//! live handle to close. The payload it defines travels inside the existing opaque
//! `StatusSnapshot.revocations` byte string, so every entry is covered by the
//! enclosing object's Ed25519 and ML-DSA signatures over the exact TBS bytes. Nothing
//! here verifies a signature, and nothing here is an authority proof: a
//! `StatusSnapshot` is signed only by the network `StatusSigner`, which is **not**
//! the `IdentityAuthority`, `NetworkRoot`, `RouteAuthority` or a Core's
//! `CoreOperationalKey` ([master plan §3.4](../../../docs/plans/BOREAS-MASTER-PLAN-v1.11.0.md)).
//! The only consumer, `boreas_pki::status_store`, keeps every revocation entry
//! fail-closed in production (`StatusStore::open` authorizes no class) and exposes
//! the accepting path only to crate tests. There is no daemon enablement here.
//!
//! Shape (canonical deterministic CBOR, unsigned integer keys, ascending):
//!
//! ```text
//! payload = {0: version(1), 1: [entry*]}      ; entry count <= MAX_REVOCATION_ENTRIES
//! entry   = {0: class,               ; 1 Identity | 2 Core | 3 Route | 4 Direct
//!            1: origin_core,          ; 0 authority-issued, 1..=16 core-scoped
//!            2: node_id,              ; permanent overlay node slot
//!            3: identity_generation,  ; >= 1
//!            4: target_id,            ; class-specific; 0 when the class has none
//!            5: epoch,                ; >= 1, monotone per scope key
//!            6: reason}               ; <= 255
//! ```
//!
//! Schema rules (structural only, never an issuer proof):
//!
//! - `Identity` and `Route` entries are authority-issued, so `origin_core` must be 0.
//! - `Core` entries are core-scoped, so `origin_core` must be the home core of
//!   `node_id`. This prevents a Core-class entry from naming another Core's node,
//!   but it does not prove that the `NetworkRoot` approved the entry.
//! - `Direct` is reserved and rejected by this version with
//!   [`Error::DirectIssuerUnverifiable`]. The subject's home Core is **not** the
//!   issuer of its `DirectGrant`: a roaming Core may sign a grant that covers the
//!   same subject, and this schema carries no grant-issuer evidence. Binding
//!   `origin_core` to `home_core_id` would therefore mislabel a roaming Core's
//!   decision as the home Core's. Direct-grant revocation must wait for a
//!   per-authority `DirectRevocation` object (or equivalent per-grant issuer proof).
//! - Only `Route` uses `target_id`: 0 means every prefix of the subject, any other
//!   value names one route-prefix id. `Identity` and `Core` require 0.
//!
//! Entries are unique and strictly ascending by `(class, origin_core, node_id,
//! identity_generation)`, so one payload never carries two decisions for one scope.
//! `epoch` is the per-scope watermark: a consumer keeps the highest epoch it has
//! accepted and rejects a lower one (see `docs/protocol/revocations-v1.md`). This is
//! a model of the merge rule, not a runtime claim: the store does not persist a
//! revocation watermark.
//!
//! An empty payload is exactly the zero-length byte string; encoding an explicitly
//! empty entry array is not canonical and is rejected. Unknown classes, unknown
//! versions, non-canonical encodings, trailing bytes and permission violations all
//! fail closed with [`Error`]; a caller must treat any decode error as "no
//! revocation information may be consumed".

use core::fmt;

/// Version of the revocation payload schema.
pub const REVOCATION_SCHEMA_VERSION: u64 = 1;
/// Maximum encoded payload size accepted by this schema.
pub const MAX_REVOCATION_PAYLOAD_BYTES: usize = 8 * 1024;
/// Maximum number of entries in one payload.
pub const MAX_REVOCATION_ENTRIES: usize = 64;
/// Highest overlay home-Core slot id.
const MAX_HOME_CORE_ID: u8 = 16;
/// Number of fields in one entry map.
const ENTRY_FIELDS: u64 = 7;

/// Schema error. Every variant means "consume nothing from this payload".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Payload exceeds [`MAX_REVOCATION_PAYLOAD_BYTES`].
    TooLarge,
    /// Payload carries more than [`MAX_REVOCATION_ENTRIES`] entries.
    TooManyEntries,
    /// Encoded bytes end early.
    Truncated,
    /// Bytes remain after the payload item.
    TrailingBytes,
    /// Encoding is valid CBOR but not this schema's canonical form.
    NotCanonical,
    /// Wrong CBOR major type, wrong map size or an unknown field.
    UnsupportedType,
    /// Payload version is not [`REVOCATION_SCHEMA_VERSION`].
    UnknownVersion,
    /// `class` is not one of the four defined classes.
    UnknownClass,
    /// `Direct` entries are reserved but cannot be accepted: this schema has no
    /// evidence that the grant issuer was the node's home Core (or any other
    /// particular Core), so binding `origin_core` to `home_core_id` would claim an
    /// authority the bytes do not prove.
    DirectIssuerUnverifiable,
    /// `origin_core` is outside the values its class permits.
    InvalidOriginCore,
    /// `node_id` is not a permanent overlay node slot.
    InvalidNodeId,
    /// `identity_generation` is zero.
    InvalidGeneration,
    /// `epoch` is zero.
    InvalidEpoch,
    /// `reason` is above 255.
    InvalidReason,
    /// Two entries share one scope key.
    DuplicateScope,
    /// The class/scope combination is not permitted by the schema's issuer rules.
    ScopeNotPermitted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Class of the authority a revocation entry names.
///
/// The class decides both which identifiers the entry may clear and what
/// `origin_core` must be; see the module documentation. The wire code is reserved
/// for `Direct`, but v1 refuses every `Direct` entry because this schema cannot
/// identify the issuer of a `DirectGrant`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum IssuerClass {
    /// Authority-issued identity revocation: every binding of the subject.
    Identity = 1,
    /// Revocation limited to the named node's own Core; not issuer proof.
    Core = 2,
    /// Authority-issued route revocation: route prefixes only.
    Route = 3,
    /// Reserved wire code for direct-grant revocation; rejected by v1 because the
    /// subject's home Core is not necessarily the grant issuer.
    Direct = 4,
}
impl IssuerClass {
    /// Every class, in payload order.
    pub const ALL: [Self; 4] = [Self::Identity, Self::Core, Self::Route, Self::Direct];

    /// Decode a class code.
    pub fn from_code(code: u64) -> Result<Self, Error> {
        Ok(match code {
            1 => Self::Identity,
            2 => Self::Core,
            3 => Self::Route,
            4 => Self::Direct,
            _ => return Err(Error::UnknownClass),
        })
    }

    /// Wire code of this class.
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// `true` only for classes this schema version can consume.
    ///
    /// `Direct` is reserved but unconsumable: the home Core of `node_id` is not the
    /// issuer of the node's direct grants, and a roaming Core may sign a grant for
    /// the same node. Accepting `Direct` would therefore invent authority evidence
    /// the payload does not carry.
    pub const fn is_consumable(self) -> bool {
        !matches!(self, Self::Direct)
    }

    /// `true` for the class that must name the node's home core.
    pub const fn is_core_scoped(self) -> bool {
        matches!(self, Self::Core)
    }

    /// `true` only for the class whose `target_id` is meaningful.
    pub const fn uses_target_id(self) -> bool {
        matches!(self, Self::Route)
    }
}

/// One bounded revocation decision for one scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationEntry {
    /// Issuing authority class.
    pub class: IssuerClass,
    /// Authority-issued (0) or the scoped home Core id (1..=16).
    pub origin_core: u8,
    /// Permanent overlay node slot.
    pub node_id: u16,
    /// Identity generation the decision applies to; never 0.
    pub identity_generation: u64,
    /// Class-specific target id; 0 when the class has none.
    pub target_id: u64,
    /// Per-scope monotone watermark; never 0.
    pub epoch: u64,
    /// Bounded audit code, 0 = unspecified.
    pub reason: u8,
}

impl RevocationEntry {
    /// Checked constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: IssuerClass,
        origin_core: u8,
        node_id: u16,
        identity_generation: u64,
        target_id: u64,
        epoch: u64,
        reason: u8,
    ) -> Result<Self, Error> {
        let entry = Self {
            class,
            origin_core,
            node_id,
            identity_generation,
            target_id,
            epoch,
            reason,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Scope key used for ordering and uniqueness.
    pub const fn scope_key(&self) -> (u64, u8, u16, u64) {
        (
            self.class.code(),
            self.origin_core,
            self.node_id,
            self.identity_generation,
        )
    }

    /// Enforce the schema's structural rules.
    ///
    /// This is not an issuer check. In particular, `Direct` is refused instead of
    /// treating `home_core_id(node_id)` as the grant issuer.
    pub fn validate(&self) -> Result<(), Error> {
        let Some(home_core) = home_core_id(self.node_id) else {
            return Err(Error::InvalidNodeId);
        };
        if self.identity_generation == 0 {
            return Err(Error::InvalidGeneration);
        }
        if self.epoch == 0 {
            return Err(Error::InvalidEpoch);
        }
        if !self.class.is_consumable() {
            return Err(Error::DirectIssuerUnverifiable);
        }
        if self.class.is_core_scoped() {
            if self.origin_core == 0 || self.origin_core > MAX_HOME_CORE_ID {
                return Err(Error::InvalidOriginCore);
            }
            if self.origin_core != home_core {
                return Err(Error::ScopeNotPermitted);
            }
        } else if self.origin_core != 0 {
            return Err(Error::InvalidOriginCore);
        }
        if !self.class.uses_target_id() && self.target_id != 0 {
            return Err(Error::ScopeNotPermitted);
        }
        Ok(())
    }

    /// Canonical CBOR bytes of this single entry.
    ///
    /// A consumer hashes these exact bytes to detect two different decisions that
    /// claim the same scope and epoch.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        encode_entry(self, &mut out);
        Ok(out)
    }
}

/// A decoded, unique, scope-ordered set of revocation entries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationPayload {
    entries: Vec<RevocationEntry>,
}

impl RevocationPayload {
    /// Build a payload, sorting entries by scope key and refusing duplicates.
    pub fn new(mut entries: Vec<RevocationEntry>) -> Result<Self, Error> {
        if entries.len() > MAX_REVOCATION_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        for entry in &entries {
            entry.validate()?;
        }
        entries.sort_by_key(|left| left.scope_key());
        let mut previous: Option<(u64, u8, u16, u64)> = None;
        for entry in &entries {
            let key = entry.scope_key();
            if previous == Some(key) {
                return Err(Error::DuplicateScope);
            }
            previous = Some(key);
        }
        Ok(Self { entries })
    }

    /// The canonical empty payload.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Decoded entries in scope order.
    pub fn entries(&self) -> &[RevocationEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when this payload carries no decision.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Canonical encoding. An empty payload encodes to zero bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        enc_head(5, 2, &mut out); // payload map of two fields
        enc_head(0, 0, &mut out); // key 0: version
        enc_head(0, REVOCATION_SCHEMA_VERSION, &mut out);
        enc_head(0, 1, &mut out); // key 1: entries
        enc_head(
            4,
            u64::try_from(self.entries.len()).map_err(|_| Error::TooManyEntries)?,
            &mut out,
        );
        for entry in &self.entries {
            encode_entry(entry, &mut out);
        }
        if out.len() > MAX_REVOCATION_PAYLOAD_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Strict canonical decode. `b""` is the canonical empty payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self::empty());
        }
        if bytes.len() > MAX_REVOCATION_PAYLOAD_BYTES {
            return Err(Error::TooLarge);
        }
        crate::validate_deterministic_cbor(bytes, 8, MAX_REVOCATION_PAYLOAD_BYTES)
            .map_err(|_| Error::NotCanonical)?;
        let mut reader = Reader {
            bytes,
            position: 0,
        };
        let (major, fields) = reader.head()?;
        if major != 5 || fields != 2 {
            return Err(Error::UnsupportedType);
        }
        if reader.field_key()? != 0 {
            return Err(Error::NotCanonical);
        }
        let version = reader.uint()?;
        if version != REVOCATION_SCHEMA_VERSION {
            return Err(Error::UnknownVersion);
        }
        if reader.field_key()? != 1 {
            return Err(Error::NotCanonical);
        }
        let (major, count) = reader.head()?;
        if major != 4 {
            return Err(Error::UnsupportedType);
        }
        if count > MAX_REVOCATION_ENTRIES as u64 {
            return Err(Error::TooManyEntries);
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            entries.push(decode_entry(&mut reader)?);
        }
        if reader.position != bytes.len() {
            return Err(Error::TrailingBytes);
        }
        let payload = Self::new(entries)?;
        // The decoded form must re-encode to the exact signed bytes: this rejects
        // unsorted entries, non-shortest integers and any other canonicality drift.
        if payload.encode()?.as_slice() != bytes {
            return Err(Error::NotCanonical);
        }
        Ok(payload)
    }
}

/// Home Core slot of a permanent overlay node id.
fn home_core_id(node_id: u16) -> Option<u8> {
    let home_core = (node_id >> 8) + 1;
    if !(1..=u16::from(MAX_HOME_CORE_ID)).contains(&home_core) {
        return None;
    }
    let octet = (node_id & 0xff) as u8;
    if octet == 1 || (2..=251).contains(&octet) {
        u8::try_from(home_core).ok()
    } else {
        None
    }
}

fn enc_head(major: u8, value: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    if value < 24 {
        out.push(prefix | value as u8);
    } else if value <= 0xff {
        out.push(prefix | 24);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(prefix | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xffff_ffff {
        out.push(prefix | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_entry(entry: &RevocationEntry, out: &mut Vec<u8>) {
    enc_head(5, ENTRY_FIELDS, out);
    let fields: [(u64, u64); 7] = [
        (0, entry.class.code()),
        (1, u64::from(entry.origin_core)),
        (2, u64::from(entry.node_id)),
        (3, entry.identity_generation),
        (4, entry.target_id),
        (5, entry.epoch),
        (6, u64::from(entry.reason)),
    ];
    for (key, value) in fields {
        enc_head(0, key, out);
        enc_head(0, value, out);
    }
}

fn decode_entry(reader: &mut Reader<'_>) -> Result<RevocationEntry, Error> {
    let (major, fields) = reader.head()?;
    if major != 5 || fields != ENTRY_FIELDS {
        return Err(Error::UnsupportedType);
    }
    let mut values = [0u64; ENTRY_FIELDS as usize];
    for (index, slot) in values.iter_mut().enumerate() {
        if reader.field_key()? != index as u64 {
            return Err(Error::NotCanonical);
        }
        *slot = reader.uint()?;
    }
    let entry = RevocationEntry {
        class: IssuerClass::from_code(values[0])?,
        origin_core: u8::try_from(values[1]).map_err(|_| Error::InvalidOriginCore)?,
        node_id: u16::try_from(values[2]).map_err(|_| Error::InvalidNodeId)?,
        identity_generation: values[3],
        target_id: values[4],
        epoch: values[5],
        reason: u8::try_from(values[6]).map_err(|_| Error::InvalidReason)?,
    };
    entry.validate()?;
    Ok(entry)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Truncated)?;
        let slice = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    fn head(&mut self) -> Result<(u8, u64), Error> {
        let byte = *self.take(1)?.first().ok_or(Error::Truncated)?;
        let major = byte >> 5;
        let info = byte & 31;
        let value = match info {
            0..=23 => u64::from(info),
            24 => {
                let short = u64::from(*self.take(1)?.first().ok_or(Error::Truncated)?);
                if short < 24 {
                    return Err(Error::NotCanonical);
                }
                short
            }
            25 => {
                let raw = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
                if value <= 0xff {
                    return Err(Error::NotCanonical);
                }
                value
            }
            26 => {
                let raw = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                if value <= 0xffff {
                    return Err(Error::NotCanonical);
                }
                value
            }
            27 => {
                let raw = self.take(8)?;
                let value = u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                if value <= u64::from(u32::MAX) {
                    return Err(Error::NotCanonical);
                }
                value
            }
            _ => return Err(Error::UnsupportedType),
        };
        Ok((major, value))
    }

    /// One unsigned-integer map key.
    fn field_key(&mut self) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(Error::UnsupportedType);
        }
        Ok(value)
    }

    /// One unsigned integer value.
    fn uint(&mut self) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(Error::UnsupportedType);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(node_id: u16, generation: u64, epoch: u64) -> RevocationEntry {
        RevocationEntry::new(IssuerClass::Identity, 0, node_id, generation, 0, epoch, 1).unwrap()
    }

    fn core_entry(core: u8, node: u16, generation: u64, epoch: u64) -> RevocationEntry {
        RevocationEntry::new(IssuerClass::Core, core, node, generation, 0, epoch, 2).unwrap()
    }

    /// Hand-built canonical CBOR for one entry with arbitrary (possibly invalid)
    /// field values, so decoder rejections can be tested.
    fn raw_entry(fields: [u64; 7]) -> Vec<u8> {
        let mut out = Vec::new();
        enc_head(5, ENTRY_FIELDS, &mut out);
        for (key, value) in fields.iter().enumerate() {
            enc_head(0, key as u64, &mut out);
            enc_head(0, *value, &mut out);
        }
        out
    }

    fn raw_payload(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        enc_head(5, 2, &mut out);
        enc_head(0, 0, &mut out);
        enc_head(0, 1, &mut out);
        enc_head(0, 1, &mut out);
        enc_head(4, entries.len() as u64, &mut out);
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out
    }

    #[test]
    fn empty_payload_is_the_zero_length_string() {
        assert_eq!(RevocationPayload::empty().encode().unwrap(), Vec::<u8>::new());
        let decoded = RevocationPayload::decode(b"").unwrap();
        assert!(decoded.is_empty());
        assert_eq!(decoded.len(), 0);
        // An explicitly encoded empty array is not canonical.
        let mut explicit = Vec::new();
        enc_head(5, 2, &mut explicit);
        enc_head(0, 0, &mut explicit);
        enc_head(0, 1, &mut explicit);
        enc_head(0, 1, &mut explicit);
        enc_head(4, 0, &mut explicit);
        assert_eq!(
            RevocationPayload::decode(&explicit),
            Err(Error::NotCanonical)
        );
    }

    #[test]
    fn roundtrip_orders_entries_and_covers_supported_classes() {
        let route = RevocationEntry::new(IssuerClass::Route, 0, 0x0207, 4, 9, 3, 7).unwrap();
        let entries = vec![route, identity(0x0207, 4, 3), core_entry(3, 0x0207, 4, 3)];
        let payload = RevocationPayload::new(entries).unwrap();
        assert_eq!(payload.entries()[0].class, IssuerClass::Identity);
        assert_eq!(payload.entries()[1].class, IssuerClass::Core);
        assert_eq!(payload.entries()[2].class, IssuerClass::Route);
        let bytes = payload.encode().unwrap();
        assert_eq!(RevocationPayload::decode(&bytes).unwrap(), payload);
        assert_eq!(payload.entries()[2].target_id, 9);
        let mut duplicate = payload.entries().to_vec();
        duplicate.push(identity(0x0207, 4, 3));
        assert_eq!(RevocationPayload::new(duplicate), Err(Error::DuplicateScope));
    }

    #[test]
    fn permission_rules_reject_core_crossing_and_missing_targets() {
        // A Core-class entry may only name a node of its own home core.
        assert_eq!(
            RevocationEntry::new(IssuerClass::Core, 3, 0x0307, 1, 0, 1, 0),
            Err(Error::ScopeNotPermitted)
        );
        // Direct is unconsumable even when origin_core equals the node's home core
        // (node 0x0207 has home core 3). The old rule treated that equality as
        // issuer evidence, which is exactly the forbidden home-Core inference.
        assert_eq!(
            RevocationEntry::new(IssuerClass::Direct, 3, 0x0207, 1, 0, 1, 0),
            Err(Error::DirectIssuerUnverifiable)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Direct, 4, 0x0207, 1, 0, 1, 0),
            Err(Error::DirectIssuerUnverifiable)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 4, 0x0207, 1, 0, 1, 0),
            Err(Error::InvalidOriginCore)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Route, 3, 0x0207, 1, 9, 1, 0),
            Err(Error::InvalidOriginCore)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0x0207, 1, 5, 1, 0),
            Err(Error::ScopeNotPermitted)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Core, 0, 0x0207, 1, 0, 1, 0),
            Err(Error::InvalidOriginCore)
        );
        // Invalid node slots, zero generation and zero epoch.
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0, 1, 0, 1, 0),
            Err(Error::InvalidNodeId)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0x02fc, 1, 0, 1, 0),
            Err(Error::InvalidNodeId)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0x2007, 1, 0, 1, 0),
            Err(Error::InvalidNodeId)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0x0207, 0, 0, 1, 0),
            Err(Error::InvalidGeneration)
        );
        assert_eq!(
            RevocationEntry::new(IssuerClass::Identity, 0, 0x0207, 1, 0, 0, 0),
            Err(Error::InvalidEpoch)
        );
    }

    #[test]
    fn decoder_rejects_unknown_class_and_version() {
        // class 5 is undefined.
        let bytes = raw_payload(&[raw_entry([5, 0, 0x0207, 1, 0, 1, 0])]);
        assert_eq!(
            RevocationPayload::decode(&bytes),
            Err(Error::UnknownClass)
        );
        // class 4 (Direct) is recognised but refused: origin_core 3 is the node's
        // home core, yet that equality is not grant-issuer evidence.
        let direct = raw_payload(&[raw_entry([4, 3, 0x0207, 1, 0, 1, 0])]);
        assert_eq!(
            RevocationPayload::decode(&direct),
            Err(Error::DirectIssuerUnverifiable)
        );
        let mut wrong_version = Vec::new();
        enc_head(5, 2, &mut wrong_version);
        enc_head(0, 0, &mut wrong_version);
        enc_head(0, 2, &mut wrong_version);
        enc_head(0, 1, &mut wrong_version);
        enc_head(4, 0, &mut wrong_version);
        assert_eq!(
            RevocationPayload::decode(&wrong_version),
            Err(Error::UnknownVersion)
        );
    }

    #[test]
    fn decoder_rejects_unsorted_trailing_and_non_shortest_forms() {
        let first = raw_entry([1, 0, 0x0207, 1, 0, 1, 0]);
        let second = raw_entry([1, 0, 0x0208, 1, 0, 1, 0]);
        let unsorted = raw_payload(&[second, first.clone()]);
        assert!(RevocationPayload::decode(&unsorted).is_err());

        let mut trailing = raw_payload(std::slice::from_ref(&first));
        trailing.push(0);
        assert_eq!(
            RevocationPayload::decode(&trailing),
            Err(Error::NotCanonical)
        );

        // Non-shortest integer encoding of the version value.
        let mut non_shortest = Vec::new();
        enc_head(5, 2, &mut non_shortest);
        enc_head(0, 0, &mut non_shortest);
        non_shortest.extend_from_slice(&[0x18, 0x01]);
        enc_head(0, 1, &mut non_shortest);
        enc_head(4, 0, &mut non_shortest);
        assert_eq!(
            RevocationPayload::decode(&non_shortest),
            Err(Error::NotCanonical)
        );

        // Truncated entry map.
        let mut truncated = raw_payload(&[first]);
        truncated.truncate(truncated.len() - 2);
        assert!(RevocationPayload::decode(&truncated).is_err());
    }

    #[test]
    fn decoder_rejects_too_many_entries_and_oversize_payloads() {
        let one = raw_entry([1, 0, 0x0207, 1, 0, 1, 0]);
        let mut counted = Vec::new();
        enc_head(5, 2, &mut counted);
        enc_head(0, 0, &mut counted);
        enc_head(0, 1, &mut counted);
        enc_head(0, 1, &mut counted);
        enc_head(4, MAX_REVOCATION_ENTRIES as u64 + 1, &mut counted);
        for _ in 0..MAX_REVOCATION_ENTRIES + 1 {
            counted.extend_from_slice(&one);
        }
        assert_eq!(
            RevocationPayload::decode(&counted),
            Err(Error::TooManyEntries)
        );
        let oversized = vec![0u8; MAX_REVOCATION_PAYLOAD_BYTES + 1];
        assert_eq!(
            RevocationPayload::decode(&oversized),
            Err(Error::TooLarge)
        );

        // A full payload of MAX entries is accepted and stays inside the bound.
        let many = (0..MAX_REVOCATION_ENTRIES).map(|i| identity(0x0202 + i as u16, 1, 1));
        let payload = RevocationPayload::new(many.collect()).unwrap();
        assert_eq!(payload.len(), MAX_REVOCATION_ENTRIES);
        let bytes = payload.encode().unwrap();
        assert!(bytes.len() <= MAX_REVOCATION_PAYLOAD_BYTES);
        assert_eq!(RevocationPayload::decode(&bytes).unwrap(), payload);
    }

    #[test]
    fn canonical_bytes_are_stable_per_entry() {
        let entry = core_entry(3, 0x0207, 9, 4);
        let bytes = entry.canonical_bytes().unwrap();
        assert_eq!(bytes, entry.canonical_bytes().unwrap());
        let other = core_entry(3, 0x0207, 9, 5);
        assert_ne!(bytes, other.canonical_bytes().unwrap());
        // The scope key ignores epoch/reason so a same-scope decision is detectable.
        assert_eq!(entry.scope_key(), other.scope_key());
        assert_eq!(entry.scope_key(), (2, 3, 0x0207, 9));
    }
}
