//! Deterministic convergence state machine (`G-CONVERGE` core) over
//! already-verified directory record envelopes, implementing the §3.3
//! three-object model of the master plan (v1.11.0).
//!
//! # Scope and non-goals
//!
//! The pure convergence engine itself performs NO cryptography: it does not
//! verify signatures, certificate/permission chains, or that the caller-supplied
//! `content_hash` is really the digest of the record's canonical TBS. The
//! production ingest path is not unverified: [`DirectoryIngest`] delegates to
//! [`ObjectVerifier`], and the reviewed `PkiObjectVerifier` binds
//! `boreas_pki::management::ManagementTrust`, which really verifies both
//! signatures over the exact signed bytes. Callers MUST supply envelopes whose
//! original signed bytes have already passed that full verification — for
//! `AttachmentLease` that means BOTH the node's primary signature and the
//! attached Core's countersignature (§3.3 requires Edge nodes to verify the
//! complete chain and dual signatures locally over the unmodified original
//! bytes; §5.4 additionally requires Ed25519 and ML-DSA over the same bytes to
//! both pass). [`WriterProof`] merely *records* which signer structure the
//! caller claims to have verified; it proves nothing by itself.
//!
//! `content_hash` is content identity, not envelope identity: it MUST be
//! `SHA-256` over the exact canonical TBS bytes (the `object_id` rule), never
//! over the signature envelope. Re-signing the same TBS changes signature
//! bytes only and MUST remain a duplicate, not an equivocation.
//!
//! Also out of scope for the pure [`DirectoryConvergence`] engine: wire encoding
//! (§5.4 structures are candidates, not a frozen wire format), persistence,
//! revocation/freshness filtering, and anti-entropy page transport. Paging and
//! original-byte evidence are provided above it by [`DirectoryIngest`],
//! [`page_snapshot`] and [`SignedObjectPage`]; they are not absent. This engine
//! has no time fields and
//! never reads a clock: §3.4 freshness depends only on signed
//! `issued_at` / `next_update` (and per-object `not_before` / `expires`),
//! so the caller MUST time-filter with trusted UTC before delivery and
//! must never treat (re-)delivery here as freshness evidence. The
//! cross-object rule of §3.2 — a lease is usable only when its
//! `identity_generation` matches the node's current `NodeIdentity` — is
//! likewise a read-time join for the upper layer: the three kinds
//! converge independently here (§3.3 keeps their version spaces
//! orthogonal), because rejecting on arrival-time cross-object state
//! would make the outcome depend on delivery order.
//!
//! # Verification gate, evidence and paging
//!
//! §3.3 also requires that only locally verified original bytes ever enter
//! convergence, that a same-version fork preserve BOTH original signed
//! objects, and that synchronisation be paged and bounded. Those duties need
//! the raw objects, so they live above the pure engine:
//!
//! * [`ObjectVerifier`] is the consumer API the trust layer implements —
//!   `PkiObjectVerifier` (feature `openssl-inner-tls`) binds
//!   `boreas_pki::management::ManagementTrust`, which verifies both signatures,
//!   the issuer permission chain, canonical encoding, scope, freshness and
//!   per-slot replay over the exact signed bytes. Nothing here decides trust
//!   from an unauthenticated frame field.
//! * [`DirectoryIngest`] is the only supported entry point: it refuses an
//!   object before convergence when verification fails, isolates a
//!   verifier-reported fork, and records bounded [`ForkEvidence`] holding both
//!   original byte strings. Persisting that evidence and raising the highest
//!   severity alert remain the caller's §3.3 duty.
//! * [`page_snapshot`] / [`DirectoryIngest::ingest_page`] implement bounded
//!   anti-entropy over the exact original signed objects, carried on the
//!   candidate `DirectoryPage` control body (`SignedObjectPage::encode_wire`),
//!   with every receiver re-verifying locally instead of trusting its attached
//!   Core.
//!
//! The periodic 5 s cadence, durable evidence storage and alerting remain
//! upper-layer responsibilities.
//!
//! # Version and epoch model (§3.3, §5.4)
//!
//! Each kind has its own composite version key; sequence spaces are
//! never compared across kinds. Within a kind, versions order
//! lexicographically, generation first:
//!
//! | Kind | Version key | Epoch (poison scope) | Within-epoch order |
//! |---|---|---|---|
//! | `NodeIdentity` | `(NodeID, identity_generation)` | `identity_generation` | — (one version per epoch) |
//! | `AttachmentLease` | `(NodeID, identity_generation, attach_generation)` | `identity_generation` | `attach_generation` |
//! | `CoreLsa` | `(core_id, core_generation, seq)` | `core_generation` | `seq` |
//!
//! # Writer model (§3.2, §3.3)
//!
//! * `NodeIdentity`: only the `IdentityAuthority`.
//! * `AttachmentLease`: primary signature by the node itself plus a
//!   countersignature by the *currently attached* Core named in the
//!   signed `target_core_id`. The target need NOT be the node's home
//!   Core — roaming leases are legitimate. `home_core_id` is permanently
//!   taken from the `NodeIdentity` record / `NodeID` encoding and never
//!   follows the current attachment (§3.2).
//! * `CoreLsa`: only that Core's own `CoreOperationalKey`.
//!
//! # Convergence contract
//!
//! Per `(kind, subject)` key the lexicographically highest version wins;
//! lower versions are `Stale` (generation rollback can never become
//! active); the same version with the same TBS hash (and lease target /
//! tombstone state) is an idempotent `Duplicate`; a different TBS hash at
//! the same version is equivocation (§3.3) and poisons its *epoch*: every
//! record of that epoch — including
//! an already-delivered higher within-epoch `seq` / `attach_generation`
//! top — is frozen out of the active view, and no higher within-epoch
//! version ever launders it. Only a strictly higher epoch (new
//! `identity_generation` issued by the `IdentityAuthority`, or new
//! `core_generation`) starts clean; the poisoned epoch remains listed in
//! the snapshot so replicas and operators can see it. A tombstone is an
//! ordinary top record: it hides the key from the active view and its
//! version becomes the anti-resurrection watermark. No arrival time,
//! local "already active" state, or other §3.5-forbidden tie-breaker
//! ever influences the outcome: any two replicas that accepted the same
//! structurally valid input set reach identical snapshots.
//!
//! # Local conventions NOT frozen by the master plan (pending ADR)
//!
//! The following are conservative local structure choices, explicitly
//! not wire format and not cryptographic evidence. They must not be
//! cited as protocol semantics until a Phase 0 ADR freezes them:
//!
//! * [`WriterProof`] itself: §5.4 wire encoding is still a candidate.
//!   `boreas-proto::messages::SignedObject` already carries a signer vector
//!   (a lease has Primary + CoSign signers), while
//!   `boreas-proto::objects::ManagementObject` carries a single
//!   `issuer_key_id`; how those signer identities are projected into this
//!   local directory key/carrier remains unfrozen. Existing
//!   `ManagementTrust` signature verification is real and is not replaced by
//!   this field. The former `writer == 0` sentinel for the
//!   `IdentityAuthority` was a local convention and has been removed rather
//!   than entrenched.
//! * Generation components must be `>= 1`. §5.4 states this only for
//!   `identity_generation` ("从 1 单调递增"); extending it to
//!   `attach_generation`, `core_generation` and `CoreLsa.seq` follows
//!   the candidate validation in `boreas-proto::objects` and is adopted
//!   fail-closed pending the Phase 0 freeze.
//! * When the same TBS is re-signed into different exact envelopes, the
//!   lexicographically smallest envelope is retained. This keeps active
//!   snapshots arrival-order independent without treating signature bytes as
//!   content identity. Local convention pending ADR.
//! * The bounded per-key evidence window (`MAX_EVIDENCE_PER_KEY`) and
//!   poisoned-epoch window (`MAX_POISONED_EPOCHS_PER_KEY`). A fork proof
//!   concerning only versions that have aged out of the evidence window
//!   may fail to retroactively poison its epoch here; preserving and
//!   acting on full equivocation evidence is the upper layer's §3.3
//!   duty. (Evicting the *smallest* poisoned epoch is safe: it can only
//!   happen once the watermark has passed that epoch, so its records
//!   can never become active again.)
//! * Same-epoch re-issuance after a tombstone (a higher within-epoch
//!   version superseding a tombstone) is left to upper-layer generation
//!   / revocation policy; this module only guarantees watermark
//!   monotonicity. NodeID recycling per §3.2 works through a strictly
//!   higher `identity_generation`, which needs no such relaxation.
//! * Whether a higher epoch alone suffices to exit equivocation
//!   isolation, or must be gated on extra revocation/status evidence
//!   (e.g. §3.3's explicitly authorized generation bump after the old
//!   writer is isolated), is an upper-layer policy decision. This module
//!   implements epoch-scoped isolation and exposes poisoned epochs so
//!   the upper layer can gate activation further; it never clears a
//!   poisoned epoch.
//! * The snapshot `digest` is FNV-1a, a non-cryptographic consistency
//!   fingerprint for replica comparison only.
//! * The ingest-layer bounds — [`MAX_PAGE_OBJECTS`], [`MAX_PAGE_BYTES`],
//!   [`MAX_EVIDENCE_ENTRIES`] and [`MAX_EVIDENCE_BYTES`]. §3.3 fixes the 16 KiB
//!   object ceiling and requires bounded paging, not these exact numbers. A
//!   page is carried on the candidate `boreas-proto` `ControlType::DirectoryPage`
//!   body (16 KiB, at most `MAX_DIRECTORY_OBJECTS` envelopes), which is still a
//!   candidate rather than a frozen frame; the in-process [`SignedObjectPage`]
//!   is exactly that body's payload model.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use boreas_proto::messages::{DirectoryPage as ProtoDirectoryPage, SignedObject};

/// Highest valid Core identifier (§3.2: `home_core_id ∈ 1..=16`).
pub const MAX_CORE_ID: u16 = 16;

/// Per-record payload bound. Basis: §3.3 caps a single directory object
/// at 16 KiB (`DirectoryPage` anti-entropy bound). The smaller §5.4
/// Control-subtype body limits (`Lease` 4 KiB, `Lsa` 8 KiB) constrain
/// transport frames, not directory objects, and are not applied here.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Number of encodable NodeID subjects. Basis: 16 home Cores × 251 valid
/// VIP octets (Core `1` plus Edge `2..=251`) = 4016 (§3.2).
pub const MAX_NODE_SUBJECTS: usize = 4016;

/// Number of encodable `CoreLsa` subjects (one per Core, `1..=16`).
pub const MAX_CORE_LSA_KEYS: usize = 16;

/// Hard bound on distinct `(kind, subject)` keys: two node-keyed kinds
/// (`NodeIdentity`, `AttachmentLease`) over all NodeID subjects, plus one
/// `CoreLsa` per Core.
pub const MAX_KEYS: usize = MAX_NODE_SUBJECTS * 2 + MAX_CORE_LSA_KEYS;

/// Bounded per-key window of distinct version fingerprints kept solely
/// to detect equivocation at already-superseded versions. Local
/// convention pending ADR (see module docs); the largest versions are
/// retained, so the top record's fingerprint is never evicted while it
/// is top.
const MAX_EVIDENCE_PER_KEY: usize = 16;

/// Bounded per-key window of poisoned epochs retained for export. Local
/// convention pending ADR; the largest epochs are retained (see module
/// docs for why evicting the smallest is safe).
const MAX_POISONED_EPOCHS_PER_KEY: usize = 16;

/// The three single-writer directory object kinds of §3.3. Declaration
/// order is the deterministic sort order used by snapshots.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DirectoryObjectKind {
    NodeIdentity,
    AttachmentLease,
    CoreLsa,
}
impl DirectoryObjectKind {
    /// Fixed tag byte for the (non-cryptographic) consistency digest.
    const fn tag(self) -> u8 {
        match self {
            Self::NodeIdentity => 1,
            Self::AttachmentLease => 2,
            Self::CoreLsa => 3,
        }
    }
}

/// Composite version key of one record, exactly per the §3.3 table.
/// Ordering is lexicographic (generation first) *within* one kind;
/// versions of different kinds are never compared (§3.3 forbids mixing
/// sequence spaces). Every component must be `>= 1` (see module docs).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VersionKey {
    NodeIdentity {
        identity_generation: u64,
    },
    AttachmentLease {
        identity_generation: u64,
        attach_generation: u64,
    },
    CoreLsa {
        core_generation: u64,
        seq: u64,
    },
}
impl VersionKey {
    pub const fn kind(self) -> DirectoryObjectKind {
        match self {
            Self::NodeIdentity { .. } => DirectoryObjectKind::NodeIdentity,
            Self::AttachmentLease { .. } => DirectoryObjectKind::AttachmentLease,
            Self::CoreLsa { .. } => DirectoryObjectKind::CoreLsa,
        }
    }
    /// The generation component that scopes equivocation poisoning:
    /// `identity_generation` for `NodeIdentity` and `AttachmentLease`,
    /// `core_generation` for `CoreLsa`.
    pub const fn epoch(self) -> u64 {
        match self {
            Self::NodeIdentity {
                identity_generation,
            }
            | Self::AttachmentLease {
                identity_generation,
                ..
            } => identity_generation,
            Self::CoreLsa {
                core_generation, ..
            } => core_generation,
        }
    }
    /// `(epoch, within-epoch order)`; `NodeIdentity` has a single
    /// version per epoch, reported as `0`. Digest/test support only.
    const fn components(self) -> (u64, u64) {
        match self {
            Self::NodeIdentity {
                identity_generation,
            } => (identity_generation, 0),
            Self::AttachmentLease {
                identity_generation,
                attach_generation,
            } => (identity_generation, attach_generation),
            Self::CoreLsa {
                core_generation,
                seq,
            } => (core_generation, seq),
        }
    }
    const fn is_valid(self) -> bool {
        match self {
            Self::NodeIdentity {
                identity_generation,
            } => identity_generation >= 1,
            Self::AttachmentLease {
                identity_generation,
                attach_generation,
            } => identity_generation >= 1 && attach_generation >= 1,
            Self::CoreLsa {
                core_generation,
                seq,
            } => core_generation >= 1 && seq >= 1,
        }
    }
}

/// Signer structure the caller claims to have *already verified* over
/// the record's original signed bytes. This is a local in-memory
/// representation ONLY — not a wire format and not cryptographic
/// evidence (see module docs, pending ADR). The fail-closed structural
/// checks in [`DirectoryConvergence::apply`] verify that the claimed
/// structure matches the kind/subject/target; whether any signature
/// actually verifies is entirely the caller's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterProof {
    /// Signed by the `IdentityAuthority` (only legitimate for
    /// `NodeIdentity`).
    IdentityAuthority,
    /// `AttachmentLease` dual signature (§3.3): primary signature by the
    /// node itself (`node_signed`) plus countersignature by the
    /// currently attached Core (`countersigning_core_id`), which must
    /// equal the lease's signed `target_core_id` and may differ from
    /// the node's home Core (roaming).
    AttachmentLease {
        node_signed: bool,
        countersigning_core_id: Option<u8>,
    },
    /// Signed by a Core's own `CoreOperationalKey` (only legitimate for
    /// that Core's own `CoreLsa`).
    CoreOperationalKey { core_id: u8 },
}

/// Convergence key. Version spaces are never shared across kinds (§3.3).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectoryKey {
    pub kind: DirectoryObjectKind,
    pub subject: u16,
}

/// A caller-verified directory record. `content_hash` is supplied by the
/// caller and is `SHA-256` of the exact canonical TBS bytes (`object_id`),
/// never of the signature envelope. This module neither recomputes it nor
/// parses `payload`. `subject` is a NodeID for
/// `NodeIdentity`/`AttachmentLease` and a Core id for `CoreLsa`.
/// `target_core_id` is the lease's signed attachment target and must be
/// `Some` exactly for `AttachmentLease`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordEnvelope {
    pub kind: DirectoryObjectKind,
    pub subject: u16,
    pub version: VersionKey,
    pub writer: WriterProof,
    pub target_core_id: Option<u8>,
    pub content_hash: [u8; 32],
    /// Exact original signed object bytes, retained for paging and fork
    /// evidence. Signature bytes are not content identity: re-signing the same
    /// TBS legitimately changes this field without changing `content_hash`.
    pub payload: Vec<u8>,
    pub tombstone: bool,
}
impl RecordEnvelope {
    pub const fn key(&self) -> DirectoryKey {
        DirectoryKey {
            kind: self.kind,
            subject: self.subject,
        }
    }
    /// Build an envelope asserting the caller verified an
    /// `IdentityAuthority`-signed `NodeIdentity`. [`apply`] still
    /// re-validates every structural rule.
    ///
    /// [`apply`]: DirectoryConvergence::apply
    pub fn node_identity(
        subject_node_id: u16,
        identity_generation: u64,
        content_hash: [u8; 32],
        payload: Vec<u8>,
        tombstone: bool,
    ) -> Self {
        Self {
            kind: DirectoryObjectKind::NodeIdentity,
            subject: subject_node_id,
            version: VersionKey::NodeIdentity {
                identity_generation,
            },
            writer: WriterProof::IdentityAuthority,
            target_core_id: None,
            content_hash,
            payload,
            tombstone,
        }
    }
    /// Build an envelope asserting the caller verified BOTH the node's
    /// primary signature and `target_core_id`'s countersignature on an
    /// `AttachmentLease`. [`apply`] still re-validates every structural
    /// rule.
    ///
    /// [`apply`]: DirectoryConvergence::apply
    pub fn attachment_lease(
        subject_node_id: u16,
        identity_generation: u64,
        attach_generation: u64,
        target_core_id: u8,
        content_hash: [u8; 32],
        payload: Vec<u8>,
        tombstone: bool,
    ) -> Self {
        Self {
            kind: DirectoryObjectKind::AttachmentLease,
            subject: subject_node_id,
            version: VersionKey::AttachmentLease {
                identity_generation,
                attach_generation,
            },
            writer: WriterProof::AttachmentLease {
                node_signed: true,
                countersigning_core_id: Some(target_core_id),
            },
            target_core_id: Some(target_core_id),
            content_hash,
            payload,
            tombstone,
        }
    }
    /// Build an envelope asserting the caller verified a `CoreLsa`
    /// signed by `core_id`'s own `CoreOperationalKey`. [`apply`] still
    /// re-validates every structural rule.
    ///
    /// [`apply`]: DirectoryConvergence::apply
    pub fn core_lsa(
        core_id: u8,
        core_generation: u64,
        seq: u64,
        content_hash: [u8; 32],
        payload: Vec<u8>,
        tombstone: bool,
    ) -> Self {
        Self {
            kind: DirectoryObjectKind::CoreLsa,
            subject: u16::from(core_id),
            version: VersionKey::CoreLsa {
                core_generation,
                seq,
            },
            writer: WriterProof::CoreOperationalKey { core_id },
            target_core_id: None,
            content_hash,
            payload,
            tombstone,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    /// `with_max_keys` was given 0 or more than `MAX_KEYS`.
    InvalidCapacity,
    /// Subject is not an encodable NodeID / Core id for this kind.
    InvalidSubject,
    /// Version variant does not match the record kind, or a generation /
    /// seq component is 0.
    InvalidVersion,
    /// Writer structure is not the single legitimate writer form for
    /// this kind/subject (e.g. a Core writing `NodeIdentity`, or one
    /// Core writing another Core's `CoreLsa`).
    InvalidWriter,
    /// `AttachmentLease` without the node's own primary signature.
    MissingNodeSignature,
    /// `AttachmentLease` countersignature missing, or by a Core other
    /// than the signed `target_core_id`.
    CountersignatureMismatch,
    /// `target_core_id` missing or out of `1..=16` for an
    /// `AttachmentLease`, or present on any other kind.
    InvalidTargetCore,
    /// Payload exceeds `MAX_PAYLOAD_BYTES`.
    PayloadTooLarge,
    /// Inserting a new key would exceed the configured key bound.
    TooManyKeys,
}

/// Result of a structurally valid record delivery. Every variant is safe to
/// receive repeatedly; duplicates and stale deliveries never change the active
/// content identity. A duplicate may only canonicalize the retained signature
/// envelope for the same TBS, deterministically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    /// The record became (or, for a tombstone, replaced) the key's top
    /// record. Also returned for the first record of a strictly higher
    /// epoch superseding a poisoned lower epoch.
    Applied,
    /// Same version and identical content identity (TBS hash, lease target and
    /// tombstone state) as the current top record. Signature-envelope bytes may
    /// legitimately differ when the same TBS was re-signed; the retained exact
    /// envelope is canonicalized to the lexicographically smallest one seen, so
    /// snapshots do not depend on arrival order.
    Duplicate,
    /// Version is below the key's watermark (including any generation
    /// rollback); the record was ignored except for bounded
    /// equivocation evidence.
    Stale,
    /// This delivery exposed a different content identity at the same version
    /// (different TBS hash, lease target or tombstone state): the record's
    /// epoch has just been poisoned. A top record in a strictly higher epoch,
    /// if any, stays active (cross-epoch isolation).
    Equivocated,
    /// The record's epoch was already poisoned; the record cannot
    /// revive it, whatever its within-epoch order.
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    Absent,
    Active,
    Tombstoned,
    /// The key's highest (watermark) epoch is poisoned, so nothing is
    /// active. A key whose *older* epoch is poisoned but whose current
    /// higher epoch has a top record reports `Active`/`Tombstoned`;
    /// use [`DirectoryConvergence::poisoned_epochs`] for the full list.
    Poisoned,
}

/// One poisoned epoch of one key, as exported in snapshots. `epoch` is
/// the `identity_generation` (`NodeIdentity`/`AttachmentLease`) or
/// `core_generation` (`CoreLsa`); `equivocation_version` is the smallest
/// version at which a fork was detected in that epoch; `watermark` is
/// the key's overall watermark at snapshot time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoisonedEpoch {
    pub key: DirectoryKey,
    pub epoch: u64,
    pub equivocation_version: VersionKey,
    pub watermark: VersionKey,
}

/// Deterministic export: active records sorted by `(kind, subject)`,
/// poisoned epochs sorted by `(kind, subject, epoch)`, and a consistency
/// `digest`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectorySnapshot {
    pub active: Vec<RecordEnvelope>,
    pub poisoned: Vec<PoisonedEpoch>,
    pub digest: u64,
}

/// Home Core encoded in a NodeID, or `None` if `node_id` is not an
/// encodable subject. This is the inverse of `boreas-pki::node_id`:
/// `NodeID = ((home_core_id - 1) << 8) | vip_octet`, with
/// `home_core_id ∈ 1..=16` and VIP octet `1` (Core) or `2..=251` (Edge);
/// the union `1..=251` needs no role here. Replicated as a pure
/// function because this crate intentionally has no dependency on
/// `boreas-pki`. §3.2: the home Core comes only from the permanent
/// `NodeIdentity` / `NodeID` encoding and NEVER follows the current
/// attachment target of an `AttachmentLease`.
pub const fn home_core_id_for_node(node_id: u16) -> Option<u8> {
    if node_id >= 4096 {
        return None;
    }
    let octet = (node_id & 0x00ff) as u8;
    if octet == 0 || octet > 251 {
        return None;
    }
    Some(((node_id >> 8) as u8) + 1)
}

fn valid_subject(kind: DirectoryObjectKind, subject: u16) -> bool {
    match kind {
        DirectoryObjectKind::NodeIdentity | DirectoryObjectKind::AttachmentLease => {
            home_core_id_for_node(subject).is_some()
        }
        DirectoryObjectKind::CoreLsa => (1..=MAX_CORE_ID).contains(&subject),
    }
}

/// Fail-closed structural validation of everything except the payload
/// bound and key capacity. Returns before any state change on error.
/// These checks are defence in depth only: they prove nothing about who
/// actually signed the record — that proof is the caller's injected
/// signature verification (both signatures, for leases).
fn validate_structure(record: &RecordEnvelope) -> Result<(), DirectoryError> {
    if !valid_subject(record.kind, record.subject) {
        return Err(DirectoryError::InvalidSubject);
    }
    if record.version.kind() != record.kind || !record.version.is_valid() {
        return Err(DirectoryError::InvalidVersion);
    }
    // `target_core_id` is meaningful (and required) only for leases.
    match record.kind {
        DirectoryObjectKind::AttachmentLease => match record.target_core_id {
            Some(target) if (1..=MAX_CORE_ID as u8).contains(&target) => {}
            _ => return Err(DirectoryError::InvalidTargetCore),
        },
        DirectoryObjectKind::NodeIdentity | DirectoryObjectKind::CoreLsa => {
            if record.target_core_id.is_some() {
                return Err(DirectoryError::InvalidTargetCore);
            }
        }
    }
    match (record.kind, record.writer) {
        // Only the IdentityAuthority may write identities (§3.3).
        (DirectoryObjectKind::NodeIdentity, WriterProof::IdentityAuthority) => Ok(()),
        // Dual signature (§3.3): the node's own primary signature is
        // mandatory, and the countersigner must be exactly the signed
        // target Core. Any target in 1..=16 is legitimate — including
        // one different from the node's home Core (roaming); the home
        // Core is never consulted here (§3.2).
        (
            DirectoryObjectKind::AttachmentLease,
            WriterProof::AttachmentLease {
                node_signed,
                countersigning_core_id,
            },
        ) => {
            if !node_signed {
                return Err(DirectoryError::MissingNodeSignature);
            }
            if countersigning_core_id != record.target_core_id {
                return Err(DirectoryError::CountersignatureMismatch);
            }
            Ok(())
        }
        // A CoreLsa may only be written by that Core itself (§3.3).
        (DirectoryObjectKind::CoreLsa, WriterProof::CoreOperationalKey { core_id })
            if u16::from(core_id) == record.subject =>
        {
            Ok(())
        }
        _ => Err(DirectoryError::InvalidWriter),
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit fold. Used ONLY for the snapshot consistency digest; never
/// for any cryptographic purpose.
fn fnv1a_64(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Content identity used for duplicate/equivocation decisions at one
/// version. The caller-supplied `content_hash` is authoritative and binds the
/// canonical TBS (`object_id`); signature-envelope bytes are deliberately not
/// compared, because re-signing the same TBS legitimately changes only those
/// bytes. A different TBS changes `content_hash`; `target_core_id`
/// additionally separates lease bodies whose signed target differs (treated
/// conservatively as equivocation, never resolved by arrival order).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fingerprint {
    content_hash: [u8; 32],
    tombstone: bool,
    target_core_id: Option<u8>,
}
fn fingerprint(record: &RecordEnvelope) -> Fingerprint {
    Fingerprint {
        content_hash: record.content_hash,
        tombstone: record.tombstone,
        target_core_id: record.target_core_id,
    }
}

#[derive(Debug)]
struct KeyEntry {
    /// Highest version ever validly delivered for this key. Advances
    /// even while its epoch is poisoned so the exported state stays
    /// order-independent; never regresses (generation rollback is
    /// `Stale`, never active).
    watermark: VersionKey,
    /// Record at `watermark` while the watermark epoch is not poisoned
    /// (active or tombstone). `None` iff the watermark epoch is
    /// poisoned.
    top: Option<RecordEnvelope>,
    /// Poisoned epoch → smallest version at which a fork was detected
    /// in it (minimum is order-independent among detected forks).
    /// Bounded to the largest `MAX_POISONED_EPOCHS_PER_KEY` epochs.
    poisoned: BTreeMap<u64, VersionKey>,
    /// Bounded window of version fingerprints for fork detection at
    /// already-superseded versions; largest versions retained.
    evidence: BTreeMap<VersionKey, Fingerprint>,
}
impl KeyEntry {
    fn new(record: RecordEnvelope, print: Fingerprint) -> Self {
        Self {
            watermark: record.version,
            evidence: BTreeMap::from([(record.version, print)]),
            top: Some(record),
            poisoned: BTreeMap::new(),
        }
    }
    fn observe(&mut self, version: VersionKey, print: Fingerprint) {
        self.evidence.entry(version).or_insert(print);
        while self.evidence.len() > MAX_EVIDENCE_PER_KEY {
            let _ = self.evidence.pop_first();
        }
        self.watermark = self.watermark.max(version);
    }
    /// Poison `version`'s epoch; returns whether that epoch was already
    /// poisoned. The top record is dropped only if it belongs to the
    /// poisoned epoch — a strictly higher epoch's top is isolated from
    /// older-epoch forks.
    fn poison(&mut self, version: VersionKey) -> bool {
        let epoch = version.epoch();
        let was_poisoned = self.poisoned.contains_key(&epoch);
        self.poisoned
            .entry(epoch)
            .and_modify(|old| *old = (*old).min(version))
            .or_insert(version);
        while self.poisoned.len() > MAX_POISONED_EPOCHS_PER_KEY {
            let _ = self.poisoned.pop_first();
        }
        self.watermark = self.watermark.max(version);
        if self.watermark.epoch() == epoch {
            self.top = None;
        }
        was_poisoned
    }
    fn epoch_poisoned(&self, epoch: u64) -> bool {
        self.poisoned.contains_key(&epoch)
    }
    fn watermark_poisoned(&self) -> bool {
        self.epoch_poisoned(self.watermark.epoch())
    }
}

/// Bounded, deterministic directory convergence state. Pure logic: no
/// IO, no clock, no cryptography. Iteration is always in sorted key
/// order.
#[derive(Debug)]
pub struct DirectoryConvergence {
    entries: BTreeMap<DirectoryKey, KeyEntry>,
    max_keys: usize,
}
impl Default for DirectoryConvergence {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            max_keys: MAX_KEYS,
        }
    }
}
impl DirectoryConvergence {
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct with a tighter key bound (e.g. for resource-constrained
    /// nodes or tests). `max_keys` must be in `1..=MAX_KEYS`.
    pub fn with_max_keys(max_keys: usize) -> Result<Self, DirectoryError> {
        if max_keys == 0 || max_keys > MAX_KEYS {
            return Err(DirectoryError::InvalidCapacity);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            max_keys,
        })
    }

    /// Number of tracked keys (active + tombstoned + poisoned).
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn status(&self, key: DirectoryKey) -> KeyStatus {
        match self.entries.get(&key) {
            None => KeyStatus::Absent,
            Some(entry) if entry.watermark_poisoned() => KeyStatus::Poisoned,
            Some(entry) => match &entry.top {
                Some(record) if record.tombstone => KeyStatus::Tombstoned,
                Some(_) => KeyStatus::Active,
                // `top` is cleared exactly when the watermark epoch is
                // poisoned (handled above); kept exhaustive and
                // fail-closed rather than unreachable.
                None => KeyStatus::Poisoned,
            },
        }
    }
    /// Current active record for `key`; `None` when absent, tombstoned,
    /// or when the watermark epoch is poisoned.
    pub fn get(&self, key: DirectoryKey) -> Option<&RecordEnvelope> {
        let entry = self.entries.get(&key)?;
        if entry.watermark_poisoned() {
            return None;
        }
        entry.top.as_ref().filter(|record| !record.tombstone)
    }
    /// Raw top record for `key`, including tombstones; `None` when
    /// absent or when the watermark epoch is poisoned. Equivocation
    /// evidence (both signed originals) is the caller's §3.3
    /// responsibility and is not retained here.
    pub fn get_including_tombstone(&self, key: DirectoryKey) -> Option<&RecordEnvelope> {
        let entry = self.entries.get(&key)?;
        if entry.watermark_poisoned() {
            return None;
        }
        entry.top.as_ref()
    }
    /// Highest version ever validly delivered for `key`
    /// (anti-resurrection / anti-rollback watermark; advances even for
    /// tombstoned and poisoned epochs).
    pub fn watermark(&self, key: DirectoryKey) -> Option<VersionKey> {
        self.entries.get(&key).map(|entry| entry.watermark)
    }
    /// Poisoned epochs of `key`, ascending, each with the smallest
    /// version at which a fork was detected in it.
    pub fn poisoned_epochs(&self, key: DirectoryKey) -> Vec<(u64, VersionKey)> {
        self.entries
            .get(&key)
            .map(|entry| {
                entry
                    .poisoned
                    .iter()
                    .map(|(epoch, version)| (*epoch, *version))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Smallest version at which equivocation was detected in `epoch`
    /// of `key`, if that epoch is poisoned.
    pub fn equivocation_version(&self, key: DirectoryKey, epoch: u64) -> Option<VersionKey> {
        self.entries
            .get(&key)
            .and_then(|entry| entry.poisoned.get(&epoch).copied())
    }

    /// Isolate a key at `version` when the trust layer caught a same-version
    /// fork before convergence saw the second body.
    ///
    /// §3.3 requires the conflicting object to be frozen immediately, not only
    /// when both bodies arrive here. This poisons `version`'s epoch exactly like
    /// an in-convergence fork and returns `true` when this view held the key
    /// (so something could be isolated); `false` when it never held it, in which
    /// case nothing is active and no state is invented.
    pub fn isolate(&mut self, key: DirectoryKey, version: VersionKey) -> bool {
        if version.kind() != key.kind {
            return false;
        }
        match self.entries.get_mut(&key) {
            Some(entry) => {
                let _ = entry.poison(version);
                true
            }
            None => false,
        }
    }

    /// Merge one already-verified record. Structural failures return
    /// `Err` and never mutate state; valid deliveries return their
    /// [`ApplyOutcome`]. Delivery order and duplication do not affect
    /// the resulting snapshot.
    pub fn apply(&mut self, record: RecordEnvelope) -> Result<ApplyOutcome, DirectoryError> {
        // Validation order: subject encodability, version-kind match and
        // component bounds, target/writer structure, payload bound, then
        // capacity for a brand-new key. Every rejection below returns
        // before any state change.
        validate_structure(&record)?;
        if record.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(DirectoryError::PayloadTooLarge);
        }
        let key = record.key();
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.max_keys {
                return Err(DirectoryError::TooManyKeys);
            }
            let print = fingerprint(&record);
            self.entries.insert(key, KeyEntry::new(record, print));
            return Ok(ApplyOutcome::Applied);
        }

        let entry = self.entries.get_mut(&key).expect("key checked");
        let print = fingerprint(&record);
        let version = record.version;
        let epoch = version.epoch();

        if entry.epoch_poisoned(epoch) {
            // No laundering inside a poisoned epoch, at any
            // within-epoch order. Still observe evidence (a fork at a
            // smaller version improves the exported fork point
            // deterministically) and advance the watermark.
            match entry.evidence.get(&version) {
                Some(known) if *known != print => {
                    let _ = entry.poison(version);
                }
                _ => entry.observe(version, print),
            }
            // Raising the watermark INTO the poisoned epoch (a fork
            // proof is in hand, but the first top arrived in a lower,
            // clean epoch) must drop that lower top: the watermark
            // epoch is poisoned, so nothing may be active — in every
            // delivery order.
            if entry.watermark_poisoned() {
                entry.top = None;
            }
            return Ok(ApplyOutcome::Poisoned);
        }

        match version.cmp(&entry.watermark) {
            Ordering::Greater => {
                // Includes entering a strictly higher, clean epoch
                // above a poisoned older one: the new record becomes
                // top; the poisoned epoch stays listed, never cleared.
                entry.watermark = version;
                entry.top = Some(record);
                entry.observe(version, print);
                Ok(ApplyOutcome::Applied)
            }
            Ordering::Equal => {
                if entry
                    .top
                    .as_ref()
                    .is_some_and(|top| fingerprint(top) == print)
                {
                    // Same content identity; envelopes may differ only in
                    // signature bytes. Retain the lexicographically smallest
                    // exact envelope so a re-signed duplicate cannot make the
                    // snapshot depend on arrival order.
                    if let Some(top) = entry.top.as_mut()
                        && record.payload < top.payload
                    {
                        top.payload = record.payload;
                    }
                    Ok(ApplyOutcome::Duplicate)
                } else {
                    // `top` is `Some` here (the watermark epoch is not
                    // poisoned), so a None above cannot occur; poisoning
                    // on mismatch stays fail-closed regardless.
                    let _ = entry.poison(version);
                    Ok(ApplyOutcome::Equivocated)
                }
            }
            Ordering::Less => {
                // Generation rollback / superseded version: never
                // active. A late-arriving second body at this version
                // is still same-version equivocation (§3.3): poison its
                // epoch rather than silently ignore, within the bounded
                // evidence window. If its epoch is the watermark epoch
                // this also drops the current top (same-epoch laundering
                // is forbidden); a higher-epoch top is unaffected.
                match entry.evidence.get(&version) {
                    Some(known) if *known != print => {
                        let _ = entry.poison(version);
                        Ok(ApplyOutcome::Equivocated)
                    }
                    Some(_) => Ok(ApplyOutcome::Stale),
                    None => {
                        entry.observe(version, print);
                        Ok(ApplyOutcome::Stale)
                    }
                }
            }
        }
    }

    /// Deterministic export. `active` excludes tombstoned keys and keys
    /// whose watermark epoch is poisoned, and is sorted by
    /// `(kind, subject)`; `poisoned` lists every retained poisoned epoch
    /// in `(kind, subject, epoch)` order (including older poisoned
    /// epochs below an active higher epoch). `digest` is FNV-1a 64-bit
    /// over, in key order: each active record's `(kind tag, subject,
    /// version components, target, content_hash)`, each tombstoned top's
    /// `(kind tag, subject, version components, content_hash)`, and each
    /// poisoned epoch's `(kind tag, subject, epoch, equivocation version
    /// components, watermark components)` — so two replicas can compare convergence
    /// state with one `u64`. It is a consistency fingerprint only, NOT
    /// a cryptographic hash.
    pub fn snapshot(&self) -> DirectorySnapshot {
        let mut active = Vec::new();
        let mut poisoned = Vec::new();
        let mut digest = FNV_OFFSET_BASIS;
        for (key, entry) in &self.entries {
            for (epoch, fork) in &entry.poisoned {
                poisoned.push(PoisonedEpoch {
                    key: *key,
                    epoch: *epoch,
                    equivocation_version: *fork,
                    watermark: entry.watermark,
                });
                digest = fnv1a_64(digest, &[0x70, key.kind.tag()]);
                digest = fnv1a_64(digest, &key.subject.to_be_bytes());
                digest = fnv1a_64(digest, &epoch.to_be_bytes());
                let (fork_epoch, fork_within) = fork.components();
                digest = fnv1a_64(digest, &fork_epoch.to_be_bytes());
                digest = fnv1a_64(digest, &fork_within.to_be_bytes());
                let (wm_epoch, wm_within) = entry.watermark.components();
                digest = fnv1a_64(digest, &wm_epoch.to_be_bytes());
                digest = fnv1a_64(digest, &wm_within.to_be_bytes());
            }
            if entry.watermark_poisoned() {
                continue;
            }
            let Some(top) = &entry.top else { continue };
            let (epoch, within) = top.version.components();
            if top.tombstone {
                digest = fnv1a_64(digest, &[0x74, key.kind.tag()]);
                digest = fnv1a_64(digest, &key.subject.to_be_bytes());
                digest = fnv1a_64(digest, &epoch.to_be_bytes());
                digest = fnv1a_64(digest, &within.to_be_bytes());
                digest = fnv1a_64(digest, &top.content_hash);
                continue;
            }
            digest = fnv1a_64(digest, &[0x61, key.kind.tag()]);
            digest = fnv1a_64(digest, &key.subject.to_be_bytes());
            digest = fnv1a_64(digest, &epoch.to_be_bytes());
            digest = fnv1a_64(digest, &within.to_be_bytes());
            digest = fnv1a_64(digest, &[top.target_core_id.unwrap_or(0)]);
            digest = fnv1a_64(digest, &top.content_hash);
            active.push(top.clone());
        }
        DirectorySnapshot {
            active,
            poisoned,
            digest,
        }
    }
}

// --- verified ingest, original-byte evidence, bounded anti-entropy pages -----
//
// §3.3 requires four duties beyond pure convergence: the exact original signed
// bytes of every object are what gets distributed, every Edge verifies the full
// permission chain and both signatures locally instead of trusting its attached
// Core, a same-version fork preserves BOTH original objects as evidence, and
// synchronisation is paged under a global receive quota. Those duties need the
// raw objects, so they live here, above [`DirectoryConvergence`], which stays
// the pure order-independent engine.
//
// This layer still performs no cryptography: [`ObjectVerifier`] is the consumer
// API the identity/PKI layer implements (`boreas-pki`'s `ManagementTrust` via
// [`pki_verifier::PkiObjectVerifier`] in production builds). An object whose
// original bytes the verifier refuses never reaches convergence, so no
// unverified record can become active, page out, or be cited as evidence.

/// Maximum number of objects one anti-entropy page carries. This matches the
/// candidate `boreas-proto` `MAX_DIRECTORY_OBJECTS` bound so an in-process page
/// is always encodable; §3.3 requires bounded paging and forbids an unbounded
/// whole-directory pull.
pub const MAX_PAGE_OBJECTS: usize = 16;

/// Candidate `ControlType::DirectoryPage` body cap (16 KiB) — one page is one
/// control body, not a bulk transfer.
const PAGE_BODY_CAP: usize = 16 * 1024;

/// Fixed page header: subtype byte, `page_seq` (u64) and the object count byte.
const PAGE_HEADER_LEN: usize = 1 + 8 + 1;

/// Per-object length prefix inside the candidate page body.
const PAGE_OBJECT_PREFIX_LEN: usize = 2;

/// Byte bound for one page, summed over its original signed objects. Derived
/// from the candidate control-body cap so [`SignedObjectPage::encode_wire`] can
/// never produce a body the codec refuses.
pub const MAX_PAGE_BYTES: usize =
    PAGE_BODY_CAP - PAGE_HEADER_LEN - PAGE_OBJECT_PREFIX_LEN * MAX_PAGE_OBJECTS;

const _: () = assert!(MAX_PAGE_BYTES == 16_342);

/// Retained fork-evidence entries per ingest state. §3.3 wants both originals
/// preserved; persistence is the caller's duty, so this window is bounded and
/// every refusal to retain is counted in [`IngestStats::evidence_dropped`].
pub const MAX_EVIDENCE_ENTRIES: usize = 8;

/// Retained fork-evidence bytes per ingest state (both originals per entry).
pub const MAX_EVIDENCE_BYTES: usize = 256 * 1024;

/// Pure-model facts reported by an injected verifier for one management object.
/// Every field is supposed to be derived from the *original signed bytes*; none
/// may be taken from an unauthenticated frame header.
///
/// These are plain Rust values, **not a capability or token**. The fields are
/// public, so any caller can fabricate a `VerifiedFacts`; trust exists only in
/// the verifier instance injected into [`DirectoryIngest`]. Production code
/// must use the reviewed PKI verifier and must never deserialize these fields
/// from a frame or cite them as authentication evidence by themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFacts {
    pub kind: DirectoryObjectKind,
    pub subject: u16,
    pub version: VersionKey,
    pub writer: WriterProof,
    pub target_core_id: Option<u8>,
    /// SHA-256 of the exact canonical TBS bytes (`object_id`) the verifier
    /// authenticated — never a hash of the signature envelope. Re-signing the
    /// same TBS must not manufacture a fork.
    pub content_hash: [u8; 32],
    /// Tombstone flag. The three §3.3 object bodies carry no tombstone field, so
    /// a verifier built on them reports `false`; revocation is a separate
    /// object class handled by the upper layer.
    pub tombstone: bool,
}

impl VerifiedFacts {
    pub fn key(&self) -> DirectoryKey {
        DirectoryKey {
            kind: self.kind,
            subject: self.subject,
        }
    }

    /// Pair the facts with the exact original signed bytes they describe.
    pub fn into_envelope(self, raw_signed_object: Vec<u8>) -> RecordEnvelope {
        RecordEnvelope {
            kind: self.kind,
            subject: self.subject,
            version: self.version,
            writer: self.writer,
            target_core_id: self.target_core_id,
            content_hash: self.content_hash,
            payload: raw_signed_object,
            tombstone: self.tombstone,
        }
    }
}

/// Why the trust layer refused an object's original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyReject {
    /// Malformed, badly signed, out of scope, stale, expired or otherwise not
    /// authorised. The object is discarded and convergence state is untouched.
    Rejected,
    /// The same writer slot and version already carried a different canonical
    /// TBS (not merely a different signature encoding), and the verifier's own
    /// signature, scope and encoding checks had already passed. The carried
    /// facts key the evidence record; they never activate a record.
    Equivocation(VerifiedFacts),
}

/// Verification gate the identity layer implements.
///
/// This is a pure-model integration boundary, **not a capability or
/// authentication token**. Any implementation can return arbitrary
/// [`VerifiedFacts`], and [`DirectoryIngest`] trusts whichever verifier it is
/// constructed with. Only the reviewed `PkiObjectVerifier` (feature
/// `openssl-inner-tls`) binds real `ManagementTrust` verification in this
/// crate. Implementations MUST verify both signatures (node primary + attached
/// Core countersignature for a lease), the issuer permission chain, canonical
/// encoding and freshness over the exact `raw_signed_object` bytes, and MUST
/// NOT report facts for an object that failed those checks.
pub trait ObjectVerifier {
    fn verify(
        &mut self,
        raw_signed_object: &[u8],
        now_us: u64,
    ) -> Result<VerifiedFacts, VerifyReject>;
}

/// Result of one verified delivery. Every variant leaves the state either
/// untouched or in a state that a repeat delivery cannot worsen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    /// The verifier accepted the original bytes; the inner outcome is from
    /// [`DirectoryConvergence::apply`].
    Verified(ApplyOutcome),
    /// The verifier refused the original bytes; nothing entered convergence.
    Rejected,
    /// Same version, different verified content: the record is isolated and both
    /// originals are preserved in [`EvidenceStore`] when the byte budget allows.
    Equivocated,
    /// Verification passed but the envelope was structurally refused (payload
    /// bound, writer structure, key capacity). Never a silent accept.
    Refused(DirectoryError),
}

impl IngestOutcome {
    /// Whether the object was kept out of the active view for a non-convergence
    /// reason (rejected or structurally refused).
    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected | Self::Refused(_))
    }

    /// Whether this delivery became the key's active top record.
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Verified(ApplyOutcome::Applied))
    }

    /// Whether this delivery preserved a same-version fork.
    pub const fn is_equivocation(&self) -> bool {
        matches!(self, Self::Equivocated)
    }
}

/// Bounded counters for operational visibility. Counters never gate traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IngestStats {
    pub verified: u64,
    pub rejected: u64,
    pub equivocated: u64,
    pub applied: u64,
    pub duplicate: u64,
    pub stale: u64,
    pub poisoned: u64,
    pub refused: u64,
    pub evidence_dropped: u64,
}

/// One preserved same-version fork: both exact original signed objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkEvidence {
    pub key: DirectoryKey,
    pub version: VersionKey,
    /// The original bytes this replica already held for that version, when it
    /// held any. `None` means only the conflicting side was seen here; the upper
    /// layer must still persist and alert on what it has.
    pub retained: Option<Vec<u8>>,
    /// The original bytes that triggered the fork.
    pub conflicting: Vec<u8>,
}

/// Bounded, deterministically ordered fork evidence. Entries are keyed by
/// `(key, version)` so repeated detections at one slot do not grow the store.
#[derive(Debug, Default)]
pub struct EvidenceStore {
    entries: BTreeMap<(DirectoryKey, VersionKey), ForkEvidence>,
    bytes: usize,
    dropped: u64,
}

impl EvidenceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Retained original bytes across all entries.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Forks the byte or entry budget refused to retain. Non-zero is an audit
    /// signal: §3.3 requires both originals on durable storage.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Ascending `(kind, subject, version)` order.
    pub fn iter(&self) -> impl Iterator<Item = &ForkEvidence> {
        self.entries.values()
    }

    pub fn get(&self, key: DirectoryKey, version: VersionKey) -> Option<&ForkEvidence> {
        self.entries.get(&(key, version))
    }

    /// Retain one fork. Returns `false` when the budget refused it; the caller
    /// counts that as a drop rather than silently losing evidence.
    fn record(
        &mut self,
        key: DirectoryKey,
        version: VersionKey,
        retained: Option<Vec<u8>>,
        conflicting: Vec<u8>,
    ) -> bool {
        let slot = (key, version);
        if self.entries.contains_key(&slot) {
            // Already preserved; a second detection at the same slot adds nothing.
            return true;
        }
        let added = retained.as_ref().map_or(0, Vec::len) + conflicting.len();
        if self.entries.len() >= MAX_EVIDENCE_ENTRIES
            || self
                .bytes
                .checked_add(added)
                .is_none_or(|n| n > MAX_EVIDENCE_BYTES)
        {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.bytes += added;
        self.entries.insert(
            slot,
            ForkEvidence {
                key,
                version,
                retained,
                conflicting,
            },
        );
        true
    }
}

impl<'a> IntoIterator for &'a EvidenceStore {
    type Item = &'a ForkEvidence;
    type IntoIter =
        std::collections::btree_map::Values<'a, (DirectoryKey, VersionKey), ForkEvidence>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.values()
    }
}

/// Pure verified-ingest model: the convergence engine, the injected verifier,
/// the bounded evidence store and the counters.
///
/// This type performs no cryptography itself. It is only as trustworthy as the
/// verifier passed to [`Self::new`]; an arbitrary implementation can fabricate
/// facts, so this is not an authentication token or a trust boundary by itself.
#[derive(Debug)]
pub struct DirectoryIngest<V> {
    convergence: DirectoryConvergence,
    verifier: V,
    evidence: EvidenceStore,
    stats: IngestStats,
}

impl<V: ObjectVerifier> DirectoryIngest<V> {
    /// `verifier` is trusted by construction. This constructor accepts any
    /// implementation, so passing an untrusted verifier yields forged facts;
    /// production must pass the reviewed `PkiObjectVerifier`.
    pub fn new(verifier: V) -> Self {
        Self {
            convergence: DirectoryConvergence::new(),
            verifier,
            evidence: EvidenceStore::new(),
            stats: IngestStats::default(),
        }
    }

    /// Same key bound as [`DirectoryConvergence::with_max_keys`] and the same
    /// verifier-trust caveat as [`Self::new`].
    pub fn with_max_keys(verifier: V, max_keys: usize) -> Result<Self, DirectoryError> {
        Ok(Self {
            convergence: DirectoryConvergence::with_max_keys(max_keys)?,
            verifier,
            evidence: EvidenceStore::new(),
            stats: IngestStats::default(),
        })
    }

    pub fn directory(&self) -> &DirectoryConvergence {
        &self.convergence
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    pub fn verifier_mut(&mut self) -> &mut V {
        &mut self.verifier
    }

    pub fn evidence(&self) -> &EvidenceStore {
        &self.evidence
    }

    pub fn stats(&self) -> IngestStats {
        self.stats
    }

    pub fn snapshot(&self) -> DirectorySnapshot {
        self.convergence.snapshot()
    }

    /// Verify one object's original bytes, then converge it.
    ///
    /// `now_us` is trusted UTC microseconds for the verifier's freshness checks;
    /// this module never reads a clock and repeated delivery never extends
    /// freshness (§3.4).
    pub fn verify_and_apply(&mut self, raw_signed_object: &[u8], now_us: u64) -> IngestOutcome {
        if raw_signed_object.is_empty() {
            self.stats.rejected = self.stats.rejected.saturating_add(1);
            return IngestOutcome::Rejected;
        }
        if raw_signed_object.len() > MAX_PAYLOAD_BYTES {
            self.stats.refused = self.stats.refused.saturating_add(1);
            return IngestOutcome::Refused(DirectoryError::PayloadTooLarge);
        }
        let facts = match self.verifier.verify(raw_signed_object, now_us) {
            Ok(facts) => facts,
            Err(VerifyReject::Rejected) => {
                self.stats.rejected = self.stats.rejected.saturating_add(1);
                return IngestOutcome::Rejected;
            }
            Err(VerifyReject::Equivocation(facts)) => {
                // The counterpart bytes are whatever this replica already held
                // at that version; when it held none the evidence says so.
                let retained = self
                    .convergence
                    .get_including_tombstone(facts.key())
                    .filter(|record| record.version == facts.version)
                    .map(|record| record.payload.clone());
                // §3.3: freeze the conflicting object at once, even though the
                // second body never enters convergence.
                self.convergence.isolate(facts.key(), facts.version);
                self.note_fork(
                    facts.key(),
                    facts.version,
                    retained,
                    raw_signed_object.to_vec(),
                );
                self.stats.equivocated = self.stats.equivocated.saturating_add(1);
                return IngestOutcome::Equivocated;
            }
        };
        self.stats.verified = self.stats.verified.saturating_add(1);
        let key = facts.key();
        let version = facts.version;
        // Capture the counterpart bytes *before* convergence runs: an in-engine
        // fork clears the top record, and evidence needs the bytes it held.
        let prior_at_version = self
            .convergence
            .get_including_tombstone(key)
            .filter(|record| record.version == version)
            .map(|record| record.payload.clone());
        let envelope = facts.into_envelope(raw_signed_object.to_vec());
        match self.convergence.apply(envelope) {
            Ok(ApplyOutcome::Applied) => {
                self.stats.applied = self.stats.applied.saturating_add(1);
                IngestOutcome::Verified(ApplyOutcome::Applied)
            }
            Ok(ApplyOutcome::Duplicate) => {
                self.stats.duplicate = self.stats.duplicate.saturating_add(1);
                IngestOutcome::Verified(ApplyOutcome::Duplicate)
            }
            Ok(ApplyOutcome::Stale) => {
                self.stats.stale = self.stats.stale.saturating_add(1);
                IngestOutcome::Verified(ApplyOutcome::Stale)
            }
            Ok(ApplyOutcome::Poisoned) => {
                self.stats.poisoned = self.stats.poisoned.saturating_add(1);
                IngestOutcome::Verified(ApplyOutcome::Poisoned)
            }
            Ok(ApplyOutcome::Equivocated) => {
                // The verifier let both bodies through and convergence saw two
                // different bodies at one version: preserve both originals.
                self.note_fork(key, version, prior_at_version, raw_signed_object.to_vec());
                self.stats.equivocated = self.stats.equivocated.saturating_add(1);
                IngestOutcome::Equivocated
            }
            Err(error) => {
                self.stats.refused = self.stats.refused.saturating_add(1);
                IngestOutcome::Refused(error)
            }
        }
    }

    fn note_fork(
        &mut self,
        key: DirectoryKey,
        version: VersionKey,
        retained: Option<Vec<u8>>,
        conflicting: Vec<u8>,
    ) {
        if !self.evidence.record(key, version, retained, conflicting) {
            self.stats.evidence_dropped = self.stats.evidence_dropped.saturating_add(1);
        }
    }

    /// Apply one anti-entropy page. Each record is re-verified locally; nothing
    /// in the page is trusted because the sender verified it (§3.3).
    pub fn ingest_page(&mut self, page: &SignedObjectPage, now_us: u64) -> PageIngest {
        let mut outcomes = Vec::with_capacity(page.records.len().min(MAX_PAGE_OBJECTS));
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for raw in page.records.iter().take(MAX_PAGE_OBJECTS) {
            let outcome = self.verify_and_apply(raw, now_us);
            if outcome.is_rejected() {
                rejected += 1;
            } else {
                accepted += 1;
            }
            outcomes.push(outcome);
        }
        let over_limit = page.records.len().saturating_sub(MAX_PAGE_OBJECTS);
        PageIngest {
            page_seq: page.page_seq,
            outcomes,
            accepted,
            rejected,
            over_limit,
        }
    }
}

/// One bounded anti-entropy page of exact original signed objects, matching the
/// candidate `boreas-proto` `DirectoryPage` control body (`page_seq` plus up to
/// [`MAX_PAGE_OBJECTS`] signed-object envelopes).
///
/// The sender emits it with [`Self::encode_wire`]; the receiver decodes with
/// [`Self::decode_wire`] and then re-verifies every object locally — decoding
/// proves nothing about who signed anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedObjectPage {
    pub page_seq: u64,
    pub records: Vec<Vec<u8>>,
}

impl SignedObjectPage {
    /// Encode as a candidate `ControlType::DirectoryPage` body. Every record
    /// must be a decodable signed-object envelope; the codec's own 16 KiB body
    /// cap is enforced again here, so an oversized page fails closed instead of
    /// being split or truncated silently.
    pub fn encode_wire(&self) -> Result<Vec<u8>, PageWireError> {
        if self.records.is_empty() || self.records.len() > MAX_PAGE_OBJECTS {
            return Err(PageWireError::InvalidCount);
        }
        let mut objects = Vec::with_capacity(self.records.len());
        for raw in &self.records {
            objects.push(SignedObject::decode(raw).map_err(|_| PageWireError::NotSignedObject)?);
        }
        ProtoDirectoryPage {
            page_seq: self.page_seq,
            objects,
        }
        .encode()
        .map_err(|_| PageWireError::BodyTooLarge)
    }

    /// Decode a candidate page body back into exact signed-object bytes. The
    /// re-encoded envelope is byte-identical to the transported one because the
    /// candidate codec is canonical and never repairs TBS bytes.
    pub fn decode_wire(body: &[u8]) -> Result<Self, PageWireError> {
        let page = ProtoDirectoryPage::decode(body).map_err(|_| PageWireError::Malformed)?;
        let mut records = Vec::with_capacity(page.objects.len());
        for object in &page.objects {
            records.push(object.encode().map_err(|_| PageWireError::Malformed)?);
        }
        Ok(Self {
            page_seq: page.page_seq,
            records,
        })
    }
}

/// Why a page could not be carried on the candidate control body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageWireError {
    /// The page carried no object, or more than [`MAX_PAGE_OBJECTS`].
    InvalidCount,
    /// A record is not a decodable signed-object envelope.
    NotSignedObject,
    /// The encoded body would exceed the candidate 16 KiB control-body cap.
    BodyTooLarge,
    /// The body or one of its envelopes failed the candidate codec.
    Malformed,
}

/// Outcome of one page, bounded by [`MAX_PAGE_OBJECTS`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageIngest {
    pub page_seq: u64,
    pub outcomes: Vec<IngestOutcome>,
    pub accepted: usize,
    pub rejected: usize,
    /// Records the page carried beyond [`MAX_PAGE_OBJECTS`]; never applied.
    pub over_limit: usize,
}

/// Splits a snapshot's active records into bounded pages. Only active records
/// are distributed: a tombstoned top is the anti-resurrection watermark, and a
/// poisoned epoch is already isolated locally.
pub struct PageIter<'a> {
    records: &'a [RecordEnvelope],
    cursor: usize,
    page_seq: u64,
}

impl<'a> Iterator for PageIter<'a> {
    type Item = SignedObjectPage;

    fn next(&mut self) -> Option<SignedObjectPage> {
        if self.cursor >= self.records.len() {
            return None;
        }
        let mut records = Vec::new();
        let mut bytes = 0usize;
        while self.cursor < self.records.len() && records.len() < MAX_PAGE_OBJECTS {
            let payload = &self.records[self.cursor].payload;
            if !records.is_empty() && bytes.saturating_add(payload.len()) > MAX_PAGE_BYTES {
                break;
            }
            bytes = bytes.saturating_add(payload.len());
            records.push(payload.clone());
            self.cursor += 1;
        }
        let page = SignedObjectPage {
            page_seq: self.page_seq,
            records,
        };
        self.page_seq = self.page_seq.saturating_add(1);
        Some(page)
    }
}

/// Page the active set of one snapshot. Bounded by [`MAX_PAGE_OBJECTS`] and
/// [`MAX_PAGE_BYTES`]; an empty active set yields no page at all.
pub fn page_snapshot(snapshot: &DirectorySnapshot) -> PageIter<'_> {
    PageIter {
        records: &snapshot.active,
        cursor: 0,
        page_seq: 0,
    }
}

/// `boreas-pki`-backed verification for real dual-signed management objects.
///
/// The production [`ObjectVerifier`]: `boreas_pki::management::ManagementTrust`
/// verifies both signatures over the exact signed bytes, the issuer permission
/// chain, canonical encoding, scope, freshness and per-slot replay, and keeps
/// the conflicting original when it detects equivocation.
///
/// The directory never parses an object to decide trust. The one place this
/// module decodes bytes itself is the equivocation path, and only to key the
/// evidence record: `ManagementTrust::verify_and_authorize` checks both
/// signatures and the permission chain *before* it consults the replay slot,
/// so an equivocation report already implies the conflicting bytes were
/// authenticated. Those facts are never turned into an active record.
///
/// Content identity is `ManagementTrust`'s `object_id`, i.e. SHA-256 of the
/// exact canonical TBS bytes, never a hash of the signature envelope.
/// Re-signing the same TBS therefore remains a duplicate.
#[cfg(feature = "openssl-inner-tls")]
pub mod pki_verifier {
    use super::{
        DirectoryObjectKind, ObjectVerifier, VerifiedFacts, VerifyReject, VersionKey, WriterProof,
    };
    use boreas_pki::management::{Error as PkiError, ManagementTrust};
    use boreas_proto::messages::SignedObject;
    use boreas_proto::objects::{self, ManagementObject, ObjectBody};

    /// Adapter pairing the tunnel directory with the PKI trust layer. The
    /// `ManagementTrust` is owned here because its replay slots are per node.
    pub struct PkiObjectVerifier {
        trust: ManagementTrust,
    }

    impl PkiObjectVerifier {
        pub fn new(trust: ManagementTrust) -> Self {
            Self { trust }
        }

        /// Empty trust for one network: identities and issuer records must be
        /// provisioned by the caller before anything verifies.
        pub fn with_net_id(net_id: [u8; 16]) -> Self {
            Self {
                trust: ManagementTrust::new(net_id),
            }
        }

        pub fn trust(&self) -> &ManagementTrust {
            &self.trust
        }

        pub fn trust_mut(&mut self) -> &mut ManagementTrust {
            &mut self.trust
        }
    }

    impl ObjectVerifier for PkiObjectVerifier {
        fn verify(
            &mut self,
            raw_signed_object: &[u8],
            now_us: u64,
        ) -> Result<VerifiedFacts, VerifyReject> {
            match self.trust.verify_and_authorize(raw_signed_object, now_us) {
                // `object_id` is SHA-256 of the exact canonical TBS bytes. It
                // is deliberately not a hash of the signature envelope: a
                // legitimate re-signing of the same TBS must stay a duplicate.
                Ok(verified) => facts_from_object(verified.object(), verified.object_id())
                    .ok_or(VerifyReject::Rejected),
                Err(PkiError::Equivocation) => match decode_original(raw_signed_object) {
                    Some((object, content_hash)) => {
                        match facts_from_object(&object, content_hash) {
                            Some(facts) => Err(VerifyReject::Equivocation(facts)),
                            None => Err(VerifyReject::Rejected),
                        }
                    }
                    None => Err(VerifyReject::Rejected),
                },
                Err(_) => Err(VerifyReject::Rejected),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl super::DirectoryIngest<PkiObjectVerifier> {
        /// Return only a usable cached lease for the authenticated subject and
        /// the target Core generation captured at admission. A revocation
        /// invalidates the lookup but does not remove signed convergence or
        /// replay evidence; duplicate and out-of-order ingest cannot undo it.
        /// `directory()`/`snapshot()` remain evidence views, not authorization.
        pub fn usable_attachment_lease(
            &self,
            status: &boreas_pki::status_store::StatusStore,
            subject: &boreas_pki::status_store::AuthenticatedPeer,
            target: &boreas_pki::status_store::AuthenticatedPeer,
            utc: u64,
            mono: std::time::Instant,
        ) -> Result<Option<&super::RecordEnvelope>, boreas_pki::status_store::Error> {
            use boreas_pki::status_store::Error;
            if status.net_id() != self.verifier.trust.net_id()
                || subject.net_id() != status.net_id() || target.net_id() != status.net_id()
            {
                return Err(Error::WrongNetwork);
            }
            status.check_active_snapshot(utc, mono)?;
            let now = utc.max(status.last_trusted_utc());
            let Some(record) = self.convergence.get(super::DirectoryKey {
                kind: DirectoryObjectKind::AttachmentLease,
                subject: subject.node_id(),
            }) else {
                return Ok(None);
            };
            let VersionKey::AttachmentLease { identity_generation, .. } = record.version else {
                return Err(Error::RevocationPermission);
            };
            if identity_generation != subject.identity_generation() {
                return Ok(None);
            }
            let Some(identity) = self.convergence.get(super::DirectoryKey {
                kind: DirectoryObjectKind::NodeIdentity,
                subject: subject.node_id(),
            }) else {
                return Ok(None);
            };
            let lease = self.verifier.trust.revalidate_attachment_lease(
                &record.payload, &identity.payload, now,
            ).map_err(|_| Error::RevocationPermission)?;
            if status.attachment_lease_revoked(target, &lease)? {
                return Ok(None);
            }
            Ok(Some(record))
        }
    }

    /// Decode the envelope this replica was handed, without trusting it. Only
    /// reachable after the trust layer reported an authenticated conflict.
    /// Returns the object and SHA-256 of its exact canonical TBS bytes
    /// (`object_id`), never the envelope hash.
    fn decode_original(raw: &[u8]) -> Option<(ManagementObject, [u8; 32])> {
        let signed = SignedObject::decode(raw).ok()?;
        let object = objects::decode_tbs(&signed.raw_tbs).ok()?;
        Some((object, openssl::sha::sha256(&signed.raw_tbs)))
    }

    fn facts_from_object(
        object: &ManagementObject,
        content_hash: [u8; 32],
    ) -> Option<VerifiedFacts> {
        match &object.body {
            ObjectBody::NodeIdentity(body) => Some(VerifiedFacts {
                kind: DirectoryObjectKind::NodeIdentity,
                subject: body.node_id,
                version: VersionKey::NodeIdentity {
                    identity_generation: body.identity_generation,
                },
                writer: WriterProof::IdentityAuthority,
                target_core_id: None,
                content_hash,
                tombstone: false,
            }),
            ObjectBody::AttachmentLease(body) => Some(VerifiedFacts {
                kind: DirectoryObjectKind::AttachmentLease,
                subject: body.node_id,
                version: VersionKey::AttachmentLease {
                    identity_generation: body.identity_generation,
                    attach_generation: body.attach_generation,
                },
                // The trust layer verified the node's primary signature and the
                // co-signature of exactly this target Core.
                writer: WriterProof::AttachmentLease {
                    node_signed: true,
                    countersigning_core_id: Some(body.target_core_id),
                },
                target_core_id: Some(body.target_core_id),
                content_hash,
                tombstone: false,
            }),
            ObjectBody::CoreLsa(body) => Some(VerifiedFacts {
                kind: DirectoryObjectKind::CoreLsa,
                subject: u16::from(body.core_id),
                version: VersionKey::CoreLsa {
                    core_generation: body.core_generation,
                    seq: body.seq,
                },
                writer: WriterProof::CoreOperationalKey {
                    core_id: body.core_id,
                },
                target_core_id: None,
                content_hash,
                tombstone: false,
            }),
            // RouteGrant / DirectGrant / StatusSnapshot are not §3.3 directory
            // objects; their authority checks belong to the upper layer.
            ObjectBody::RouteGrant(_)
            | ObjectBody::DirectGrant(_)
            | ObjectBody::StatusSnapshot(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-seed LCG (Numerical Recipes constants). Test-only; never
    /// used as a source of security randomness.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 11
        }
        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }
    fn shuffle(values: &mut [RecordEnvelope], rng: &mut Lcg) {
        for i in (1..values.len()).rev() {
            let j = rng.below(i + 1);
            values.swap(i, j);
        }
    }
    fn hash(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }
    fn node_id(core: u8, octet: u8) -> u16 {
        ((u16::from(core) - 1) << 8) | u16::from(octet)
    }
    /// Non-tombstone body whose bytes carry `seed` (and not the version),
    /// so same-seed records are exact duplicates and different seeds at
    /// one version are forks.
    fn payload_of(seed: u8) -> Vec<u8> {
        vec![seed, seed, seed]
    }
    fn identity(subject: u16, generation: u64, seed: u8) -> RecordEnvelope {
        RecordEnvelope::node_identity(subject, generation, hash(seed), payload_of(seed), false)
    }
    fn lease(subject: u16, id_gen: u64, attach_gen: u64, target: u8, seed: u8) -> RecordEnvelope {
        RecordEnvelope::attachment_lease(
            subject,
            id_gen,
            attach_gen,
            target,
            hash(seed),
            payload_of(seed),
            false,
        )
    }
    fn lsa(core: u8, core_gen: u64, seq: u64, seed: u8) -> RecordEnvelope {
        RecordEnvelope::core_lsa(core, core_gen, seq, hash(seed), payload_of(seed), false)
    }

    #[test]
    fn roaming_lease_countersigned_by_non_home_core_is_accepted() {
        // §3.3: the countersigner is the *currently attached* Core,
        // which may differ from the home Core; §3.2: home_core_id never
        // follows the attachment.
        let subject = node_id(2, 7); // home Core 2
        assert_eq!(home_core_id_for_node(subject), Some(2));
        let key = DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject,
        };
        let mut state = DirectoryConvergence::new();
        // Attached to / countersigned by Core 5 (roaming).
        assert_eq!(
            state.apply(lease(subject, 1, 1, 5, 10)),
            Ok(ApplyOutcome::Applied)
        );
        let top = state.get(key).expect("roaming lease active");
        assert_eq!(top.target_core_id, Some(5));
        // The node's home Core is unchanged by the attachment.
        assert_eq!(home_core_id_for_node(top.subject), Some(2));
        // Re-attaching to the home Core at a higher attach_generation
        // supersedes the roaming lease.
        assert_eq!(
            state.apply(lease(subject, 1, 2, 2, 11)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.get(key).unwrap().target_core_id, Some(2));
    }

    #[test]
    fn lease_without_node_signature_or_with_wrong_countersigner_is_rejected() {
        let subject = node_id(2, 7);
        let mut state = DirectoryConvergence::new();

        // Countersigned but not node-signed: the node's primary
        // signature is mandatory (§3.3).
        let mut missing_primary = lease(subject, 1, 1, 5, 10);
        missing_primary.writer = WriterProof::AttachmentLease {
            node_signed: false,
            countersigning_core_id: Some(5),
        };
        assert_eq!(
            state.apply(missing_primary),
            Err(DirectoryError::MissingNodeSignature)
        );

        // Node-signed but no countersignature at all.
        let mut missing_counter = lease(subject, 1, 1, 5, 10);
        missing_counter.writer = WriterProof::AttachmentLease {
            node_signed: true,
            countersigning_core_id: None,
        };
        assert_eq!(
            state.apply(missing_counter),
            Err(DirectoryError::CountersignatureMismatch)
        );

        // Countersigned by a Core other than the signed target —
        // including the home Core itself: home is not a substitute for
        // the target's acceptance (§3.3 附签确认接受).
        for wrong in [2u8, 3, 16] {
            let mut wrong_counter = lease(subject, 1, 1, 5, 10);
            wrong_counter.writer = WriterProof::AttachmentLease {
                node_signed: true,
                countersigning_core_id: Some(wrong),
            };
            assert_eq!(
                state.apply(wrong_counter),
                Err(DirectoryError::CountersignatureMismatch)
            );
        }

        // Wrong writer *forms* entirely.
        let mut authority_form = lease(subject, 1, 1, 5, 10);
        authority_form.writer = WriterProof::IdentityAuthority;
        assert_eq!(
            state.apply(authority_form),
            Err(DirectoryError::InvalidWriter)
        );
        let mut core_form = lease(subject, 1, 1, 5, 10);
        core_form.writer = WriterProof::CoreOperationalKey { core_id: 5 };
        assert_eq!(state.apply(core_form), Err(DirectoryError::InvalidWriter));

        // Missing / out-of-range target.
        let mut no_target = lease(subject, 1, 1, 5, 10);
        no_target.target_core_id = None;
        assert_eq!(
            state.apply(no_target),
            Err(DirectoryError::InvalidTargetCore)
        );
        for bad_target in [0u8, 17] {
            let mut bad = lease(subject, 1, 1, 5, 10);
            bad.target_core_id = Some(bad_target);
            bad.writer = WriterProof::AttachmentLease {
                node_signed: true,
                countersigning_core_id: Some(bad_target),
            };
            assert_eq!(state.apply(bad), Err(DirectoryError::InvalidTargetCore));
        }

        // Every rejection left the state untouched, and the legitimate
        // roaming lease is still accepted afterwards.
        assert!(state.is_empty());
        assert_eq!(
            state.apply(lease(subject, 1, 1, 5, 10)),
            Ok(ApplyOutcome::Applied)
        );
    }

    #[test]
    fn illegal_writers_are_rejected_for_identity_and_lsa() {
        let mut state = DirectoryConvergence::new();

        // A Core may not write identities (§3.3).
        let mut by_core = identity(node_id(1, 7), 1, 1);
        by_core.writer = WriterProof::CoreOperationalKey { core_id: 1 };
        assert_eq!(state.apply(by_core), Err(DirectoryError::InvalidWriter));
        let mut by_lease_form = identity(node_id(1, 7), 1, 1);
        by_lease_form.writer = WriterProof::AttachmentLease {
            node_signed: true,
            countersigning_core_id: Some(1),
        };
        assert_eq!(
            state.apply(by_lease_form),
            Err(DirectoryError::InvalidWriter)
        );
        // A target on a non-lease kind is structurally invalid.
        let mut identity_with_target = identity(node_id(1, 7), 1, 1);
        identity_with_target.target_core_id = Some(1);
        assert_eq!(
            state.apply(identity_with_target),
            Err(DirectoryError::InvalidTargetCore)
        );

        // A Core may only write its own LSA (§3.3).
        let mut other_core = lsa(4, 1, 1, 3);
        other_core.writer = WriterProof::CoreOperationalKey { core_id: 5 };
        assert_eq!(state.apply(other_core), Err(DirectoryError::InvalidWriter));
        let mut authority_lsa = lsa(4, 1, 1, 3);
        authority_lsa.writer = WriterProof::IdentityAuthority;
        assert_eq!(
            state.apply(authority_lsa),
            Err(DirectoryError::InvalidWriter)
        );

        assert!(state.is_empty());
        assert_eq!(
            state.apply(identity(node_id(1, 7), 1, 1)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.apply(lsa(4, 1, 1, 3)), Ok(ApplyOutcome::Applied));
    }

    #[test]
    fn invalid_versions_and_subjects_are_rejected() {
        let mut state = DirectoryConvergence::new();
        assert_eq!(home_core_id_for_node(0), None);
        assert_eq!(home_core_id_for_node(node_id(1, 1)), Some(1));
        assert_eq!(home_core_id_for_node(node_id(16, 251)), Some(16));
        assert_eq!(home_core_id_for_node(node_id(16, 252)), None);
        assert_eq!(home_core_id_for_node(4096), None);

        // Generation / seq components start at 1 (§5.4; fail-closed for
        // the components the plan does not explicitly bound yet).
        assert_eq!(
            state.apply(identity(node_id(1, 2), 0, 1)),
            Err(DirectoryError::InvalidVersion)
        );
        assert_eq!(
            state.apply(lease(node_id(1, 2), 0, 1, 1, 1)),
            Err(DirectoryError::InvalidVersion)
        );
        assert_eq!(
            state.apply(lease(node_id(1, 2), 1, 0, 1, 1)),
            Err(DirectoryError::InvalidVersion)
        );
        assert_eq!(
            state.apply(lsa(1, 0, 1, 1)),
            Err(DirectoryError::InvalidVersion)
        );
        assert_eq!(
            state.apply(lsa(1, 1, 0, 1)),
            Err(DirectoryError::InvalidVersion)
        );

        // Version variant must match the record kind (no mixing of
        // sequence spaces across kinds, §3.3).
        let mut mismatched = identity(node_id(1, 2), 1, 1);
        mismatched.version = VersionKey::CoreLsa {
            core_generation: 1,
            seq: 1,
        };
        assert_eq!(state.apply(mismatched), Err(DirectoryError::InvalidVersion));
        let mut mismatched = lsa(1, 1, 1, 1);
        mismatched.version = VersionKey::NodeIdentity {
            identity_generation: 1,
        };
        assert_eq!(state.apply(mismatched), Err(DirectoryError::InvalidVersion));

        // Subject encodability.
        let mut bad_subject = identity(node_id(1, 2), 1, 1);
        bad_subject.subject = 0;
        assert_eq!(
            state.apply(bad_subject),
            Err(DirectoryError::InvalidSubject)
        );
        let mut bad_subject = lease(node_id(1, 2), 1, 1, 1, 1);
        bad_subject.subject = node_id(1, 252);
        assert_eq!(
            state.apply(bad_subject),
            Err(DirectoryError::InvalidSubject)
        );
        assert_eq!(
            state.apply(lsa(17, 1, 1, 1)),
            Err(DirectoryError::InvalidSubject)
        );
        assert!(state.is_empty());
    }

    #[test]
    fn lease_to_different_target_at_same_version_is_equivocation() {
        // target_core_id is part of the signed body (§5.4): two leases
        // at one version naming different targets (each correctly
        // countersigned by its own target) are a node double-sign.
        let subject = node_id(2, 9);
        let key = DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject,
        };
        let mut a_first = DirectoryConvergence::new();
        assert_eq!(
            a_first.apply(lease(subject, 1, 3, 5, 20)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            a_first.apply(lease(subject, 1, 3, 6, 20)),
            Ok(ApplyOutcome::Equivocated)
        );
        let mut b_first = DirectoryConvergence::new();
        assert_eq!(
            b_first.apply(lease(subject, 1, 3, 6, 20)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            b_first.apply(lease(subject, 1, 3, 5, 20)),
            Ok(ApplyOutcome::Equivocated)
        );
        assert_eq!(a_first.status(key), KeyStatus::Poisoned);
        assert!(a_first.get(key).is_none());
        assert_eq!(a_first.snapshot(), b_first.snapshot());
    }

    #[test]
    fn composite_versions_order_generation_first_and_reject_rollback() {
        // --- NodeIdentity: (NodeID, identity_generation) ---
        let id_key = DirectoryKey {
            kind: DirectoryObjectKind::NodeIdentity,
            subject: node_id(1, 8),
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(state.status(id_key), KeyStatus::Absent);
        assert_eq!(
            state.apply(identity(id_key.subject, 5, 5)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            state.apply(identity(id_key.subject, 5, 5)),
            Ok(ApplyOutcome::Duplicate)
        );
        // Generation rollback can never become active.
        assert_eq!(
            state.apply(identity(id_key.subject, 4, 4)),
            Ok(ApplyOutcome::Stale)
        );
        assert_eq!(
            state.watermark(id_key),
            Some(VersionKey::NodeIdentity {
                identity_generation: 5
            })
        );
        assert_eq!(
            state.apply(identity(id_key.subject, 6, 6)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.get(id_key).unwrap().content_hash, hash(6));

        // --- AttachmentLease: (NodeID, identity_generation, attach_generation) ---
        let lease_key = DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject: node_id(1, 8),
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(
            state.apply(lease(lease_key.subject, 2, 1, 1, 21)),
            Ok(ApplyOutcome::Applied)
        );
        // Older identity_generation loses even with a huge
        // attach_generation: generation orders first.
        assert_eq!(
            state.apply(lease(lease_key.subject, 1, 999, 1, 22)),
            Ok(ApplyOutcome::Stale)
        );
        // Same identity_generation: attach_generation orders.
        assert_eq!(
            state.apply(lease(lease_key.subject, 2, 7, 3, 23)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            state.apply(lease(lease_key.subject, 2, 6, 3, 24)),
            Ok(ApplyOutcome::Stale)
        );
        // Newer identity_generation wins even with attach_generation 1.
        assert_eq!(
            state.apply(lease(lease_key.subject, 3, 1, 4, 25)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            state.watermark(lease_key),
            Some(VersionKey::AttachmentLease {
                identity_generation: 3,
                attach_generation: 1,
            })
        );

        // --- CoreLsa: (core_id, core_generation, seq) ---
        let lsa_key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 9,
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(state.apply(lsa(9, 2, 1, 31)), Ok(ApplyOutcome::Applied));
        // core_generation rollback loses even with seq = u64::MAX.
        assert_eq!(
            state.apply(lsa(9, 1, u64::MAX, 32)),
            Ok(ApplyOutcome::Stale)
        );
        assert_eq!(state.apply(lsa(9, 2, 50, 33)), Ok(ApplyOutcome::Applied));
        assert_eq!(state.apply(lsa(9, 2, 49, 34)), Ok(ApplyOutcome::Stale));
        // New core_generation restarts seq ordering.
        assert_eq!(state.apply(lsa(9, 3, 1, 35)), Ok(ApplyOutcome::Applied));
        assert_eq!(
            state.watermark(lsa_key),
            Some(VersionKey::CoreLsa {
                core_generation: 3,
                seq: 1,
            })
        );
    }

    #[test]
    fn same_epoch_higher_seq_never_launders_poison_but_new_epoch_starts_clean() {
        let key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 5,
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(state.apply(lsa(5, 1, 9, 10)), Ok(ApplyOutcome::Applied));
        assert_eq!(state.apply(lsa(5, 1, 9, 11)), Ok(ApplyOutcome::Equivocated));
        assert_eq!(state.status(key), KeyStatus::Poisoned);
        // Same core_generation, far higher seq: no laundering.
        assert_eq!(state.apply(lsa(5, 1, 9999, 12)), Ok(ApplyOutcome::Poisoned));
        assert!(state.get(key).is_none());
        assert!(state.get_including_tombstone(key).is_none());
        assert_eq!(
            state.poisoned_epochs(key),
            vec![(
                1,
                VersionKey::CoreLsa {
                    core_generation: 1,
                    seq: 9,
                },
            )]
        );
        // A strictly higher core_generation starts clean; the poisoned
        // epoch stays visible, never cleared.
        assert_eq!(state.apply(lsa(5, 2, 1, 13)), Ok(ApplyOutcome::Applied));
        assert_eq!(state.status(key), KeyStatus::Active);
        assert_eq!(state.get(key).unwrap().content_hash, hash(13));
        assert_eq!(state.poisoned_epochs(key).len(), 1);
        let snap = state.snapshot();
        assert_eq!(snap.poisoned.len(), 1);
        assert_eq!(snap.poisoned[0].epoch, 1);
        assert_eq!(snap.active.len(), 1);
        // Old-epoch records arriving late still cannot displace it.
        assert_eq!(
            state.apply(lsa(5, 1, 10_000, 14)),
            Ok(ApplyOutcome::Poisoned)
        );
        assert_eq!(state.get(key).unwrap().content_hash, hash(13));

        // Same rule for AttachmentLease across identity_generation.
        let subject = node_id(3, 8);
        let lease_key = DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject,
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(
            state.apply(lease(subject, 1, 4, 3, 40)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            state.apply(lease(subject, 1, 4, 3, 41)),
            Ok(ApplyOutcome::Equivocated)
        );
        assert_eq!(
            state.apply(lease(subject, 1, 500, 3, 42)),
            Ok(ApplyOutcome::Poisoned)
        );
        assert_eq!(
            state.apply(lease(subject, 2, 1, 3, 43)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.status(lease_key), KeyStatus::Active);
        assert_eq!(
            state.equivocation_version(lease_key, 1),
            Some(VersionKey::AttachmentLease {
                identity_generation: 1,
                attach_generation: 4,
            })
        );
    }

    #[test]
    fn new_identity_generation_recycled_nodeid_supersedes_poisoned_old_generation() {
        // §3.2 NodeID recycling: the recycled identity carries a
        // strictly higher identity_generation, which is exactly the
        // clean-epoch transition; anything from the old generation —
        // including its equivocation — cannot resurrect.
        let subject = node_id(3, 8);
        let key = DirectoryKey {
            kind: DirectoryObjectKind::NodeIdentity,
            subject,
        };
        let mut state = DirectoryConvergence::new();
        assert_eq!(
            state.apply(identity(subject, 9, 10)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            state.apply(identity(subject, 9, 11)),
            Ok(ApplyOutcome::Equivocated)
        );
        assert_eq!(state.status(key), KeyStatus::Poisoned);
        assert!(state.get(key).is_none());
        // Same generation cannot recover (NodeIdentity has no
        // within-epoch order to climb).
        assert_eq!(
            state.apply(identity(subject, 9, 10)),
            Ok(ApplyOutcome::Poisoned)
        );
        // Recycled NodeID at generation 10.
        assert_eq!(
            state.apply(identity(subject, 10, 12)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.status(key), KeyStatus::Active);
        assert_eq!(
            state.poisoned_epochs(key),
            vec![(
                9,
                VersionKey::NodeIdentity {
                    identity_generation: 9,
                },
            )]
        );
        assert_eq!(
            state.watermark(key),
            Some(VersionKey::NodeIdentity {
                identity_generation: 10,
            })
        );
    }

    #[test]
    fn equivocation_is_isolated_across_epochs_in_both_directions() {
        let key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 6,
        };
        // Direction 1: a fork discovered in an OLD epoch, after a newer
        // epoch became top, must not drop the newer top.
        let mut state = DirectoryConvergence::new();
        state.apply(lsa(6, 1, 3, 30)).unwrap();
        state.apply(lsa(6, 2, 1, 31)).unwrap();
        assert_eq!(state.apply(lsa(6, 1, 3, 32)), Ok(ApplyOutcome::Equivocated));
        assert_eq!(state.status(key), KeyStatus::Active);
        assert_eq!(state.get(key).unwrap().content_hash, hash(31));
        assert_eq!(state.poisoned_epochs(key).len(), 1);

        // Direction 2: a fork in the NEW epoch drops the new top and
        // must NOT fall back to the old epoch's record.
        let mut state = DirectoryConvergence::new();
        state.apply(lsa(6, 1, 3, 30)).unwrap();
        state.apply(lsa(6, 2, 1, 31)).unwrap();
        assert_eq!(state.apply(lsa(6, 2, 1, 33)), Ok(ApplyOutcome::Equivocated));
        assert_eq!(state.status(key), KeyStatus::Poisoned);
        assert!(state.get(key).is_none());
        // The old record cannot resurrect while the watermark epoch is
        // poisoned.
        assert_eq!(state.apply(lsa(6, 1, 3, 30)), Ok(ApplyOutcome::Stale));
        assert!(state.get(key).is_none());
        assert_eq!(
            state.poisoned_epochs(key),
            vec![(
                2,
                VersionKey::CoreLsa {
                    core_generation: 2,
                    seq: 1,
                },
            )]
        );

        // Direction 2 with the fork revealed at a stale within-epoch
        // version: the whole current epoch is frozen, not just the
        // forked version.
        let mut state = DirectoryConvergence::new();
        state.apply(lsa(6, 2, 3, 30)).unwrap();
        state.apply(lsa(6, 2, 8, 38)).unwrap();
        assert_eq!(state.apply(lsa(6, 2, 3, 39)), Ok(ApplyOutcome::Equivocated));
        assert_eq!(state.status(key), KeyStatus::Poisoned);
        assert!(state.get(key).is_none());
        assert_eq!(
            state.equivocation_version(key, 2),
            Some(VersionKey::CoreLsa {
                core_generation: 2,
                seq: 3,
            })
        );
    }

    #[test]
    fn poisoned_epoch_entry_via_fork_proof_first_drops_lower_top() {
        // Order stress: the fork proof for epoch 2 is complete before
        // any epoch-2 record could be top, while a clean epoch-1 record
        // arrived first. The watermark advances into the poisoned
        // epoch, so the epoch-1 top must be dropped in this order too.
        let key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 8,
        };
        let mut state = DirectoryConvergence::new();
        state.apply(lsa(8, 1, 1, 50)).unwrap();
        assert_eq!(state.apply(lsa(8, 2, 1, 51)), Ok(ApplyOutcome::Applied));
        assert_eq!(state.apply(lsa(8, 2, 1, 52)), Ok(ApplyOutcome::Equivocated));
        assert_eq!(state.status(key), KeyStatus::Poisoned);
        assert!(state.get(key).is_none());
    }

    #[test]
    fn stale_fork_poisons_within_evidence_window_in_any_order() {
        let key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 5,
        };
        let old_a = lsa(5, 1, 3, 30);
        let old_b = lsa(5, 1, 3, 31);
        let newer = lsa(5, 1, 8, 38);

        let mut forward = DirectoryConvergence::new();
        forward.apply(old_a.clone()).unwrap();
        forward.apply(newer.clone()).unwrap();
        assert_eq!(forward.apply(old_b.clone()), Ok(ApplyOutcome::Equivocated));

        let mut reverse = DirectoryConvergence::new();
        reverse.apply(old_b).unwrap();
        reverse.apply(newer).unwrap();
        assert_eq!(reverse.apply(old_a), Ok(ApplyOutcome::Equivocated));

        assert_eq!(forward.snapshot(), reverse.snapshot());
        assert_eq!(forward.status(key), KeyStatus::Poisoned);
        assert_eq!(
            forward.equivocation_version(key, 1),
            Some(VersionKey::CoreLsa {
                core_generation: 1,
                seq: 3,
            })
        );
    }

    #[test]
    fn tombstone_hides_record_and_blocks_resurrection() {
        let subject = node_id(1, 20);
        let key = DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject,
        };
        let mut state = DirectoryConvergence::new();
        let old = lease(subject, 1, 3, 1, 7);
        state.apply(old.clone()).unwrap();
        assert!(state.get(key).is_some());

        let mut tombstone = lease(subject, 1, 10, 1, 70);
        tombstone.tombstone = true;
        assert_eq!(state.apply(tombstone.clone()), Ok(ApplyOutcome::Applied));
        assert_eq!(state.status(key), KeyStatus::Tombstoned);
        assert!(state.get(key).is_none());
        assert!(state.get_including_tombstone(key).unwrap().tombstone);
        assert_eq!(
            state.watermark(key),
            Some(VersionKey::AttachmentLease {
                identity_generation: 1,
                attach_generation: 10,
            })
        );
        assert!(state.snapshot().active.is_empty());

        // No pre-tombstone version can resurrect the key (watermark).
        assert_eq!(state.apply(old), Ok(ApplyOutcome::Stale));
        assert_eq!(
            state.apply(lease(subject, 1, 9, 1, 71)),
            Ok(ApplyOutcome::Stale)
        );
        assert_eq!(state.status(key), KeyStatus::Tombstoned);
        // Re-delivering the tombstone itself is idempotent.
        assert_eq!(state.apply(tombstone), Ok(ApplyOutcome::Duplicate));
        // Post-tombstone re-issuance rules within one epoch are an
        // upper-layer generation/revocation policy (module docs); this
        // machine only guarantees watermark monotonicity.
        assert_eq!(
            state.apply(lease(subject, 1, 11, 1, 72)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(state.status(key), KeyStatus::Active);
    }

    #[test]
    fn oversized_payload_and_capacity_are_rejected_without_state_change() {
        let mut state = DirectoryConvergence::new();
        let key = DirectoryKey {
            kind: DirectoryObjectKind::NodeIdentity,
            subject: node_id(1, 30),
        };
        state.apply(identity(key.subject, 1, 1)).unwrap();
        let before = state.snapshot();

        let mut too_big = identity(key.subject, 2, 2);
        too_big.payload = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(state.apply(too_big), Err(DirectoryError::PayloadTooLarge));
        let mut new_big = identity(node_id(1, 31), 1, 3);
        new_big.payload = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(state.apply(new_big), Err(DirectoryError::PayloadTooLarge));
        assert_eq!(state.snapshot(), before);
        assert_eq!(state.key_count(), 1);
        // Exactly at the §3.3 16 KiB single-object bound is accepted.
        let mut at_bound = identity(key.subject, 2, 2);
        at_bound.payload = vec![0; MAX_PAYLOAD_BYTES];
        assert_eq!(state.apply(at_bound), Ok(ApplyOutcome::Applied));

        // Key bound (basis: 4016 NodeID subjects × 2 kinds + 16 CoreLsa).
        assert_eq!(MAX_NODE_SUBJECTS, 4016);
        assert_eq!(MAX_KEYS, 8048);
        assert_eq!(
            DirectoryConvergence::with_max_keys(0).err(),
            Some(DirectoryError::InvalidCapacity)
        );
        assert_eq!(
            DirectoryConvergence::with_max_keys(MAX_KEYS + 1).err(),
            Some(DirectoryError::InvalidCapacity)
        );
        let mut state = DirectoryConvergence::with_max_keys(2).unwrap();
        state.apply(identity(node_id(1, 2), 1, 1)).unwrap();
        state.apply(identity(node_id(1, 3), 1, 2)).unwrap();
        let before = state.snapshot();
        assert_eq!(
            state.apply(identity(node_id(1, 4), 1, 3)),
            Err(DirectoryError::TooManyKeys)
        );
        assert_eq!(state.snapshot(), before);
        // Updates to existing keys still work at the bound.
        assert_eq!(
            state.apply(identity(node_id(1, 2), 2, 4)),
            Ok(ApplyOutcome::Applied)
        );
    }

    #[test]
    fn same_content_hash_with_different_envelope_bytes_is_a_duplicate() {
        // `content_hash` is SHA-256 of the canonical TBS, not of the signature
        // envelope. Re-signing identical TBS bytes changes only `payload`
        // bytes here, so it must not be reported as a fork.
        let key = DirectoryKey {
            kind: DirectoryObjectKind::CoreLsa,
            subject: 7,
        };
        let mut state = DirectoryConvergence::new();
        let first = lsa(7, 1, 4, 40);
        let mut second = lsa(7, 1, 4, 40);
        second.payload = vec![2];
        assert_eq!(state.apply(first), Ok(ApplyOutcome::Applied));
        assert_eq!(state.apply(second), Ok(ApplyOutcome::Duplicate));
        assert_eq!(state.status(key), KeyStatus::Active);
        // Both envelopes carry the same TBS; the smaller exact envelope is
        // retained so a re-signed duplicate is order independent.
        assert_eq!(
            state.get(key).expect("active").payload.as_slice(),
            &[2u8][..]
        );

        let mut reverse = DirectoryConvergence::new();
        let mut smaller_first = lsa(7, 1, 4, 40);
        smaller_first.payload = vec![2];
        assert_eq!(reverse.apply(smaller_first), Ok(ApplyOutcome::Applied));
        assert_eq!(reverse.apply(lsa(7, 1, 4, 40)), Ok(ApplyOutcome::Duplicate));
        assert_eq!(reverse.snapshot(), state.snapshot());
    }

    /// Deterministic body for (key, version) in the generated set:
    /// identical (key, version) always yields identical content, so the
    /// set is fork-free except for the explicitly appended forks.
    fn generated_record(key: DirectoryKey, epoch: u64, within: u64) -> RecordEnvelope {
        let base = u64::from(key.subject) * 31
            + epoch.wrapping_mul(131)
            + within.wrapping_mul(17)
            + u64::from(key.kind.tag());
        let seed = (base % 251) as u8;
        let payload = base.to_be_bytes().to_vec();
        let mut record = match key.kind {
            // Emitted with within == 1 (unused for this kind).
            DirectoryObjectKind::NodeIdentity => {
                RecordEnvelope::node_identity(key.subject, epoch, hash(seed), payload, false)
            }
            DirectoryObjectKind::AttachmentLease => {
                // Deterministic roaming: target cycles over all Cores,
                // independent of the subject's home Core.
                let target = (base % 16 + 1) as u8;
                RecordEnvelope::attachment_lease(
                    key.subject,
                    epoch,
                    within,
                    target,
                    hash(seed),
                    payload,
                    false,
                )
            }
            DirectoryObjectKind::CoreLsa => RecordEnvelope::core_lsa(
                key.subject as u8,
                epoch,
                within,
                hash(seed),
                payload,
                false,
            ),
        };
        // Deterministic tombstones at the top of some epochs.
        record.tombstone = within == 4 && epoch == 2;
        record
    }

    fn generated_records() -> Vec<RecordEnvelope> {
        let mut rng = Lcg(0x5eed_5eed_5eed_5eed);
        let mut keys: Vec<DirectoryKey> = Vec::new();
        for core in 1..=4u8 {
            for octet in [1u8, 2, 3, 4, 9, 251] {
                let subject = node_id(core, octet);
                keys.push(DirectoryKey {
                    kind: DirectoryObjectKind::NodeIdentity,
                    subject,
                });
                keys.push(DirectoryKey {
                    kind: DirectoryObjectKind::AttachmentLease,
                    subject,
                });
            }
            keys.push(DirectoryKey {
                kind: DirectoryObjectKind::CoreLsa,
                subject: u16::from(core),
            });
        }
        // Every key is guaranteed one record at its maximal version
        // (epoch 3), so reference keys are all tracked; forks are all in
        // epoch <= 2, keeping poison/active outcomes order-stable.
        let mut out: Vec<RecordEnvelope> = keys
            .iter()
            .map(|key| generated_record(*key, 3, 1))
            .collect();
        for _ in 0..260 {
            let key = keys[rng.below(keys.len())];
            let epoch = 1 + (rng.next_u64() % 3);
            let within = match key.kind {
                DirectoryObjectKind::NodeIdentity => 1,
                _ => 1 + (rng.next_u64() % 4),
            };
            out.push(generated_record(key, epoch, within));
        }
        // Forks: lease epoch 1, identity generation 2, LSA epoch 2.
        out.push(lease(node_id(2, 42), 1, 7, 9, 200));
        out.push(lease(node_id(2, 42), 1, 7, 9, 201));
        out.push(identity(node_id(3, 42), 2, 202));
        out.push(identity(node_id(3, 42), 2, 203));
        out.push(lsa(7, 2, 5, 204));
        out.push(lsa(7, 2, 5, 205));
        // Clean higher epochs above two of the forks (the lease fork
        // deliberately has none, so its key ends Poisoned).
        out.push(identity(node_id(3, 42), 3, 206));
        out.push(lsa(7, 3, 1, 207));
        out
    }

    #[test]
    fn shuffled_and_duplicated_delivery_converges_to_identical_snapshot() {
        let records = generated_records();
        assert!(records.len() >= 300);

        let mut reference_state = DirectoryConvergence::new();
        for record in &records {
            reference_state.apply(record.clone()).unwrap();
        }
        let reference = reference_state.snapshot();

        // The three forked epochs are all reported, in key order.
        let poisoned_keys: Vec<(DirectoryObjectKind, u16, u64)> = reference
            .poisoned
            .iter()
            .map(|p| (p.key.kind, p.key.subject, p.epoch))
            .collect();
        assert_eq!(
            poisoned_keys,
            vec![
                (DirectoryObjectKind::NodeIdentity, node_id(3, 42), 2),
                (DirectoryObjectKind::AttachmentLease, node_id(2, 42), 1),
                (DirectoryObjectKind::CoreLsa, 7, 2),
            ]
        );
        // Forked key without a clean higher epoch ends Poisoned; the
        // other two are Active on their new epochs.
        assert_eq!(
            reference_state.status(DirectoryKey {
                kind: DirectoryObjectKind::AttachmentLease,
                subject: node_id(2, 42),
            }),
            KeyStatus::Poisoned
        );
        assert_eq!(
            reference_state.status(DirectoryKey {
                kind: DirectoryObjectKind::NodeIdentity,
                subject: node_id(3, 42),
            }),
            KeyStatus::Active
        );
        assert_eq!(
            reference_state.status(DirectoryKey {
                kind: DirectoryObjectKind::CoreLsa,
                subject: 7,
            }),
            KeyStatus::Active
        );
        assert!(!reference.active.is_empty());

        for seed in [1u64, 42, 0xfeed, 0xdead_beef, 0xc0ff_ee00] {
            let mut delivered = records.clone();
            // Duplicate roughly a third of the set.
            delivered.extend(records.iter().step_by(3).cloned());
            shuffle(&mut delivered, &mut Lcg(seed));
            let mut state = DirectoryConvergence::new();
            for record in delivered {
                state.apply(record).unwrap();
            }
            assert_eq!(state.snapshot(), reference, "seed {seed}");
        }

        // Re-delivery of the whole set to a converged replica is
        // idempotent.
        for record in &records {
            reference_state.apply(record.clone()).unwrap();
        }
        assert_eq!(reference_state.snapshot(), reference);
    }
}

#[cfg(test)]
mod ingest_tests {
    use super::*;

    /// Test-only pseudo-envelope layout. It is NOT a wire format and carries no
    /// signature: these tests probe the verification gate, the evidence bound and
    /// the paging bound, not cryptography. Real dual-signed objects are exercised
    /// through [`pki_verifier::PkiObjectVerifier`] in `tests/mesh_runtime.rs`.
    const MAGIC: u8 = 0xA1;
    const FORK_MAGIC: u8 = 0xE0;
    const PREFIX_LEN: usize = 23;

    /// Non-cryptographic digest for the test verifier's `content_hash`.
    fn hash32(raw: &[u8]) -> [u8; 32] {
        let mut state = FNV_OFFSET_BASIS;
        for byte in raw {
            state ^= u64::from(*byte);
            state = state.wrapping_mul(FNV_PRIME);
        }
        let mut out = [0u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = state.rotate_left((index % 64) as u32) as u8;
        }
        out
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct RawSpec {
        kind: u8,
        subject: u16,
        epoch: u64,
        within: u64,
        target: u8,
        countersigner: u8,
        node_signed: bool,
    }

    fn envelope(magic: u8, spec: RawSpec, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREFIX_LEN + body.len());
        out.push(magic);
        out.push(spec.kind);
        out.extend_from_slice(&spec.subject.to_be_bytes());
        out.extend_from_slice(&spec.epoch.to_be_bytes());
        out.extend_from_slice(&spec.within.to_be_bytes());
        out.push(spec.target);
        out.push(spec.countersigner);
        out.push(u8::from(spec.node_signed));
        out.extend_from_slice(body);
        out
    }

    fn parse(raw: &[u8]) -> Option<VerifiedFacts> {
        if raw.len() < PREFIX_LEN {
            return None;
        }
        let subject = u16::from_be_bytes([raw[2], raw[3]]);
        let epoch = u64::from_be_bytes(raw[4..12].try_into().ok()?);
        let within = u64::from_be_bytes(raw[12..20].try_into().ok()?);
        let target = (raw[20] != 0).then_some(raw[20]);
        let countersigner = (raw[21] != 0).then_some(raw[21]);
        let node_signed = raw[22] == 1;
        let (kind, version, writer, target_core_id) = match raw[1] {
            1 => (
                DirectoryObjectKind::NodeIdentity,
                VersionKey::NodeIdentity {
                    identity_generation: epoch,
                },
                WriterProof::IdentityAuthority,
                None,
            ),
            2 => (
                DirectoryObjectKind::AttachmentLease,
                VersionKey::AttachmentLease {
                    identity_generation: epoch,
                    attach_generation: within,
                },
                WriterProof::AttachmentLease {
                    node_signed,
                    countersigning_core_id: countersigner.or(target),
                },
                target,
            ),
            3 => (
                DirectoryObjectKind::CoreLsa,
                VersionKey::CoreLsa {
                    core_generation: epoch,
                    seq: within,
                },
                WriterProof::CoreOperationalKey {
                    core_id: u8::try_from(subject).ok()?,
                },
                None,
            ),
            _ => return None,
        };
        Some(VerifiedFacts {
            kind,
            subject,
            version,
            writer,
            target_core_id,
            content_hash: hash32(raw),
            tombstone: false,
        })
    }

    #[derive(Default)]
    struct TestVerifier {
        calls: usize,
    }

    impl ObjectVerifier for TestVerifier {
        fn verify(
            &mut self,
            raw_signed_object: &[u8],
            _now_us: u64,
        ) -> Result<VerifiedFacts, VerifyReject> {
            self.calls += 1;
            match raw_signed_object.first() {
                Some(&MAGIC) | Some(&FORK_MAGIC) => {
                    let facts = parse(raw_signed_object).ok_or(VerifyReject::Rejected)?;
                    if raw_signed_object[0] == FORK_MAGIC {
                        Err(VerifyReject::Equivocation(facts))
                    } else {
                        Ok(facts)
                    }
                }
                _ => Err(VerifyReject::Rejected),
            }
        }
    }

    fn node(core: u8, octet: u8) -> u16 {
        ((u16::from(core) - 1) << 8) | u16::from(octet)
    }

    fn identity_raw(subject: u16, generation: u64, body: &[u8]) -> Vec<u8> {
        envelope(
            MAGIC,
            RawSpec {
                kind: 1,
                subject,
                epoch: generation,
                ..RawSpec::default()
            },
            body,
        )
    }

    fn lease_raw(subject: u16, id_gen: u64, attach_gen: u64, target: u8, body: &[u8]) -> Vec<u8> {
        envelope(
            MAGIC,
            RawSpec {
                kind: 2,
                subject,
                epoch: id_gen,
                within: attach_gen,
                target,
                node_signed: true,
                ..RawSpec::default()
            },
            body,
        )
    }

    fn lease_key(subject: u16) -> DirectoryKey {
        DirectoryKey {
            kind: DirectoryObjectKind::AttachmentLease,
            subject,
        }
    }

    fn lease_version(id_gen: u64, attach_gen: u64) -> VersionKey {
        VersionKey::AttachmentLease {
            identity_generation: id_gen,
            attach_generation: attach_gen,
        }
    }

    #[test]
    fn unverified_bytes_never_reach_convergence() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        // Unknown envelope: the verifier refuses it.
        let rejected = [0xB0u8; 24];
        assert_eq!(
            ingest.verify_and_apply(&rejected, 1),
            IngestOutcome::Rejected
        );
        assert_eq!(ingest.directory().key_count(), 0);
        assert_eq!(ingest.stats().rejected, 1);
        assert_eq!(ingest.verifier().calls, 1);

        // Oversize input is refused by the payload bound before any verifier
        // call, so a huge frame cannot even reach the trust layer.
        let oversize = vec![MAGIC; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            ingest.verify_and_apply(&oversize, 1),
            IngestOutcome::Refused(DirectoryError::PayloadTooLarge)
        );
        assert_eq!(ingest.verifier().calls, 1);
        assert_eq!(ingest.stats().refused, 1);

        // Empty input is not an object.
        assert_eq!(ingest.verify_and_apply(&[], 1), IngestOutcome::Rejected);
        assert_eq!(ingest.stats().rejected, 2);
    }

    #[test]
    fn dual_signature_requirement_is_enforced_before_convergence() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        let subject = node(2, 9);
        let good = lease_raw(subject, 1, 1, 2, b"lease");
        assert_eq!(
            ingest.verify_and_apply(&good, 1),
            IngestOutcome::Verified(ApplyOutcome::Applied)
        );

        // The co-signer claims to be Core 3 while the lease names Core 2.
        let mut wrong_core = lease_raw(subject, 1, 2, 2, b"lease-2");
        wrong_core[21] = 3;
        assert_eq!(
            ingest.verify_and_apply(&wrong_core, 1),
            IngestOutcome::Refused(DirectoryError::CountersignatureMismatch)
        );

        // A lease without the node's own primary signature.
        let mut unsigned = lease_raw(subject, 1, 3, 2, b"lease-3");
        unsigned[22] = 0;
        assert_eq!(
            ingest.verify_and_apply(&unsigned, 1),
            IngestOutcome::Refused(DirectoryError::MissingNodeSignature)
        );

        // Neither refused lease advanced the accepted attach generation.
        let top = ingest
            .directory()
            .get(lease_key(subject))
            .expect("first lease still active");
        assert_eq!(top.version, lease_version(1, 1));
        assert_eq!(top.target_core_id, Some(2));
        assert_eq!(ingest.stats().applied, 1);
        assert_eq!(ingest.stats().refused, 2);
    }

    #[test]
    fn same_version_fork_preserves_both_original_bytes() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        let subject = node(2, 11);
        let first = lease_raw(subject, 1, 4, 2, b"body-a");
        let second = lease_raw(subject, 1, 4, 2, b"body-b");
        assert_eq!(
            ingest.verify_and_apply(&first, 1),
            IngestOutcome::Verified(ApplyOutcome::Applied)
        );
        assert_eq!(
            ingest.verify_and_apply(&second, 1),
            IngestOutcome::Equivocated
        );
        assert_eq!(
            ingest.directory().status(lease_key(subject)),
            KeyStatus::Poisoned
        );
        let evidence = ingest
            .evidence()
            .get(lease_key(subject), lease_version(1, 4))
            .expect("fork evidence retained");
        assert_eq!(evidence.retained.as_deref(), Some(first.as_slice()));
        assert_eq!(evidence.conflicting, second);
        assert_eq!(ingest.evidence().dropped(), 0);
        assert_eq!(ingest.stats().equivocated, 1);
    }

    #[test]
    fn verifier_reported_fork_is_keyed_without_a_counterpart() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        let subject = node(5, 3);
        let forked = envelope(
            FORK_MAGIC,
            RawSpec {
                kind: 2,
                subject,
                epoch: 4,
                within: 2,
                target: 5,
                node_signed: true,
                ..RawSpec::default()
            },
            b"forked",
        );
        assert_eq!(
            ingest.verify_and_apply(&forked, 1),
            IngestOutcome::Equivocated
        );
        let evidence = ingest
            .evidence()
            .get(lease_key(subject), lease_version(4, 2))
            .expect("conflicting original retained");
        // This replica never held the counterpart, and says so instead of
        // inventing one.
        assert_eq!(evidence.retained, None);
        assert_eq!(evidence.conflicting, forked);
        assert_eq!(
            ingest.directory().status(lease_key(subject)),
            KeyStatus::Absent
        );
    }

    #[test]
    fn evidence_budget_is_bounded_and_every_drop_is_counted() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        // Thirteen distinct keys at one byte each: the evidence window holds
        // eight, so five forks must be reported as dropped.
        let total = 13u64;
        for octet in 2..=14u8 {
            let subject = node(3, octet);
            assert_eq!(
                ingest.verify_and_apply(&lease_raw(subject, 1, 1, 3, &[octet]), 1),
                IngestOutcome::Verified(ApplyOutcome::Applied)
            );
            assert_eq!(
                ingest.verify_and_apply(&lease_raw(subject, 1, 1, 3, &[octet, octet]), 1),
                IngestOutcome::Equivocated
            );
            assert_eq!(
                ingest.directory().status(lease_key(subject)),
                KeyStatus::Poisoned
            );
        }
        assert_eq!(ingest.evidence().len(), MAX_EVIDENCE_ENTRIES);
        assert!(ingest.evidence().bytes() <= MAX_EVIDENCE_BYTES);
        assert_eq!(
            ingest.evidence().dropped(),
            total - MAX_EVIDENCE_ENTRIES as u64
        );
        assert_eq!(ingest.stats().evidence_dropped, ingest.evidence().dropped());
    }

    #[test]
    fn paged_anti_entropy_converges_in_any_delivery_order() {
        let mut source = DirectoryIngest::new(TestVerifier::default());
        for octet in 2..=60u8 {
            let subject = node(2, octet);
            let body = [octet; 16];
            assert_eq!(
                source.verify_and_apply(&identity_raw(subject, 1, &body), 10),
                IngestOutcome::Verified(ApplyOutcome::Applied)
            );
            assert_eq!(
                source.verify_and_apply(&lease_raw(subject, 1, 1, 2, &body), 10),
                IngestOutcome::Verified(ApplyOutcome::Applied)
            );
        }
        let snapshot = source.snapshot();
        assert_eq!(snapshot.active.len(), 118);

        let pages: Vec<SignedObjectPage> = page_snapshot(&snapshot).collect();
        assert!(pages.len() > 1, "118 objects must not fit one page");
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(page.page_seq, u64::try_from(index).expect("page index"));
            assert!(page.records.len() <= MAX_PAGE_OBJECTS);
            assert!(
                page.records.iter().map(Vec::len).sum::<usize>() <= MAX_PAGE_BYTES,
                "page {} exceeded the byte bound",
                page.page_seq
            );
            assert!(page.records.iter().all(|record| !record.is_empty()));
        }
        assert_eq!(
            pages.iter().flat_map(|page| page.records.iter()).count(),
            snapshot.active.len()
        );

        // Deliver every page in reverse order to a second replica. Convergence is
        // order independent; the periodic cycle repeats whole pages, so the same
        // set delivered again must change nothing.
        let mut replica = DirectoryIngest::new(TestVerifier::default());
        for page in pages.iter().rev() {
            let outcome = replica.ingest_page(page, 10);
            assert_eq!(outcome.page_seq, page.page_seq);
            assert_eq!(outcome.over_limit, 0);
            assert_eq!(outcome.rejected, 0);
            assert_eq!(outcome.outcomes.len(), page.records.len());
        }
        assert_eq!(replica.snapshot(), snapshot);
        let converged = replica.stats();
        for page in &pages {
            replica.ingest_page(page, 10);
        }
        assert_eq!(replica.snapshot(), snapshot);
        assert!(replica.stats().duplicate >= converged.duplicate);
        assert_eq!(replica.stats().equivocated, 0);
        assert_eq!(replica.evidence().len(), 0);
    }

    #[test]
    fn page_bounds_hold_for_large_objects() {
        let mut ingest = DirectoryIngest::new(TestVerifier::default());
        let body = vec![0x5a; 4096];
        for octet in 2..=41u8 {
            ingest.verify_and_apply(&identity_raw(node(4, octet), 1, &body), 1);
        }
        let snapshot = ingest.snapshot();
        assert_eq!(snapshot.active.len(), 40);
        let pages: Vec<SignedObjectPage> = page_snapshot(&snapshot).collect();
        for page in &pages {
            assert!(page.records.len() <= MAX_PAGE_OBJECTS);
            assert!(page.records.iter().map(Vec::len).sum::<usize>() <= MAX_PAGE_BYTES);
        }
        assert_eq!(
            pages.iter().flat_map(|page| page.records.iter()).count(),
            40
        );
        // 4 KiB bodies cannot fill 16 per page under the 16 KiB page bound.
        assert!(pages[0].records.len() < MAX_PAGE_OBJECTS);
        assert!(pages.len() > 1);
    }

    /// Codec-only fixture: a structurally valid signed-object envelope with
    /// zero-filled signatures. `SignedObject::encode` validates lengths and
    /// shape, never a signature, so this exercises the page codec without
    /// claiming any cryptographic evidence.
    fn codec_identity(home_core: u8) -> Vec<u8> {
        let node_id = ((u16::from(home_core) - 1) << 8) | 1;
        let body = boreas_proto::objects::NodeIdentity {
            net_id: [0x39; 16],
            node_id,
            home_core_id: home_core,
            vip: [10, 20, home_core, 1],
            vip6: [0u8; 16],
            role: boreas_proto::objects::NodeRole::Core,
            mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet::Mldsa65,
            identity_pub_mldsa: vec![0x11; 32],
            identity_pub_ed25519: [0x22; 32],
            identity_generation: 1,
            not_before: 1_000_000,
            expires: 9_000_000_000_000_000,
            scope: Vec::new(),
        };
        let object = boreas_proto::objects::ManagementObject {
            net_id: [0x39; 16],
            issuer_key_id: b"codec-fixture".to_vec(),
            issuer_generation: 1,
            subject_identity: boreas_proto::objects::SubjectIdentity::Node(node_id),
            seq: 1,
            issued_at: 1_000_000,
            expires: 9_000_000_000_000_000,
            extensions: Vec::new(),
            body: boreas_proto::objects::ObjectBody::NodeIdentity(body),
        };
        let raw_tbs = boreas_proto::objects::encode_tbs(&object).expect("codec fixture TBS");
        boreas_proto::messages::SignedObject {
            object_type: boreas_proto::objects::ObjectType::NodeIdentity,
            raw_tbs,
            signers: vec![boreas_proto::messages::SignerSignatures {
                role: boreas_proto::messages::SignerRole::Primary,
                ed25519: [0u8; 64],
                mldsa_parameter_set: boreas_proto::objects::MldsaParameterSet::Mldsa65,
                mldsa: vec![0u8; 3309],
            }],
        }
        .encode()
        .expect("codec fixture envelope")
    }

    #[test]
    fn page_body_round_trips_through_the_candidate_control_codec() {
        let first = codec_identity(2);
        let second = codec_identity(3);
        let page = SignedObjectPage {
            page_seq: 7,
            records: vec![first.clone(), second.clone()],
        };
        let body = page.encode_wire().expect("candidate page body");
        assert_eq!(body.len(), 1 + 8 + 1 + 2 + first.len() + 2 + second.len());
        assert!(body.len() <= 16 * 1024);
        assert_eq!(SignedObjectPage::decode_wire(&body).expect("decode"), page);
        // The subtype byte is the candidate `ControlType::DirectoryPage` tag.
        assert_eq!(body[0], 4);

        // A record that is not a signed-object envelope cannot be paged out.
        let bogus = SignedObjectPage {
            page_seq: 1,
            records: vec![b"not-an-envelope".to_vec()],
        };
        assert_eq!(bogus.encode_wire(), Err(PageWireError::NotSignedObject));

        // The candidate count bound and the empty-page rule are enforced first.
        let too_many = SignedObjectPage {
            page_seq: 1,
            records: vec![first.clone(); MAX_PAGE_OBJECTS + 1],
        };
        assert_eq!(too_many.encode_wire(), Err(PageWireError::InvalidCount));
        let empty = SignedObjectPage {
            page_seq: 0,
            records: Vec::new(),
        };
        assert_eq!(empty.encode_wire(), Err(PageWireError::InvalidCount));

        // Hand-building an oversized page must fail closed, not truncate.
        let oversize = SignedObjectPage {
            page_seq: 2,
            records: vec![first; 6],
        };
        assert_eq!(oversize.encode_wire(), Err(PageWireError::BodyTooLarge));

        // A malformed body is refused by the candidate codec.
        assert_eq!(
            SignedObjectPage::decode_wire(&[0xFF; 12]),
            Err(PageWireError::Malformed)
        );
    }

    #[test]
    fn empty_directory_pages_nothing() {
        let ingest = DirectoryIngest::new(TestVerifier::default());
        let snapshot = ingest.snapshot();
        assert!(page_snapshot(&snapshot).next().is_none());
    }
}
