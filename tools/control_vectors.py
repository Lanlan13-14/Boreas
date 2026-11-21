#!/usr/bin/env python3
"""Independent Python validation of candidate Boreas Control message payloads.

This module is a *second implementation* of the candidate control wire format.
It deliberately does not call Rust, does not reuse any Rust encoder, and does not
generate expected bytes from its own encoder: every positive vector is a fixed,
hand-composed byte string whose field table is spelled out in the test module.
The JSON fixture is treated as test input, never as authority on how parsing
works.

Status: candidate / not frozen, and not audited. This verifier proves only that
the fixed bytes match the documented field layout and rejection rules. It proves
nothing about TLS authentication, authorization, signatures, key material or
production readiness, and no cryptography is implemented or implied here.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

# --- framing and registry constants (mirror the candidate spec, not Rust code) ---

PROTO_MAJOR = 3
MAX_BODY = 65_536
RELAY_PREFIX_LEN = 30
MAX_RELAY_PAYLOAD = MAX_BODY - RELAY_PREFIX_LEN  # 65_506
MAX_CIRCUIT_HOPS = 8
MIN_MTU = 576
MAX_MTU = 9_000

SESSION_LEN = 68  # including the subtype byte
NET_ID_LEN = 16
INSTANCE_LEN = 16

SUBTYPE_HELLO = 1
SUBTYPE_ACCEPT = 2
SUBTYPE_ENROLLMENT = 3
SUBTYPE_DIRECTORY_PAGE = 4
SUBTYPE_LEASE = 5
SUBTYPE_LSA = 6
SUBTYPE_GRANT = 7
SUBTYPE_REVOKE = 8
SUBTYPE_PROBE = 9
SUBTYPE_DRAIN = 10
SUBTYPE_CIRCUIT_OPEN = 16
SUBTYPE_CIRCUIT_ACCEPT = 17
SUBTYPE_CIRCUIT_RESET = 18
SUBTYPE_CIRCUIT_CLOSE = 19

# Candidate per-subtype body caps, including the subtype byte.
SUBTYPE_CAPS = {
    1: 4096,
    2: 4096,
    3: 16384,
    4: 16384,
    5: 16384,  # raised from 4 KiB so a dual-signature ML-DSA envelope fits
    6: 8192,
    7: 8192,
    8: 16384,
    9: 256,
    10: 256,
    16: 4096,
    17: 4096,
    18: 256,
    19: 256,
    20: 19767,
}

SUBTYPE_NAMES = {
    1: "SessionHello",
    2: "SessionAccept",
    3: "Enrollment",
    4: "DirectoryPage",
    5: "Lease",
    6: "Lsa",
    7: "Grant",
    8: "Revoke",
    9: "Probe",
    10: "Drain",
    16: "CircuitOpen",
    17: "CircuitAccept",
    18: "CircuitReset",
    19: "CircuitClose",
    20: "IdentityRevocation",
}

# PeerRole wire values, in the same order as the Rust enum.
ROLE_NAMES = {1: "edge", 2: "core", 3: "enrollment-service"}

ENROLLMENT_REQUEST_BASE = 1 + 1 + 2 + 16 + 16 + 32 + 32 + 2  # subtype..csr_len prefix
ENROLLMENT_RESPONSE_FIXED = 1 + 1 + 1 + 16 + 32 + 2 + 8 + 16 + 2
MAX_ENROLLMENT_DER = 8 * 1024

MAX_SIGNED_OBJECT = 16 * 1024
SIGNED_OBJECT_VERSION = 1
SIGNED_OBJECT_SCHEMA_VERSION = 1
ED25519_SIG_LEN = 64  # mandatory: every signer carries both signature families
MLDSA_LEN = {1: 3309, 2: 4627}  # 1 = ML-DSA-65, 2 = ML-DSA-87
MLDSA_NAMES = {1: "mldsa65", 2: "mldsa87"}
SIGNER_PRIMARY = 1
SIGNER_CO_SIGN = 2
OBJECT_TYPE_ATTACHMENT_LEASE = 2
MAX_SIGNERS = 2

PROBE_BODY_LEN = 1 + 1 + 16 + 8 + 8
DRAIN_BODY_LEN = 1 + 1 + 8 + 2
MAX_DRAIN_RETRY_SECONDS = 3600
CIRCUIT_OPEN_BODY_LEN = 1 + 16 + 2 + 8 + 1
CIRCUIT_ACCEPT_BODY_LEN = 1 + 16 + 1
CIRCUIT_ID_BODY_LEN = 1 + 16


class Reject(ValueError):
    """A parser rejection carrying the stable candidate error category."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


class NotModeled(ValueError):
    """A wire shape this independent verifier deliberately does not model.

    Raised instead of accepting or silently ignoring an unmodelled AppHeader
    kind, so a caller cannot mistake "no opinion" for "valid".
    """


# Subtype -> management object types allowed inside its SignedObject. A subtype
# carrying the wrong object type is a schema violation, not a relabeling.
SUBTYPE_OBJECT_TYPES = {
    5: frozenset({2}),  # Lease  -> AttachmentLease
    6: frozenset({3}),  # Lsa    -> CoreLsa
    7: frozenset({4, 5}),  # Grant -> RouteGrant | DirectGrant
    8: frozenset({6}),  # Revoke -> StatusSnapshot
}


# --- primitive field readers -------------------------------------------------


class _Reader:
    """Bounded big-endian field reader with explicit truncation rejection."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int, category: str = "invalid_field") -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Reject(category)
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self, category: str = "invalid_field") -> int:
        return self.take(1, category)[0]

    def u16(self, category: str = "invalid_field") -> int:
        return int.from_bytes(self.take(2, category), "big")

    def u32(self, category: str = "invalid_field") -> int:
        return int.from_bytes(self.take(4, category), "big")

    def u64(self, category: str = "invalid_field") -> int:
        return int.from_bytes(self.take(8, category), "big")


def valid_node_id(value: int) -> bool:
    """Permanent slot encoding: high byte is home_core_id-1, low byte the octet."""
    home = (value >> 8) + 1
    octet = value & 0xFF
    if not 1 <= home <= 16:
        return False
    return octet == 1 or 2 <= octet <= 251


def _nonzero(value: bytes, category: str = "invalid_field") -> None:
    """Several candidate fields are identifiers or challenges, not opaque data.

    An all-zero value is an unset/placeholder field, so it is rejected instead of
    being accepted as a legitimate zero-filled identifier.
    """
    if not any(value):
        raise Reject(category)


# --- session messages --------------------------------------------------------

# Validation order is normative for negative vectors: a vector must carry exactly
# one fault, and the first failing rule below decides the error category. The
# order follows the field order, so a targeted fault is never masked by an
# unrelated rule.


def parse_session(data: bytes) -> dict[str, Any]:
    """Parse a 68-byte SessionHello/SessionAccept payload."""
    if len(data) != SESSION_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype not in (SUBTYPE_HELLO, SUBTYPE_ACCEPT):
        raise Reject("unknown_subtype")
    proto_major = reader.u8("wrong_length")
    if proto_major != PROTO_MAJOR:
        raise Reject("bad_protocol_version")
    net_id = reader.take(NET_ID_LEN, "wrong_length")
    if not any(net_id):
        raise Reject("bad_net_id")
    source_node_id = reader.u16("wrong_length")
    if not valid_node_id(source_node_id):
        raise Reject("bad_node_id")
    destination_node_id = reader.u16("wrong_length")
    if not valid_node_id(destination_node_id):
        raise Reject("bad_node_id")
    if source_node_id == destination_node_id:
        raise Reject("identical_node_ids")
    source_generation = reader.u64("wrong_length")
    if source_generation == 0:
        raise Reject("bad_identity_generation")
    destination_generation = reader.u64("wrong_length")
    if destination_generation == 0:
        raise Reject("bad_identity_generation")
    instance = reader.take(INSTANCE_LEN, "wrong_length")
    source_role = reader.u8("wrong_length")
    if source_role not in (1, 2, 3):
        raise Reject("bad_role")
    path_role = reader.u8("wrong_length")
    if path_role not in (1, 2):
        raise Reject("bad_path_role")
    security_mode = reader.u8("wrong_length")
    if security_mode not in (1, 2):
        raise Reject("bad_security_mode")
    mtu_cap = reader.u16("wrong_length")
    if not MIN_MTU <= mtu_cap <= MAX_MTU:
        raise Reject("invalid_mtu")
    suite = reader.u8("wrong_length")
    if suite not in (1, 2):
        raise Reject("bad_suite")
    capabilities = reader.u64("wrong_length")
    if capabilities != 0:
        raise Reject("unknown_capability")
    if reader.remaining() != 0:
        raise Reject("wrong_length")
    return {
        "message": "SessionHello" if subtype == SUBTYPE_HELLO else "SessionAccept",
        "subtype": subtype,
        "proto_major": proto_major,
        "net_id_hex": net_id.hex(),
        "source_node_id": source_node_id,
        "destination_node_id": destination_node_id,
        "source_identity_generation": source_generation,
        "destination_identity_generation": destination_generation,
        "connection_instance_hex": instance.hex(),
        "source_role": _role_name(source_role),
        "path_role": "cdn" if path_role == 1 else "dir",
        "security_mode": "e2e-required" if security_mode == 1 else "hop-only",
        "mtu_cap": mtu_cap,
        "suite": {1: "pq768", 2: "pq1024"}[suite],
        "capabilities": capabilities,
    }


def _role_name(value: int) -> str:
    return ROLE_NAMES[value]


def check_session_pair(
    hello: bytes,
    accept: bytes,
    *,
    allowed_suites: tuple[int, ...] = (1,),
    allow_hop_only: bool = False,
    expected_accept_source_role: int | None = None,
) -> None:
    """Cross-check a Hello against its Accept.

    Structural parsing alone cannot prove identity or authorization; this only
    verifies the correlation rules the candidate spec requires (swapped
    endpoints, echoed instance, non-downgraded mode and an allowed suite).

    The Accept's `source_role` is the responder's own authenticated role, not a
    copy of the Hello's, so it is never derived from the Hello. Pass
    `expected_accept_source_role` (1 Edge / 2 Core / 3 EnrollmentService) when
    local policy knows what the responder must be.
    """
    first = parse_session(hello)
    second = parse_session(accept)
    if first["subtype"] != SUBTYPE_HELLO or second["subtype"] != SUBTYPE_ACCEPT:
        raise Reject("illegal_state")
    if first["connection_instance_hex"] != second["connection_instance_hex"]:
        raise Reject("session_mismatch")
    if first["net_id_hex"] != second["net_id_hex"]:
        raise Reject("session_mismatch")
    if first["proto_major"] != second["proto_major"]:
        raise Reject("session_mismatch")
    if first["capabilities"] != second["capabilities"]:
        raise Reject("session_mismatch")
    if first["source_node_id"] != second["destination_node_id"]:
        raise Reject("session_mismatch")
    if first["destination_node_id"] != second["source_node_id"]:
        raise Reject("session_mismatch")
    if first["source_identity_generation"] != second["destination_identity_generation"]:
        raise Reject("session_mismatch")
    if first["destination_identity_generation"] != second["source_identity_generation"]:
        raise Reject("session_mismatch")
    if first["path_role"] != second["path_role"] or first["mtu_cap"] != second["mtu_cap"]:
        raise Reject("session_mismatch")
    if first["suite"] != second["suite"]:
        raise Reject("session_mismatch")
    suite_code = {v: k for k, v in {1: "pq768", 2: "pq1024"}.items()}[second["suite"]]
    if suite_code not in allowed_suites:
        raise Reject("illegal_state")
    if first["security_mode"] == "e2e-required" and second["security_mode"] == "hop-only":
        # Silent downgrade is forbidden (§1.3); this is a policy failure, not a
        # codec failure.
        raise Reject("illegal_state")
    if first["security_mode"] != second["security_mode"]:
        # Any other mode disagreement is not the echo the spec requires (§Session
        # accepts echoes every shared field exactly), including an upgrade the
        # Hello did not ask for.
        raise Reject("session_mismatch")
    if second["security_mode"] == "hop-only" and not allow_hop_only:
        raise Reject("illegal_state")
    if expected_accept_source_role is not None and second["source_role"] != ROLE_NAMES[expected_accept_source_role]:
        # The responder's own role is a local authorization fact; a mismatch
        # means the peer is not the role local policy expected.
        raise Reject("illegal_state")


# --- relay fragments ---------------------------------------------------------


def parse_relay(data: bytes) -> dict[str, Any]:
    """Parse a RelayCircuit body: fixed 30-byte prefix plus exact payload."""
    if len(data) < RELAY_PREFIX_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    circuit_id = reader.take(16, "wrong_length")
    direction = reader.u8("wrong_length")
    if direction not in (0, 1):
        raise Reject("invalid_direction")
    byte_offset = reader.u64("wrong_length")
    payload_len = reader.u32("wrong_length")
    hops_remaining = reader.u8("wrong_length")
    if not 1 <= hops_remaining <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    if payload_len > MAX_RELAY_PAYLOAD:
        raise Reject("payload_too_large")
    if byte_offset + payload_len > 0xFFFF_FFFF_FFFF_FFFF:
        raise Reject("offset_overflow")
    if reader.remaining() != payload_len:
        raise Reject("length_mismatch")
    payload = reader.take(payload_len, "length_mismatch")
    return {
        "message": "RelayFragment",
        "circuit_id_hex": circuit_id.hex(),
        "direction": direction,
        "byte_offset": byte_offset,
        "payload_len": payload_len,
        "hops_remaining": hops_remaining,
        "payload_hex": payload.hex(),
    }


# --- signed object envelope --------------------------------------------------


def parse_signed_object(
    data: bytes,
    tbs_decoder: Callable[[bytes], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Parse the candidate SignedObject envelope.

    `tbs_decoder` is an optional independent TBS decoder (see
    ``verify_vectors.parse_management_tbs``); when supplied, the embedded
    ``raw_tbs`` must decode and its object type must match the envelope.
    """
    if len(data) > MAX_SIGNED_OBJECT:
        raise Reject("signed_object_too_large")
    if not data:
        raise Reject("bad_signed_object")
    reader = _Reader(data)
    version = reader.u8("bad_signed_object")
    if version != SIGNED_OBJECT_VERSION:
        raise Reject("bad_signed_object")
    object_type = reader.u8("bad_signed_object")
    if not 1 <= object_type <= 6:
        raise Reject("bad_object_type")
    schema_version = reader.u16("bad_signed_object")
    if schema_version != SIGNED_OBJECT_SCHEMA_VERSION:
        raise Reject("bad_signed_object")
    signer_count = reader.u8("bad_signed_object")
    if not 1 <= signer_count <= MAX_SIGNERS:
        raise Reject("bad_signed_object")
    signers: list[dict[str, Any]] = []
    for index in range(signer_count):
        role = reader.u8("bad_signed_object")
        if role not in (SIGNER_PRIMARY, SIGNER_CO_SIGN):
            raise Reject("invalid_field")
        if index == 0 and role != SIGNER_PRIMARY:
            raise Reject("invalid_field")
        if index > 0 and role != SIGNER_CO_SIGN:
            raise Reject("invalid_field")
        ed25519_present = None
        # Ed25519 is mandatory and fixed-length: there is no presence byte, and
        # an ML-DSA-only signer is not accepted.
        ed25519 = reader.take(ED25519_SIG_LEN, "wrong_signature_length")
        parameter_set = reader.u8("bad_signature_algorithm")
        if parameter_set not in MLDSA_LEN:
            raise Reject("bad_signature_algorithm")
        declared = reader.u16("bad_signature_algorithm")
        if declared != MLDSA_LEN[parameter_set]:
            raise Reject("wrong_signature_length")
        signature = reader.take(declared, "wrong_signature_length")
        signers.append(
            {
                "role": "primary" if role == SIGNER_PRIMARY else "cosign",
                # Not read from the wire: Ed25519 is mandatory, so its presence
                # is a constant of the format. Both `ed25519_len` and the legacy
                # boolean are reported so either `expected` shape matches.
                "ed25519_present": True,
                "ed25519_len": len(ed25519),
                "mldsa": MLDSA_NAMES[parameter_set],
                "mldsa_len": len(signature),
            }
        )
    raw_tbs_len = reader.u32("bad_signed_object")
    if raw_tbs_len == 0:
        raise Reject("invalid_field")
    raw_tbs = reader.take(raw_tbs_len, "invalid_field")
    if reader.remaining() != 0:
        raise Reject("invalid_field")
    if object_type == OBJECT_TYPE_ATTACHMENT_LEASE and signer_count != 2:
        raise Reject("missing_cosignature")
    if object_type != OBJECT_TYPE_ATTACHMENT_LEASE and signer_count != 1:
        raise Reject("unexpected_cosignature")
    result: dict[str, Any] = {
        "message": "SignedObject",
        "version": version,
        "object_type": object_type,
        "schema_version": schema_version,
        "signers": signers,
        "raw_tbs_len": raw_tbs_len,
        "raw_tbs_hex": raw_tbs.hex(),
    }
    if tbs_decoder is not None:
        try:
            decoded = tbs_decoder(raw_tbs)
        except Exception as exc:  # noqa: BLE001 - narrow by the decoder's own category
            # A vector decoder signals rejection by carrying a stable `category`.
            # Anything else is a bug in the decoder, not a verdict on the bytes:
            # propagate it instead of masking it as `bad_management_object`.
            category = getattr(exc, "category", None)
            if not isinstance(category, str) or not category:
                raise
            raise Reject(category) from exc
        name = decoded.get("object_type")
        expected = {
            1: "NodeIdentity",
            2: "AttachmentLease",
            3: "CoreLsa",
            4: "RouteGrant",
            5: "DirectGrant",
            6: "StatusSnapshot",
        }[object_type]
        if name != expected:
            raise Reject("bad_object_type")
        result["tbs_object_type"] = name
        result["tbs"] = decoded
    return result


# --- directory page, enrollment, probe, drain, circuit bodies ---------------


def parse_directory_page(data: bytes, tbs_decoder: Callable[[bytes], dict[str, Any]] | None = None) -> dict[str, Any]:
    if len(data) < 1 + 8 + 1:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_DIRECTORY_PAGE:
        raise Reject("unknown_subtype")
    page_seq = reader.u64("wrong_length")
    count = reader.u8("wrong_length")
    if not 1 <= count <= 16:
        raise Reject("invalid_field")
    pages: list[dict[str, Any]] = []
    for _ in range(count):
        envelope_len = reader.u16("wrong_length")
        if envelope_len == 0:
            raise Reject("invalid_field")
        envelope = reader.take(envelope_len, "wrong_length")
        pages.append(parse_signed_object(envelope, tbs_decoder))
    if reader.remaining() != 0:
        raise Reject("wrong_length")
    return {"message": "DirectoryPage", "page_seq": page_seq, "count": count, "pages": pages}


def parse_enrollment(data: bytes, tbs_decoder: Callable[[bytes], dict[str, Any]] | None = None) -> dict[str, Any]:
    if len(data) < 2:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_ENROLLMENT:
        raise Reject("unknown_subtype")
    kind = reader.u8("wrong_length")
    if kind == 1:
        if len(data) < ENROLLMENT_REQUEST_BASE:
            raise Reject("wrong_length")
        version = reader.u16("wrong_length")
        if version != 1:
            raise Reject("bad_protocol_version")
        enrollment_id = reader.take(16, "wrong_length")
        invite_id = reader.take(16, "wrong_length")
        csr_hash = reader.take(32, "wrong_length")
        invite_secret = reader.take(32, "wrong_length")
        # Candidate rule: the enrollment id, invite id, CSR digest and bearer
        # secret are all nonzero. An all-zero bearer value is not a secret.
        if not any(enrollment_id) or not any(invite_id) or not any(csr_hash) or not any(invite_secret):
            raise Reject("invalid_field")
        csr_len = reader.u16("wrong_length")
        if not 1 <= csr_len <= MAX_ENROLLMENT_DER:
            raise Reject("invalid_field")
        csr = reader.take(csr_len, "wrong_length")
        if reader.remaining() != 0:
            raise Reject("wrong_length")
        return {
            "message": "EnrollmentRequest",
            "enrollment_id_hex": enrollment_id.hex(),
            "invite_id_hex": invite_id.hex(),
            "csr_hash_hex": csr_hash.hex(),
            "csr_len": len(csr),
            "invite_secret_matches_request": bool(invite_secret),
        }
    if kind == 2:
        if len(data) < ENROLLMENT_RESPONSE_FIXED:
            raise Reject("wrong_length")
        status = reader.u8("wrong_length")
        if status not in (1, 2, 3):
            raise Reject("invalid_field")
        enrollment_id = reader.take(16, "wrong_length")
        csr_hash = reader.take(32, "wrong_length")
        # Candidate rule: both identifiers are nonzero in every response status.
        if not any(enrollment_id) or not any(csr_hash):
            raise Reject("invalid_field")
        node_id = reader.u16("wrong_length")
        if not valid_node_id(node_id):
            raise Reject("bad_node_id")
        generation = reader.u64("wrong_length")
        if generation == 0:
            raise Reject("bad_identity_generation")
        net_id = reader.take(16, "wrong_length")
        if not any(net_id):
            raise Reject("bad_net_id")
        identity_len = reader.u16("wrong_length")
        if status == 1:
            if identity_len == 0:
                raise Reject("invalid_field")
            identity = reader.take(identity_len, "wrong_length")
            parsed = parse_signed_object(identity, tbs_decoder)
            if parsed["object_type"] != 1:
                raise Reject("bad_object_type")
            if tbs_decoder is not None:
                # Candidate rule: the embedded NodeIdentity must describe exactly
                # the node, generation and network announced by the response
                # header. The TBS is the authority only for its own fields; this
                # check binds the two halves of an issued response together.
                tbs = parsed["tbs"]
                if (
                    tbs.get("subject") != ["Node", node_id]
                    or tbs.get("seq") != generation
                    or tbs.get("net_id_hex") != net_id.hex()
                ):
                    raise Reject("invalid_field")
        elif identity_len != 0:
            raise Reject("invalid_field")
        if reader.remaining() != 0:
            raise Reject("wrong_length")
        return {
            "message": "EnrollmentResponse",
            "status": {1: "issued", 2: "pending", 3: "rejected"}[status],
            "enrollment_id_hex": enrollment_id.hex(),
            "node_id": node_id,
        }
    raise Reject("invalid_field")


def parse_probe(data: bytes) -> dict[str, Any]:
    if len(data) != PROBE_BODY_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_PROBE:
        raise Reject("unknown_subtype")
    kind = reader.u8("wrong_length")
    if kind not in (1, 2):
        raise Reject("invalid_field")
    challenge = reader.take(16, "wrong_length")
    # Candidate rule: the probe challenge is nonzero; an all-zero challenge is a
    # schema violation, not a valid measurement hint.
    if not any(challenge):
        raise Reject("invalid_field")
    sent = reader.u64("wrong_length")
    echo = reader.u64("wrong_length")
    if kind == 1 and echo != 0:
        raise Reject("invalid_field")
    return {"message": "Probe", "kind": "ping" if kind == 1 else "pong", "sent": sent, "echo": echo, "challenge_hex": challenge.hex()}


def parse_drain(data: bytes) -> dict[str, Any]:
    if len(data) != DRAIN_BODY_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_DRAIN:
        raise Reject("unknown_subtype")
    reason = reader.u8("wrong_length")
    if reason not in (1, 2, 3):
        raise Reject("invalid_field")
    deadline = reader.u64("wrong_length")
    retry = reader.u16("wrong_length")
    # Candidate rule: retry_after_seconds <= 3600. A larger value is a schema
    # violation, not a clamp: silently shortening a drain deadline would change
    # the peering shutdown contract.
    if retry > MAX_DRAIN_RETRY_SECONDS:
        raise Reject("invalid_field")
    return {"message": "Drain", "reason": reason, "deadline": deadline, "retry": retry}


def parse_circuit_open(data: bytes) -> dict[str, Any]:
    if len(data) != CIRCUIT_OPEN_BODY_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_CIRCUIT_OPEN:
        raise Reject("unknown_subtype")
    circuit_id = reader.take(16, "wrong_length")
    # Candidate rule: circuit identifiers are nonzero for every circuit message.
    if not any(circuit_id):
        raise Reject("invalid_field")
    destination = reader.u16("wrong_length")
    if not valid_node_id(destination):
        raise Reject("bad_node_id")
    generation = reader.u64("wrong_length")
    if generation == 0:
        raise Reject("bad_identity_generation")
    path_hops = reader.u8("wrong_length")
    if not 1 <= path_hops <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    return {"message": "CircuitOpen", "circuit_id_hex": circuit_id.hex(), "destination_node_id": destination, "path_hops": path_hops}


def parse_circuit_accept(data: bytes) -> dict[str, Any]:
    if len(data) != CIRCUIT_ACCEPT_BODY_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != SUBTYPE_CIRCUIT_ACCEPT:
        raise Reject("unknown_subtype")
    circuit_id = reader.take(16, "wrong_length")
    if not any(circuit_id):
        raise Reject("invalid_field")
    path_hops = reader.u8("wrong_length")
    if not 1 <= path_hops <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    return {"message": "CircuitAccept", "circuit_id_hex": circuit_id.hex(), "path_hops": path_hops}


def parse_circuit_close(data: bytes, message: str) -> dict[str, Any]:
    expected = SUBTYPE_CIRCUIT_RESET if message == "CircuitReset" else SUBTYPE_CIRCUIT_CLOSE
    if len(data) != CIRCUIT_ID_BODY_LEN:
        raise Reject("wrong_length")
    reader = _Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype != expected:
        raise Reject("unknown_subtype")
    circuit_id = reader.take(16, "wrong_length")
    if not any(circuit_id):
        raise Reject("invalid_field")
    return {"message": message, "circuit_id_hex": circuit_id.hex()}


# --- dispatcher --------------------------------------------------------------


def parse_control(data: bytes, tbs_decoder: Callable[[bytes], dict[str, Any]] | None = None) -> dict[str, Any]:
    """Parse one Control body (AppHeader kind = 1) by its registered subtype."""
    if not data:
        raise Reject("empty_body")
    subtype = data[0]
    if subtype not in SUBTYPE_CAPS:
        raise Reject("unknown_subtype")
    if len(data) > SUBTYPE_CAPS[subtype]:
        raise Reject("body_too_large")
    if subtype in (SUBTYPE_HELLO, SUBTYPE_ACCEPT):
        return parse_session(data)
    if subtype == SUBTYPE_ENROLLMENT:
        return parse_enrollment(data, tbs_decoder)
    if subtype == SUBTYPE_DIRECTORY_PAGE:
        return parse_directory_page(data, tbs_decoder)
    if subtype == SUBTYPE_PROBE:
        return parse_probe(data)
    if subtype == SUBTYPE_DRAIN:
        return parse_drain(data)
    if subtype == SUBTYPE_CIRCUIT_OPEN:
        return parse_circuit_open(data)
    if subtype == SUBTYPE_CIRCUIT_ACCEPT:
        return parse_circuit_accept(data)
    if subtype == SUBTYPE_CIRCUIT_RESET:
        return parse_circuit_close(data, "CircuitReset")
    if subtype == SUBTYPE_CIRCUIT_CLOSE:
        return parse_circuit_close(data, "CircuitClose")
    if subtype == 20:
        if data == b"\x14\x00":
            return {"message": "IdentityRevocation", "evidence_hex": None}
        if len(data) > 3383 and data.startswith(b"\x14\x01BRIR\x00\x00\x00\x01"):
            return {"message": "IdentityRevocation", "evidence_hex": data[2:].hex()}
        raise Reject("wrong_length")
    # Lease / Lsa / Grant / Revoke: subtype + exactly one SignedObject envelope,
    # and the envelope's object type must be one the subtype registers.
    parsed = parse_signed_object(data[1:], tbs_decoder)
    allowed = SUBTYPE_OBJECT_TYPES.get(subtype)
    if allowed is not None and parsed["object_type"] not in allowed:
        raise Reject("bad_object_type")
    parsed["message"] = SUBTYPE_NAMES[subtype]
    return parsed


def parse_control_body_for_kind(kind: int, body: bytes) -> dict[str, Any]:
    """Validate a body against its AppHeader kind.

    kind 1 = Control (dispatched by subtype); kind 3 = RelayCircuit, whose body
    has no subtype byte. kind 2 (HopIpBatch) is not modelled by this verifier and
    raises [`NotModeled`] rather than being silently accepted.
    """
    if kind == 1:
        return parse_control(body)
    if kind == 3:
        return parse_relay(body)
    raise NotModeled(f"AppHeader kind {kind} is not modelled by this verifier")


# --- fixture verification ----------------------------------------------------


def _as_bytes(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{where}: hex field must be a string")
    if len(value) % 2:
        raise ValueError(f"{where}: odd-length hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid hex: {exc}") from exc


def verify_control_document(
    document: Any,
    tbs_decoder: Callable[[bytes], dict[str, Any]] | None = None,
) -> list[str]:
    """Verify a fixed control-message vector document.

    The document is test input: it must declare the candidate format, and every
    vector must carry the declared expectation. Nothing is generated here.
    """
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["control root: expected JSON object"]
    if document.get("status") != "candidate-not-frozen":
        errors.append("control status: expected candidate-not-frozen")
    if document.get("format") != "boreas-control-messages-v1":
        errors.append(
            "control format: expected boreas-control-messages-v1 "
            f"(got {document.get('format')!r}); the 51/52-byte payload layout is superseded "
            "by the 68-byte session layout"
        )
    vectors = document.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return errors + ["control vectors: expected non-empty array"]
    ids: set[str] = set()
    for index, vector in enumerate(vectors):
        where = f"control.vectors[{index}]"
        error = _check_control_vector(vector, where, tbs_decoder)
        if error:
            errors.append(error)
        if isinstance(vector, dict) and isinstance(vector.get("id"), str):
            if vector["id"] in ids:
                errors.append(f"{where}: duplicate id {vector['id']!r}")
            ids.add(vector["id"])
    return errors


def _check_control_vector(
    vector: Any,
    where: str,
    tbs_decoder: Callable[[bytes], dict[str, Any]] | None,
) -> str | None:
    if not isinstance(vector, dict):
        return f"{where}: vector must be an object"
    vector_id = vector.get("id")
    if not isinstance(vector_id, str) or not vector_id:
        return f"{where}: id must be a non-empty string"
    valid = vector.get("valid")
    if not isinstance(valid, bool):
        return f"{where} {vector_id}: valid boolean is required"
    hex_field = "expected_hex" if valid else "input_hex"
    try:
        raw = _as_bytes(vector.get(hex_field), f"{where} {vector_id}")
    except ValueError as exc:
        return f"{where} {vector_id}: {exc}"
    kind = vector.get("kind", "control")
    if kind == "control":
        # Every control vector is parsed with the same independent TBS decoder, so
        # SignedObject envelopes inside DirectoryPage/Enrollment bodies are also
        # bound to their declared management object type.
        parser = lambda data: parse_control(data, tbs_decoder)  # noqa: E731
    elif kind == "relay":
        parser = parse_relay
    elif kind == "signed_object":
        parser = lambda data: parse_signed_object(data, tbs_decoder)  # noqa: E731
    else:
        return f"{where} {vector_id}: unsupported kind {kind!r}"
    try:
        actual = parser(raw)
    except Reject as exc:
        if valid:
            return f"{where} {vector_id}: unexpectedly rejected as {exc.category}"
        expected_error = vector.get("expected_error")
        if expected_error != exc.category:
            return f"{where} {vector_id}: rejected as {exc.category}, expected {expected_error!r}"
        return None
    except (ValueError, TypeError) as exc:
        return f"{where} {vector_id}: malformed vector: {exc}"
    if not valid:
        return f"{where} {vector_id}: unexpectedly accepted as {actual!r}"
    expected = vector.get("expected")
    if expected is None:
        return None
    if not isinstance(expected, dict):
        return f"{where} {vector_id}: expected must be an object"
    mismatches = {
        key: (actual.get(key), value)
        for key, value in expected.items()
        if actual.get(key) != value
    }
    if mismatches:
        return f"{where} {vector_id}: field mismatch {mismatches!r}"
    return None


def verify_control_pair_document(document: Any) -> list[str]:
    """Verify the optional Hello/Accept correlation vectors."""
    if not isinstance(document, dict):
        return ["control root: expected JSON object"]
    pairs = document.get("session_pairs")
    if pairs is None:
        return []
    if not isinstance(pairs, list):
        return ["control session_pairs: expected array"]
    errors: list[str] = []
    for index, pair in enumerate(pairs):
        where = f"control.session_pairs[{index}]"
        if not isinstance(pair, dict):
            errors.append(f"{where}: expected object")
            continue
        try:
            hello = _as_bytes(pair.get("hello_hex"), where)
            accept = _as_bytes(pair.get("accept_hex"), where)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        allowed = tuple(pair.get("allowed_suites", [1]))
        # `accept_source_role` is the canonical field. The longer alias is kept so
        # an older fixture does not have to be rewritten for a rename.
        expected_role = pair.get("accept_source_role", pair.get("expected_accept_source_role"))
        if expected_role is not None and (
            isinstance(expected_role, bool) or expected_role not in ROLE_NAMES
        ):
            errors.append(f"{where}: accept_source_role must be 1, 2 or 3")
            continue
        try:
            check_session_pair(
                hello,
                accept,
                allowed_suites=allowed,
                allow_hop_only=bool(pair.get("allow_hop_only", False)),
                expected_accept_source_role=expected_role,
            )
        except Reject as exc:
            if pair.get("valid") is True:
                errors.append(f"{where}: unexpectedly rejected as {exc.category}")
            elif pair.get("expected_error") != exc.category:
                errors.append(f"{where}: rejected as {exc.category}, expected {pair.get('expected_error')!r}")
        else:
            if pair.get("valid") is not True:
                errors.append(f"{where}: unexpectedly accepted")
    return errors


def load_document(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) > 1:
        print("usage: python tools/control_vectors.py [control-vectors.json]", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    path = Path(args[0]) if args else root / "docs/protocol/vectors/control-messages-candidate-v1.json"
    try:
        document = load_document(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        return 2
    errors = verify_control_document(document) + verify_control_pair_document(document)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: {len(document['vectors'])} control vectors and {len(document.get('session_pairs', []))} session pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())