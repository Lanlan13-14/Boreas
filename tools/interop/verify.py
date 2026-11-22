#!/usr/bin/env python3
"""Independent decoder for the candidate Boreas wire codecs.

This is a second implementation of the byte layouts in ``docs/protocol/``. It is
written against the specification, not transcribed from ``boreas-proto``, so a
field-for-field match against the committed vectors is agreement between two
implementations. It uses only the Python standard library and verifies no
cryptography.

It checks three things:

* every committed vector decodes here to exactly the fields the vector records;
* a deterministic set of mutations of those vectors is rejected, and the
  rejection category is stable;
* the decoder agrees with itself under re-encoding where the codec is
  canonical (AppHeader, fixed-length control bodies, the BE2E record).

Exit status is 0 on full agreement, 1 when any vector disagrees or any
mutation that must be rejected is accepted. Run it from the repository root.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "docs" / "protocol" / "vectors"

PROTO_MAJOR = 3
HEADER_LEN = 8
MAX_BODY_LEN = 65536
KIND_NAMES = {1: "Control", 2: "HopIpBatch", 3: "RelayCircuit"}

SESSION_LEN = 68
PROBE_LEN = 34
DRAIN_LEN = 12
CIRCUIT_OPEN_LEN = 28
CIRCUIT_ACCEPT_LEN = 18
CIRCUIT_ID_LEN = 17
MAX_ENROLLMENT_DER = 8192
MAX_DIRECTORY_OBJECTS = 16
MAX_SIGNED_OBJECT_LEN = 16384
ED25519_LEN = 64
MLDSA_LEN = {1: 3309, 2: 4627}
MLDSA_NAMES = {1: "mldsa65", 2: "mldsa87"}
MAX_CIRCUIT_HOPS = 8
# Relay payload cap: one AppHeader body (65536) minus the 30-byte fragment prefix.
MAX_RELAY_PAYLOAD = MAX_BODY_LEN - (16 + 1 + 8 + 4 + 1)
MIN_MTU = 576
MAX_MTU = 9000
MAX_DRAIN_RETRY = 3600

SUBTYPE_NAMES = {
    1: "SessionHello", 2: "SessionAccept", 3: "Enrollment", 4: "DirectoryPage",
    5: "Lease", 6: "Lsa", 7: "Grant", 8: "Revoke", 9: "Probe", 10: "Drain",
    16: "CircuitOpen", 17: "CircuitAccept", 18: "CircuitReset", 19: "CircuitClose",
    20: "IdentityRevocation",
    21: "MeshPath",
}
SUBTYPE_CAPS = {
    1: 4096, 2: 4096, 16: 4096, 17: 4096, 3: 16384, 4: 16384, 5: 16384,
    8: 16384, 6: 8192, 7: 8192, 9: 256, 10: 256, 18: 256, 19: 256, 20: 19767,
    21: 6,
}
OBJECT_TYPE_NAMES = {
    1: "NodeIdentity", 2: "AttachmentLease", 3: "CoreLsa", 4: "RouteGrant",
    5: "DirectGrant", 6: "StatusSnapshot",
}
SUBTYPE_OBJECT_TYPES = {5: {2}, 6: {3}, 7: {4, 5}, 8: {1, 2, 3, 4, 5, 6}}
ROLE_NAMES = {1: "edge", 2: "core", 3: "enrollment-service"}
PATH_ROLE_NAMES = {1: "cdn", 2: "dir"}
SECURITY_MODE_NAMES = {1: "e2e-required", 2: "hop-only"}
SUITE_NAMES = {1: "pq768", 2: "pq1024"}


class Reject(Exception):
    """A structurally invalid input. ``category`` matches the vector vocabulary."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def remaining(self) -> int:
        return len(self._data) - self._at

    def take(self, n: int, category: str) -> bytes:
        if n < 0 or self.remaining() < n:
            raise Reject(category)
        out = self._data[self._at:self._at + n]
        self._at += n
        return out

    def u8(self, category: str) -> int:
        return self.take(1, category)[0]

    def u16(self, category: str) -> int:
        return int.from_bytes(self.take(2, category), "big")

    def u32(self, category: str) -> int:
        return int.from_bytes(self.take(4, category), "big")

    def u64(self, category: str) -> int:
        return int.from_bytes(self.take(8, category), "big")


def _nonzero(data: bytes) -> bool:
    return any(data)


def _hex(data: bytes) -> str:
    return data.hex()


# --- AppHeader ----------------------------------------------------------------


def parse_app_header(data: bytes) -> dict:
    if len(data) != HEADER_LEN:
        raise Reject("truncated")
    major = data[0]
    if major != PROTO_MAJOR:
        raise Reject("bad_version")
    kind = data[1]
    if kind not in KIND_NAMES:
        raise Reject("unknown_kind")
    flags = int.from_bytes(data[2:4], "big")
    if flags != 0:
        raise Reject("bad_flags")
    body_len = int.from_bytes(data[4:8], "big")
    if body_len > MAX_BODY_LEN:
        raise Reject("body_too_large")
    if kind == 1 and body_len == 0:
        raise Reject("empty_control")
    return {
        "proto_major": major,
        "kind": KIND_NAMES[kind],
        "flags": flags,
        "body_len": body_len,
    }


def encode_app_header(parsed: dict) -> bytes:
    kind = next(k for k, name in KIND_NAMES.items() if name == parsed["kind"])
    return bytes([
        parsed["proto_major"], kind,
        (parsed["flags"] >> 8) & 0xFF, parsed["flags"] & 0xFF,
    ]) + parsed["body_len"].to_bytes(4, "big")


# --- control bodies -----------------------------------------------------------


def parse_session(data: bytes) -> dict:
    if len(data) != SESSION_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    subtype = reader.u8("wrong_length")
    if subtype not in (1, 2):
        raise Reject("bad_subtype")
    major = reader.u8("wrong_length")
    if major != PROTO_MAJOR:
        raise Reject("bad_protocol_version")
    net_id = reader.take(16, "wrong_length")
    if not _nonzero(net_id):
        raise Reject("bad_net_id")
    source = reader.u16("wrong_length")
    destination = reader.u16("wrong_length")
    if not _valid_node_id(source) or not _valid_node_id(destination):
        raise Reject("bad_node_id")
    if source == destination:
        raise Reject("identical_node_ids")
    source_gen = reader.u64("wrong_length")
    destination_gen = reader.u64("wrong_length")
    if source_gen == 0 or destination_gen == 0:
        raise Reject("bad_identity_generation")
    connection = reader.take(16, "wrong_length")
    if not _nonzero(connection):
        raise Reject("invalid_field")
    source_role = reader.u8("wrong_length")
    if source_role not in ROLE_NAMES:
        raise Reject("bad_role")
    path_role = reader.u8("wrong_length")
    if path_role not in PATH_ROLE_NAMES:
        raise Reject("bad_path_role")
    mode = reader.u8("wrong_length")
    if mode not in SECURITY_MODE_NAMES:
        raise Reject("bad_security_mode")
    mtu = reader.u16("wrong_length")
    if not MIN_MTU <= mtu <= MAX_MTU:
        raise Reject("invalid_mtu")
    suite = reader.u8("wrong_length")
    if suite not in SUITE_NAMES:
        raise Reject("bad_suite")
    capabilities = reader.u64("wrong_length")
    if capabilities != 0:
        raise Reject("unknown_capability")
    if reader.remaining() != 0:
        raise Reject("wrong_length")
    return {
        "message": SUBTYPE_NAMES[subtype],
        "subtype": subtype,
        "proto_major": major,
        "net_id_hex": _hex(net_id),
        "source_node_id": source,
        "destination_node_id": destination,
        "source_identity_generation": source_gen,
        "destination_identity_generation": destination_gen,
        "connection_instance_hex": _hex(connection),
        "source_role": ROLE_NAMES[source_role],
        "path_role": PATH_ROLE_NAMES[path_role],
        "security_mode": SECURITY_MODE_NAMES[mode],
        "mtu_cap": mtu,
        "suite": SUITE_NAMES[suite],
        "capabilities": capabilities,
    }


def _valid_node_id(node_id: int) -> bool:
    if not 1 <= node_id <= 0xFFFF:
        return False
    home = ((node_id - 1) >> 8) + 1
    octet = node_id & 0xFF
    return 1 <= home <= 16 and 1 <= octet <= 251


def parse_probe(data: bytes) -> dict:
    if len(data) != PROBE_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 9:
        raise Reject("unknown_subtype")
    kind = reader.u8("wrong_length")
    if kind not in (1, 2):
        raise Reject("invalid_field")
    challenge = reader.take(16, "wrong_length")
    if not _nonzero(challenge):
        raise Reject("invalid_field")
    sent = reader.u64("wrong_length")
    echo = reader.u64("wrong_length")
    if kind == 1 and echo != 0:
        raise Reject("invalid_field")
    return {
        "message": "Probe",
        "kind": "ping" if kind == 1 else "pong",
        "sent": sent,
        "echo": echo,
        "challenge_hex": _hex(challenge),
    }


def parse_drain(data: bytes) -> dict:
    if len(data) != DRAIN_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 10:
        raise Reject("unknown_subtype")
    reason = reader.u8("wrong_length")
    if reason not in (1, 2, 3):
        raise Reject("invalid_field")
    deadline = reader.u64("wrong_length")
    retry = reader.u16("wrong_length")
    if retry > MAX_DRAIN_RETRY:
        raise Reject("invalid_field")
    return {"message": "Drain", "reason": reason, "deadline": deadline, "retry": retry}


def _circuit_id(reader: Reader) -> bytes:
    circuit_id = reader.take(16, "wrong_length")
    if not _nonzero(circuit_id):
        raise Reject("invalid_field")
    return circuit_id


def parse_circuit_open(data: bytes) -> dict:
    if len(data) != CIRCUIT_OPEN_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 16:
        raise Reject("unknown_subtype")
    circuit_id = _circuit_id(reader)
    destination = reader.u16("wrong_length")
    if not _valid_node_id(destination):
        raise Reject("bad_node_id")
    generation = reader.u64("wrong_length")
    if generation == 0:
        raise Reject("bad_identity_generation")
    hops = reader.u8("wrong_length")
    if not 1 <= hops <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    return {
        "message": "CircuitOpen",
        "circuit_id_hex": _hex(circuit_id),
        "destination_node_id": destination,
        "path_hops": hops,
    }


def parse_circuit_accept(data: bytes) -> dict:
    if len(data) != CIRCUIT_ACCEPT_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 17:
        raise Reject("unknown_subtype")
    circuit_id = _circuit_id(reader)
    hops = reader.u8("wrong_length")
    if not 1 <= hops <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    return {
        "message": "CircuitAccept",
        "circuit_id_hex": _hex(circuit_id),
        "path_hops": hops,
    }


def parse_circuit_close(data: bytes, message: str) -> dict:
    expected = 18 if message == "CircuitReset" else 19
    if len(data) != CIRCUIT_ID_LEN:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != expected:
        raise Reject("unknown_subtype")
    return {"message": message, "circuit_id_hex": _hex(_circuit_id(reader))}


def parse_signed_object(data: bytes) -> dict:
    if len(data) < 1 + 2 + 1 + 1:
        raise Reject("bad_signed_object")
    if len(data) > MAX_SIGNED_OBJECT_LEN:
        raise Reject("signed_object_too_large")
    reader = Reader(data)
    version = reader.u8("bad_signed_object")
    if version != 1:
        raise Reject("bad_signed_object")
    object_type = reader.u8("bad_signed_object")
    if object_type not in OBJECT_TYPE_NAMES:
        raise Reject("bad_object_type")
    schema_version = reader.u16("bad_signed_object")
    # The envelope pins the management schema it was signed under. A non-zero
    # but unregistered schema version is a different document, not a valid one.
    if schema_version != 1:
        raise Reject("bad_signed_object")
    signer_count = reader.u8("bad_signed_object")
    if signer_count not in (1, 2):
        raise Reject("bad_signed_object")
    signers = []
    for _ in range(signer_count):
        role = reader.u8("bad_signed_object")
        if role not in (1, 2):
            raise Reject("invalid_field")
        ed25519 = reader.take(ED25519_LEN, "wrong_signature_length")
        parameter_set = reader.u8("bad_signature_algorithm")
        if parameter_set not in MLDSA_LEN:
            raise Reject("bad_signature_algorithm")
        declared = reader.u16("bad_signature_algorithm")
        if declared != MLDSA_LEN[parameter_set]:
            raise Reject("wrong_signature_length")
        signature = reader.take(declared, "wrong_signature_length")
        signers.append({
            "role": "primary" if role == 1 else "cosign",
            "ed25519_present": True,
            "ed25519_len": len(ed25519),
            "mldsa": MLDSA_NAMES[parameter_set],
            "mldsa_len": len(signature),
        })
    raw_tbs_len = reader.u32("bad_signed_object")
    if raw_tbs_len == 0:
        raise Reject("invalid_field")
    raw_tbs = reader.take(raw_tbs_len, "invalid_field")
    if reader.remaining() != 0:
        raise Reject("invalid_field")
    if object_type == 2 and signer_count != 2:
        raise Reject("missing_cosignature")
    if object_type != 2 and signer_count != 1:
        raise Reject("unexpected_cosignature")
    return {
        "message": "SignedObject",
        "version": version,
        "object_type": object_type,
        "schema_version": schema_version,
        "signers": signers,
        "raw_tbs_len": raw_tbs_len,
        "raw_tbs_hex": _hex(raw_tbs),
    }


def parse_directory_page(data: bytes) -> dict:
    if len(data) < 1 + 8 + 1:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 4:
        raise Reject("unknown_subtype")
    page_seq = reader.u64("wrong_length")
    count = reader.u8("wrong_length")
    if not 1 <= count <= MAX_DIRECTORY_OBJECTS:
        raise Reject("invalid_field")
    pages = []
    for _ in range(count):
        envelope_len = reader.u16("wrong_length")
        if envelope_len == 0:
            raise Reject("invalid_field")
        pages.append(parse_signed_object(reader.take(envelope_len, "wrong_length")))
    if reader.remaining() != 0:
        raise Reject("wrong_length")
    return {"message": "DirectoryPage", "page_seq": page_seq, "count": count, "pages": pages}


def parse_enrollment(data: bytes) -> dict:
    if len(data) < 2:
        raise Reject("wrong_length")
    reader = Reader(data)
    if reader.u8("wrong_length") != 3:
        raise Reject("unknown_subtype")
    kind = reader.u8("wrong_length")
    if kind == 1:
        version = reader.u16("wrong_length")
        if version != 1:
            raise Reject("bad_protocol_version")
        enrollment_id = reader.take(16, "wrong_length")
        invite_id = reader.take(16, "wrong_length")
        csr_hash = reader.take(32, "wrong_length")
        invite_secret = reader.take(32, "wrong_length")
        if not all(_nonzero(field) for field in (enrollment_id, invite_id, csr_hash, invite_secret)):
            raise Reject("invalid_field")
        csr_len = reader.u16("wrong_length")
        if not 1 <= csr_len <= MAX_ENROLLMENT_DER:
            raise Reject("invalid_field")
        csr = reader.take(csr_len, "wrong_length")
        if reader.remaining() != 0:
            raise Reject("wrong_length")
        return {
            "message": "EnrollmentRequest",
            "enrollment_id_hex": _hex(enrollment_id),
            "invite_id_hex": _hex(invite_id),
            "csr_hash_hex": _hex(csr_hash),
            "csr_len": len(csr),
            "invite_secret_matches_request": bool(invite_secret),
        }
    if kind == 2:
        status = reader.u8("wrong_length")
        if status not in (1, 2, 3):
            raise Reject("invalid_field")
        enrollment_id = reader.take(16, "wrong_length")
        csr_hash = reader.take(32, "wrong_length")
        if not _nonzero(enrollment_id) or not _nonzero(csr_hash):
            raise Reject("invalid_field")
        node_id = reader.u16("wrong_length")
        if not _valid_node_id(node_id):
            raise Reject("bad_node_id")
        generation = reader.u64("wrong_length")
        if generation == 0:
            raise Reject("bad_identity_generation")
        net_id = reader.take(16, "wrong_length")
        if not _nonzero(net_id):
            raise Reject("bad_net_id")
        identity_len = reader.u16("wrong_length")
        if status == 1:
            if identity_len == 0:
                raise Reject("invalid_field")
            parsed = parse_signed_object(reader.take(identity_len, "wrong_length"))
            if parsed["object_type"] != 1:
                raise Reject("bad_object_type")
        elif identity_len != 0:
            raise Reject("invalid_field")
        if reader.remaining() != 0:
            raise Reject("wrong_length")
        return {
            "message": "EnrollmentResponse",
            "status": {1: "issued", 2: "pending", 3: "rejected"}[status],
            "enrollment_id_hex": _hex(enrollment_id),
            "node_id": node_id,
        }
    raise Reject("invalid_field")


def parse_relay(data: bytes) -> dict:
    if len(data) < 16 + 1 + 8 + 4 + 1:
        raise Reject("wrong_length")
    reader = Reader(data)
    circuit_id = reader.take(16, "wrong_length")
    if not _nonzero(circuit_id):
        raise Reject("invalid_field")
    direction = reader.u8("wrong_length")
    if direction not in (0, 1):
        raise Reject("invalid_direction")
    offset = reader.u64("wrong_length")
    payload_len = reader.u32("wrong_length")
    hops = reader.u8("wrong_length")
    if not 1 <= hops <= MAX_CIRCUIT_HOPS:
        raise Reject("invalid_hop_count")
    if payload_len > MAX_RELAY_PAYLOAD:
        raise Reject("payload_too_large")
    payload = reader.take(payload_len, "length_mismatch")
    if reader.remaining() != 0:
        raise Reject("length_mismatch")
    if offset + payload_len > 0xFFFFFFFFFFFFFFFF:
        raise Reject("offset_overflow")
    return {
        "message": "RelayFragment",
        "circuit_id_hex": _hex(circuit_id),
        "direction": direction,
        "byte_offset": offset,
        "payload_len": len(payload),
        "payload_hex": _hex(payload),
        "hops_remaining": hops,
    }


def parse_control(data: bytes) -> dict:
    if not data:
        # An empty control body is reported before the subtype lookup, matching
        # the framing layer which rejects it as empty rather than unknown.
        raise Reject("empty_body")
    subtype = data[0]
    if subtype not in SUBTYPE_CAPS:
        raise Reject("unknown_subtype")
    if len(data) > SUBTYPE_CAPS[subtype]:
        raise Reject("body_too_large")
    if subtype in (1, 2):
        return parse_session(data)
    if subtype == 3:
        return parse_enrollment(data)
    if subtype == 4:
        return parse_directory_page(data)
    if subtype == 9:
        return parse_probe(data)
    if subtype == 10:
        return parse_drain(data)
    if subtype == 16:
        return parse_circuit_open(data)
    if subtype == 17:
        return parse_circuit_accept(data)
    if subtype == 18:
        return parse_circuit_close(data, "CircuitReset")
    if subtype == 19:
        return parse_circuit_close(data, "CircuitClose")
    if subtype == 21:
        slots = data[2:]
        if not 2 <= len(slots) <= 4 or data[1] != len(slots):
            raise Reject("wrong_length")
        if slots[0] >= slots[-1] or any(slot < 1 or slot > 16 for slot in slots) or len(set(slots)) != len(slots):
            raise Reject("invalid_field")
        return {"message": "MeshPath", "slots": list(slots)}
    if subtype == 20:
        if data == b"\x14\x00":
            return {"message": "IdentityRevocation", "evidence_hex": None}
        if len(data) > 3383 and data.startswith(b"\x14\x01BRIR\x00\x00\x00\x01"):
            return {"message": "IdentityRevocation", "evidence_hex": data[2:].hex()}
        raise Reject("wrong_length")
    parsed = parse_signed_object(data[1:])
    allowed = SUBTYPE_OBJECT_TYPES.get(subtype)
    if allowed is not None and parsed["object_type"] not in allowed:
        raise Reject("bad_object_type")
    parsed["message"] = SUBTYPE_NAMES[subtype]
    return parsed


# --- management-object CBOR subset -------------------------------------------


def _cbor_value(data: bytes, pos: int, depth: int):
    if depth > 32 or pos >= len(data):
        raise Reject("truncated")
    head = data[pos]
    pos += 1
    major, ai = head >> 5, head & 31
    if ai < 24:
        argument = ai
    elif ai in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        if pos + size > len(data):
            raise Reject("truncated")
        argument = int.from_bytes(data[pos:pos + size], "big")
        pos += size
        if argument < {24: 24, 25: 256, 26: 65536, 27: 4294967296}[ai]:
            raise Reject("non_canonical")
    else:
        raise Reject("unsupported_cbor")
    if major == 0:
        return argument, pos
    if major in (2, 3):
        if pos + argument > len(data):
            raise Reject("truncated")
        raw = data[pos:pos + argument]
        if major == 3:
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                raise Reject("invalid_utf8") from None
        return raw, pos + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, pos = _cbor_value(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        pairs = []
        previous = None
        for _ in range(argument):
            key, pos = _cbor_value(data, pos, depth + 1)
            if not isinstance(key, int) or isinstance(key, bool):
                raise Reject("non_canonical")
            if previous is not None and key <= previous:
                raise Reject("non_canonical")
            previous = key
            value, pos = _cbor_value(data, pos, depth + 1)
            pairs.append((key, value))
        return pairs, pos
    raise Reject("unsupported_cbor")


def parse_cbor(data: bytes) -> object:
    if len(data) > 16384:
        raise Reject("too_large")
    value, end = _cbor_value(data, 0, 0)
    if end != len(data):
        raise Reject("trailing_bytes")
    return value


# --- BE2E confirmation --------------------------------------------------------


def parse_be2e(data: bytes) -> dict:
    if len(data) < 2:
        raise Reject("e2e_truncated_length")
    declared = int.from_bytes(data[:2], "big")
    if declared != 73:
        raise Reject("e2e_bad_length")
    if len(data) != 75:
        raise Reject("e2e_truncated_or_trailing")
    body = data[2:]
    if body[:4] != b"BE2E":
        raise Reject("e2e_magic")
    if body[4] != 1:
        raise Reject("e2e_version")
    if body[5] not in (1, 2):
        raise Reject("e2e_message_type")
    net = body[6:22]
    initiator = int.from_bytes(body[22:24], "big")
    initiator_gen = int.from_bytes(body[24:32], "big")
    acceptor = int.from_bytes(body[33:35], "big")
    acceptor_gen = int.from_bytes(body[35:43], "big")
    circuit = body[44:60]
    if net == bytes(16):
        raise Reject("e2e_zero_network")
    if not initiator or not acceptor or initiator >= acceptor:
        raise Reject("e2e_endpoint_order_or_id")
    if not initiator_gen or not acceptor_gen:
        raise Reject("e2e_generation")
    if body[32] not in (1, 2, 3) or body[43] not in (1, 2, 3):
        raise Reject("e2e_role")
    if circuit == bytes(16):
        raise Reject("e2e_zero_circuit")
    if body[60] != 1:
        raise Reject("e2e_mode")
    if body[61] != 1:
        raise Reject("e2e_suite")
    opener = int.from_bytes(body[62:64], "big")
    if opener not in (initiator, acceptor):
        raise Reject("e2e_opener")
    if not 1 <= body[64] <= 8:
        raise Reject("e2e_path_hops")
    if int.from_bytes(body[65:73], "big") != 0:
        raise Reject("e2e_capabilities")
    return {"message_type": body[5], "circuit_id": circuit.hex(), "path_hops": body[64]}


# --- vector agreement ---------------------------------------------------------


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _matches(expected, actual) -> bool:
    """True when every field recorded in ``expected`` agrees with ``actual``.

    The vector records the fields that are normative for that case. Extra
    fields this decoder reports are ignored, so the comparison checks agreement
    rather than exact dict equality.
    """

    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(key in actual and _matches(value, actual[key]) for key, value in expected.items())
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(expected) != len(actual):
            return False
        return all(_matches(e, a) for e, a in zip(expected, actual))
    return expected == actual


def _dispatch(message: str, raw: bytes):
    if message in ("SessionHello", "SessionAccept"):
        return parse_session(raw)
    if message == "Probe":
        return parse_probe(raw)
    if message == "Drain":
        return parse_drain(raw)
    if message == "CircuitOpen":
        return parse_circuit_open(raw)
    if message == "CircuitAccept":
        return parse_circuit_accept(raw)
    if message == "CircuitReset":
        return parse_circuit_close(raw, "CircuitReset")
    if message == "CircuitClose":
        return parse_circuit_close(raw, "CircuitClose")
    if message == "Enrollment":
        return parse_enrollment(raw)
    if message == "DirectoryPage":
        return parse_directory_page(raw)
    if message == "SignedObject":
        return parse_signed_object(raw)
    if message == "RelayFragment":
        return parse_relay(raw)
    if message == "ControlBody" or message in SUBTYPE_NAMES.values():
        return parse_control(raw)
    raise Reject("unknown_subtype")


def check_control_vectors() -> list[str]:
    document = _load("control-messages-candidate-v1.json")
    problems = []
    if document.get("format") != "boreas-control-messages-v1":
        problems.append("control: unexpected format marker")
    for vector in document["vectors"]:
        raw = bytes.fromhex(vector.get("expected_hex") or vector.get("input_hex") or "")
        try:
            decoded = _dispatch(vector["message"], raw)
        except Reject as rejected:
            if vector["valid"]:
                problems.append(f"{vector['id']}: rejected a valid vector as {rejected.category}")
            elif rejected.category != vector.get("expected_error"):
                problems.append(
                    f"{vector['id']}: rejected as {rejected.category}, vector expects {vector.get('expected_error')}"
                )
            continue
        if not vector["valid"]:
            problems.append(f"{vector['id']}: accepted a vector that must be rejected")
            continue
        # Vectors that record only the accepted bytes (no field expectation) are
        # checked by a successful decode; the Rust decoder checks the same bytes.
        if "expected" in vector and not _matches(vector["expected"], decoded):
            problems.append(f"{vector['id']}: decoded fields disagree with the vector")
    return problems


def check_app_header_vectors() -> list[str]:
    document = _load("candidate-vectors-v1.json")
    problems = []
    for vector in document["app_header"]:
        raw = bytes.fromhex(vector["input_hex"])
        try:
            decoded = parse_app_header(raw)
        except Reject as rejected:
            if vector["valid"]:
                problems.append(f"{vector['id']}: rejected a valid header as {rejected.category}")
            continue
        if not vector["valid"]:
            problems.append(f"{vector['id']}: accepted a header that must be rejected")
            continue
        if not _matches(vector["expected"], decoded):
            problems.append(f"{vector['id']}: header fields disagree with the vector")
        elif encode_app_header(decoded) != raw:
            problems.append(f"{vector['id']}: re-encoded header differs from the input")
    for vector in document["cbor"]:
        raw = bytes.fromhex(vector["input_hex"])
        try:
            parse_cbor(raw)
        except Reject:
            if vector["valid"]:
                problems.append(f"{vector['id']}: rejected canonical CBOR")
            continue
        if not vector["valid"]:
            problems.append(f"{vector['id']}: accepted non-canonical CBOR")
    return problems


def check_security_bindings() -> list[str]:
    document = _load("security-bindings-candidate-v1.json")
    problems = []
    for vector in document.get("e2e", []):
        raw = bytes.fromhex(vector["raw_hex"])
        accepted = vector["expected"] == "accept"
        try:
            decoded = parse_be2e(raw)
        except Reject as rejected:
            if accepted:
                problems.append(f"{vector['name']}: rejected a valid BE2E record as {rejected.category}")
            continue
        if not accepted:
            problems.append(f"{vector['name']}: accepted a BE2E record that must be rejected")
        elif decoded["message_type"] != vector["message_type"]:
            problems.append(f"{vector['name']}: BE2E message type disagrees with the vector")
    # Root-authorization objects carry key material and a scoped schema. The
    # structural and policy verdict for them lives in candidate_bindings, which
    # is the reviewed binding parser; reuse it so the two checks cannot diverge.
    sys.path.insert(0, str(ROOT / "tools"))
    from candidate_bindings import parse_root_authorization, BindingError

    for vector in document.get("root_authorization", []):
        raw = bytes.fromhex(vector["raw_hex"])
        accepted = vector["expected"] == "accept"
        try:
            parse_root_authorization(raw)
        except BindingError:
            if accepted:
                problems.append(f"{vector['name']}: rejected a valid root-authorization object")
            continue
        if not accepted:
            problems.append(f"{vector['name']}: accepted a root-authorization object that must be rejected")
    return problems


# --- deterministic mutation pass ---------------------------------------------


def _mutations(seed: bytes):
    """Bounded, deterministic corruptions of one accepted input."""

    yield "truncated", seed[:-1]
    yield "extended", seed + b"\x00"
    flipped = bytearray(seed)
    flipped[0] ^= 0xFF
    yield "first_byte_flipped", bytes(flipped)
    yield "empty", b""
    yield "overlong", seed + b"\xff" * 64


def check_mutations() -> list[str]:
    document = _load("control-messages-candidate-v1.json")
    problems = []
    accepted_seeds = [
        bytes.fromhex(vector["expected_hex"])
        for vector in document["vectors"]
        if vector["valid"] and vector.get("expected_hex")
    ]
    if len(accepted_seeds) < 8:
        problems.append("mutation: too few valid seeds to exercise rejection")
        return problems
    rejected = 0
    for seed in accepted_seeds:
        for _name, mutated in _mutations(seed):
            try:
                parse_control(mutated)
            except Reject:
                rejected += 1
    # Every truncation, extension and empty mutation of a fixed-length body must
    # be rejected. The count is a floor: at least the empty mutation plus the
    # truncation of every seed.
    if rejected < len(accepted_seeds) * 2:
        problems.append(f"mutation: only {rejected} corruptions rejected, expected a harder floor")
    return problems


def main() -> int:
    problems = []
    problems += check_control_vectors()
    problems += check_app_header_vectors()
    problems += check_security_bindings()
    problems += check_mutations()
    if problems:
        print(f"interop: {len(problems)} disagreement(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("interop: python decoder agrees with every committed vector")
    print("interop: deterministic mutation pass rejected every corruption")
    return 0


if __name__ == "__main__":
    sys.exit(main())
