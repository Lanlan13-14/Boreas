#!/usr/bin/env python3
"""Independently verify Boreas candidate AppHeader, CBOR and Control vectors.

This module intentionally uses only the Python standard library and does not
import or mirror any Rust implementation. The vector files are treated as test
input, not as an authority on how parsing works.

Control payloads are handled by the sibling `control_vectors.py`, which is a
second, independent implementation of the candidate layout. It is imported by
file path so this module keeps working when loaded through `importlib` by the
unit tests.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


class Reject(ValueError):
    """A parser rejection with the stable vector error category."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


KIND_NAMES = {1: "Control", 2: "HopIpBatch", 3: "RelayCircuit"}
MAX_BODY = 65_536


def parse_app_header(data: bytes) -> dict[str, Any]:
    if len(data) != 8:
        raise Reject("invalid_length")
    major, kind = data[0], data[1]
    flags = int.from_bytes(data[2:4], "big")
    body_len = int.from_bytes(data[4:8], "big")
    if major != 3:
        raise Reject("bad_version")
    if kind not in KIND_NAMES:
        raise Reject("unknown_kind")
    if flags != 0:
        raise Reject("bad_flags")
    if body_len > MAX_BODY:
        raise Reject("body_too_large")
    if kind == 1 and body_len == 0:
        raise Reject("empty_control")
    return {"proto_major": major, "kind": KIND_NAMES[kind], "flags": flags, "body_len": body_len}


class _CBORMap(list):
    """Distinguish a decoded CBOR map from an array of key/value pairs."""


class _CBORParser:
    def __init__(self, data: bytes, *, max_depth: int | None, max_len: int | None):
        self.data = data
        self.pos = 0
        self.max_depth = max_depth
        self.max_len = max_len

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Reject("truncated")
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def _argument(self, ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 24:
            n, minimum = 1, 24
        elif ai == 25:
            n, minimum = 2, 256
        elif ai == 26:
            n, minimum = 4, 65_536
        elif ai == 27:
            n, minimum = 8, 4_294_967_296
        elif ai == 31:
            raise Reject("unsupported_indefinite")
        elif ai in (28, 29, 30):
            raise Reject("unsupported_reserved")
        else:
            raise Reject("malformed_input")
        value = int.from_bytes(self._take(n), "big")
        if value < minimum:
            raise Reject("non_shortest")
        return value

    def _length(self, n: int) -> int:
        if self.max_len is not None and n > self.max_len:
            raise Reject("length_limit")
        # No allocation is made from this length. Payload reads will reject
        # truncation, while array/map iteration stops at the first missing item.
        return n

    def item(self, depth: int = 0) -> Any:
        if self.pos >= len(self.data):
            raise Reject("truncated")
        if self.max_depth is not None and depth > self.max_depth:
            raise Reject("depth_limit")
        start = self.pos
        initial = self._take(1)[0]
        major, ai = initial >> 5, initial & 31
        if major == 0:
            value = self._argument(ai)
        elif major == 1:
            value = -1 - self._argument(ai)
        elif major in (2, 3):
            length = self._length(self._argument(ai))
            payload = self._take(length)
            if major == 3:
                try:
                    value = payload.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise Reject("invalid_utf8") from exc
            else:
                value = payload
        elif major == 4:
            count = self._length(self._argument(ai))
            if count > len(self.data) - self.pos:
                raise Reject("truncated")
            value = [self.item(depth + 1) for _ in range(count)]
        elif major == 5:
            count = self._length(self._argument(ai))
            if count > (len(self.data) - self.pos) // 2:
                raise Reject("truncated")
            previous: bytes | None = None
            seen: set[bytes] = set()
            value = _CBORMap()
            for _ in range(count):
                key_start = self.pos
                key = self.item(depth + 1)
                encoded_key = self.data[key_start:self.pos]
                if encoded_key in seen:
                    raise Reject("duplicate_or_key_order")
                seen.add(encoded_key)
                if previous is not None and (len(encoded_key), encoded_key) <= (len(previous), previous):
                    raise Reject("duplicate_or_key_order")
                previous = encoded_key
                value.append((key, self.item(depth + 1)))
        else:
            # Tags, all floats, and simple values (including break) are outside
            # this deliberately small data-model subset.
            raise Reject("unsupported_float_simple_tag")
        return value


def decode_cbor(data: bytes, *, max_depth: int = 32, max_len: int = 16_384) -> Any:
    if max_depth < 0 or max_len < 0:
        raise Reject("invalid_field")
    effective_depth = min(max_depth, 32)
    effective_len = min(max_len, 16_384)
    if len(data) > effective_len:
        raise Reject("length_limit")
    parser = _CBORParser(data, max_depth=effective_depth, max_len=effective_len)
    result = parser.item()
    if parser.pos != len(data):
        raise Reject("trailing_bytes")
    return result


def parse_cbor(data: bytes, *, max_depth: int | None = None, max_len: int | None = None) -> str:
    decode_cbor(
        data,
        max_depth=32 if max_depth is None else max_depth,
        max_len=16_384 if max_len is None else max_len,
    )
    return "canonical_item"


def _map(value: Any, category: str = "invalid_field") -> dict[int, Any]:
    if not isinstance(value, _CBORMap):
        raise Reject(category)
    result: dict[int, Any] = {}
    for key, item in value:
        if not isinstance(key, int) or isinstance(key, bool) or key in result:
            raise Reject(category)
        result[key] = item
    return result


def _uint(value: Any, maximum: int | None = None, minimum: int = 0) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value
        and (maximum is None or value <= maximum)
    )


def _bytes(value: Any, minimum: int = 0, maximum: int | None = None) -> bool:
    return isinstance(value, bytes) and len(value) >= minimum and (maximum is None or len(value) <= maximum)


def _subject(value: Any) -> tuple[str, int | None]:
    if not isinstance(value, list):
        raise Reject("invalid_field")
    if value == [3]:
        return "Network", None
    if len(value) != 2 or not _uint(value[0], 3, 1):
        raise Reject("invalid_field")
    if value[0] == 1 and _uint(value[1], 65535):
        return "Node", value[1]
    if value[0] == 2 and _uint(value[1], 255):
        return "Core", value[1]
    raise Reject("invalid_field")


def parse_management_tbs(data: bytes) -> dict[str, Any]:
    if len(data) > 16_384:
        raise Reject("length_limit")
    try:
        decoded = decode_cbor(data, max_depth=32, max_len=16_384)
    except Reject as exc:
        if exc.category == "unsupported_indefinite":
            raise Reject("unsupported_cbor") from exc
        if exc.category in {"non_shortest", "duplicate_or_key_order", "unsupported_float_simple_tag", "unsupported_reserved"}:
            raise Reject("noncanonical") from exc
        raise
    if not isinstance(decoded, _CBORMap):
        raise Reject("invalid_field")
    envelope = _map(decoded)
    if set(envelope) != set(range(11)):
        raise Reject("invalid_field")
    schema, object_type, net_id, issuer_id, issuer_generation, subject_raw, seq, issued_at, expires, body_raw, ext_raw = (envelope[i] for i in range(11))
    if schema != 1 or not _uint(object_type, 6, 1) or not _bytes(net_id, 16, 16):
        raise Reject("invalid_field")
    if not _bytes(issuer_id, 1, 64) or not _uint(issuer_generation, minimum=1):
        raise Reject("invalid_field")
    subject_kind, subject_id = _subject(subject_raw)
    if not _uint(seq) or not _uint(issued_at) or not _uint(expires) or issued_at >= expires:
        raise Reject("invalid_field")
    body = _map(body_raw)
    extension_values = ext_raw
    if not isinstance(extension_values, list) or len(extension_values) > 32:
        raise Reject("invalid_field")
    previous_ext = -1
    for extension in extension_values:
        if not isinstance(extension, list) or len(extension) != 3:
            raise Reject("invalid_field")
        ext_id, critical, ext_data = extension
        if not _uint(ext_id) or ext_id <= previous_ext or not _uint(critical, 1) or not _bytes(ext_data, 0, 2048):
            raise Reject("invalid_field")
        previous_ext = ext_id
        if critical == 1:
            raise Reject("unknown_critical_extension")

    name = {1: "NodeIdentity", 2: "AttachmentLease", 3: "CoreLsa", 4: "RouteGrant", 5: "DirectGrant", 6: "StatusSnapshot"}[object_type]
    required = {1: set(range(13)), 2: set(range(6)), 3: set(range(4)), 4: set(range(7)), 5: set(range(6)), 6: set(range(4))}[object_type]
    if set(body) != required:
        raise Reject("invalid_field")
    semantic: dict[str, Any] = {"object_type": name}
    if object_type == 1:
        # Candidate revision 2: body key 11 is identity_pub_ed25519[32] and scope
        # moved to key 12. The Ed25519 key is the management-signing key, not the
        # TLS key; this decoder only enforces its shape and nonzero value.
        node_id, home, vip, vip6, role, param, pub, generation, not_before, body_expires, ed25519, scope = (body[i] for i in range(1, 13))
        if (
            not _bytes(body[0], 16, 16)
            or body[0] != net_id
            or not _uint(node_id, 65535)
            or not _uint(home, 16, 1)
            or not _bytes(vip, 4, 4)
            or not _bytes(vip6, 16, 16)
            or not _uint(role, 3, 1)
            or not _uint(param, 2, 1)
            or not _bytes(pub, 1, 8192)
            or not _uint(generation, minimum=1)
            or not _uint(not_before)
            or not _uint(body_expires)
            or body_expires <= not_before
            or not _bytes(ed25519, 32, 32)
            or ed25519 == bytes(32)
            or not _bytes(scope, 0, 1024)
        ):
            raise Reject("invalid_field")
        expected_node_id = ((home - 1) << 8) | vip[3]
        vip_ok = (
            vip[0] == 10
            and vip[1] == 20
            and (
                (role == 1 and vip[2] == home and 2 <= vip[3] <= 251)
                or (role == 2 and vip[2] == home and vip[3] == 1)
                or (role == 3 and vip[2] == 0 and vip[3] != 0)
            )
        )
        if (
            not vip_ok
            or node_id != expected_node_id
            or subject_kind != "Node"
            or subject_id != node_id
            or seq != generation
            or issued_at != not_before
            or expires != body_expires
        ):
            raise Reject("invalid_field")
        semantic.update({"net_id_hex": net_id.hex(), "issuer_key_id_hex": issuer_id.hex(), "issuer_generation": issuer_generation, "subject": ["Node", node_id], "seq": seq, "issued_at": issued_at, "expires": expires, "identity_pub_ed25519_hex": ed25519.hex()})
    elif object_type == 2:
        node_id, identity_gen, attach_gen, target_core, not_before, body_expires = (body[i] for i in range(6))
        if not _uint(node_id,65535) or not _uint(identity_gen,minimum=1) or not _uint(attach_gen,minimum=1) or not _uint(target_core,16,1) or not _uint(not_before) or not _uint(body_expires) or body_expires <= not_before or subject_kind != "Node" or subject_id != node_id or issued_at != not_before or expires != body_expires:
            raise Reject("invalid_field")
        semantic.update({"subject":["Node",node_id],"seq":seq,"issued_at":issued_at,"expires":expires})
    elif object_type == 3:
        core_id, generation, body_seq, neighbors = (body[i] for i in range(4))
        if not _uint(core_id,16,1) or not _uint(generation,minimum=1) or not _uint(body_seq,minimum=1) or not isinstance(neighbors,list) or len(neighbors)>15 or subject_kind!="Core" or subject_id!=core_id or seq!=body_seq:
            raise Reject("invalid_field")
        peers=set()
        for neighbor in neighbors:
            if not isinstance(neighbor,list) or len(neighbor)!=4:
                raise Reject("invalid_field")
            peer,rtt,loss,path=neighbor
            if not _uint(peer,16,1) or peer==core_id or peer in peers or not _uint(rtt,65535) or not _uint(loss,1_000_000) or not _uint(path,2,1):
                raise Reject("invalid_field")
            peers.add(peer)
        semantic.update({"subject":["Core",core_id],"seq":seq,"issued_at":issued_at,"expires":expires})
    elif object_type == 4:
        node_id,prefix,prefix_len,metric,ha_group,body_seq,body_expires=(body[i] for i in range(7))
        if not _uint(node_id,65535) or not _bytes(prefix) or len(prefix) not in (4,16) or not _uint(prefix_len,len(prefix)*8) or not _uint(metric,65535) or not _bytes(ha_group,0,64) or not _uint(body_seq) or not _uint(body_expires) or subject_kind!="Node" or subject_id!=node_id or seq!=body_seq or expires!=body_expires:
            raise Reject("invalid_field")
        address=int.from_bytes(prefix,"big")
        host_bits=len(prefix)*8-prefix_len
        if host_bits and address & ((1<<host_bits)-1):
            raise Reject("invalid_field")
        semantic.update({"subject":["Node",node_id],"seq":seq,"issued_at":issued_at,"expires":expires})
    elif object_type == 5:
        node_id,endpoint_kind,endpoint,port,sni,body_expires=(body[i] for i in range(6))
        valid_endpoint = (_bytes(endpoint,4,16) and len(endpoint) in (4,16)) if endpoint_kind==1 else False
        if endpoint_kind==2 and _bytes(endpoint,1,253):
            try:
                hostname=endpoint.decode("ascii")
                labels=hostname.split(".")
                valid_endpoint=all(1<=len(label)<=63 and label[0].isalnum() and label[-1].isalnum() and all(c.isalnum() or c=="-" for c in label) for label in labels)
            except UnicodeDecodeError:
                valid_endpoint=False
        if not _uint(node_id,65535) or not _uint(endpoint_kind,2,1) or not valid_endpoint or not _uint(port,65535,1) or not _bytes(sni,0,253) or not _uint(body_expires) or subject_kind!="Node" or subject_id!=node_id or expires!=body_expires:
            raise Reject("invalid_field")
        semantic.update({"subject":["Node",node_id],"seq":seq,"issued_at":issued_at,"expires":expires})
    else:
        body_issued,next_update,body_seq,revocations=(body[i] for i in range(4))
        if not _uint(body_issued) or not _uint(next_update) or not _uint(body_seq) or not _bytes(revocations,0,16_384) or next_update<=body_issued or next_update-body_issued>86_400_000_000 or subject_kind!="Network" or seq!=body_seq or issued_at!=body_issued or expires!=next_update:
            raise Reject("invalid_field")
        semantic.update({"net_id_hex":net_id.hex(),"issuer_key_id_hex":issuer_id.hex(),"issuer_generation":issuer_generation,"subject":"Network","seq":seq,"issued_at":issued_at,"expires":expires,"status_body":{"issued_at":body_issued,"next_update":next_update,"sequence":body_seq,"revocations_hex":revocations.hex()},"extensions":extension_values})
    return semantic


def _hex_bytes(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{where}: input_hex must be a string")
    try:
        if len(value) % 2:
            raise ValueError("odd-length hex")
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid input_hex: {exc}") from exc


def _check_vector(family: str, vector: Any, index: int) -> str | None:
    where = f"{family}[{index}]"
    if not isinstance(vector, dict):
        raise ValueError(f"{where}: vector must be an object")
    if not isinstance(vector.get("id"), str) or not vector["id"]:
        raise ValueError(f"{where}: id must be a non-empty string")
    if not isinstance(vector.get("valid"), bool) or "expected" not in vector:
        raise ValueError(f"{where}: valid boolean and expected are required")
    data = _hex_bytes(vector.get("input_hex"), where)
    try:
        actual = parse_app_header(data) if family == "app_header" else parse_cbor(data)
    except Reject as exc:
        if vector["valid"]:
            return f"{where} {vector['id']}: unexpectedly rejected as {exc.category}"
        expected = vector["expected"]
        if not isinstance(expected, dict) or expected.get("error") != exc.category:
            return f"{where} {vector['id']}: rejected as {exc.category}, expected {expected!r}"
        return None
    if not vector["valid"]:
        expected = vector["expected"]
        return f"{where} {vector['id']}: unexpectedly accepted as {actual!r} (expected {expected!r})"
    if family == "app_header":
        if not isinstance(vector["expected"], dict) or actual != vector["expected"]:
            return f"{where} {vector['id']}: got {actual!r}, expected {vector['expected']!r}"
    elif vector["expected"] != actual:
        return f"{where} {vector['id']}: got {actual!r}, expected {vector['expected']!r}"
    return None


def _management_vector(vector: Any, index: int) -> str | None:
    where = f"management.vectors[{index}]"
    if not isinstance(vector, dict) or not isinstance(vector.get("id"), str):
        return f"{where}: expected vector object with id"
    kind = vector.get("kind")
    try:
        raw = _hex_bytes(vector.get("raw_tbs_hex"), where)
    except ValueError as exc:
        return f"{where} {vector['id']}: malformed raw_tbs_hex: {exc}"
    try:
        if kind == "tbs":
            actual = parse_management_tbs(raw)
        elif kind == "signature_input":
            object_type = vector.get("object_type")
            schema_version = vector.get("schema_version")
            if not _uint(object_type, 255, 1) or not _uint(schema_version, 65535, 0):
                raise Reject("invalid_field")
            actual = (
                b"BOREAS-MGMT-OBJECT\0"
                + schema_version.to_bytes(2, "big")
                + bytes((object_type,))
                + len(raw).to_bytes(8, "big")
                + raw
            ).hex()
            if actual != vector.get("expected_hex"):
                return f"{where} {vector['id']}: signature input {actual}, expected {vector.get('expected_hex')!r}"
            if vector.get("valid") is not True:
                return f"{where} {vector['id']}: signature input vector must be valid"
            return None
        else:
            return f"{where} {vector['id']}: unsupported kind {kind!r}"
    except (Reject, ValueError) as exc:
        category = exc.category if isinstance(exc, Reject) else "invalid_field"
        expected_error = vector.get("expected_error")
        if vector.get("valid") is False and expected_error == category:
            return None
        return f"{where} {vector['id']}: rejected as {category}, expected {expected_error!r}"
    if vector.get("valid") is not True:
        return f"{where} {vector['id']}: unexpectedly accepted as {actual!r}"
    expected = vector.get("expected")
    if not isinstance(expected, dict):
        return f"{where} {vector['id']}: valid TBS needs expected object"
    mismatches = {key: (actual.get(key), value) for key, value in expected.items() if actual.get(key) != value}
    if mismatches:
        return f"{where} {vector['id']}: semantic mismatch {mismatches!r}"
    return None


def verify_management_document(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["management root: expected JSON object"]
    errors: list[str] = []
    if document.get("status") != "candidate-not-frozen":
        errors.append("management status: expected candidate-not-frozen")
    if document.get("format") != "boreas-management-object-tbs-v1":
        errors.append("management format: unsupported")
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        return errors + ["management vectors: expected array"]
    ids: set[str] = set()
    for index, vector in enumerate(vectors):
        error = _management_vector(vector, index)
        if error:
            errors.append(error)
        if isinstance(vector, dict) and isinstance(vector.get("id"), str):
            if vector["id"] in ids:
                errors.append(f"management.vectors[{index}]: duplicate id {vector['id']!r}")
            ids.add(vector["id"])
    return errors


_CONTROL_MODULE: Any = None


def control_module() -> Any:
    """Load the independent control-payload verifier by file path."""
    global _CONTROL_MODULE
    if _CONTROL_MODULE is None:
        path = Path(__file__).resolve().parent / "control_vectors.py"
        spec = importlib.util.spec_from_file_location("boreas_control_vectors", path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CONTROL_MODULE = module
    return _CONTROL_MODULE


def verify_control_document(document: Any) -> list[str]:
    """Verify the control-message fixture with the embedded TBS decoder.

    The control verifier is handed this module's independent TBS parser so a
    SignedObject envelope must carry a management object whose declared type
    matches the envelope. No encoder is involved on either side.
    """
    module = control_module()
    errors = module.verify_control_document(document, parse_management_tbs)
    errors.extend(module.verify_control_pair_document(document))
    return errors


def verify_document(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["root: expected JSON object"]
    errors: list[str] = []
    if document.get("status") != "candidate-not-frozen":
        errors.append("root.status: expected 'candidate-not-frozen'")
    if document.get("format") != "boreas-proto-fixed-vectors-v1":
        errors.append("root.format: unsupported vector format")
    for family in ("app_header", "cbor"):
        vectors = document.get(family)
        if not isinstance(vectors, list):
            errors.append(f"root.{family}: expected array")
            continue
        ids: set[str] = set()
        for index, vector in enumerate(vectors):
            try:
                message = _check_vector(family, vector, index)
            except (ValueError, TypeError) as exc:
                message = f"{family}[{index}]: malformed vector: {exc}"
            if message:
                errors.append(message)
            if isinstance(vector, dict) and isinstance(vector.get("id"), str):
                if vector["id"] in ids:
                    errors.append(f"{family}[{index}]: duplicate id {vector['id']!r}")
                ids.add(vector["id"])
    limits = document.get("limits")
    if not isinstance(limits, dict):
        errors.append("root.limits: expected object")
    else:
        try:
            depth_data = _hex_bytes(limits.get("depth_test_value_hex", limits.get("cbor_max_depth_test_value_hex")), "limits.depth")
            length_data = _hex_bytes(limits.get("length_test_value_hex", limits.get("cbor_max_length_test_value_hex")), "limits.length")
            depth = limits.get("max_depth", limits.get("depth_limit"))
            max_length = limits.get("max_len", limits.get("max_length"))
            depth_expected = limits.get("depth_expected_error", limits.get("expected_error", "depth_limit"))
            length_expected = limits.get("length_expected_error", limits.get("expected_error_length", "length_limit"))
            if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
                raise ValueError("limits.depth_limit must be a non-negative integer")
            if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 0:
                raise ValueError("limits.max_length must be a non-negative integer")
            try:
                parse_cbor(depth_data, max_depth=depth)
            except Reject as exc:
                if exc.category != depth_expected:
                    errors.append(f"limits.depth: got {exc.category}, expected {depth_expected!r}")
            else:
                errors.append("limits.depth: expected parser rejection")
            try:
                parse_cbor(length_data, max_len=max_length)
            except Reject as exc:
                if exc.category != length_expected:
                    errors.append(f"limits.length: got {exc.category}, expected {length_expected!r}")
            else:
                errors.append("limits.length: expected parser rejection")
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) > 3:
        print(
            "usage: python tools/verify_vectors.py "
            "[proto-vectors.json [management-vectors.json [control-vectors.json]]]",
            file=sys.stderr,
        )
        return 2
    root = Path(__file__).resolve().parents[1]
    proto_path = Path(args[0]) if args else root / "docs/protocol/vectors/candidate-vectors-v1.json"
    management_path = (
        Path(args[1]) if len(args) > 1 else root / "docs/protocol/vectors/management-objects-candidate-v1.json"
    )
    control_path = (
        Path(args[2]) if len(args) > 2 else root / "docs/protocol/vectors/control-messages-candidate-v1.json"
    )
    errors: list[str] = []
    documents: list[tuple[str, Any]] = []
    for label, fixture_path, verifier in (
        ("vectors", proto_path, verify_document),
        ("management vectors", management_path, verify_management_document),
        ("control vectors", control_path, verify_control_document),
    ):
        try:
            document = json.loads(fixture_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            print(f"FAIL: cannot load {fixture_path}: {exc}", file=sys.stderr)
            return 2
        documents.append((label, document))
        errors.extend(f"{label}: {error}" for error in verifier(document))
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    proto_document = documents[0][1]
    management_document = documents[1][1]
    control_document = documents[2][1]
    print(
        f"PASS: {len(proto_document['app_header'])} AppHeader and "
        f"{len(proto_document['cbor'])} CBOR vectors plus limits; "
        f"{len(management_document['vectors'])} management vectors; "
        f"{len(control_document['vectors'])} control vectors and "
        f"{len(control_document.get('session_pairs', []))} session pairs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
