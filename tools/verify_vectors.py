#!/usr/bin/env python3
"""Independently verify Boreas candidate AppHeader and strict CBOR vectors.

This module intentionally uses only the Python standard library and does not
import or mirror any Rust implementation. The vector file is treated as test
input, not as an authority on how parsing works.
"""
from __future__ import annotations

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

    def item(self, depth: int = 0) -> bytes:
        if self.pos >= len(self.data):
            raise Reject("truncated")
        if self.max_depth is not None and depth > self.max_depth:
            raise Reject("depth_limit")
        start = self.pos
        initial = self._take(1)[0]
        major, ai = initial >> 5, initial & 31
        if major in (0, 1):
            self._argument(ai)
        elif major in (2, 3):
            length = self._length(self._argument(ai))
            payload = self._take(length)
            if major == 3:
                try:
                    payload.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise Reject("invalid_utf8") from exc
        elif major == 4:
            count = self._length(self._argument(ai))
            if count > len(self.data) - self.pos:
                raise Reject("truncated")
            for _ in range(count):
                self.item(depth + 1)
        elif major == 5:
            count = self._length(self._argument(ai))
            previous: bytes | None = None
            seen: set[bytes] = set()
            for _ in range(count):
                key_start = self.pos
                self.item(depth + 1)
                encoded_key = self.data[key_start:self.pos]
                if encoded_key in seen:
                    raise Reject("duplicate_or_key_order")
                seen.add(encoded_key)
                if previous is not None and (len(encoded_key), encoded_key) <= (len(previous), previous):
                    raise Reject("duplicate_or_key_order")
                previous = encoded_key
                self.item(depth + 1)
        else:
            # Tags, all floats, and simple values (including break) are outside
            # this deliberately small data-model subset.
            raise Reject("unsupported_float_simple_tag")
        return self.data[start:self.pos]


def parse_cbor(data: bytes, *, max_depth: int | None = None, max_len: int | None = None) -> str:
    # max_len bounds the complete encoded item, including its initial/length bytes.
    if max_len is not None and len(data) > max_len:
        raise Reject("length_limit")
    parser = _CBORParser(data, max_depth=max_depth, max_len=max_len)
    parser.item()
    if parser.pos != len(data):
        raise Reject("trailing_bytes")
    return "canonical_item"


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
            message = _check_vector(family, vector, index)
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
    fixture = Path(args[0]) if args else Path(__file__).resolve().parents[1] / "docs/protocol/vectors/candidate-vectors-v1.json"
    try:
        document = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot load {fixture}: {exc}", file=sys.stderr)
        return 2
    errors = verify_document(document)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    header_count = len(document["app_header"])
    cbor_count = len(document["cbor"])
    print(f"PASS: {header_count} AppHeader and {cbor_count} CBOR vectors plus limits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
