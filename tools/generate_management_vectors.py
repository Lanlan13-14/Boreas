#!/usr/bin/env python3
"""Regenerate candidate management-object raw CBOR fixtures from explicit typed maps.

This is a fixture generator, not the independent protocol validator. Do not import it from
or share its encoder with the verifier. It intentionally uses Python's standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/protocol/vectors/management-objects-candidate-v1.json"


def head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n <= 0xFF:
        return bytes([(major << 5) | 24, n])
    if n <= 0xFFFF:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor(value: object) -> bytes:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("candidate subset fixture integers are unsigned only")
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(x) for x in value)
    if isinstance(value, dict):
        # All schema keys are unsigned integers and pre-sorted in deterministic order.
        keys = sorted(value)
        if keys != list(value):
            raise ValueError("fixture map keys must be supplied in deterministic order")
        return head(5, len(keys)) + b"".join(cbor(k) + cbor(value[k]) for k in keys)
    raise TypeError(f"unsupported fixture type: {type(value)!r}")


ZERO16 = bytes(16)
ZERO4 = bytes(4)
ZERO_V6 = bytes(16)
# Candidate NodeIdentity body key 11: node Ed25519 management-signing public key.
ED25519_PUB = bytes([0x55]) * 32


def envelope(kind: int, subject: list[int], body: dict[int, object], *,
             net: bytes = ZERO16, issuer: bytes = b"\x01", seq: int = 1,
             issued: int = 1, expires: int = 2, extensions: list[object] | None = None) -> dict[int, object]:
    return {0: 1, 1: kind, 2: net, 3: issuer, 4: 1, 5: subject, 6: seq,
            7: issued, 8: expires, 9: body, 10: [] if extensions is None else extensions}


node_body = {0: ZERO16, 1: 2, 2: 1, 3: bytes([10, 20, 1, 2]), 4: ZERO_V6,
             5: 1, 6: 1, 7: b"\xaa", 8: 1, 9: 1, 10: 2,
             11: ED25519_PUB, 12: b""}
objects = {
    "node-identity-minimal-valid": envelope(1, [1, 2], node_body),
    "attachment-lease-minimal-valid": envelope(2, [1, 2],
        {0: 2, 1: 1, 2: 1, 3: 1, 4: 1, 5: 2}),
    "core-lsa-minimal-valid": envelope(3, [2, 1],
        {0: 1, 1: 1, 2: 1, 3: []}),
    "route-grant-minimal-valid": envelope(4, [1, 2],
        {0: 2, 1: ZERO4, 2: 0, 3: 0, 4: b"", 5: 1, 6: 2}),
    "direct-grant-minimal-valid": envelope(5, [1, 2],
        {0: 2, 1: 2, 2: b"a", 3: 443, 4: b"", 5: 2}),
    "status-snapshot-minimal-valid": envelope(6, [3],
        {0: 1, 1: 2, 2: 1, 3: b""}),
    "node-identity-cross-net-mismatch": envelope(1, [1, 2],
        {**node_body, 0: bytes([1]) + bytes(15)},
        net=ZERO16),
    "node-identity-common-sequence-mismatch": envelope(1, [1, 2], node_body, seq=2),
    "cross-type-body": envelope(3, [2, 1], {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 2}),
    "empty-issuer-key-id": envelope(1, [1, 2], node_body, issuer=b""),
    "unknown-critical-extension": envelope(6, [3],
        {0: 1, 1: 2, 2: 1, 3: b""}, extensions=[[3, 1, b""]]),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write regenerated fixture JSON")
    args = parser.parse_args()
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    found: set[str] = set()
    expected = {name: cbor(obj).hex() for name, obj in objects.items()}
    for entry in doc["vectors"]:
        if entry.get("kind") == "signature_input":
            continue
        if entry["id"] in expected:
            entry["raw_tbs_hex"] = expected[entry["id"]]
            found.add(entry["id"])
    missing = set(expected) - found
    if missing:
        print(f"missing fixtures: {sorted(missing)}", file=sys.stderr)
        return 1
    rendered = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    current = FIXTURE.read_text(encoding="utf-8")
    if rendered == current:
        print("management-object fixtures match generator")
        return 0
    if args.write:
        FIXTURE.write_text(rendered, encoding="utf-8")
        print(f"wrote {FIXTURE.relative_to(ROOT)}")
        return 0
    print("management-object fixtures differ; inspect generator and run with --write", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
