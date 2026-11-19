#!/usr/bin/env python3
"""Deterministic mutation corpus for the differential rejection check.

For every committed control vector this derives a fixed set of corruptions and
records the independent Python decoder's verdict for each. The Rust decoder is
checked against the same bytes in CI: a mutation the Python decoder rejects
must also be rejected by ``boreas-proto``, and a mutation it still accepts must
also be accepted there. Disagreement is a real interop bug, not a fixture
drift, because neither side reads the other's verdict.

The corpus is regenerated rather than hand-edited. ``--check`` fails when the
checked-in file differs from what this script produces.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "interop"))

import verify  # noqa: E402

VECTORS = ROOT / "docs" / "protocol" / "vectors" / "control-messages-candidate-v1.json"
CORPUS = ROOT / "tools" / "interop" / "mutation-corpus.json"


def _mutate(seed: bytes):
    yield "truncate_one", seed[:-1]
    yield "truncate_half", seed[: max(1, len(seed) // 2)]
    yield "append_zero", seed + b"\x00"
    yield "append_ff", seed + b"\xff"
    flipped = bytearray(seed)
    flipped[0] ^= 0x80
    yield "flip_high_bit", bytes(flipped)
    if len(seed) > 4:
        swapped = bytearray(seed)
        swapped[2], swapped[3] = swapped[3], swapped[2]
        yield "swap_len_bytes", bytes(swapped)
    yield "empty", b""


def build() -> dict:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    cases = []
    for vector in document["vectors"]:
        if not vector["valid"]:
            continue
        seed = bytes.fromhex(vector["expected_hex"])
        for name, mutated in _mutate(seed):
            try:
                verify._dispatch(vector["message"], mutated)
                verdict = "accept"
            except verify.Reject as rejected:
                verdict = rejected.category
            cases.append({
                "id": f"{vector['id']}::{name}",
                "message": vector["message"],
                "input_hex": mutated.hex(),
                "python_verdict": verdict,
            })
    digest = hashlib.sha256(
        json.dumps(cases, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema": "boreas-mutation-corpus-v1",
        "source": "docs/protocol/vectors/control-messages-candidate-v1.json",
        "sha256": digest,
        "cases": cases,
    }


def main() -> int:
    corpus = build()
    rendered = json.dumps(corpus, indent=2) + "\n"
    check = "--check" in sys.argv
    if check:
        current = CORPUS.read_text(encoding="utf-8") if CORPUS.exists() else ""
        if current != rendered:
            print("mutation corpus is stale; regenerate with tools/interop/mutations.py", file=sys.stderr)
            return 1
        print(f"mutation corpus matches ({len(corpus['cases'])} cases, {corpus['sha256'][:12]})")
        return 0
    CORPUS.write_text(rendered, encoding="utf-8")
    rejected = sum(1 for case in corpus["cases"] if case["python_verdict"] != "accept")
    print(f"wrote {len(corpus['cases'])} cases ({rejected} rejected) to {CORPUS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
