import json
from pathlib import Path
import unittest

from tools.candidate_bindings import BindingError, parse_e2e_record, parse_root_authorization

VECTORS = Path(__file__).resolve().parents[2] / "docs/protocol/vectors/security-bindings-candidate-v1.json"

class CandidateBindingVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_e2e_vectors(self):
        for v in self.vectors["e2e"]:
            with self.subTest(v=v["name"]):
                raw = bytes.fromhex(v["raw_hex"])
                if v["expected"] == "accept":
                    self.assertEqual(parse_e2e_record(raw)["message_type"], v["message_type"])
                else:
                    with self.assertRaises(BindingError) as cm: parse_e2e_record(raw)
                    self.assertEqual(cm.exception.category, v["failure"])

    def test_root_vectors(self):
        for v in self.vectors["root_authorization"]:
            with self.subTest(v=v["name"]):
                raw = bytes.fromhex(v["raw_hex"])
                if v["expected"] == "accept":
                    parsed = parse_root_authorization(raw)
                    self.assertEqual(parsed["purpose"], v["purpose"])
                else:
                    with self.assertRaises(BindingError) as cm: parse_root_authorization(raw)
                    self.assertEqual(cm.exception.category, v["failure"])

    def test_root_bounded_malformed_inputs(self):
        cases = [
            (b"\x00" * 16385, "root_too_large"),
            (b"\xb1", "root_map_too_large"),  # declared map size 17; reject before iterating
            (b"\x99\x01\x01", "root_scope_too_large"),  # declared array size 257
            (b"\xbf", "root_cbor_indefinite_or_reserved"),
            (b"\xa2\x00\x00\x00\x01", "root_map_keys"),  # duplicate key
            (b"\x81" * 9 + b"\x00", "root_cbor_truncated_or_depth"),
        ]
        for raw, category in cases:
            with self.subTest(category=category):
                with self.assertRaises(BindingError) as cm:
                    parse_root_authorization(raw)
                self.assertEqual(cm.exception.category, category)

if __name__ == "__main__": unittest.main()
