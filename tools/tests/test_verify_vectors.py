"""Unit tests for the standalone Boreas vector verifier."""
import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "verify_vectors.py"
SPEC = importlib.util.spec_from_file_location("verify_vectors", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_vectors = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_vectors)


class AppHeaderTests(unittest.TestCase):
    def test_accepts_all_header_kinds_and_zero_body(self):
        for kind, name in ((1, "Control"), (2, "HopIpBatch"), (3, "RelayCircuit")):
            with self.subTest(kind=name):
                raw = bytes((3, kind, 0, 0, 0, 0, 0, 0))
                if kind == 1:
                    with self.assertRaises(verify_vectors.Reject) as caught:
                        verify_vectors.parse_app_header(raw)
                    self.assertEqual(caught.exception.category, "empty_control")
                else:
                    parsed = verify_vectors.parse_app_header(raw)
                    self.assertEqual(parsed["kind"], name)
                    self.assertEqual(parsed["body_len"], 0)

    def test_accepts_maximum_body_length(self):
        raw = bytes.fromhex("0302000000010000")
        self.assertEqual(verify_vectors.parse_app_header(raw)["body_len"], 65536)

    def test_rejects_wrong_size_and_invalid_fields(self):
        cases = (
            (bytes.fromhex("03030000000000"), "invalid_length"),
            (bytes.fromhex("0203000000000000"), "bad_version"),
            (bytes.fromhex("0304000000000000"), "unknown_kind"),
            (bytes.fromhex("0303000100000000"), "bad_flags"),
            (bytes.fromhex("0303000000010001"), "body_too_large"),
            (bytes.fromhex("0301000000000000"), "empty_control"),
        )
        for raw, category in cases:
            with self.subTest(category=category):
                with self.assertRaises(verify_vectors.Reject) as caught:
                    verify_vectors.parse_app_header(raw)
                self.assertEqual(caught.exception.category, category)


class StrictCBORTests(unittest.TestCase):
    def test_accepts_supported_item_types(self):
        vectors = (
            "00",          # unsigned integer
            "20",          # negative integer
            "4100",        # byte string
            "6161",        # UTF-8 text
            "80",          # empty array
            "a0",          # empty map
            "a201000200",  # canonical integer-keyed map
        )
        for encoded in vectors:
            with self.subTest(encoded=encoded):
                self.assertEqual(verify_vectors.parse_cbor(bytes.fromhex(encoded)), "canonical_item")

    def test_rejects_non_shortest_arguments(self):
        for encoded in ("1801", "1900ff", "1a0000ffff", "1b00000000ffffffff"):
            with self.subTest(encoded=encoded):
                self.assertRejects(encoded, "non_shortest")

    def test_rejects_duplicate_or_noncanonical_map_order(self):
        for encoded in ("a201000101", "a202000100", "a2616200616100"):
            with self.subTest(encoded=encoded):
                self.assertRejects(encoded, "duplicate_or_key_order")

    def test_rejects_unsupported_indefinite_float_simple_and_tag(self):
        for encoded in ("9fff", "5fff", "f90000", "f4", "c000"):
            with self.subTest(encoded=encoded):
                category = "unsupported_indefinite" if encoded in ("9fff", "5fff") else "unsupported_float_simple_tag"
                self.assertRejects(encoded, category)

    def test_rejects_bad_text_and_trailing_bytes(self):
        self.assertRejects("61ff", "invalid_utf8")
        self.assertRejects("0000", "trailing_bytes")

    def test_rejects_truncation_and_limits(self):
        self.assertRejects("4100", "length_limit", max_len=1)
        self.assertRejects("8100", "depth_limit", max_depth=0)
        self.assertRejects("4200", "truncated")
        self.assertRejects("18", "truncated")
        self.assertRejects("1c", "unsupported_reserved")

    def assertRejects(self, encoded, category, **kwargs):
        with self.assertRaises(verify_vectors.Reject) as caught:
            verify_vectors.parse_cbor(bytes.fromhex(encoded), **kwargs)
        self.assertEqual(caught.exception.category, category)


class FixtureValidationTests(unittest.TestCase):
    def test_rejects_expected_result_mismatch(self):
        fixture = {
            "status": "candidate-not-frozen",
            "format": "boreas-proto-fixed-vectors-v1",
            "app_header": [],
            "cbor": [
                {"id": "lie", "input_hex": "00", "valid": False,
                 "expected": {"error": "malformed_input"}}
            ],
            "limits": {
                "depth_test_value_hex": "8100", "max_depth": 0,
                "depth_expected_error": "depth_limit",
                "length_test_value_hex": "4100", "max_len": 1,
                "length_expected_error": "length_limit",
            },
        }
        errors = verify_vectors.verify_document(fixture)
        self.assertTrue(any("unexpectedly accepted" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
