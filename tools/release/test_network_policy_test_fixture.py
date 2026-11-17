"""Pure-function checks for the test-only network policy fixture generator."""
import hashlib
import unittest

import network_policy_test_fixture as fixture


class FixtureEncodingTests(unittest.TestCase):
    def test_fingerprint_matches_pinned_contract(self):
        net_id = bytes(range(16))
        ed = b"ed-spki-der"
        ml = b"mldsa65-spki-der"
        expected_input = (
            b"BOREAS-NETWORK-ROOT-PIN-FINGERPRINT\0"
            + (16).to_bytes(4, "big") + net_id
            + b"\x01" + len(ed).to_bytes(4, "big") + ed
            + b"\x41" + len(ml).to_bytes(4, "big") + ml
        )
        self.assertEqual(fixture.fingerprint(net_id, ed, ml), hashlib.sha256(expected_input).digest())
        with self.assertRaises(ValueError):
            fixture.fingerprint(bytes(16), ed, ml)

    def test_candidate_has_default_prefix_and_signature_domain(self):
        net_id, root_fp = bytes.fromhex("0123456789abcdef0123456789abcdef"), bytes([0xA5]) * 32
        tbs = fixture.encode_tbs(net_id, root_fp, 7, 1_000_000, 2_000_000)
        # Deterministic full TBS bytes anchor canonical CBOR layout and 10.20/16.
        self.assertEqual(
            tbs.hex(),
            "ab000101070250" + bytes.fromhex("0123456789abcdef0123456789abcdef").hex() + "034f6e6574776f726b2d726f6f742d763104010581030607071a000f4240081a001e848009a50050"
            + bytes.fromhex("0123456789abcdef0123456789abcdef").hex() + "01440a1400000210035820" + "a5" * 32 + "04000a80",
        )
        self.assertEqual(
            fixture.signature_input(tbs),
            b"BOREAS-MGMT-OBJECT\0" + b"\x00\x01\x07" + len(tbs).to_bytes(8, "big") + tbs,
        )

    def test_refuses_noncanonical_scope_and_invalid_window(self):
        with self.assertRaises(ValueError):
            fixture.encode_tbs(bytes(16), bytes(32), 1, 1, 2)
        with self.assertRaises(ValueError):
            fixture.encode_tbs(bytes([3]) * 16, bytes([1]) * 32, 1, 2, 2)


if __name__ == "__main__":
    unittest.main()
