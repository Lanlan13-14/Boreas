"""Unit tests for the independent Python control-message verifier.

Fixtures are composed field by field from the documented byte table. They are
never produced by the module's own decoder, so a layout mistake cannot "prove
itself": the canonical cases are also pinned as literal hex strings.
"""
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = _load("control_vectors", "control_vectors.py")
verify = _load("verify_vectors", "verify_vectors.py")

# Canonical SessionHello, 68 bytes, assembled directly from the field table:
# subtype 01 | proto_major 03 | net_id 16B | src 0001 | dst 0002 | src_gen 1 |
# dst_gen 2 | instance 16B | source_role 01 | path_role 01 | mode 01 |
# mtu 05dc | suite 01 | capabilities 0000000000000000
HELLO_HEX = (
    "0103"
    "00112233445566778899aabbccddeeff"
    "0001"
    "0002"
    "0000000000000001"
    "0000000000000002"
    "0102030405060708090a0b0c0d0e0f10"
    "01"  # source_role: edge
    "01"  # path_role: CDN
    "01"  # security_mode: e2e-required
    "05dc"  # mtu_cap: 1500
    "01"  # suite: pq768
    "0000000000000000"  # capabilities
)

INSTANCE_HEX = "0102030405060708090a0b0c0d0e0f10"
NET_ID_HEX = "00112233445566778899aabbccddeeff"


def session(
    subtype=1,
    proto=3,
    net_id=NET_ID_HEX,
    src=1,
    dst=2,
    src_gen=1,
    dst_gen=2,
    instance=INSTANCE_HEX,
    role=1,
    path_role=1,
    mode=1,
    mtu=1500,
    suite=1,
    caps=0,
):
    return (
        bytes([subtype, proto])
        + bytes.fromhex(net_id)
        + src.to_bytes(2, "big")
        + dst.to_bytes(2, "big")
        + src_gen.to_bytes(8, "big")
        + dst_gen.to_bytes(8, "big")
        + bytes.fromhex(instance)
        + bytes([role, path_role, mode])
        + mtu.to_bytes(2, "big")
        + bytes([suite])
        + caps.to_bytes(8, "big")
    )


def relay(direction=0, offset=0, payload=b"abc", hops=8, declared=None, circuit="000102030405060708090a0b0c0d0e0f"):
    length = len(payload) if declared is None else declared
    return (
        bytes.fromhex(circuit)
        + bytes([direction])
        + offset.to_bytes(8, "big")
        + length.to_bytes(4, "big")
        + bytes([hops])
        + payload
    )


def envelope(object_type=1, tbs=b"\x00", signers=((1, 1),)):
    """Build a SignedObject envelope.

    Signer wire order is role u8, Ed25519[64] (mandatory, no presence byte),
    ML-DSA parameter set u8, ML-DSA length u16, ML-DSA signature. Both signature
    families are always present; an ML-DSA-only signer is not a valid encoding.
    """
    out = bytes([1, object_type]) + (1).to_bytes(2, "big") + bytes([len(signers)])
    for role, param in signers:
        out += bytes([role]) + b"\x00" * control.ED25519_SIG_LEN
        out += bytes([param]) + control.MLDSA_LEN[param].to_bytes(2, "big")
        out += b"\x00" * control.MLDSA_LEN[param]
    out += len(tbs).to_bytes(4, "big") + tbs
    return out


def management_node_tbs():
    """Fixed NodeIdentity TBS bytes taken from the management fixture."""
    fixture = json.loads(
        (ROOT / "docs/protocol/vectors/management-objects-candidate-v1.json").read_text(encoding="utf-8")
    )
    vector = next(v for v in fixture["vectors"] if v.get("id") == "node-identity-minimal-valid")
    return bytes.fromhex(vector["raw_tbs_hex"])


def enrollment_request(csr=b"\x30", kind=1, version=1, csr_len=None):
    length = len(csr) if csr_len is None else csr_len
    return (
        bytes([control.SUBTYPE_ENROLLMENT, kind])
        + version.to_bytes(2, "big")
        + bytes(range(16))
        + bytes(range(16, 32))
        + bytes(range(32, 64))
        + bytes(range(64, 96))
        + length.to_bytes(2, "big")
        + csr
    )


def enrollment_response(status=2, identity=b"", node_id=1, generation=1, net_id=NET_ID_HEX):
    return (
        bytes([control.SUBTYPE_ENROLLMENT, 2, status])
        + bytes(range(16))
        + bytes(range(32, 64))
        + node_id.to_bytes(2, "big")
        + generation.to_bytes(8, "big")
        + bytes.fromhex(net_id)
        + len(identity).to_bytes(2, "big")
        + identity
    )


def directory_page(envelopes=None, page_seq=7, count=None, declared_len=None):
    envs = envelopes if envelopes is not None else [envelope(object_type=1, tbs=b"\x00")]
    declared = len(envs) if count is None else count
    out = bytes([control.SUBTYPE_DIRECTORY_PAGE]) + page_seq.to_bytes(8, "big") + bytes([declared])
    for env in envs:
        length = len(env) if declared_len is None else declared_len
        out += length.to_bytes(2, "big") + env
    return out


class SessionTests(unittest.TestCase):
    def test_canonical_literal_is_68_bytes_and_parses(self):
        raw = bytes.fromhex(HELLO_HEX)
        self.assertEqual(len(raw), control.SESSION_LEN)
        parsed = control.parse_control(raw)
        self.assertEqual(parsed["message"], "SessionHello")
        self.assertEqual(parsed["proto_major"], 3)
        self.assertEqual(parsed["net_id_hex"], NET_ID_HEX)
        self.assertEqual(parsed["source_node_id"], 1)
        self.assertEqual(parsed["destination_node_id"], 2)
        self.assertEqual(parsed["source_identity_generation"], 1)
        self.assertEqual(parsed["destination_identity_generation"], 2)
        self.assertEqual(parsed["connection_instance_hex"], INSTANCE_HEX)
        self.assertEqual(parsed["source_role"], "edge")
        self.assertEqual(parsed["path_role"], "cdn")
        self.assertEqual(parsed["security_mode"], "e2e-required")
        self.assertEqual(parsed["mtu_cap"], 1500)
        self.assertEqual(parsed["suite"], "pq768")
        self.assertEqual(parsed["capabilities"], 0)

    def test_helper_matches_the_literal_layout(self):
        self.assertEqual(session().hex(), HELLO_HEX)

    def test_accept_swaps_endpoints_and_echoes_instance(self):
        accept = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1)
        self.assertEqual(len(accept), control.SESSION_LEN)
        control.check_session_pair(bytes.fromhex(HELLO_HEX), accept)

    def test_rejects_single_field_faults(self):
        cases = (
            ("bad_protocol_version", session(proto=2)),
            ("bad_net_id", session(net_id="00" * 16)),
            ("bad_node_id", session(src=0x00FC)),  # octet 252 is not a node slot
            ("identical_node_ids", session(dst=1)),
            ("bad_identity_generation", session(src_gen=0)),
            ("bad_role", session(role=4)),
            ("bad_path_role", session(path_role=3)),
            ("bad_security_mode", session(mode=3)),
            ("invalid_mtu", session(mtu=575)),
            ("invalid_mtu", session(mtu=9001)),
            ("bad_suite", session(suite=3)),
            ("unknown_capability", session(caps=1)),
            ("unknown_subtype", session(subtype=0x0B)),
            ("wrong_length", session()[:-1]),
            ("wrong_length", session() + b"\x00"),
        )
        for category, raw in cases:
            with self.subTest(category=category, hex=raw.hex()[:16]):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, category)

    def test_node_slot_boundaries(self):
        # home_core_id 16 + octet 251 is the last permanent slot.
        parsed = control.parse_control(session(src=0x0FFB, dst=0x0002))
        self.assertEqual(parsed["source_node_id"], 0x0FFB)
        for bad in (0x0000, 0x00FC, 0x1001):
            with self.subTest(node=bad):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(session(src=bad, dst=0x0002))
                self.assertEqual(caught.exception.category, "bad_node_id")

    def test_pair_mismatch_and_downgrade_are_rejected(self):
        hello = bytes.fromhex(HELLO_HEX)
        wrong_instance = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, instance="ff" * 16)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(hello, wrong_instance)
        self.assertEqual(caught.exception.category, "session_mismatch")

        # Silent e2e-required -> hop-only downgrade is a policy failure.
        downgraded = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, mode=2)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(hello, downgraded)
        self.assertEqual(caught.exception.category, "illegal_state")

        # A pq1024 session is refused when local policy only allows pq768. Both
        # sides must agree on the suite first, otherwise this would be reported
        # as a correlation mismatch instead of a policy failure.
        pq1024_hello = session(suite=2)
        pq1024_accept = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, suite=2)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(pq1024_hello, pq1024_accept, allowed_suites=(1,))
        self.assertEqual(caught.exception.category, "illegal_state")

    def test_hello_accept_role_swap_is_required(self):
        hello = bytes.fromhex(HELLO_HEX)
        same_direction = session(subtype=2, src=1, dst=2, src_gen=1, dst_gen=2)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(hello, same_direction)
        self.assertEqual(caught.exception.category, "session_mismatch")


class RelayTests(unittest.TestCase):
    def test_canonical_literal_prefix(self):
        raw = relay()
        self.assertEqual(raw[:30].hex(), "000102030405060708090a0b0c0d0e0f" + "00" + "00" * 8 + "00000003" + "08")
        parsed = control.parse_control_body_for_kind(3, raw)
        self.assertEqual(parsed["payload_len"], 3)
        self.assertEqual(parsed["hops_remaining"], 8)
        self.assertEqual(parsed["payload_hex"], "616263")

    def test_rejects_single_fault_relays(self):
        cases = (
            ("invalid_direction", relay(direction=2)),
            ("invalid_hop_count", relay(hops=0)),
            ("invalid_hop_count", relay(hops=9)),
            ("length_mismatch", relay(declared=4)),
            ("payload_too_large", relay(declared=control.MAX_RELAY_PAYLOAD + 1)),
            ("offset_overflow", relay(offset=0xFFFF_FFFF_FFFF_FFFF, declared=3)),
            ("wrong_length", relay()[:29]),
        )
        for category, raw in cases:
            with self.subTest(category=category):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_relay(raw)
                self.assertEqual(caught.exception.category, category)

    def test_maximum_payload_is_accepted(self):
        payload = b"\x00" * control.MAX_RELAY_PAYLOAD
        parsed = control.parse_relay(relay(payload=payload, declared=len(payload)))
        self.assertEqual(parsed["payload_len"], 65_506)


class RegistryTests(unittest.TestCase):
    def test_identity_revocation_control_carries_exact_evidence(self):
        end = control.parse_control(bytes.fromhex("1400"))
        self.assertEqual(end, {"message": "IdentityRevocation", "evidence_hex": None})
        carrier = b"BRIR\0\0\0\x01" + bytes(64 + 3309) + b"\xa0"
        parsed = control.parse_control(b"\x14\x01" + carrier)
        self.assertEqual(parsed["evidence_hex"], carrier.hex())

    def test_mesh_path_registry_and_strict_body(self):
        self.assertEqual(control.SUBTYPE_CAPS[0x15], 6)
        self.assertEqual(control.parse_control(bytes.fromhex("150401030210")),
                         {"message": "MeshPath", "slots": [1, 3, 2, 16]})
        for raw, category in (
            ("15", "wrong_length"),
            ("15030110", "wrong_length"),
            ("1503010110", "invalid_field"),
            ("15020010", "invalid_field"),
            ("15021001", "invalid_field"),
            ("15050102030410", "body_too_large"),
        ):
            with self.subTest(raw=raw), self.assertRaises(control.Reject) as caught:
                control.parse_control(bytes.fromhex(raw))
            self.assertEqual(caught.exception.category, category)

    def test_unregistered_subtypes_are_rejected(self):
        for subtype in (0, 0x0B, 0x0F, 0x16, 0x1F, 0xFF):
            with self.subTest(subtype=subtype):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(bytes([subtype]))
                self.assertEqual(caught.exception.category, "unknown_subtype")

    def test_empty_body_and_registry_caps(self):
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(b"")
        self.assertEqual(caught.exception.category, "empty_body")

        # Probe's registered cap is 256 bytes including the subtype byte.
        oversized = bytes([control.SUBTYPE_PROBE]) + b"\x00" * control.SUBTYPE_CAPS[control.SUBTYPE_PROBE]
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(oversized)
        self.assertEqual(caught.exception.category, "body_too_large")

    def test_registry_names_cover_every_cap(self):
        self.assertEqual(set(control.SUBTYPE_CAPS), set(control.SUBTYPE_NAMES))


class SignedObjectTests(unittest.TestCase):
    def management_node_tbs(self):
        return management_node_tbs()

    def test_node_identity_envelope_round_trips_against_independent_tbs_decoder(self):
        tbs = self.management_node_tbs()
        raw = envelope(object_type=1, tbs=tbs)
        parsed = control.parse_signed_object(raw, verify.parse_management_tbs)
        self.assertEqual(parsed["object_type"], 1)
        self.assertEqual(parsed["tbs_object_type"], "NodeIdentity")
        self.assertEqual(parsed["signers"][0]["mldsa"], "mldsa65")
        self.assertEqual(parsed["signers"][0]["mldsa_len"], 3309)

    def test_envelope_type_must_match_embedded_object(self):
        raw = envelope(object_type=3, tbs=self.management_node_tbs())
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(raw, verify.parse_management_tbs)
        self.assertEqual(caught.exception.category, "bad_object_type")

    def test_rejects_envelope_faults(self):
        tbs = self.management_node_tbs()
        good = envelope(object_type=1, tbs=tbs)
        cases = (
            ("bad_signed_object", bytes([2]) + good[1:]),
            ("bad_object_type", bytes([1, 9]) + good[2:]),
            # Byte offsets: 70 = ML-DSA parameter set, 71..73 = declared signature len.
            ("wrong_signature_length", good[:71] + (3308).to_bytes(2, "big") + good[73:]),
            ("bad_signature_algorithm", good[:70] + bytes([3]) + good[71:]),
            ("signed_object_too_large", good + b"\x00" * (control.MAX_SIGNED_OBJECT + 1 - len(good))),
        )
        for category, raw in cases:
            with self.subTest(category=category):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_signed_object(raw)
                self.assertEqual(caught.exception.category, category)

    def test_lease_requires_cosignature_and_others_forbid_it(self):
        tbs = self.management_node_tbs()
        one_signer = envelope(object_type=2, tbs=tbs, signers=((1, 1),))
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(one_signer)
        self.assertEqual(caught.exception.category, "missing_cosignature")

        two_signers = envelope(object_type=1, tbs=tbs, signers=((1, 1), (2, 2)))
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(two_signers)
        self.assertEqual(caught.exception.category, "unexpected_cosignature")

    def test_cosignature_must_not_come_first(self):
        tbs = self.management_node_tbs()
        bad_order = envelope(object_type=2, tbs=tbs, signers=((2, 1), (1, 2)))
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(bad_order)
        self.assertEqual(caught.exception.category, "invalid_field")


class OtherBodyTests(unittest.TestCase):
    def test_probe_ping_and_pong(self):
        challenge = bytes(range(1, 17))
        ping = bytes([9, 1]) + challenge + (1).to_bytes(8, "big") + bytes(8)
        self.assertEqual(len(ping), control.PROBE_BODY_LEN)
        parsed_ping = control.parse_control(ping)
        self.assertEqual(parsed_ping["kind"], "ping")
        self.assertEqual(parsed_ping["challenge_hex"], challenge.hex())
        self.assertEqual(parsed_ping["sent"], 1)
        self.assertEqual(parsed_ping["echo"], 0)

        pong = bytes([9, 2]) + challenge + (1).to_bytes(8, "big") + (2).to_bytes(8, "big")
        parsed_pong = control.parse_control(pong)
        self.assertEqual(parsed_pong["kind"], "pong")
        self.assertEqual(parsed_pong["challenge_hex"], challenge.hex())
        self.assertEqual(parsed_pong["sent"], 1)
        self.assertEqual(parsed_pong["echo"], 2)

        cases = (
            ("invalid_field", bytes([9, 1]) + bytes(16) + (1).to_bytes(8, "big") + bytes(8)),
            ("invalid_field", bytes([9, 1]) + challenge + (1).to_bytes(8, "big") + (1).to_bytes(8, "big")),
            ("invalid_field", bytes([9, 3]) + challenge + (1).to_bytes(8, "big") + bytes(8)),
            ("wrong_length", ping[:-1]),
        )
        for category, raw in cases:
            with self.subTest(category=category, raw=raw.hex()):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, category)

    def test_drain_length_and_reason(self):
        drain = bytes([10, 1]) + (5).to_bytes(8, "big") + (30).to_bytes(2, "big")
        self.assertEqual(len(drain), control.DRAIN_BODY_LEN)
        self.assertEqual(control.parse_control(drain)["retry"], 30)
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(bytes([10, 4]) + bytes(10))
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_circuit_bodies(self):
        open_body = bytes([16]) + bytes(range(16)) + (2).to_bytes(2, "big") + (1).to_bytes(8, "big") + bytes([3])
        self.assertEqual(len(open_body), control.CIRCUIT_OPEN_BODY_LEN)
        parsed = control.parse_control(open_body)
        self.assertEqual(parsed["destination_node_id"], 2)
        self.assertEqual(parsed["path_hops"], 3)

        accept = bytes([17]) + bytes(range(16)) + bytes([2])
        self.assertEqual(len(accept), control.CIRCUIT_ACCEPT_BODY_LEN)
        self.assertEqual(control.parse_control(accept)["path_hops"], 2)

        for subtype, name in ((18, "CircuitReset"), (19, "CircuitClose")):
            body = bytes([subtype]) + bytes(range(16))
            self.assertEqual(len(body), control.CIRCUIT_ID_BODY_LEN)
            self.assertEqual(control.parse_control(body)["message"], name)

        with self.assertRaises(control.Reject) as caught:
            control.parse_control(bytes([16]) + bytes(range(16)) + (2).to_bytes(2, "big") + (1).to_bytes(8, "big") + bytes([9]))
        self.assertEqual(caught.exception.category, "invalid_hop_count")


class DocumentTests(unittest.TestCase):
    def test_stale_format_is_rejected_with_actionable_message(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-payload-fixed-v1",
            "vectors": [{"id": "x", "valid": True, "expected_hex": HELLO_HEX}],
        }
        errors = control.verify_control_document(document)
        self.assertTrue(any("superseded" in error for error in errors), errors)

    def test_valid_vector_document_passes(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [
                {"id": "hello", "valid": True, "expected_hex": HELLO_HEX, "expected": {"source_node_id": 1}},
                {
                    "id": "relay-bad-direction",
                    "kind": "relay",
                    "valid": False,
                    "input_hex": relay(direction=2).hex(),
                    "expected_error": "invalid_direction",
                },
            ],
            "session_pairs": [
                {
                    "id": "hello-accept",
                    "valid": True,
                    "hello_hex": HELLO_HEX,
                    "accept_hex": session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1).hex(),
                }
            ],
        }
        self.assertEqual(control.verify_control_document(document), [])
        self.assertEqual(control.verify_control_pair_document(document), [])

    def test_expected_mismatch_and_wrong_error_are_reported(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [
                {"id": "lie", "valid": True, "expected_hex": HELLO_HEX, "expected": {"source_node_id": 99}},
                {
                    "id": "wrong-category",
                    "kind": "relay",
                    "valid": False,
                    "input_hex": relay(direction=2).hex(),
                    "expected_error": "length_mismatch",
                },
            ],
        }
        errors = control.verify_control_document(document)
        self.assertTrue(any("field mismatch" in error for error in errors), errors)
        self.assertTrue(any("expected 'length_mismatch'" in error for error in errors), errors)

    def test_duplicate_ids_are_reported(self):
        vector = {"id": "dup", "valid": True, "expected_hex": HELLO_HEX}
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [vector, dict(vector)],
        }
        errors = control.verify_control_document(document)
        self.assertTrue(any("duplicate id" in error for error in errors), errors)


class EnvelopeLayoutTests(unittest.TestCase):
    def test_ed25519_is_mandatory_and_fixed_length(self):
        parsed = control.parse_signed_object(envelope(object_type=1, tbs=b"\x00"))
        signer = parsed["signers"][0]
        self.assertTrue(signer["ed25519_present"])
        self.assertEqual(signer["ed25519_len"], control.ED25519_SIG_LEN)

    def test_legacy_presence_byte_encoding_is_rejected(self):
        # The superseded layout inserted a 0/1 presence byte after the role and
        # allowed an ML-DSA-only signer. Re-encoding that shape must not parse.
        legacy = (
            bytes([1, 1])
            + (1).to_bytes(2, "big")
            + bytes([1])
            + bytes([1])  # role
            + bytes([0])  # legacy ed25519_present = 0
            + bytes([1])  # parameter set
            + (3309).to_bytes(2, "big")
            + b"\x00" * 3309
            + (1).to_bytes(4, "big")
            + b"\x00"
        )
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(legacy)
        self.assertEqual(caught.exception.category, "bad_signature_algorithm")

    def test_exact_size_boundary(self):
        # 5 header + 68 signer + 3309 signature + 4 length + tbs = 16384
        tbs_len = control.MAX_SIGNED_OBJECT - (5 + (1 + 64 + 1 + 2) + 3309 + 4)
        raw = envelope(object_type=1, tbs=b"\x00" * tbs_len)
        self.assertEqual(len(raw), control.MAX_SIGNED_OBJECT)
        self.assertEqual(control.parse_signed_object(raw)["raw_tbs_len"], tbs_len)

        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(raw + b"\x00")
        self.assertEqual(caught.exception.category, "signed_object_too_large")

    def test_signer_count_and_structural_faults(self):
        cases = (
            ("bad_signed_object", bytes([1, 1, 0, 1, 0]) + (1).to_bytes(4, "big") + b"\x00"),
            ("bad_signed_object", bytes([1, 1, 0, 1, 3]) + (1).to_bytes(4, "big") + b"\x00"),
            ("invalid_field", envelope(object_type=1, tbs=b"")),
            ("invalid_field", envelope(object_type=1, tbs=b"\x00") + b"\x00"),
        )
        for category, raw in cases:
            with self.subTest(category=category, length=len(raw)):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_signed_object(raw)
                self.assertEqual(caught.exception.category, category)


class EnrollmentTests(unittest.TestCase):
    def test_request_minimal(self):
        parsed = control.parse_control(enrollment_request())
        self.assertEqual(parsed["message"], "EnrollmentRequest")
        self.assertEqual(parsed["csr_len"], 1)

    def test_request_negatives(self):
        cases = (
            ("bad_protocol_version", enrollment_request(version=2)),
            ("invalid_field", enrollment_request(csr_len=0)),
            ("invalid_field", enrollment_request(csr_len=control.MAX_ENROLLMENT_DER + 1)),
            ("wrong_length", enrollment_request()[:-1]),
            ("invalid_field", enrollment_request(kind=9)),
        )
        for category, raw in cases:
            with self.subTest(category=category):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, category)

    def test_response_pending_has_no_identity(self):
        parsed = control.parse_control(enrollment_response(status=2))
        self.assertEqual(parsed["status"], "pending")
        self.assertEqual(parsed["node_id"], 1)

    def test_response_issued_requires_a_node_identity_envelope(self):
        identity = envelope(object_type=1, tbs=b"\x00")
        parsed = control.parse_control(enrollment_response(status=1, identity=identity))
        self.assertEqual(parsed["status"], "issued")

        for bad in (
            enrollment_response(status=1, identity=b""),
            enrollment_response(status=2, identity=identity),
            enrollment_response(status=1, identity=envelope(object_type=3, tbs=b"\x00")),
        ):
            with self.subTest(length=len(bad)):
                with self.assertRaises(control.Reject):
                    control.parse_control(bad)

    def test_response_field_faults(self):
        cases = (
            ("invalid_field", enrollment_response(status=4)),
            ("bad_node_id", enrollment_response(status=2, node_id=0x00FC)),
            ("bad_identity_generation", enrollment_response(status=2, generation=0)),
            ("bad_net_id", enrollment_response(status=2, net_id="00" * 16)),
            ("wrong_length", enrollment_response(status=2)[:-1]),
        )
        for category, raw in cases:
            with self.subTest(category=category):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, category)


class DirectoryPageTests(unittest.TestCase):
    def test_minimal_page(self):
        parsed = control.parse_control(directory_page())
        self.assertEqual(parsed["message"], "DirectoryPage")
        self.assertEqual(parsed["page_seq"], 7)
        self.assertEqual(parsed["count"], 1)
        self.assertEqual(parsed["pages"][0]["object_type"], 1)

    def test_page_negatives(self):
        cases = (
            ("invalid_field", directory_page(count=0)),
            ("invalid_field", directory_page(count=17)),
            ("invalid_field", directory_page(declared_len=0)),
            ("wrong_length", directory_page() + b"\x00"),
            ("bad_signed_object", directory_page(envelopes=[bytes([2]) + envelope()[1:]])),
        )
        for category, raw in cases:
            with self.subTest(category=category):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, category)

    def test_page_body_cap(self):
        large = envelope(object_type=1, tbs=b"\x00" * 9000)
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(directory_page(envelopes=[large, large]))
        self.assertEqual(caught.exception.category, "body_too_large")


class SubtypeObjectTypeTests(unittest.TestCase):
    def test_each_subtype_accepts_only_its_registered_object_types(self):
        tbs = b"\x00"
        # A structurally valid AttachmentLease envelope: two signers, Lease type.
        lease_shaped = envelope(object_type=2, tbs=tbs, signers=((1, 1), (2, 2)))
        parsed = control.parse_control(bytes([control.SUBTYPE_LEASE]) + lease_shaped)
        self.assertEqual(parsed["message"], "Lease")
        self.assertEqual(parsed["object_type"], 2)

        # Each case is structurally valid on its own; only the subtype/object-type
        # pairing is wrong, so `bad_object_type` must be the reported category
        # (an ill-formed envelope would report its own structural fault first).
        cases = (
            (control.SUBTYPE_LEASE, envelope(object_type=3, tbs=tbs)),
            (control.SUBTYPE_LSA, lease_shaped),
            (control.SUBTYPE_REVOKE, envelope(object_type=4, tbs=tbs)),
            (control.SUBTYPE_GRANT, envelope(object_type=6, tbs=tbs)),
        )
        for subtype, body in cases:
            with self.subTest(subtype=subtype, object_type=body[:2]):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(bytes([subtype]) + body)
                self.assertEqual(caught.exception.category, "bad_object_type")

    def test_grant_accepts_both_grant_types(self):
        for object_type in (4, 5):
            with self.subTest(object_type=object_type):
                parsed = control.parse_control(
                    bytes([control.SUBTYPE_GRANT]) + envelope(object_type=object_type, tbs=b"\x00")
                )
                self.assertEqual(parsed["message"], "Grant")


class KindDispatchTests(unittest.TestCase):
    def test_dispatch_matches_header_kind(self):
        hello = bytes.fromhex(HELLO_HEX)
        self.assertEqual(control.parse_control_body_for_kind(1, hello)["message"], "SessionHello")
        self.assertEqual(control.parse_control_body_for_kind(3, relay())["message"], "RelayFragment")

    def test_unmodelled_kinds_are_not_silently_accepted(self):
        hello = bytes.fromhex(HELLO_HEX)
        for kind in (0, 2, 4, 255):
            with self.subTest(kind=kind):
                with self.assertRaises(control.NotModeled):
                    control.parse_control_body_for_kind(kind, hello)


class SessionPairRoleTests(unittest.TestCase):
    def test_accept_role_is_asserted_only_when_supplied(self):
        hello = bytes.fromhex(HELLO_HEX)
        accept = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, role=2)

        control.check_session_pair(hello, accept)  # no assertion: accepted
        control.check_session_pair(hello, accept, expected_accept_source_role=2)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(hello, accept, expected_accept_source_role=1)
        self.assertEqual(caught.exception.category, "illegal_state")

    def test_pair_document_uses_accept_source_role(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [{"id": "hello", "valid": True, "expected_hex": HELLO_HEX}],
            "session_pairs": [
                {
                    "id": "correlated-core-responder",
                    "valid": True,
                    "hello_hex": HELLO_HEX,
                    "accept_hex": session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, role=2).hex(),
                    "accept_source_role": 2,
                },
                {
                    "id": "wrong-role",
                    "valid": False,
                    "hello_hex": HELLO_HEX,
                    "accept_hex": session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, role=1).hex(),
                    "accept_source_role": 2,
                    "expected_error": "illegal_state",
                },
            ],
        }
        self.assertEqual(control.verify_control_document(document), [])
        self.assertEqual(control.verify_control_pair_document(document), [])


class MainTests(unittest.TestCase):
    def _write(self, directory, name, document):
        path = Path(directory) / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_exit_codes_and_usage(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [{"id": "hello", "valid": True, "expected_hex": HELLO_HEX}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            good = self._write(tmp, "good.json", document)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(control.main([str(good)]), 0)
            self.assertIn("PASS: 1 control vectors", out.getvalue())

            stale = self._write(tmp, "stale.json", dict(document, format="boreas-control-payload-fixed-v1"))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(control.main([str(stale)]), 1)
            self.assertIn("superseded", err.getvalue())

            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(control.main([str(Path(tmp) / "missing.json")]), 2)
                self.assertEqual(control.main(["a", "b"]), 2)


class VerifyVectorsDelegationTests(unittest.TestCase):
    def test_verify_vectors_delegates_with_the_independent_tbs_decoder(self):
        document = {
            "status": "candidate-not-frozen",
            "format": "boreas-control-messages-v1",
            "vectors": [
                {"id": "hello", "valid": True, "expected_hex": HELLO_HEX},
                {
                    "id": "envelope",
                    "kind": "signed_object",
                    "valid": True,
                    "expected_hex": envelope(object_type=1, tbs=management_node_tbs()).hex(),
                    "expected": {"tbs_object_type": "NodeIdentity"},
                },
            ],
            "session_pairs": [
                {
                    "id": "correlated",
                    "valid": True,
                    "hello_hex": HELLO_HEX,
                    "accept_hex": session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, role=2).hex(),
                    "accept_source_role": 2,
                }
            ],
        }
        self.assertEqual(verify.verify_control_document(document), [])


class DrainRetryBoundaryTests(unittest.TestCase):
    """Drain retry_after_seconds is u16 with a hard candidate cap of 3600."""

    def drain(self, retry, reason=1, deadline=100):
        return (
            bytes([control.SUBTYPE_DRAIN, reason])
            + deadline.to_bytes(8, "big")
            + retry.to_bytes(2, "big")
        )

    def test_retry_just_below_maximum_is_accepted(self):
        raw = self.drain(3599)
        self.assertEqual(len(raw), control.DRAIN_BODY_LEN)
        self.assertEqual(raw.hex(), "0a0100000000000000640e0f")
        self.assertEqual(control.parse_control(raw)["retry"], 3599)

    def test_retry_equal_to_maximum_is_accepted(self):
        raw = self.drain(control.MAX_DRAIN_RETRY_SECONDS)
        self.assertEqual(control.MAX_DRAIN_RETRY_SECONDS, 3600)
        self.assertEqual(raw.hex(), "0a0100000000000000640e10")
        parsed = control.parse_control(raw)
        self.assertEqual(parsed["retry"], 3600)
        self.assertEqual(parsed["reason"], 1)
        self.assertEqual(parsed["deadline"], 100)

    def test_retry_one_above_maximum_is_rejected(self):
        raw = self.drain(3601)
        self.assertEqual(raw.hex(), "0a0100000000000000640e11")
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(raw)
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_retry_is_not_clamped_to_the_cap(self):
        # A too-large hint is a schema violation. It must never be silently
        # shortened to 3600, which would change the peering shutdown contract.
        with self.assertRaises(control.Reject):
            control.parse_control(self.drain(3601))
        with self.assertRaises(control.Reject):
            control.parse_control(self.drain(0xFFFE))

    def test_retry_zero_and_uint16_maximum(self):
        self.assertEqual(control.parse_control(self.drain(0))["retry"], 0)
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(self.drain(0xFFFF))
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_fixture_pins_the_3601_rejection(self):
        fixture = json.loads(
            (ROOT / "docs/protocol/vectors/control-messages-candidate-v1.json").read_text(encoding="utf-8")
        )
        by_id = {vector["id"]: vector for vector in fixture["vectors"]}
        too_large = by_id["drain-retry-too-large"]
        self.assertFalse(too_large["valid"])
        self.assertEqual(too_large["expected_error"], "invalid_field")
        self.assertEqual(bytes.fromhex(too_large["input_hex"]).hex(), "0a0100000000000000640e11")
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(bytes.fromhex(too_large["input_hex"]))
        self.assertEqual(caught.exception.category, "invalid_field")
        # The positive fixture pins retry 30, which is well inside the cap.
        minimal = by_id["drain-minimal"]
        self.assertTrue(minimal["valid"])
        self.assertEqual(bytes.fromhex(minimal["expected_hex"]).hex(), "0a010000000000000064001e")


class SpecZeroFieldTests(unittest.TestCase):
    """Nonzero rules the candidate documents mandate for probe/circuit/enrollment."""

    def test_probe_challenge_must_be_nonzero(self):
        zero = bytes([control.SUBTYPE_PROBE, 1]) + bytes(16) + (1).to_bytes(8, "big") + bytes(8)
        self.assertEqual(len(zero), control.PROBE_BODY_LEN)
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(zero)
        self.assertEqual(caught.exception.category, "invalid_field")

        nonzero = (
            bytes([control.SUBTYPE_PROBE, 1])
            + bytes([7])
            + bytes(15)
            + (1).to_bytes(8, "big")
            + bytes(8)
        )
        self.assertEqual(control.parse_control(nonzero)["kind"], "ping")

    def test_circuit_identifier_must_be_nonzero(self):
        zero_open = (
            bytes([control.SUBTYPE_CIRCUIT_OPEN])
            + bytes(16)
            + (2).to_bytes(2, "big")
            + (1).to_bytes(8, "big")
            + bytes([2])
        )
        zero_accept = bytes([control.SUBTYPE_CIRCUIT_ACCEPT]) + bytes(16) + bytes([2])
        zero_reset = bytes([control.SUBTYPE_CIRCUIT_RESET]) + bytes(16)
        zero_close = bytes([control.SUBTYPE_CIRCUIT_CLOSE]) + bytes(16)
        for raw in (zero_open, zero_accept, zero_reset, zero_close):
            with self.subTest(subtype=raw[0], length=len(raw)):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(raw)
                self.assertEqual(caught.exception.category, "invalid_field")

    def test_enrollment_request_rejects_zero_identifiers(self):
        base = enrollment_request()
        for name, start, end in (
            ("enrollment_id", 4, 20),
            ("invite_id", 20, 36),
            ("csr_hash", 36, 68),
            ("invite_secret", 68, 100),
        ):
            raw = bytearray(base)
            raw[start:end] = bytes(end - start)
            with self.subTest(field=name):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(bytes(raw))
                self.assertEqual(caught.exception.category, "invalid_field")

    def test_enrollment_response_rejects_zero_identifiers(self):
        base = enrollment_response(status=2)
        for name, start, end in (("enrollment_id", 3, 19), ("csr_hash", 19, 51)):
            raw = bytearray(base)
            raw[start:end] = bytes(end - start)
            with self.subTest(field=name):
                with self.assertRaises(control.Reject) as caught:
                    control.parse_control(bytes(raw))
                self.assertEqual(caught.exception.category, "invalid_field")


def node_identity_tbs_with_nonzero_net():
    """Fixture NodeIdentity TBS with both net_id copies set nonzero.

    The management fixture uses a zero net_id, which a valid issued enrollment
    response cannot carry. Only the two bstr payloads change; the canonical map
    shape and the Ed25519 key stay untouched.
    """
    raw = management_node_tbs()
    patched = raw.replace(b"\x02\x50" + bytes(16), b"\x02\x50" + bytes([1]) * 16, 1)
    patched = patched.replace(b"\x00\x50" + bytes(16), b"\x00\x50" + bytes([1]) * 16, 1)
    return patched


class EnrollmentIssuedBindingTests(unittest.TestCase):
    """An issued response must bind its header to the embedded NodeIdentity."""

    def setUp(self):
        self.net = bytes([1]) * 16
        self.tbs = node_identity_tbs_with_nonzero_net()
        self.identity = envelope(object_type=1, tbs=self.tbs)

    def response(self, **overrides):
        fields = dict(
            status=1,
            identity=self.identity,
            node_id=2,
            generation=1,
            net_id=self.net.hex(),
        )
        fields.update(overrides)
        return enrollment_response(**fields)

    def test_matching_identity_is_accepted(self):
        parsed = control.parse_control(self.response(), verify.parse_management_tbs)
        self.assertEqual(parsed["status"], "issued")
        self.assertEqual(parsed["node_id"], 2)

    def test_identity_without_decoder_is_only_structural(self):
        parsed = control.parse_control(self.response())
        self.assertEqual(parsed["status"], "issued")

    def test_mismatched_header_node_is_rejected(self):
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(self.response(node_id=3), verify.parse_management_tbs)
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_mismatched_header_generation_is_rejected(self):
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(self.response(generation=2), verify.parse_management_tbs)
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_mismatched_header_net_id_is_rejected(self):
        with self.assertRaises(control.Reject) as caught:
            control.parse_control(
                self.response(net_id=(bytes([2]) * 16).hex()), verify.parse_management_tbs
            )
        self.assertEqual(caught.exception.category, "invalid_field")


class SessionModeEchoTests(unittest.TestCase):
    def test_accept_cannot_upgrade_a_hop_only_hello(self):
        hello = session(mode=2)
        accept = session(subtype=2, src=2, dst=1, src_gen=2, dst_gen=1, mode=1)
        with self.assertRaises(control.Reject) as caught:
            control.check_session_pair(hello, accept, allow_hop_only=True)
        self.assertEqual(caught.exception.category, "session_mismatch")


class DecoderBoundaryTests(unittest.TestCase):
    """The verifier must not hide decoder bugs behind a rejection category."""

    def test_decoder_rejection_category_is_preserved(self):
        raw = envelope(object_type=1, tbs=b"\x00")
        with self.assertRaises(control.Reject) as caught:
            control.parse_signed_object(raw, verify.parse_management_tbs)
        self.assertEqual(caught.exception.category, "invalid_field")

    def test_decoder_programming_errors_are_not_masked(self):
        def broken(_raw):
            raise RuntimeError("decoder bug, not a vector verdict")

        with self.assertRaises(RuntimeError):
            control.parse_signed_object(envelope(object_type=1, tbs=b"\x00"), broken)


class DirectoryPageLayoutTests(unittest.TestCase):
    def test_fixture_entry_length_matches_embedded_envelope(self):
        fixture = json.loads(
            (ROOT / "docs/protocol/vectors/control-messages-candidate-v1.json").read_text(encoding="utf-8")
        )
        vector = next(item for item in fixture["vectors"] if item["id"] == "directory-page-minimal")
        body = bytes.fromhex(vector["expected_hex"])
        self.assertEqual(body[0], control.SUBTYPE_DIRECTORY_PAGE)
        self.assertEqual(body[9], 1, "the minimal page carries exactly one object")
        declared = int.from_bytes(body[10:12], "big")
        envelope = body[12:]
        # A DirectoryPage entry length is exact: the embedded SignedObject and the
        # declared u16 must agree, otherwise a correct decoder sees trailing bytes.
        self.assertEqual(len(envelope), declared)
        parsed = control.parse_control(body, verify.parse_management_tbs)
        self.assertEqual(parsed["message"], "DirectoryPage")
        self.assertEqual(parsed["count"], 1)
        self.assertEqual(parsed["pages"][0]["tbs_object_type"], "NodeIdentity")


class ControlFixtureLayoutTests(unittest.TestCase):
    """Guard the fixed candidate layout: 54 vectors plus 4 session pairs.

    Negative vectors are evidence and must not be deleted or relabelled to make a
    gate pass; this test fails loudly if the fixture shrinks.
    """

    def test_fixture_keeps_all_54_vectors_and_4_pairs(self):
        fixture = json.loads(
            (ROOT / "docs/protocol/vectors/control-messages-candidate-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(fixture["vectors"]), 54)
        self.assertEqual(len(fixture["session_pairs"]), 4)
        ids = [vector["id"] for vector in fixture["vectors"]]
        self.assertEqual(len(set(ids)), 54)
        self.assertEqual(sum(1 for vector in fixture["vectors"] if vector["valid"]), 16)
        self.assertEqual(sum(1 for vector in fixture["vectors"] if not vector["valid"]), 38)
        self.assertEqual(sum(1 for pair in fixture["session_pairs"] if pair["valid"]), 1)
        self.assertEqual(sum(1 for pair in fixture["session_pairs"] if not pair["valid"]), 3)


if __name__ == "__main__":
    unittest.main()