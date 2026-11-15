"""Run via GitHub Actions, never as a local substitute for gate evidence."""
import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('gate_verify', Path(__file__).with_name('verify.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
SHA = 'a' * 40


def complete_metadata():
    evidence = {'commit': SHA, 'command': 'reviewed gate command', 'environment': 'native runner',
                'expected': 'documented acceptance', 'observed': 'documented result', 'reviewer': 'reviewer',
                'actions_run': 'https://github.com/Lanlan13-14/Boreas/actions/runs/123',
                'report_sha256': 'b' * 64, 'outcome': 'pass', 'recorded_at': '2026-11-15T00:00:00Z'}
    gates = {name: {'status': 'accepted', 'evidence': [copy.deepcopy(evidence)]} for name in v.REQUIRED}
    gates['G-EXTERNAL-REVIEW']['independent_review'] = {
        'independent': True, 'organization': 'independent-reviewer', 'scope': 'crypto and protocol',
        'report_url': 'https://example.org/review', 'report_sha256': 'c' * 64, 'open_high_or_critical': 0}
    platforms = {name: {'commit': SHA, 'functional_test': 'pass',
                       'actions_run': evidence['actions_run'], 'native_execution': True,
                       'real_packet_io': True, 'static_linkage': True} for name in v.PLATFORMS}
    return {'schema_version': 1, 'release_commit': SHA, 'production_approved': True,
            'blocking_findings': [], 'gates': gates, 'platforms': platforms}


class GateEvidenceTests(unittest.TestCase):
    def test_empty_ledger_blocks(self):
        self.assertTrue(v.verify({}, SHA))

    def test_complete_metadata_is_not_a_real_audit(self):
        self.assertEqual(v.verify(complete_metadata(), SHA), [])

    def test_every_gate_mandatory(self):
        for name in v.REQUIRED:
            ledger = complete_metadata()
            del ledger['gates'][name]
            self.assertTrue(v.verify(ledger, SHA), name)

    def test_commit_evidence_and_boolean_only_cannot_pass(self):
        ledger = complete_metadata()
        ledger['gates']['G-E2E'] = {'status': 'accepted', 'evidence': []}
        self.assertTrue(v.verify(ledger, SHA))
        self.assertTrue(v.verify(complete_metadata(), 'd' * 40))

    def test_native_real_io_and_static_are_required(self):
        for key in ('native_execution', 'real_packet_io', 'static_linkage'):
            ledger = complete_metadata()
            ledger['platforms']['linux-aarch64-static'][key] = False
            self.assertTrue(v.verify(ledger, SHA), key)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            v.json.loads('{"status": "open", "status": "accepted"}', object_pairs_hook=v.unique_object)

    def test_external_review_required(self):
        ledger = complete_metadata()
        ledger['gates']['G-EXTERNAL-REVIEW']['independent_review']['open_high_or_critical'] = 1
        self.assertTrue(v.verify(ledger, SHA))

    def test_invalid_run_and_timestamp(self):
        ledger = complete_metadata()
        item = ledger['gates']['G-CRYPTO']['evidence'][0]
        item['actions_run'] = 'https://github.com.evil/Lanlan13-14/Boreas/actions/runs/123'
        item['recorded_at'] = '2026-11-15T00:00:00'
        self.assertGreaterEqual(len(v.verify(ledger, SHA)), 2)


if __name__ == '__main__':
    unittest.main()
