"""Promotion-report freshness regressions; execute only in GitHub Actions.

Synthetic fixtures and mock verifiers test orchestration, NOT cryptographic
validity or the trustworthiness/independence of a configured verifier.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import production_promotion as promotion
from common import MAX_JSON_BYTES


class PromotionVerifierFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="promotion-regression-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.args = promotion._build_positive_fixture(self.root)
        self.bundle, self.commit, self.root_hash = self.args[:3]
        self.template = json.loads(
            (self.root / "test-only-report-template.json").read_text(encoding="utf-8")
        )

    def invoke(self, command):
        errors = []
        report = promotion.run_external_verifier(
            command,
            self.bundle,
            self.bundle / promotion.RELEASE_MANIFEST_NAME,
            self.bundle / promotion.RELEASE_ENVELOPE_NAME,
            self.bundle / promotion.PROMOTION_MANIFEST_NAME,
            self.bundle / promotion.PROMOTION_ENVELOPE_NAME,
            self.commit,
            self.root_hash,
            errors,
        )
        return report, errors

    def fake_result(self, code=0):
        return subprocess.CompletedProcess([], code, stdout="", stderr="fixture failure")

    def test_positive_fixture_writes_fresh_report_but_proves_no_crypto(self):
        self.assertEqual(promotion.evaluate(*self.args), [])
        self.assertFalse((self.bundle / "verification" / "verification.json").exists())

    def test_noop_cannot_reuse_embedded_pass_report(self):
        embedded = self.bundle / "verification" / "verification.json"
        promotion._write_json(embedded, self.template)
        noop = shlex.join([sys.executable, "-c", "import sys; sys.exit(0)"])
        args = (*self.args[:5], noop)
        errors = promotion.evaluate(*args)
        self.assertTrue(any("fresh verification report" in error for error in errors))
        self.assertEqual(json.loads(embedded.read_text(encoding="utf-8")), self.template)

    def test_noop_without_any_report_is_refused(self):
        with patch.object(promotion, "run_command", return_value=self.fake_result()):
            report, errors = self.invoke("test-only-verifier")
        self.assertIsNone(report)
        self.assertTrue(errors)

    def test_report_path_is_absent_private_external_and_removed_after_read(self):
        outputs = []

        def writer(command, timeout):
            output = Path(command[command.index("--json-out") + 1])
            outputs.append(output)
            self.assertFalse(output.exists())
            self.assertFalse(output.is_symlink())
            self.assertFalse(output.resolve().is_relative_to(self.bundle.resolve()))
            self.assertEqual(timeout, 600)
            if os.name != "nt":
                self.assertEqual(output.parent.stat().st_mode & 0o077, 0)
            promotion._write_json(output, self.template)
            return self.fake_result()

        with patch.object(promotion, "run_command", side_effect=writer):
            for _ in range(2):
                report, errors = self.invoke("test-only-verifier")
                self.assertEqual(report, self.template)
                self.assertEqual(errors, [])
        self.assertNotEqual(outputs[0], outputs[1])
        self.assertTrue(all(not output.parent.exists() for output in outputs))

    def test_nonzero_verifier_cannot_supply_pass_report(self):
        def writer(command, timeout):
            promotion._write_json(Path(command[command.index("--json-out") + 1]), self.template)
            return self.fake_result(1)

        with patch.object(promotion, "run_command", side_effect=writer):
            report, errors = self.invoke("test-only-verifier")
        self.assertIsNone(report)
        self.assertTrue(any("refused the bundle" in error for error in errors))

    def test_invalid_new_reports_are_refused(self):
        cases = (
            b"not JSON",
            b"[]",
            b'{"result":"pass","result":"fail"}',
            b" " * (MAX_JSON_BYTES + 1),
        )
        for data in cases:
            with self.subTest(size=len(data), prefix=data[:32]):
                def writer(command, timeout):
                    Path(command[command.index("--json-out") + 1]).write_bytes(data)
                    return self.fake_result()

                with patch.object(promotion, "run_command", side_effect=writer):
                    report, errors = self.invoke("test-only-verifier")
                self.assertIsNone(report)
                self.assertTrue(errors)

    @unittest.skipIf(os.name == "nt", "symlink creation requires extra Windows privilege")
    def test_new_symlink_report_is_refused(self):
        def writer(command, timeout):
            Path(command[command.index("--json-out") + 1]).symlink_to(
                self.root / "test-only-report-template.json"
            )
            return self.fake_result()

        with patch.object(promotion, "run_command", side_effect=writer):
            report, errors = self.invoke("test-only-verifier")
        self.assertIsNone(report)
        self.assertTrue(any("regular single-link file" in error for error in errors))

    @unittest.skipIf(os.name == "nt", "hard-link fixture is exercised on Linux Actions")
    def test_hardlinked_report_is_refused(self):
        def writer(command, timeout):
            os.link(
                self.root / "test-only-report-template.json",
                command[command.index("--json-out") + 1],
            )
            return self.fake_result()

        with patch.object(promotion, "run_command", side_effect=writer):
            report, errors = self.invoke("test-only-verifier")
        self.assertIsNone(report)
        self.assertTrue(any("regular single-link file" in error for error in errors))

    def test_timeout_and_missing_executable_are_refused(self):
        for failure in (OSError("test-only missing executable"), subprocess.TimeoutExpired("fixture", 600)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(promotion, "run_command", side_effect=failure):
                    report, errors = self.invoke("test-only-verifier")
                self.assertIsNone(report)
                self.assertTrue(any("could not run" in error for error in errors))

    def test_directory_report_is_refused(self):
        def writer(command, timeout):
            Path(command[command.index("--json-out") + 1]).mkdir()
            return self.fake_result()

        with patch.object(promotion, "run_command", side_effect=writer):
            report, errors = self.invoke("test-only-verifier")
        self.assertIsNone(report)
        self.assertTrue(errors)

    def test_new_report_still_requires_every_hash_signature_and_artifact(self):
        release = json.loads(
            (self.bundle / promotion.RELEASE_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        for mutation in ("root", "release", "promotion", "signature", "artifact"):
            with self.subTest(mutation=mutation):
                report = json.loads(json.dumps(self.template))
                if mutation in ("root", "release", "promotion"):
                    field = {
                        "root": "release_root_sha256",
                        "release": "release_manifest_sha256",
                        "promotion": "promotion_manifest_sha256",
                    }[mutation]
                    report[field] = "0" * 64
                elif mutation == "signature":
                    report["signatures"].pop()
                else:
                    report["artifacts"].pop()
                errors = []
                promotion.validate_external_report(
                    report, release,
                    self.template["release_manifest_sha256"],
                    self.template["promotion_manifest_sha256"],
                    self.root_hash, errors,
                )
                self.assertTrue(errors)

    def test_fresh_synthetic_report_is_not_an_independence_or_crypto_check(self):
        # Deliberate boundary: a configured malicious verifier can write lies.
        # This structurally valid fixture uses zero signatures and must never be
        # mistaken for signature verification or a production acceptance test.
        report, errors = self.invoke(self.args[5])
        self.assertEqual(errors, [])
        self.assertEqual(report["verifier"]["version"], "test-only")


if __name__ == "__main__":
    unittest.main()
