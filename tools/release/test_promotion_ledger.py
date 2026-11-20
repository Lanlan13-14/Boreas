"""Production ledger provenance regressions; run only in GitHub Actions."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import production_promotion as promotion
from promotion_ledger import LEDGER_PATH, gate_policy, load_ledger, verify_ledger


class PromotionLedgerSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="promotion-ledger-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--initial-branch=main", "--object-format=sha1")
        self.git("config", "user.name", "Fixture Reviewer")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "core.autocrlf", "false")
        self.path = self.repo / LEDGER_PATH
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"{}\n")
        self.candidate = self.commit("freeze candidate")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args]).decode().strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def test_frozen_candidate_then_reviewed_ledger_then_bundle_verification(self):
        bundle, candidate, root_hash, ledger, verifier = promotion._build_positive_fixture(
            self.root / "fixture", commit=self.candidate,
        )
        self.path.write_bytes(ledger)
        source = self.commit("record exact-candidate evidence after independent review")
        committed = load_ledger(self.repo, candidate, source)
        self.assertEqual(verify_ledger(committed, candidate), [])
        self.assertEqual(promotion.evaluate(bundle, candidate, root_hash, committed, verifier), [])

    def test_later_main_commit_supplies_only_the_fixed_raw_blob(self):
        reviewed = b'{"evidence": "reviewed"}\r\n'
        self.path.write_bytes(reviewed)
        source = self.commit("record reviewed evidence")
        self.path.write_bytes(b"{\"changed\": true}\n")
        self.commit("later main state")
        self.path.unlink()
        self.assertEqual(load_ledger(self.repo, self.candidate, source), reviewed)

    def test_same_commit_short_sha_uppercase_and_non_commit_objects_are_refused(self):
        source = self.commit("separate ledger source")
        tree = self.git("rev-parse", "HEAD^{tree}")
        cases = (
            (self.candidate, self.candidate, "must not be the candidate"),
            (self.candidate[:12], source, "full lowercase"),
            (self.candidate, source.upper(), "full lowercase"),
            (tree, source, "must identify a commit object"),
            (self.candidate, tree, "must identify a commit object"),
            (source, self.candidate, "must descend from the candidate"),
        )
        for candidate, ledger, error in cases:
            with self.subTest(candidate=candidate, ledger=ledger):
                with self.assertRaisesRegex(ValueError, error):
                    load_ledger(self.repo, candidate, ledger)

    def test_inherited_candidate_ledger_is_not_a_separate_review(self):
        source = self.commit("unrelated main change")
        with self.assertRaisesRegex(ValueError, "must introduce or update"):
            load_ledger(self.repo, self.candidate, source)

    def test_side_branch_ledger_is_not_the_reviewed_main_snapshot(self):
        self.git("switch", "-c", "side")
        self.path.write_bytes(b'{"reviewed": false}\n')
        side = self.commit("proposed ledger")
        self.git("switch", "main")
        self.git("merge", "--no-ff", "-m", "reviewed merge", "side")
        with self.assertRaisesRegex(ValueError, "first-parent"):
            load_ledger(self.repo, self.candidate, side)

    def test_missing_exact_path_does_not_fall_back_to_repository_ledger(self):
        self.path.rename(self.repo / "docs/engineering/gates.json")
        source = self.commit("only repository status ledger exists")
        with self.assertRaisesRegex(ValueError, "regular 100644 blob"):
            load_ledger(self.repo, self.candidate, source)

    @unittest.skipIf(os.name == "nt", "symlink fixture requires Linux Actions")
    def test_symlink_refused(self):
        self.path.unlink()
        self.path.symlink_to("../gates.json")
        source = self.commit("non-regular reviewed ledger path")
        with self.assertRaisesRegex(ValueError, "regular 100644 blob"):
            load_ledger(self.repo, self.candidate, source)

    def test_oversize_ledger_refused(self):
        self.path.write_bytes(b" " * (gate_policy.MAX_LEDGER_BYTES + 1))
        source = self.commit("oversize ledger")
        with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
            load_ledger(self.repo, self.candidate, source)


class PromotionLedgerBindingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="promotion-ledger-binding-")
        self.addCleanup(temp.cleanup)
        self.args = promotion._build_positive_fixture(Path(temp.name))

    def test_stale_candidate_evidence_refused_at_every_level(self):
        _, candidate, _, ledger, _ = self.args
        for section, error in [
            ("release_commit", "ledger release_commit does not match candidate"),
            ("gates", "G-CRYPTO: evidence belongs to another commit"),
            ("platforms", "linux-x86_64-static: exact-commit native functional evidence absent"),
        ]:
            with self.subTest(section=section):
                document = json.loads(ledger)
                if section == "release_commit":
                    document[section] = "b" * 40
                elif section == "gates":
                    document[section]["G-CRYPTO"]["evidence"][0]["commit"] = "b" * 40
                else:
                    document[section]["linux-x86_64-static"]["commit"] = "b" * 40
                self.assertIn(error, verify_ledger(json.dumps(document).encode(), candidate))

    def test_changed_raw_bytes_fail_signed_manifest_binding(self):
        bundle, candidate, root_hash, ledger, verifier = self.args
        with patch.object(promotion, "run_external_verifier") as external:
            errors = promotion.evaluate(bundle, candidate, root_hash, ledger + b"\n", verifier)
            external.assert_not_called()
        self.assertIn("promotion manifest gate_ledger_sha256 mismatch", errors)

    def test_matching_digest_does_not_replace_metadata_validation(self):
        bundle, candidate, root_hash, ledger, verifier = self.args
        document = json.loads(ledger)
        document["release_commit"] = "b" * 40
        stale = json.dumps(document).encode()
        manifest_path = bundle / promotion.PROMOTION_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_bytes())
        manifest["gate_ledger_sha256"] = hashlib.sha256(stale).hexdigest()
        promotion._write_json(manifest_path, manifest)
        envelope_path = bundle / promotion.PROMOTION_ENVELOPE_NAME
        envelope = json.loads(envelope_path.read_bytes())
        envelope["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        promotion._write_json(envelope_path, envelope)
        with patch.object(promotion, "run_external_verifier") as external:
            errors = promotion.evaluate(bundle, candidate, root_hash, stale, verifier)
            external.assert_not_called()
        self.assertIn("ledger release_commit does not match candidate", errors)
