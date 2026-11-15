"""Negative and contract tests for the development release tooling.

Run only in GitHub Actions:
    python -m unittest discover -s tools/release -p 'test_*.py' -v

These tests use synthetic archives only.  They never build Boreas, generate a
ReleaseRoot key or claim production evidence.
"""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import common
import functional_smoke
import package
import production_promotion
import verify_bundle


def make_tar(path: Path, members: list[tuple[str, bytes, str]]) -> None:
    """members: (name, data, kind) where kind is file|symlink."""

    with tarfile.open(path, "w:gz") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode("utf-8")
                info.size = 0
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def make_zip(path: Path, members: list[tuple[str, bytes, bool]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data, symlink in members:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (0o120777 if symlink else 0o100644) << 16
            archive.writestr(info, data)


class BoundedReadTests(unittest.TestCase):
    def test_read_json_strict_rejects_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(b"{" + b" " * 32 + b"}")
            with self.assertRaises(ValueError):
                common.read_json_strict(path, max_bytes=16)

    def test_read_json_strict_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text('{"status":"open","status":"accepted"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                common.read_json_strict(path)


class ArchiveBoundTests(unittest.TestCase):
    def test_rejects_duplicate_member(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "duplicate.tar.gz"
            make_tar(
                archive,
                [
                    ("RELEASE.json", b"{}", "file"),
                    ("RELEASE.json", b"{}", "file"),
                ],
            )
            with self.assertRaises(ValueError):
                common.archive_member_bytes(archive, "RELEASE.json")

    def test_rejects_symlink_tar_member(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "symlink.tar.gz"
            make_tar(archive, [("RELEASE.json", b"/etc/passwd", "symlink")])
            with self.assertRaises(ValueError):
                common.archive_member_bytes(archive, "RELEASE.json")

    def test_rejects_symlink_zip_member(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "symlink.zip"
            make_zip(archive, [("RELEASE.json", b"/etc/passwd", True)])
            with self.assertRaises(ValueError):
                common.archive_member_bytes(archive, "RELEASE.json")

    def test_rejects_too_many_members(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "many.tar.gz"
            make_tar(
                archive,
                [("RELEASE.json", b"{}", "file")]
                + [(f"f{index}", b"", "file") for index in range(8)],
            )
            with self.assertRaises(ValueError):
                common.archive_member_bytes(archive, "RELEASE.json", max_members=4)

    def test_rejects_compressed_archive_over_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "small.tar.gz"
            make_tar(archive, [("RELEASE.json", b"{}", "file")])
            with self.assertRaises(ValueError):
                common.archive_member_bytes(
                    archive, "RELEASE.json", max_archive_bytes=4
                )

    def test_rejects_unsafe_member_name(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "small.tar.gz"
            make_tar(archive, [("RELEASE.json", b"{}", "file")])
            with self.assertRaises(ValueError):
                common.archive_member_bytes(archive, "../RELEASE.json")


class BundlePathTests(unittest.TestCase):
    def test_rejects_traversal_and_absolute_names(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for name in ("../outside", "nested/file", "..", "C:\\outside"):
                with self.assertRaises(ValueError, msg=name):
                    common.safe_bundle_file(bundle, name)

    @unittest.skipIf(os.name == "nt", "symlink creation needs extra Windows privilege")
    def test_rejects_symlink_inside_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            outside = bundle.parent / "outside-secret.txt"
            outside.write_text("secret", encoding="utf-8")
            try:
                link = bundle / "release-index.json"
                os.symlink(outside, link)
                with self.assertRaises(ValueError):
                    common.safe_bundle_file(bundle, "release-index.json")
            finally:
                outside.unlink(missing_ok=True)

    def test_parse_checksums_rejects_traversal_name(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "SHA256SUMS").write_text(
                "a" * 64 + "  ../outside\n", encoding="utf-8"
            )
            with self.assertRaises(verify_bundle.VerificationFailure):
                verify_bundle.parse_checksums(bundle)

    def test_index_sidecar_rejects_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            index = bundle / "release-index.json"
            index.write_text("{}", encoding="utf-8")
            (bundle / "release-index.json.sha256").write_text("", encoding="utf-8")
            with self.assertRaises(verify_bundle.VerificationFailure):
                verify_bundle.read_index_sidecar(bundle, index)


class CapabilityReportTests(unittest.TestCase):
    def test_foundation_report_is_accepted(self):
        observed = functional_smoke.validate_capability_report(
            {
                "status": "foundation_only",
                "phase": "Phase 0",
                "daemon": False,
                "tls_backend": False,
                "networking": False,
                "phase0_complete": False,
            },
            "doctor",
        )
        self.assertEqual(observed["profile"], "foundation")

    def test_false_daemon_cannot_claim_networking(self):
        with self.assertRaises(functional_smoke.CheckFailure):
            functional_smoke.validate_capability_report(
                {
                    "status": "foundation_only",
                    "daemon": False,
                    "tls_backend": False,
                    "networking": True,
                },
                "doctor",
            )

    def test_live_daemon_cannot_keep_foundation_status(self):
        with self.assertRaises(functional_smoke.CheckFailure):
            functional_smoke.validate_capability_report(
                {
                    "status": "foundation_only",
                    "daemon": True,
                    "tls_backend": True,
                    "networking": True,
                },
                "doctor",
            )

    def test_live_daemon_with_runtime_status_is_accepted(self):
        observed = functional_smoke.validate_capability_report(
            {
                "status": "running",
                "daemon": True,
                "tls_backend": True,
                "networking": True,
                "phase0_complete": False,
            },
            "doctor",
        )
        self.assertEqual(observed["profile"], "runtime-claimed")


class PackageManifestTests(unittest.TestCase):
    def test_reads_package_version(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text(
                '[package]\nname = "example"\nversion = "1.2.3-test.4"\n',
                encoding="utf-8",
            )
            self.assertEqual(package.read_manifest_version(manifest), "1.2.3-test.4")

    def test_rejects_missing_version(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text('[package]\nname = "example"\n', encoding="utf-8")
            with self.assertRaises(package.PackagingFailure):
                package.read_manifest_version(manifest)


class ProductionPromotionTests(unittest.TestCase):
    def test_safe_child_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "artifacts"
            base.mkdir()
            for name in ("../outside", "nested/file", "C:\\outside", ".."):
                with self.assertRaises(ValueError, msg=name):
                    production_promotion.safe_child(base, name, "artifact")

    def test_empty_release_manifest_is_refused(self):
        errors: list[str] = []
        production_promotion.validate_release_manifest({}, errors)
        self.assertTrue(errors)

    def test_release_manifest_rejects_unknown_critical_field(self):
        errors: list[str] = []
        production_promotion.validate_release_manifest(
            {"unexpected_critical_field": True}, errors
        )
        self.assertTrue(any("unknown top-level" in error for error in errors))

    def test_self_test_accepts_positive_fixture_and_refuses_negatives(self):
        self.assertEqual(production_promotion.self_test(), 0)


if __name__ == "__main__":
    unittest.main()
