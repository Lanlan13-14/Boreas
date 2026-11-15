#!/usr/bin/env python3
"""Offline verification of a downloaded Boreas development release bundle.

This verifies internal integrity only: the index, ``SHA256SUMS``, archive
hashes/sizes and each embedded ``RELEASE.json``.  It does **not** verify a
production signature or an external audit, and it intentionally fails if the
bundle or its platform candidate claims to be production-eligible.

Every name inside the bundle is untrusted.  Archive and sidecar names are
accepted only as single basenames, resolved inside the bundle directory, and
rejected if they are symlinks.  Archive inspection is bounded (compressed
size, member count, declared uncompressed total and member size) because even
an archive whose SHA-256 matches an index is not trustworthy until its
signatures are verified.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

from common import (
    EXPECTED_TARGETS,
    GATE_PLATFORM_NAMES,
    archive_member_bytes,
    is_safe_basename,
    parse_json_text,
    read_json_strict,
    safe_bundle_file,
    sha256_file,
)

MAX_CHECKSUM_BYTES = 256 * 1024
MAX_CHECKSUM_LINES = 64
MAX_INDEX_ASSETS = 16


class VerificationFailure(Exception):
    pass


def parse_checksums(bundle: Path) -> dict[str, str]:
    path = safe_bundle_file(bundle, "SHA256SUMS")
    with path.open("rb") as handle:
        data = handle.read(MAX_CHECKSUM_BYTES + 1)
    if len(data) > MAX_CHECKSUM_BYTES:
        raise VerificationFailure("SHA256SUMS exceeds its size limit")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationFailure(f"SHA256SUMS is not UTF-8: {error}") from error
    if len(lines) > MAX_CHECKSUM_LINES:
        raise VerificationFailure("SHA256SUMS has too many lines")
    checksums = {}
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise VerificationFailure(f"SHA256SUMS line {line_number} is malformed")
        digest, name = match.groups()
        if not is_safe_basename(name):
            raise VerificationFailure(
                f"SHA256SUMS line {line_number} has an unsafe file name"
            )
        if name in checksums:
            raise VerificationFailure(f"SHA256SUMS repeats {name}")
        checksums[name] = digest
    return checksums


def read_index_sidecar(bundle: Path, index_path: Path) -> str:
    sidecar = safe_bundle_file(bundle, "release-index.json.sha256")
    with sidecar.open("rb") as handle:
        data = handle.read(4096 + 1)
    if len(data) > 4096:
        raise VerificationFailure("release-index.json.sha256 is too large")
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise VerificationFailure(f"index sidecar is not UTF-8: {error}") from error
    match = re.fullmatch(r"([0-9a-f]{64})  release-index\.json", text)
    if not match:
        raise VerificationFailure("release-index.json.sha256 is malformed")
    if match.group(1) != sha256_file(index_path):
        raise VerificationFailure("release-index.json SHA-256 mismatch")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()

    try:
        bundle = args.bundle
        if not bundle.is_dir():
            raise VerificationFailure(f"bundle is not a directory: {bundle}")
        index_path = safe_bundle_file(bundle, "release-index.json")
        index = read_json_strict(index_path)
        if index.get("schema") != "boreas.development.release-index.v1":
            raise VerificationFailure("unsupported release index schema")
        if index.get("channel") != "development":
            raise VerificationFailure("release index is not a development bundle")
        if index.get("production_release") is not False:
            raise VerificationFailure("release index claims production status")
        if index.get("production_eligible") is not False:
            raise VerificationFailure("release index claims production eligibility")
        if index.get("promotion_status") != "blocked":
            raise VerificationFailure("release index does not mark promotion blocked")

        assets = index.get("assets")
        if not isinstance(assets, list):
            raise VerificationFailure("release index assets must be a list")
        if len(assets) > MAX_INDEX_ASSETS:
            raise VerificationFailure("release index has too many assets")
        by_target = {}
        for asset in assets:
            if not isinstance(asset, dict):
                raise VerificationFailure("release index contains a non-object asset")
            archive_name = asset.get("archive")
            if not isinstance(archive_name, str) or not is_safe_basename(archive_name):
                raise VerificationFailure("release index has an unsafe archive name")
            target = asset.get("target")
            if target not in EXPECTED_TARGETS:
                raise VerificationFailure(f"unexpected target in index: {target!r}")
            if target in by_target:
                raise VerificationFailure(f"duplicate target in index: {target}")
            by_target[target] = asset
        missing = [target for target in EXPECTED_TARGETS if target not in by_target]
        if missing:
            raise VerificationFailure("index is missing targets: " + ", ".join(missing))

        checksums = parse_checksums(bundle)
        expected_names = {asset["archive"] for asset in by_target.values()}
        if len(expected_names) != len(EXPECTED_TARGETS):
            raise VerificationFailure("index does not name five distinct archives")
        if set(checksums) != expected_names:
            raise VerificationFailure(
                "SHA256SUMS entries do not exactly match the indexed archives"
            )
        allowed_archive_files = expected_names | {
            f"{name}.sha256" for name in expected_names
        }
        for path in bundle.iterdir():
            if path.name.startswith("boreas-") and path.name not in allowed_archive_files:
                raise VerificationFailure(
                    f"bundle contains an unindexed archive-like file: {path.name}"
                )

        for target in EXPECTED_TARGETS:
            asset = by_target[target]
            archive = safe_bundle_file(bundle, asset["archive"])
            if sha256_file(archive) != asset.get("sha256"):
                raise VerificationFailure(f"{archive.name}: SHA-256 mismatch")
            if archive.stat().st_size != asset.get("size"):
                raise VerificationFailure(f"{archive.name}: size mismatch")
            if checksums[archive.name] != asset.get("sha256"):
                raise VerificationFailure(f"{archive.name}: SHA256SUMS mismatch")
            release = parse_json_text(
                archive_member_bytes(archive, "RELEASE.json").decode("utf-8")
            )
            if not isinstance(release, dict):
                raise VerificationFailure(f"{archive.name}: embedded JSON is not an object")
            if release.get("target") != target:
                raise VerificationFailure(f"{archive.name}: embedded target mismatch")
            if release.get("production_release") is not False:
                raise VerificationFailure(f"{archive.name}: embedded production claim")
            source = release.get("source")
            if not isinstance(source, dict) or source.get("commit") != index.get("source_sha"):
                raise VerificationFailure(f"{archive.name}: embedded commit mismatch")

        read_index_sidecar(bundle, index_path)

        candidate_path = safe_bundle_file(
            bundle, "platform-evidence-candidate.json", must_exist=False
        )
        if candidate_path.is_file():
            candidate = read_json_strict(candidate_path)
            if candidate.get("not_production_evidence") is not True:
                raise VerificationFailure("platform candidate is not marked non-production")
            if candidate.get("production_eligible") is not False:
                raise VerificationFailure("platform candidate claims production eligibility")
            platforms = candidate.get("platforms")
            if not isinstance(platforms, dict):
                raise VerificationFailure("platform candidate has no platform map")
            allowed_platform_names = set(GATE_PLATFORM_NAMES.values())
            if set(platforms) - allowed_platform_names:
                raise VerificationFailure("platform candidate has unknown platform names")
            for name, record in platforms.items():
                if not isinstance(record, dict):
                    raise VerificationFailure(f"{name}: platform record is not an object")
                if record.get("real_packet_io") is not False:
                    raise VerificationFailure(
                        f"{name}: CLI-only bundle must not claim real packet I/O"
                    )
                if record.get("functional_test") != "not_run":
                    raise VerificationFailure(
                        f"{name}: CLI-only bundle must not claim a VPN functional test"
                    )

        print(
            json.dumps(
                {
                    "result": "passed",
                    "channel": "development",
                    "production_release": False,
                    "version": index.get("version"),
                    "source_sha": index.get("source_sha"),
                    "targets": list(EXPECTED_TARGETS),
                    "signature_verification": "not_performed_development_bundle",
                },
                indent=2,
            )
        )
        return 0
    except (
        VerificationFailure,
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"VERIFY FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
