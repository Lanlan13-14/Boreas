#!/usr/bin/env python3
"""Package one Boreas development binary into a deterministic archive.

The archive contains only the executable, ``LICENSE``, ``SOURCE.txt`` and a
machine-readable ``RELEASE.json``.  It never contains production signatures,
a production ReleaseRoot key or a claim that the binary is a production VPN.
The sidecar ``provenance-<target>.json`` records the CI run that produced it.

Archive metadata is fixed (uid/gid 0, empty owner names, 1980-01-01 mtime,
sorted members), so repeated packaging of identical staged bytes produces an
identical tar.gz/zip archive.  The executable itself is whatever the native CI
build produced; this script does not rebuild or modify it.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from common import (
    EXPECTED_TARGETS,
    TARGET_ARCH,
    TARGET_PLATFORM,
    archive_name_for,
    atomic_write_bytes,
    read_json_strict,
    sha256_file,
    utc_now_iso,
)

FIXED_MTIME = 315532800  # 1980-01-01T00:00:00Z, the ZIP epoch.
REPO_ROOT = Path(__file__).resolve().parents[2]


class PackagingFailure(Exception):
    pass


def read_manifest_version(manifest: Path) -> str:
    if not manifest.is_file():
        raise PackagingFailure(f"manifest does not exist: {manifest}")
    in_package = False
    version = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_package = stripped == "[package]"
            continue
        if in_package:
            match = re.match(r'version\s*=\s*"([^"]+)"\s*$', stripped)
            if match:
                version = match.group(1)
                break
    if version is None:
        raise PackagingFailure(f"no [package] version found in {manifest}")
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", version):
        raise PackagingFailure(f"unsafe package version: {version!r}")
    return version


def write_tar_gz(stage: Path, entries: list[tuple[str, int]], destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
                ) as archive:
                    for name, mode in sorted(entries):
                        path = stage / name
                        info = tarfile.TarInfo(name)
                        info.size = path.stat().st_size
                        info.mtime = FIXED_MTIME
                        info.mode = mode
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_zip(stage: Path, entries: list[tuple[str, int]], destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for name, mode in sorted(entries):
                path = stage / name
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, path.read_bytes())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_release_document(
    arguments: argparse.Namespace,
    version: str,
    smoke: dict,
    static: dict | None,
) -> dict:
    if not isinstance(smoke, dict):
        raise PackagingFailure("functional smoke report must be a JSON object")
    if smoke.get("result") != "passed":
        raise PackagingFailure("functional smoke report did not pass")
    if smoke.get("production_release") is not False:
        raise PackagingFailure("functional smoke report is not marked development-only")
    if smoke.get("target") != arguments.target:
        raise PackagingFailure("functional smoke target does not match the package target")

    static_linkage = {"required": False, "verified": None}
    if arguments.target.endswith("-unknown-linux-musl"):
        if not isinstance(static, dict):
            raise PackagingFailure("Linux packages require a static-linkage report")
        if static.get("fully_static") is not True:
            raise PackagingFailure("static-linkage report did not verify a static binary")
        if static.get("target") != arguments.target:
            raise PackagingFailure("static-linkage target does not match package target")
        static_linkage = {
            "required": True,
            "verified": True,
            "elf_type": static.get("elf_type"),
            "machine": static.get("machine"),
            "file_description": static.get("file_description"),
            "sha256": static.get("sha256"),
        }

    return {
        "schema": "boreas.development.release.v1",
        "product": "Boreas",
        "channel": "development",
        "production_release": False,
        "version": version,
        "target": arguments.target,
        "architecture": TARGET_ARCH[arguments.target],
        "platform": TARGET_PLATFORM[arguments.target],
        "source": {
            "repository": f"https://github.com/{arguments.repository}",
            "commit": arguments.source_sha,
            "cargo_lock_sha256": sha256_file(arguments.cargo_lock),
        },
        "build": {
            "profile": "release",
            "rustc": arguments.rustc,
            "runner_os": arguments.runner_os,
        },
        "functional_test": {
            "kind": "cli-capability-consistency-smoke",
            "vpn_data_plane": False,
            "result": "passed",
            "report_sha256": sha256_file(arguments.smoke_report),
        },
        "static_linkage": static_linkage,
        "signing": {
            "production_signatures": False,
            "release_root": None,
        },
        "production_gate": {
            "status": "blocked",
            "reason": (
                "Development artifact only. Production promotion requires the "
                "gate ledger, offline Ed25519+ML-DSA ReleaseRoot signatures and "
                "an independent verifier; CI never generates the ReleaseRoot key."
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=EXPECTED_TARGETS)
    parser.add_argument("--manifest", type=Path, default=REPO_ROOT / "crates/boreas-cli/Cargo.toml")
    parser.add_argument("--license", type=Path, default=REPO_ROOT / "LICENSE")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--smoke-report", required=True, type=Path)
    parser.add_argument("--static-report", type=Path)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
            raise PackagingFailure("--source-sha must be a full lowercase 40-hex commit")
        if not args.binary.is_file():
            raise PackagingFailure(f"binary does not exist: {args.binary}")
        if not args.license.is_file():
            raise PackagingFailure(f"license does not exist: {args.license}")
        if not args.cargo_lock.is_file():
            raise PackagingFailure(f"Cargo.lock does not exist: {args.cargo_lock}")
        version = read_manifest_version(args.manifest)
        smoke = read_json_strict(args.smoke_report)
        static = read_json_strict(args.static_report) if args.static_report else None
        release_document = build_release_document(args, version, smoke, static)

        args.out_dir.mkdir(parents=True, exist_ok=True)
        archive_name = archive_name_for(version, args.target)
        archive_path = args.out_dir / archive_name

        source_text = (
            "Boreas corresponding source\n"
            f"Repository: https://github.com/{args.repository}\n"
            f"Commit: {args.source_sha}\n"
            "License: GPL-3.0-only (see LICENSE)\n"
            "This is an unsigned development artifact, not a production release.\n"
        )
        release_bytes = (json.dumps(release_document, indent=2) + "\n").encode("utf-8")
        with tempfile.TemporaryDirectory(
            prefix="boreas-package-", dir=args.out_dir
        ) as temporary_directory:
            stage = Path(temporary_directory)
            binary_name = args.binary.name
            shutil.copyfile(args.binary, stage / binary_name)
            os.chmod(stage / binary_name, 0o755)
            shutil.copyfile(args.license, stage / "LICENSE")
            os.chmod(stage / "LICENSE", 0o644)
            (stage / "SOURCE.txt").write_text(source_text, encoding="utf-8")
            os.chmod(stage / "SOURCE.txt", 0o644)
            atomic_write_bytes(stage / "RELEASE.json", release_bytes)
            os.chmod(stage / "RELEASE.json", 0o644)
            entries = [
                (binary_name, 0o755),
                ("LICENSE", 0o644),
                ("SOURCE.txt", 0o644),
                ("RELEASE.json", 0o644),
            ]
            if archive_name.endswith(".zip"):
                write_zip(stage, entries, archive_path)
            else:
                write_tar_gz(stage, entries, archive_path)

        archive_sha256 = sha256_file(archive_path)
        release_json_sha256 = hashlib.sha256(release_bytes).hexdigest()
        provenance = {
            "schema": "boreas.development.package.v1",
            "channel": "development",
            "production_release": False,
            "version": version,
            "target": args.target,
            "architecture": TARGET_ARCH[args.target],
            "archive": archive_name,
            "sha256": archive_sha256,
            "size": archive_path.stat().st_size,
            "release_json_sha256": release_json_sha256,
            "source_sha": args.source_sha,
            "cargo_lock_sha256": sha256_file(args.cargo_lock),
            "workflow": {
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
                "run_url": args.run_url,
                "runner": args.runner,
                "runner_os": args.runner_os,
            },
            "rustc": args.rustc,
            "functional_smoke_sha256": sha256_file(args.smoke_report),
            "static_linkage_verified": bool(
                release_document["static_linkage"]["verified"]
            ),
            "packaged_at": utc_now_iso(),
        }
        provenance_bytes = (json.dumps(provenance, indent=2) + "\n").encode("utf-8")
        atomic_write_bytes(
            args.out_dir / f"provenance-{args.target}.json", provenance_bytes
        )
        atomic_write_bytes(
            args.out_dir / f"{archive_name}.sha256",
            f"{archive_sha256}  {archive_name}\n".encode("utf-8"),
        )
        print(json.dumps(provenance, indent=2))
        return 0
    except (PackagingFailure, OSError, ValueError, KeyError) as error:
        print(f"PACKAGING FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
