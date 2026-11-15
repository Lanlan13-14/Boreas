#!/usr/bin/env python3
"""Assemble and verify the five-target Boreas development release bundle.

Input is the per-target artifact tree produced by ``platforms.yml``.  Every
target must have exactly one provenance record whose archive hash and size are
recomputed, and whose embedded ``RELEASE.json`` must agree with the record.
The output is deliberately named and marked as a development bundle: it is
unsigned, contains no production ReleaseRoot material, and is not eligible for
production promotion by itself.

The generated ``platform-evidence-candidate.json`` is a *candidate*, not
acceptance evidence.  It records ``functional_test: "not_run"`` and
``real_packet_io: false`` because the packaged CLI has no VPN data plane; that
prevents it from being pasted into the production gate ledger as a passing
platform record.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

from common import (
    EXPECTED_TARGETS,
    GATE_PLATFORM_NAMES,
    TARGET_ARCH,
    archive_member_bytes,
    atomic_write_bytes,
    is_safe_basename,
    parse_json_text,
    read_json_strict,
    sha256_file,
    utc_now_iso,
)


class BundleFailure(Exception):
    pass


def load_packages(dist: Path, source_sha: str) -> dict[str, dict]:
    provenance_paths = sorted(dist.rglob("provenance-*.json"))
    if not provenance_paths:
        raise BundleFailure(f"no provenance-*.json records found under {dist}")

    packages: dict[str, dict] = {}
    for provenance_path in provenance_paths:
        if provenance_path.is_symlink():
            raise BundleFailure(f"symlinked provenance record is not allowed: {provenance_path}")
        record = read_json_strict(provenance_path)
        if not isinstance(record, dict):
            raise BundleFailure(f"{provenance_path}: provenance must be a JSON object")
        if record.get("schema") != "boreas.development.package.v1":
            raise BundleFailure(f"{provenance_path}: unsupported package schema")
        if record.get("channel") != "development":
            raise BundleFailure(f"{provenance_path}: not a development package")
        if record.get("production_release") is not False:
            raise BundleFailure(f"{provenance_path}: production_release must be false")
        if record.get("source_sha") != source_sha:
            raise BundleFailure(
                f"{provenance_path}: source_sha does not match the bundle commit"
            )
        target = record.get("target")
        if target not in EXPECTED_TARGETS:
            raise BundleFailure(f"{provenance_path}: unexpected target {target!r}")
        if target in packages:
            raise BundleFailure(f"duplicate package for target {target}")
        if record.get("architecture") != TARGET_ARCH[target]:
            raise BundleFailure(f"{provenance_path}: architecture does not match target")
        if not isinstance(record.get("version"), str):
            raise BundleFailure(f"{provenance_path}: version is missing")
        archive_name = record.get("archive")
        if not isinstance(archive_name, str) or not is_safe_basename(archive_name):
            raise BundleFailure(f"{provenance_path}: unsafe archive name")
        archive = provenance_path.parent / archive_name
        if archive.is_symlink():
            raise BundleFailure(f"{archive}: symlinked archive is not allowed")
        if archive.resolve().parent != provenance_path.parent.resolve():
            raise BundleFailure(f"{archive}: archive escapes its artifact directory")
        if not archive.is_file():
            raise BundleFailure(f"{provenance_path}: archive is missing: {archive}")
        actual_sha = sha256_file(archive)
        if actual_sha != record.get("sha256"):
            raise BundleFailure(f"{archive}: SHA-256 does not match provenance")
        if archive.stat().st_size != record.get("size"):
            raise BundleFailure(f"{archive}: size does not match provenance")

        release_bytes = archive_member_bytes(archive, "RELEASE.json")
        try:
            release = parse_json_text(release_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise BundleFailure(f"{archive}: embedded RELEASE.json is invalid: {error}") from error
        if not isinstance(release, dict):
            raise BundleFailure(f"{archive}: embedded RELEASE.json is not an object")
        for field, expected in (
            ("schema", "boreas.development.release.v1"),
            ("channel", "development"),
            ("production_release", False),
            ("target", target),
            ("version", record.get("version")),
        ):
            if release.get(field) != expected:
                raise BundleFailure(
                    f"{archive}: embedded {field!r} is {release.get(field)!r}, "
                    f"expected {expected!r}"
                )
        source = release.get("source")
        if not isinstance(source, dict) or source.get("commit") != source_sha:
            raise BundleFailure(f"{archive}: embedded source commit mismatch")

        packages[target] = {
            "target": target,
            "architecture": TARGET_ARCH[target],
            "archive": archive,
            "provenance": provenance_path,
            "record": record,
            "release": release,
        }

    missing = [target for target in EXPECTED_TARGETS if target not in packages]
    if missing:
        raise BundleFailure("missing required target(s): " + ", ".join(missing))
    unexpected = sorted(set(packages) - set(EXPECTED_TARGETS))
    if unexpected:
        raise BundleFailure("unexpected target(s): " + ", ".join(unexpected))
    versions = {package["record"]["version"] for package in packages.values()}
    if len(versions) != 1:
        raise BundleFailure("all five packages must have the same version")
    return packages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()

    try:
        packages = load_packages(args.dist, args.source_sha)
        args.out.mkdir(parents=True, exist_ok=True)
        assets = []
        platform_records = {}
        checksum_lines = []

        for target in EXPECTED_TARGETS:
            package = packages[target]
            record = package["record"]
            release = package["release"]
            archive = package["archive"]
            shutil.copyfile(archive, args.out / archive.name)
            shutil.copyfile(
                package["provenance"], args.out / package["provenance"].name
            )
            sidecar = archive.with_name(f"{archive.name}.sha256")
            if sidecar.is_symlink():
                raise BundleFailure(f"{sidecar}: symlinked sidecar is not allowed")
            if sidecar.is_file():
                shutil.copyfile(sidecar, args.out / sidecar.name)
            checksum_lines.append(f"{record['sha256']}  {archive.name}\n")
            assets.append(
                {
                    "target": target,
                    "architecture": record["architecture"],
                    "archive": archive.name,
                    "sha256": record["sha256"],
                    "size": record["size"],
                    "version": record["version"],
                    "source_sha": record["source_sha"],
                    "functional_smoke_sha256": record.get("functional_smoke_sha256"),
                    "static_linkage_verified": record.get("static_linkage_verified"),
                    "production_release": False,
                }
            )
            platform_records[GATE_PLATFORM_NAMES[target]] = {
                "commit": args.source_sha,
                "actions_run": args.run_url,
                "cli_functional_smoke": "pass",
                "functional_test": "not_run",
                "native_execution": True,
                "native_execution_scope": "cli_process_only",
                "real_packet_io": False,
                "static_linkage": (
                    True
                    if target.endswith("-unknown-linux-musl")
                    and record.get("static_linkage_verified") is True
                    else None
                ),
                "qualifies_as_production_platform_evidence": False,
            }

        version = packages[EXPECTED_TARGETS[0]]["record"]["version"]
        index = {
            "schema": "boreas.development.release-index.v1",
            "product": "Boreas",
            "channel": "development",
            "production_release": False,
            "production_eligible": False,
            "promotion_status": "blocked",
            "version": version,
            "source_sha": args.source_sha,
            "repository": f"https://github.com/{args.repository}",
            "generated_at": utc_now_iso(),
            "workflow_run": {"id": args.run_id, "url": args.run_url},
            "assets": assets,
            "checks": {
                "all_five_targets_present": True,
                "archive_hashes_recomputed": True,
                "embedded_release_json_verified": True,
                "production_signatures_present": False,
            },
            "production_blockers_reference": (
                "docs/engineering/platform-release-gates.md and "
                "docs/engineering/gates.json"
            ),
            "notes": [
                "Unsigned development bundle. It is not a production release.",
                "CLI functional smoke is not a VPN/TLS/TUN/data-plane test.",
                "Production promotion requires the gate ledger, offline "
                "Ed25519+ML-DSA ReleaseRoot signatures and an independent verifier.",
            ],
        }
        index_bytes = (json.dumps(index, indent=2) + "\n").encode("utf-8")
        atomic_write_bytes(args.out / "release-index.json", index_bytes)
        atomic_write_bytes(
            args.out / "release-index.json.sha256",
            f"{sha256_file(args.out / 'release-index.json')}  release-index.json\n".encode(
                "utf-8"
            ),
        )
        atomic_write_bytes(
            args.out / "SHA256SUMS", "".join(checksum_lines).encode("utf-8")
        )

        candidate = {
            "schema": "boreas.platform-evidence-candidate.v1",
            "commit": args.source_sha,
            "actions_run": args.run_url,
            "production_eligible": False,
            "not_production_evidence": True,
            "note": (
                "This is a CLI-foundation candidate only. functional_test is "
                "'not_run' and real_packet_io is false, so tools/gates/verify.py "
                "must reject it as production platform evidence."
            ),
            "platforms": platform_records,
        }
        atomic_write_bytes(
            args.out / "platform-evidence-candidate.json",
            (json.dumps(candidate, indent=2) + "\n").encode("utf-8"),
        )

        readme = (
            "BOREAS DEVELOPMENT ARTIFACTS - NOT A PRODUCTION RELEASE\n"
            "=======================================================\n\n"
            f"Source commit: {args.source_sha}\n"
            f"Version: {version}\n"
            f"Workflow run: {args.run_url}\n\n"
            "This bundle contains unsigned development packages for exactly five\n"
            "targets: Linux x86_64 static, Linux aarch64 static, Windows x86_64,\n"
            "macOS Intel x86_64 and macOS Apple Silicon aarch64.\n\n"
            "What a green build proves:\n"
            "  - the CLI compiled and its workspace tests passed on native runners;\n"
            "  - the Linux executables have no ELF interpreter and no DT_NEEDED;\n"
            "  - the packaged CLI executed and reported its foundation-only state;\n"
            "  - archive hashes match the index.\n\n"
            "What it does NOT prove:\n"
            "  - a VPN daemon, TLS backend, WSS transport, TUN/Wintun/utun data\n"
            "    plane, routing, DNS, failover, upgrade or security acceptance;\n"
            "  - that any master-plan gate (G-CRYPTO, G-DATA, G-TUN, ...) passed;\n"
            "  - production authenticity: there are no production signatures.\n\n"
            "Production promotion is BLOCKED. It requires the exact-commit gate\n"
            "ledger to pass tools/gates/verify.py, an independent audit, and an\n"
            "offline Ed25519+ML-DSA ReleaseRoot signature bundle verified by an\n"
            "independent verifier. CI never generates the ReleaseRoot private key\n"
            "and never publishes a release from this workflow.\n\n"
            "Verify this bundle with:\n"
            "  python tools/release/verify_bundle.py --bundle <this directory>\n\n"
            "See docs/engineering/platform-release-gates.md for the full gate and\n"
            "unmet-condition record.\n"
        )
        atomic_write_bytes(args.out / "README-DEVELOPMENT.txt", readme.encode("utf-8"))

        print(
            json.dumps(
                {
                    "result": "passed",
                    "channel": "development",
                    "production_release": False,
                    "version": version,
                    "source_sha": args.source_sha,
                    "assets": len(assets),
                    "out": str(args.out),
                },
                indent=2,
            )
        )
        return 0
    except (
        BundleFailure,
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"BUNDLE FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
