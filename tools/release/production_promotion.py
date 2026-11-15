#!/usr/bin/env python3
"""Fail-closed production promotion verification.

There are **two** manifests, and both are dual-signed over their own exact raw
bytes with detached Ed25519 + ML-DSA-65 envelopes:

1. ``release-manifest.json`` — the actual release manifest.  Its schema is the
   strict schema parsed by ``boreas-supervisor``: ``product`` is ``"boreas"``,
   ``published_at <= issued_at < expires``, ``min_compatible_state``,
   ``signing_key_id`` and assets with ``name``/``arch``/``size``/``sha256``/
   ``url``.  The supervisor is the independent consumer of these exact bytes.
2. ``promotion-manifest.json`` — the outer promotion binding.  It records the
   exact commit, the hash of the release manifest, the gate-ledger hash, the
   pinned ReleaseRoot hash and the five artifact hashes.  It never repeats a
   hash of itself.

Neither manifest contains a hash of itself.  ``signature-envelope.json`` files
live outside the signed bytes and carry the detached signatures; they are allowed
to record the SHA-256 of the file they sign.  This avoids the impossible
self-referential fixed point of putting ``signed_sha256`` inside the manifest.

The tool does not generate a ReleaseRoot private key, does not sign and does not
publish.  It requires:

* the exact-commit gate ledger to pass ``tools/gates/verify.py``;
* both detached dual signatures over both manifests;
* the pinned ReleaseRoot hash;
* all five artifacts with matching sizes and hashes;
* an independently supplied verifier report covering both manifests and all
  artifacts.

Any missing, malformed or unverified input refuses promotion with exit code 2.
``--self-test`` builds a complete synthetic *test-key-only* positive fixture and
negative cases; it is not production evidence.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from common import (
    EXPECTED_TARGETS,
    GATE_PLATFORM_NAMES,
    MAX_JSON_BYTES,
    archive_suffix_for_target,
    is_safe_basename,
    read_json_strict,
    sha256_file,
    utc_now_iso,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_MAX_BYTES = MAX_JSON_BYTES
MANIFEST_VERSION = 1
MAX_ASSETS = 5
MAX_ROOT_KEYS = 8
MAX_MANIFEST_LIFETIME = dt.timedelta(days=90)  # supervisor policy ceiling
MAX_FUTURE_SKEW = dt.timedelta(minutes=10)
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
ALGORITHMS = ("ed25519", "mldsa65")
ED25519_SIGNATURE_BYTES = 64
ML_DSA_65_SIGNATURE_BYTES = 3309
MAX_ED25519_SPKI_BYTES = 64
MAX_ML_DSA_65_SPKI_BYTES = 4096
MAX_URL_BYTES = 2048
MAX_IDENTIFIER_BYTES = 128
MAX_ASSET_NAME_BYTES = 128
MAX_ARCH_BYTES = 64

RELEASE_MANIFEST_NAME = "release-manifest.json"
RELEASE_ENVELOPE_NAME = "release-signature-envelope.json"
PROMOTION_MANIFEST_NAME = "promotion-manifest.json"
PROMOTION_ENVELOPE_NAME = "promotion-signature-envelope.json"
ROOTS_NAME = "roots.json"
ARTIFACTS_DIR = "artifacts"

ALLOWED_RELEASE_KEYS = {
    "product",
    "manifest_version",
    "sequence",
    "published_at",
    "issued_at",
    "expires",
    "min_compatible_state",
    "signing_key_id",
    "assets",
}
ALLOWED_RELEASE_ASSET_KEYS = {"name", "arch", "size", "sha256", "url"}
ALLOWED_ENVELOPE_KEYS = {
    "schema",
    "key_id",
    "manifest_sha256",
    "ed25519",
    "ml_dsa_65",
}
ALLOWED_ROOTS_KEYS = {"schema", "roots"}
ALLOWED_ROOT_KEYS = {"key_id", "ed25519_spki_der", "ml_dsa_65_spki_der"}
ALLOWED_PROMOTION_KEYS = {
    "schema",
    "product",
    "manifest_version",
    "sequence",
    "created_at",
    "expires",
    "commit",
    "release_manifest_sha256",
    "release_manifest_name",
    "gate_ledger_sha256",
    "release_root_sha256",
    "signing_key_id",
    "artifacts",
}
ALLOWED_PROMOTION_ARTIFACT_KEYS = {"name", "target", "size", "sha256"}
ALLOWED_VERIFICATION_KEYS = {
    "schema",
    "result",
    "release_root_sha256",
    "release_manifest_sha256",
    "promotion_manifest_sha256",
    "signatures",
    "artifacts",
    "verifier",
    "verified_at",
}
ALLOWED_VERIFICATION_SIGNATURE_KEYS = {
    "manifest",
    "algorithm",
    "key_id",
    "valid",
}
ALLOWED_VERIFICATION_ARTIFACT_KEYS = {"name", "size", "sha256"}

TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9._+-]+")
ASSET_NAME_RE = re.compile(r"[A-Za-z0-9._+-]+")
ARCH_RE = re.compile(r"[A-Za-z0-9_-]+")
URL_PATH_RE = re.compile(r"[A-Za-z0-9/._~-]+")

ARCH_TO_TARGET = {value: key for key, value in GATE_PLATFORM_NAMES.items()}
PLATFORM_TOKENS = set(GATE_PLATFORM_NAMES.values())


def parse_timestamp(value: str, field: str, errors: list[str]):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        errors.append(
            f"{field} must be RFC3339 with an explicit UTC offset or Z"
        )
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        errors.append(f"{field} is not a valid calendar timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{field} must include an explicit UTC offset")
        return None
    return parsed.astimezone(dt.timezone.utc)


def validate_identifier(value, field: str, max_bytes: int, errors: list[str]) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_bytes
        or value.startswith(".")
        or not IDENTIFIER_RE.fullmatch(value)
    ):
        errors.append(
            f"{field} must be a bounded identifier (alphanumeric . _ + -, no leading dot)"
        )
        return False
    return True


def validate_asset_name(value, errors: list[str]) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ASSET_NAME_BYTES
        or value in (".", "..")
        or value.startswith(".")
        or ".." in value
        or not ASSET_NAME_RE.fullmatch(value)
    ):
        errors.append("asset name must be a safe filename without traversal")
        return False
    return True


def validate_arch(value, errors: list[str]) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ARCH_BYTES
        or not ARCH_RE.fullmatch(value)
    ):
        errors.append("asset arch must be a bounded ASCII architecture token")
        return False
    return True


def validate_https_url(value, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_BYTES:
        errors.append(f"{label}: url must be a bounded https URL")
        return False
    if not all(33 <= ord(character) <= 126 for character in value):
        errors.append(f"{label}: url must be printable ASCII without controls")
        return False
    if "\\" in value or "%" in value:
        errors.append(f"{label}: url must not contain backslashes or percent-encoding")
        return False
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        errors.append(f"{label}: url authority is malformed")
        return False
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        errors.append(f"{label}: url must be https with no userinfo/query/fragment")
        return False
    host = parts.hostname
    if not host or len(host) > 253:
        errors.append(f"{label}: url host is missing or too long")
        return False
    for host_label in host.split("."):
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", host_label):
            errors.append(f"{label}: url host label is invalid")
            return False
    if port is not None and not 1 <= port <= 65535:
        errors.append(f"{label}: url port is out of range")
        return False
    if parts.path:
        if not parts.path.startswith("/") or any(
            segment in (".", "..") for segment in parts.path.split("/")
        ):
            errors.append(f"{label}: url path contains a dot segment")
            return False
        if not URL_PATH_RE.fullmatch(parts.path):
            errors.append(f"{label}: url path contains unsupported characters")
            return False
    return True


def safe_child(base: Path, name: str, label: str) -> Path:
    if not isinstance(name, str) or not is_safe_basename(name):
        raise ValueError(f"{label} has an unsafe file name")
    candidate = base / name
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve()
    if resolved.parent != base.resolve():
        raise ValueError(f"{label} escapes its directory")
    if not resolved.is_file():
        raise ValueError(f"{label} is missing or not a regular file")
    return resolved


def read_document(path: Path, label: str, errors: list[str]):
    if path.is_symlink():
        errors.append(f"{label} must not be a symlink")
        return None
    if not path.is_file():
        errors.append(f"{label} is missing")
        return None
    try:
        document = read_json_strict(path, max_bytes=MANIFEST_MAX_BYTES)
    except (OSError, ValueError) as error:
        errors.append(f"{label} is invalid: {error}")
        return None
    if not isinstance(document, dict):
        errors.append(f"{label} must contain one JSON object")
        return None
    return document


def validate_release_manifest(manifest: dict, errors: list[str]):
    if set(manifest) - ALLOWED_RELEASE_KEYS:
        errors.append("release manifest has unknown top-level keys")
    if manifest.get("product") != "boreas":
        errors.append("release manifest product must be 'boreas'")
    version = manifest.get("manifest_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        errors.append("release manifest manifest_version must be 1")
    sequence = manifest.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        errors.append("release manifest sequence must be a positive integer")

    published = parse_timestamp(manifest.get("published_at"), "published_at", errors)
    issued = parse_timestamp(manifest.get("issued_at"), "issued_at", errors)
    expires = parse_timestamp(manifest.get("expires"), "expires", errors)
    now = dt.datetime.now(dt.timezone.utc)
    if published and issued and published > issued:
        errors.append("release manifest requires published_at <= issued_at")
    if issued and expires and issued >= expires:
        errors.append("release manifest requires issued_at < expires")
    if issued and issued > now + MAX_FUTURE_SKEW:
        errors.append("release manifest issued_at is too far in the future")
    if expires and expires <= now:
        errors.append("release manifest has expired")
    if issued and expires and expires - issued > MAX_MANIFEST_LIFETIME:
        errors.append("release manifest lifetime exceeds 90 days")

    validate_identifier(
        manifest.get("min_compatible_state"),
        "release manifest min_compatible_state",
        MAX_IDENTIFIER_BYTES,
        errors,
    )
    signing_key_id = manifest.get("signing_key_id")
    if not validate_identifier(
        signing_key_id,
        "release manifest signing_key_id",
        MAX_IDENTIFIER_BYTES,
        errors,
    ):
        signing_key_id = None

    assets = manifest.get("assets")
    if not isinstance(assets, list) or len(assets) != MAX_ASSETS:
        errors.append("release manifest must contain exactly five assets")
        return signing_key_id
    seen_names = set()
    seen_arches = set()
    for index, asset in enumerate(assets):
        label = f"release asset[{index}]"
        if not isinstance(asset, dict):
            errors.append(f"{label} must be an object")
            continue
        if set(asset) - ALLOWED_RELEASE_ASSET_KEYS:
            errors.append(f"{label} has unknown keys")
        name = asset.get("name")
        arch = asset.get("arch")
        if not validate_asset_name(name, errors):
            continue
        if name in seen_names:
            errors.append(f"{label} duplicates asset name {name}")
        seen_names.add(name)
        if not validate_arch(arch, errors):
            continue
        if arch not in PLATFORM_TOKENS:
            errors.append(f"{label} arch is not one of the five release platforms")
            continue
        if arch in seen_arches:
            errors.append(f"{label} duplicates arch {arch}")
        seen_arches.add(arch)
        target = ARCH_TO_TARGET[arch]
        if not name.endswith(archive_suffix_for_target(target)):
            errors.append(f"{label} archive suffix does not match {arch}")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            errors.append(f"{label} size must be a positive integer")
        elif size > MAX_ARTIFACT_BYTES:
            errors.append(f"{label} size exceeds the 2 GiB bound")
        if not isinstance(asset.get("sha256"), str) or not SHA256_RE.fullmatch(
            asset.get("sha256", "")
        ):
            errors.append(f"{label} sha256 must be 64 lowercase hex digits")
        validate_https_url(asset.get("url"), label, errors)
    if seen_arches != PLATFORM_TOKENS:
        errors.append("release manifest must cover exactly the five platform arches")
    return signing_key_id


def validate_envelope(
    envelope: dict,
    label: str,
    manifest_sha256: str,
    expected_key_id: str | None,
    errors: list[str],
) -> None:
    if set(envelope) - ALLOWED_ENVELOPE_KEYS:
        errors.append(f"{label} has unknown keys")
    if envelope.get("schema") != "boreas.release.signature-envelope.v1":
        errors.append(f"{label} has an unsupported schema")
    key_id = envelope.get("key_id")
    if not validate_identifier(key_id, f"{label} key_id", MAX_IDENTIFIER_BYTES, errors):
        key_id = None
    if expected_key_id is not None and key_id != expected_key_id:
        errors.append(f"{label} key_id does not match the signed manifest")
    if envelope.get("manifest_sha256") != manifest_sha256:
        errors.append(f"{label} manifest_sha256 does not match the signed bytes")
    for field, length in (
        ("ed25519", ED25519_SIGNATURE_BYTES),
        ("ml_dsa_65", ML_DSA_65_SIGNATURE_BYTES),
    ):
        encoded = envelope.get(field)
        if not isinstance(encoded, str):
            errors.append(f"{label} {field} must be base64 text")
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            errors.append(f"{label} {field} is not valid base64")
            continue
        if len(raw) != length:
            errors.append(f"{label} {field} must decode to exactly {length} bytes")


def validate_roots(
    roots: dict,
    roots_path: Path,
    expected_sha256: str,
    signing_key_id: str | None,
    errors: list[str],
) -> None:
    if set(roots) - ALLOWED_ROOTS_KEYS:
        errors.append("release roots has unknown top-level keys")
    if roots.get("schema") != "boreas.release.roots.v1":
        errors.append("release roots has an unsupported schema")
    entries = roots.get("roots")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ROOT_KEYS:
        errors.append("release roots must contain 1..8 public roots")
        return
    seen = set()
    for index, entry in enumerate(entries):
        label = f"release root[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be an object")
            continue
        if set(entry) - ALLOWED_ROOT_KEYS:
            errors.append(f"{label} has unknown keys")
        key_id = entry.get("key_id")
        if not validate_identifier(key_id, f"{label} key_id", MAX_IDENTIFIER_BYTES, errors):
            continue
        if key_id in seen:
            errors.append(f"{label} duplicates key_id {key_id}")
        seen.add(key_id)
        for field, maximum in (
            ("ed25519_spki_der", MAX_ED25519_SPKI_BYTES),
            ("ml_dsa_65_spki_der", MAX_ML_DSA_65_SPKI_BYTES),
        ):
            encoded = entry.get(field)
            if not isinstance(encoded, str):
                errors.append(f"{label} {field} must be base64 text")
                continue
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                errors.append(f"{label} {field} is not valid base64")
                continue
            if not 1 <= len(raw) <= maximum:
                errors.append(f"{label} {field} has an invalid DER length")
    if signing_key_id is not None and signing_key_id not in seen:
        errors.append("release roots do not contain the manifest signing_key_id")
    for path in roots_path.parent.iterdir():
        if path.is_symlink():
            errors.append(f"release-root contains a symlink: {path.name}")
        elif path.name != ROOTS_NAME:
            errors.append(f"release-root contains an unlisted file: {path.name}")
    try:
        roots_sha256 = sha256_file(roots_path)
    except OSError as error:
        errors.append(f"release-root/roots.json cannot be read: {error}")
        return
    if roots_sha256 != expected_sha256:
        errors.append("release-root/roots.json does not match the pinned SHA-256")


def validate_promotion_manifest(
    promotion: dict,
    release_manifest: dict,
    commit: str,
    release_manifest_sha256: str,
    ledger_sha256: str | None,
    root_sha256: str,
    errors: list[str],
) -> None:
    if set(promotion) - ALLOWED_PROMOTION_KEYS:
        errors.append("promotion manifest has unknown top-level keys")
    if promotion.get("schema") != "boreas.production.promotion-manifest.v1":
        errors.append("promotion manifest has an unsupported schema")
    if promotion.get("product") != "boreas":
        errors.append("promotion manifest product must be 'boreas'")
    version = promotion.get("manifest_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        errors.append("promotion manifest manifest_version must be 1")
    sequence = promotion.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        errors.append("promotion manifest sequence must be a positive integer")

    created = parse_timestamp(promotion.get("created_at"), "promotion created_at", errors)
    expires = parse_timestamp(promotion.get("expires"), "promotion expires", errors)
    now = dt.datetime.now(dt.timezone.utc)
    if created and created > now + MAX_FUTURE_SKEW:
        errors.append("promotion manifest created_at is too far in the future")
    if expires and expires <= now:
        errors.append("promotion manifest has expired")
    if created and expires:
        if expires <= created:
            errors.append("promotion expires must be after created_at")
        elif expires - created > MAX_MANIFEST_LIFETIME:
            errors.append("promotion manifest lifetime exceeds 90 days")

    if promotion.get("commit") != commit:
        errors.append("promotion manifest commit does not match the candidate")
    if promotion.get("release_manifest_sha256") != release_manifest_sha256:
        errors.append("promotion manifest release_manifest_sha256 mismatch")
    if promotion.get("release_manifest_name") != RELEASE_MANIFEST_NAME:
        errors.append("promotion manifest release_manifest_name must be release-manifest.json")
    if ledger_sha256 is None or promotion.get("gate_ledger_sha256") != ledger_sha256:
        errors.append("promotion manifest gate_ledger_sha256 mismatch")
    if promotion.get("release_root_sha256") != root_sha256:
        errors.append("promotion manifest release_root_sha256 mismatch")
    if promotion.get("signing_key_id") != release_manifest.get("signing_key_id"):
        errors.append("promotion manifest signing_key_id does not match the release manifest")

    artifacts = promotion.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != MAX_ASSETS:
        errors.append("promotion manifest must contain exactly five artifacts")
        return
    release_by_target = {}
    for asset in release_manifest.get("assets", []):
        if not isinstance(asset, dict):
            continue
        arch = asset.get("arch")
        if arch in ARCH_TO_TARGET:
            release_by_target[ARCH_TO_TARGET[arch]] = asset
    seen_targets = set()
    for index, artifact in enumerate(artifacts):
        label = f"promotion artifact[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{label} must be an object")
            continue
        if set(artifact) - ALLOWED_PROMOTION_ARTIFACT_KEYS:
            errors.append(f"{label} has unknown keys")
        target = artifact.get("target")
        if target not in EXPECTED_TARGETS:
            errors.append(f"{label} target is not one of the five required targets")
            continue
        if target in seen_targets:
            errors.append(f"{label} duplicates target {target}")
        seen_targets.add(target)
        asset = release_by_target.get(target)
        if asset is None:
            errors.append(f"{label} has no matching release asset")
            continue
        if artifact.get("name") != asset.get("name"):
            errors.append(f"{label} name does not match the release manifest")
        if artifact.get("size") != asset.get("size"):
            errors.append(f"{label} size does not match the release manifest")
        if artifact.get("sha256") != asset.get("sha256"):
            errors.append(f"{label} sha256 does not match the release manifest")
    if seen_targets != set(EXPECTED_TARGETS):
        errors.append("promotion manifest must cover exactly the five targets")


def validate_artifacts(bundle: Path, release_manifest: dict, errors: list[str]) -> None:
    artifacts_dir = bundle / ARTIFACTS_DIR
    if artifacts_dir.is_symlink():
        errors.append("artifacts directory must not be a symlink")
        return
    if not artifacts_dir.is_dir():
        errors.append("artifacts directory is missing")
        return
    expected = {}
    for asset in release_manifest.get("assets", []):
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        if not isinstance(name, str):
            continue
        try:
            path = safe_child(artifacts_dir, name, f"artifact {name!r}")
        except ValueError as error:
            errors.append(str(error))
            continue
        expected[name] = path
        if path.stat().st_size != asset.get("size"):
            errors.append(f"artifact {name}: size does not match manifest")
        if sha256_file(path) != asset.get("sha256"):
            errors.append(f"artifact {name}: SHA-256 does not match manifest")
    for path in artifacts_dir.iterdir():
        if path.is_symlink():
            errors.append(f"artifacts directory contains a symlink: {path.name}")
        elif path.is_file() and path.name not in expected:
            errors.append(f"artifacts directory contains an unlisted file: {path.name}")


def build_gate_command(raw: str, commit: str, ledger: Path) -> list[str]:
    command = raw.replace("{commit}", commit)
    tokens = shlex.split(command)
    if not any(token == "--commit" or token.startswith("--commit=") for token in tokens):
        tokens.extend(["--commit", commit])
    if not any(token == "--ledger" or token.startswith("--ledger=") for token in tokens):
        tokens.extend(["--ledger", str(ledger)])
    return tokens


def run_command(command: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def run_gate_verifier(raw: str, commit: str, ledger: Path, errors: list[str]) -> None:
    if not raw.strip():
        errors.append("gate verifier command is empty")
        return
    try:
        command = build_gate_command(raw, commit, ledger)
    except ValueError as error:
        errors.append(f"gate verifier command is malformed: {error}")
        return
    for token in command:
        if token.endswith(".py"):
            candidate = Path(token)
            if not candidate.is_absolute():
                candidate = REPO_ROOT / candidate
            if not candidate.is_file():
                errors.append(f"gate verifier script is missing: {token}")
                return
    try:
        result = run_command(command)
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"gate verifier could not run: {error}")
        return
    if result.returncode != 0:
        errors.append(
            "gate verifier refused promotion (exit "
            f"{result.returncode}): {result.stderr.strip()[:2000]}"
        )


def run_external_verifier(
    raw: str,
    bundle: Path,
    release_manifest: Path,
    release_envelope: Path,
    promotion_manifest: Path,
    promotion_envelope: Path,
    commit: str,
    root_sha256: str,
    errors: list[str],
) -> dict | None:
    if not raw.strip():
        errors.append("independent signature verifier is required")
        return None
    try:
        command = shlex.split(raw)
    except ValueError as error:
        errors.append(f"independent verifier command is malformed: {error}")
        return None
    if not command:
        errors.append("independent signature verifier command is empty")
        return None
    verification_dir = bundle / "verification"
    if verification_dir.is_symlink():
        errors.append("verification directory must not be a symlink")
        return None
    try:
        verification_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        errors.append(f"verification directory cannot be created: {error}")
        return None
    output_path = verification_dir / "verification.json"
    command.extend(
        [
            "--release-manifest",
            str(release_manifest),
            "--release-signature-envelope",
            str(release_envelope),
            "--promotion-manifest",
            str(promotion_manifest),
            "--promotion-signature-envelope",
            str(promotion_envelope),
            "--release-root",
            str(bundle / "release-root"),
            "--artifacts",
            str(bundle / ARTIFACTS_DIR),
            "--json-out",
            str(output_path),
            "--commit",
            commit,
            "--release-root-sha256",
            root_sha256,
        ]
    )
    try:
        result = run_command(command, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"independent verifier could not run: {error}")
        return None
    if result.returncode != 0:
        errors.append(
            "independent verifier refused the bundle (exit "
            f"{result.returncode}): {result.stderr.strip()[:2000]}"
        )
        return None
    if not output_path.is_file() or output_path.is_symlink():
        errors.append("independent verifier did not write verification/verification.json")
        return None
    try:
        report = read_json_strict(output_path)
    except (OSError, ValueError) as error:
        errors.append(f"independent verification report is invalid: {error}")
        return None
    if not isinstance(report, dict):
        errors.append("independent verification report must be a JSON object")
        return None
    return report


def validate_external_report(
    report: dict,
    release_manifest: dict,
    release_manifest_sha256: str,
    promotion_manifest_sha256: str,
    root_sha256: str,
    errors: list[str],
) -> None:
    if set(report) - ALLOWED_VERIFICATION_KEYS:
        errors.append("independent verification report has unknown keys")
    if report.get("schema") != "boreas.production.external-verification.v1":
        errors.append("independent verification report has an unsupported schema")
    if report.get("result") != "pass":
        errors.append("independent verifier did not report result 'pass'")
    if report.get("release_root_sha256") != root_sha256:
        errors.append("independent verifier ReleaseRoot hash mismatch")
    if report.get("release_manifest_sha256") != release_manifest_sha256:
        errors.append("independent verifier release manifest hash mismatch")
    if report.get("promotion_manifest_sha256") != promotion_manifest_sha256:
        errors.append("independent verifier promotion manifest hash mismatch")

    verifier = report.get("verifier")
    if (
        not isinstance(verifier, dict)
        or not isinstance(verifier.get("name"), str)
        or not verifier["name"].strip()
    ):
        errors.append("independent verifier identity is missing")

    key_id = release_manifest.get("signing_key_id")
    expected_signatures = {
        ("release", "ed25519", key_id),
        ("release", "mldsa65", key_id),
        ("promotion", "ed25519", key_id),
        ("promotion", "mldsa65", key_id),
    }
    seen_signatures = set()
    signatures = report.get("signatures")
    if not isinstance(signatures, list):
        errors.append("independent verifier did not report signature results")
    else:
        for record in signatures:
            if not isinstance(record, dict):
                continue
            if set(record) - ALLOWED_VERIFICATION_SIGNATURE_KEYS:
                errors.append("independent verifier signature record has unknown keys")
                continue
            if record.get("valid") is not True:
                continue
            manifest_name = record.get("manifest")
            if manifest_name == RELEASE_MANIFEST_NAME:
                manifest_name = "release"
            elif manifest_name == PROMOTION_MANIFEST_NAME:
                manifest_name = "promotion"
            identity = (
                manifest_name,
                record.get("algorithm"),
                record.get("key_id"),
            )
            if identity in expected_signatures:
                seen_signatures.add(identity)
    if seen_signatures != expected_signatures:
        errors.append("independent verifier did not validate both manifests' dual signatures")

    expected_artifacts = {
        asset.get("name"): (asset.get("size"), asset.get("sha256"))
        for asset in release_manifest.get("assets", [])
        if isinstance(asset, dict)
    }
    seen_artifacts = set()
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("independent verifier did not report artifact results")
    else:
        for record in artifacts:
            if not isinstance(record, dict):
                continue
            if set(record) - ALLOWED_VERIFICATION_ARTIFACT_KEYS:
                errors.append("independent verifier artifact record has unknown keys")
                continue
            name = record.get("name")
            if expected_artifacts.get(name) == (record.get("size"), record.get("sha256")):
                seen_artifacts.add(name)
    if seen_artifacts != set(expected_artifacts):
        errors.append("independent verifier did not validate all five artifacts")


def evaluate(
    bundle_dir: Path,
    commit: str,
    root_sha256: str,
    ledger_path: Path,
    gate_verifier: str,
    verifier: str,
) -> list[str]:
    errors: list[str] = []
    if not COMMIT_RE.fullmatch(commit):
        return ["commit must be a full lowercase 40-hex SHA-1"]
    if not SHA256_RE.fullmatch(root_sha256):
        return ["expected ReleaseRoot SHA-256 must be 64 lowercase hex characters"]
    bundle = bundle_dir
    if bundle.is_symlink():
        return ["promotion bundle directory must not be a symlink"]
    if not bundle.is_dir():
        return [f"promotion bundle directory is missing: {bundle}"]

    release_manifest_path = bundle / RELEASE_MANIFEST_NAME
    release_envelope_path = bundle / RELEASE_ENVELOPE_NAME
    promotion_manifest_path = bundle / PROMOTION_MANIFEST_NAME
    promotion_envelope_path = bundle / PROMOTION_ENVELOPE_NAME
    roots_path = bundle / "release-root" / ROOTS_NAME

    root_dir = bundle / "release-root"
    if root_dir.is_symlink():
        errors.append("release-root directory must not be a symlink")
    elif not root_dir.is_dir():
        errors.append("release-root directory is missing")

    release_manifest = read_document(release_manifest_path, RELEASE_MANIFEST_NAME, errors)
    release_envelope = read_document(release_envelope_path, RELEASE_ENVELOPE_NAME, errors)
    promotion_manifest = read_document(
        promotion_manifest_path, PROMOTION_MANIFEST_NAME, errors
    )
    promotion_envelope = read_document(
        promotion_envelope_path, PROMOTION_ENVELOPE_NAME, errors
    )
    roots = read_document(roots_path, f"release-root/{ROOTS_NAME}", errors)

    if ledger_path.is_symlink():
        errors.append("gate ledger must not be a symlink")
    if not ledger_path.is_file():
        errors.append(f"gate ledger is missing: {ledger_path}")
    ledger_sha256 = sha256_file(ledger_path) if ledger_path.is_file() else None
    if errors:
        return errors

    release_manifest_sha256 = sha256_file(release_manifest_path)
    promotion_manifest_sha256 = sha256_file(promotion_manifest_path)
    signing_key_id = validate_release_manifest(release_manifest, errors)
    validate_envelope(
        release_envelope,
        "release signature envelope",
        release_manifest_sha256,
        signing_key_id,
        errors,
    )
    validate_promotion_manifest(
        promotion_manifest,
        release_manifest,
        commit,
        release_manifest_sha256,
        ledger_sha256,
        root_sha256,
        errors,
    )
    validate_envelope(
        promotion_envelope,
        "promotion signature envelope",
        promotion_manifest_sha256,
        promotion_manifest.get("signing_key_id"),
        errors,
    )
    validate_roots(roots, roots_path, root_sha256, signing_key_id, errors)
    validate_artifacts(bundle, release_manifest, errors)
    if errors:
        return errors

    run_gate_verifier(gate_verifier, commit, ledger_path, errors)
    if errors:
        return errors

    report = run_external_verifier(
        verifier,
        bundle,
        release_manifest_path,
        release_envelope_path,
        promotion_manifest_path,
        promotion_envelope_path,
        commit,
        root_sha256,
        errors,
    )
    if errors:
        return errors
    if report is None:
        return errors or ["independent verifier produced no report"]
    validate_external_report(
        report,
        release_manifest,
        release_manifest_sha256,
        promotion_manifest_sha256,
        root_sha256,
        errors,
    )
    return errors


def _write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def _build_positive_fixture(root: Path):
    """Build a complete synthetic bundle for the *test-only* positive path.

    The signatures are zero-filled placeholders of the correct lengths and the
    external verifier is a no-op.  This proves the promotion tool accepts a
    structurally complete bundle and rejects tampering; it is not cryptographic
    evidence.  Real dual-signature verification is exercised by the supervisor
    and rust-tls workflows with test-generated keys.
    """

    bundle = root / "positive-bundle"
    (bundle / ARTIFACTS_DIR).mkdir(parents=True)
    (bundle / "release-root").mkdir()
    (bundle / "verification").mkdir()

    commit = "a" * 40
    key_id = "fixture-release-root"
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    published = (now - dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    issued = (now - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    artifacts = []
    for target in EXPECTED_TARGETS:
        name = f"boreas-0.1.0-{target}{archive_suffix_for_target(target)}"
        data = f"fixture-artifact-{target}".encode("utf-8")
        (bundle / ARTIFACTS_DIR / name).write_bytes(data)
        artifacts.append(
            {
                "target": target,
                "name": name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    release_assets = [
        {
            "name": artifact["name"],
            "arch": GATE_PLATFORM_NAMES[artifact["target"]],
            "size": artifact["size"],
            "sha256": artifact["sha256"],
            "url": f"https://example.invalid/boreas/{artifact['name']}",
        }
        for artifact in artifacts
    ]
    release_manifest = {
        "product": "boreas",
        "manifest_version": 1,
        "sequence": 1,
        "published_at": published,
        "issued_at": issued,
        "expires": expires,
        "min_compatible_state": "state-v1",
        "signing_key_id": key_id,
        "assets": release_assets,
    }
    _write_json(bundle / RELEASE_MANIFEST_NAME, release_manifest)
    release_sha = sha256_file(bundle / RELEASE_MANIFEST_NAME)
    _write_json(
        bundle / RELEASE_ENVELOPE_NAME,
        {
            "schema": "boreas.release.signature-envelope.v1",
            "key_id": key_id,
            "manifest_sha256": release_sha,
            "ed25519": base64.b64encode(b"\x00" * ED25519_SIGNATURE_BYTES).decode("ascii"),
            "ml_dsa_65": base64.b64encode(b"\x00" * ML_DSA_65_SIGNATURE_BYTES).decode("ascii"),
        },
    )

    ledger = bundle / "gate-ledger.json"
    ledger.write_text("{}\n", encoding="utf-8")
    ledger_sha = sha256_file(ledger)
    roots = {
        "schema": "boreas.release.roots.v1",
        "roots": [
            {
                "key_id": key_id,
                "ed25519_spki_der": base64.b64encode(b"\x30\x00").decode("ascii"),
                "ml_dsa_65_spki_der": base64.b64encode(b"\x30\x00").decode("ascii"),
            }
        ],
    }
    _write_json(bundle / "release-root" / ROOTS_NAME, roots)
    root_sha = sha256_file(bundle / "release-root" / ROOTS_NAME)

    promotion_manifest = {
        "schema": "boreas.production.promotion-manifest.v1",
        "product": "boreas",
        "manifest_version": 1,
        "sequence": 1,
        "created_at": issued,
        "expires": expires,
        "commit": commit,
        "release_manifest_sha256": release_sha,
        "release_manifest_name": RELEASE_MANIFEST_NAME,
        "gate_ledger_sha256": ledger_sha,
        "release_root_sha256": root_sha,
        "signing_key_id": key_id,
        "artifacts": [
            {
                "name": artifact["name"],
                "target": artifact["target"],
                "size": artifact["size"],
                "sha256": artifact["sha256"],
            }
            for artifact in artifacts
        ],
    }
    _write_json(bundle / PROMOTION_MANIFEST_NAME, promotion_manifest)
    promotion_sha = sha256_file(bundle / PROMOTION_MANIFEST_NAME)
    _write_json(
        bundle / PROMOTION_ENVELOPE_NAME,
        {
            "schema": "boreas.release.signature-envelope.v1",
            "key_id": key_id,
            "manifest_sha256": promotion_sha,
            "ed25519": base64.b64encode(b"\x00" * ED25519_SIGNATURE_BYTES).decode("ascii"),
            "ml_dsa_65": base64.b64encode(b"\x00" * ML_DSA_65_SIGNATURE_BYTES).decode("ascii"),
        },
    )

    verification = {
        "schema": "boreas.production.external-verification.v1",
        "result": "pass",
        "release_root_sha256": root_sha,
        "release_manifest_sha256": release_sha,
        "promotion_manifest_sha256": promotion_sha,
        "signatures": [
            {"manifest": "release", "algorithm": "ed25519", "key_id": key_id, "valid": True},
            {"manifest": "release", "algorithm": "mldsa65", "key_id": key_id, "valid": True},
            {"manifest": "promotion", "algorithm": "ed25519", "key_id": key_id, "valid": True},
            {"manifest": "promotion", "algorithm": "mldsa65", "key_id": key_id, "valid": True},
        ],
        "artifacts": [
            {"name": artifact["name"], "size": artifact["size"], "sha256": artifact["sha256"]}
            for artifact in artifacts
        ],
        "verifier": {"name": "fixture-verifier", "version": "test-only"},
    }
    _write_json(bundle / "verification" / "verification.json", verification)

    return (
        bundle,
        commit,
        root_sha,
        ledger,
        'python -c "import sys; sys.exit(0)"',
        'python -c "import sys; sys.exit(0)"',
    )


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="boreas-promotion-selftest-") as directory:
        root = Path(directory)

        positive_args = _build_positive_fixture(root / "positive")
        positive_errors = evaluate(*positive_args)
        print(f"positive fixture: {'passed' if not positive_errors else 'FAILED'}")
        if positive_errors:
            failures.append("positive fixture was refused: " + "; ".join(positive_errors))

        def negative(name: str, mutate) -> None:
            case_root = root / name.replace(" ", "-")
            case_root.mkdir()
            args = _build_positive_fixture(case_root)
            mutate(args[0])
            errors = evaluate(*args)
            print(f"{name}: refused ({len(errors)} reason(s))")
            if not errors:
                failures.append(f"{name} was not refused")

        def remove_release_field(bundle: Path) -> None:
            path = bundle / RELEASE_MANIFEST_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            del document["issued_at"]
            _write_json(path, document)

        negative("missing issued_at", remove_release_field)

        def uppercase_product(bundle: Path) -> None:
            path = bundle / RELEASE_MANIFEST_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            document["product"] = "Boreas"
            _write_json(path, document)

        negative("wrong product case", uppercase_product)

        def unsafe_asset(bundle: Path) -> None:
            path = bundle / RELEASE_MANIFEST_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            document["assets"][0]["name"] = "../escape.tar.gz"
            _write_json(path, document)

        negative("asset path traversal", unsafe_asset)

        def bad_envelope(bundle: Path) -> None:
            path = bundle / RELEASE_ENVELOPE_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            document["ml_dsa_65"] = base64.b64encode(b"\x00\x00\x00").decode("ascii")
            _write_json(path, document)

        negative("bad ML-DSA signature length", bad_envelope)

        def tamper_artifact(bundle: Path) -> None:
            target = EXPECTED_TARGETS[0]
            name = f"boreas-0.1.0-{target}{archive_suffix_for_target(target)}"
            (bundle / ARTIFACTS_DIR / name).write_bytes(b"tampered")

        negative("tampered artifact", tamper_artifact)

        def remove_roots(bundle: Path) -> None:
            (bundle / "release-root" / ROOTS_NAME).unlink()

        negative("missing release roots", remove_roots)

        def remove_ledger(bundle: Path) -> None:
            (bundle / "gate-ledger.json").unlink()

        negative("missing gate ledger", remove_ledger)

        def wrong_commit(bundle: Path) -> None:
            path = bundle / PROMOTION_MANIFEST_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            document["commit"] = "b" * 40
            _write_json(path, document)

        negative("promotion commit mismatch", wrong_commit)

        def unknown_release_field(bundle: Path) -> None:
            path = bundle / RELEASE_MANIFEST_NAME
            document = json.loads(path.read_text(encoding="utf-8"))
            document["signed_sha256"] = "c" * 64
            _write_json(path, document)

        negative("self-referential field", unknown_release_field)

    if failures:
        for failure in failures:
            print(f"SELF-TEST FAILED: {failure}", file=sys.stderr)
        return 1
    print("production promotion positive fixture passed and every negative case was refused")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit")
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument(
        "--ledger", type=Path, default=REPO_ROOT / "docs/engineering/gates.json"
    )
    parser.add_argument(
        "--gate-verifier",
        default=(
            "python tools/gates/verify.py --ledger docs/engineering/gates.json "
            "--commit {commit}"
        ),
    )
    parser.add_argument("--expected-release-root-sha256")
    parser.add_argument("--verifier")
    parser.add_argument(
        "--report", type=Path, default=Path("production-promotion-report.json")
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if (
        not args.commit
        or not args.bundle_dir
        or not args.expected_release_root_sha256
        or not args.verifier
    ):
        parser.error(
            "--commit, --bundle-dir, --expected-release-root-sha256 and --verifier "
            "are required unless --self-test is used"
        )

    ledger = args.ledger if args.ledger.is_absolute() else REPO_ROOT / args.ledger
    errors = evaluate(
        args.bundle_dir,
        args.commit,
        args.expected_release_root_sha256,
        ledger,
        args.gate_verifier,
        args.verifier,
    )
    report = {
        "schema": "boreas.production.promotion-report.v1",
        "checked_at": utc_now_iso(),
        "commit": args.commit,
        "bundle_dir": str(args.bundle_dir),
        "gate_verifier": args.gate_verifier,
        "independent_verifier": args.verifier,
        "production_release": False,
        "published": False,
        "promotion_verified": not errors,
        "status": "refused" if errors else "approved-for-offline-publication",
        "reasons": errors,
        "publication_note": (
            "This tool never publishes. Even on success, publication remains an "
            "offline human release-manager action; CI holds no ReleaseRoot key."
        ),
    }
    _write_json(args.report, report)
    if errors:
        for error in errors:
            print(f"PROMOTION REFUSED: {error}", file=sys.stderr)
        print(f"refusal report written to {args.report}", file=sys.stderr)
        return 2
    print(
        "promotion bundle verified for offline publication "
        f"({args.commit}); this tool did not publish anything"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
