"""Shared helpers for the Boreas *development* release tooling.

Nothing in this directory holds or generates a production ``ReleaseRoot``
private key, and nothing here publishes a release.  The helpers only create
and inspect unsigned development artifacts with deterministic archive
metadata.  Production promotion is a separate, offline, signature-requiring
operation (see ``production_promotion.py``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

MAX_JSON_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
MAX_ARCHIVE_UNCOMPRESSED = 512 * 1024 * 1024

# The five targets the user requires for a release.  Order is the canonical
# order used in indexes and summaries.
EXPECTED_TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)

TARGET_ARCH = {
    "x86_64-unknown-linux-musl": "x86_64",
    "aarch64-unknown-linux-musl": "aarch64",
    "x86_64-pc-windows-msvc": "x86_64",
    "x86_64-apple-darwin": "x86_64",
    "aarch64-apple-darwin": "aarch64",
}

TARGET_PLATFORM = {
    "x86_64-unknown-linux-musl": "linux",
    "aarch64-unknown-linux-musl": "linux",
    "x86_64-pc-windows-msvc": "windows",
    "x86_64-apple-darwin": "macos",
    "aarch64-apple-darwin": "macos",
}

# Names used by docs/engineering/gates.json for the same five platforms.
GATE_PLATFORM_NAMES = {
    "x86_64-unknown-linux-musl": "linux-x86_64-static",
    "aarch64-unknown-linux-musl": "linux-aarch64-static",
    "x86_64-pc-windows-msvc": "windows-x86_64",
    "x86_64-apple-darwin": "macos-x86_64",
    "aarch64-apple-darwin": "macos-aarch64",
}


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is not allowed: {value}")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_text(text: str):
    """Parse one JSON value, rejecting duplicate keys and non-finite numbers."""

    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


def read_json_strict(path: Path, max_bytes: int = MAX_JSON_BYTES):
    """Read one bounded UTF-8 JSON document, rejecting duplicate keys.

    Duplicate-key rejection matters for signed manifests and for local
    provenance: ``json.loads`` would otherwise silently keep the last value.
    The read itself is bounded; the file is never slurped before the size
    check.
    """

    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{path} exceeds the {max_bytes}-byte JSON limit")
    text = data.decode("utf-8")
    return parse_json_text(text)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes via a same-directory temporary file and atomic replace."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def archive_member_bytes(
    archive: Path,
    member: str,
    max_bytes: int = MAX_JSON_BYTES,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_total_uncompressed: int = MAX_ARCHIVE_UNCOMPRESSED,
) -> bytes:
    """Read one regular archive member with resource and traversal bounds.

    The archive is untrusted even when its SHA-256 matches a manifest: the
    manifest itself is not trusted until signatures are verified.  Bounds are
    therefore enforced before and during inspection:

    * compressed archive size, member count and declared uncompressed total;
    * exactly one member with the requested basename;
    * no directory, symlink or special-file member;
    * the declared member size and the actual bytes read are both bounded.

    Only the requested member is read; the archive is never extracted.
    """

    if not is_safe_basename(member):
        raise ValueError(f"unsafe archive member name: {member!r}")
    if not archive.is_file():
        raise ValueError(f"archive is not a regular file: {archive}")
    if archive.stat().st_size > max_archive_bytes:
        raise ValueError(
            f"{archive}: compressed size exceeds the {max_archive_bytes}-byte limit"
        )

    if archive.name.endswith(".tar.gz"):
        data = None
        matches = 0
        members = 0
        declared_total = 0
        with tarfile.open(archive, "r:gz") as tar:
            while True:
                info = tar.next()
                if info is None:
                    break
                members += 1
                if members > max_members:
                    raise ValueError(
                        f"{archive}: more than {max_members} archive members"
                    )
                declared_total += max(info.size, 0)
                if declared_total > max_total_uncompressed:
                    raise ValueError(
                        f"{archive}: declared uncompressed total exceeds "
                        f"{max_total_uncompressed} bytes"
                    )
                if info.name != member:
                    continue
                matches += 1
                if matches > 1:
                    raise ValueError(f"{archive}: duplicate member {member!r}")
                if not info.isfile():
                    raise ValueError(f"{archive}: {member} is not a regular file")
                if info.size > max_bytes:
                    raise ValueError(f"{archive}: {member} exceeds {max_bytes} bytes")
                handle = tar.extractfile(info)
                if handle is None:
                    raise ValueError(f"{archive}: cannot read {member}")
                data = handle.read(max_bytes + 1)
        if matches != 1 or data is None:
            raise ValueError(f"{archive}: member {member!r} is missing")
    elif archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            if len(infos) > max_members:
                raise ValueError(f"{archive}: more than {max_members} archive members")
            declared_total = sum(max(info.file_size, 0) for info in infos)
            if declared_total > max_total_uncompressed:
                raise ValueError(
                    f"{archive}: declared uncompressed total exceeds "
                    f"{max_total_uncompressed} bytes"
                )
            matches = [info for info in infos if info.filename == member]
            if len(matches) != 1:
                raise ValueError(f"{archive}: expected exactly one member {member!r}")
            info = matches[0]
            if info.is_dir():
                raise ValueError(f"{archive}: {member} is a directory")
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == 0o120000:
                raise ValueError(f"{archive}: {member} is a symlink")
            if info.file_size > max_bytes:
                raise ValueError(f"{archive}: {member} exceeds {max_bytes} bytes")
            data = bundle.read(info)
    else:
        raise ValueError(f"unsupported archive type: {archive}")

    if len(data) > max_bytes:
        raise ValueError(f"{archive}: {member} exceeds {max_bytes} bytes")
    return data


def safe_bundle_file(
    bundle: Path, name: str, must_exist: bool = True
) -> Path:
    """Resolve a single basename inside a bundle, rejecting traversal/symlinks.

    Bundle indexes and checksum lists are untrusted input.  A name such as
    ``../secret`` or an absolute path must never be joined to the bundle
    directory, and a symlink inside the bundle must not redirect the read
    outside it.
    """

    if not is_safe_basename(name):
        raise ValueError(f"unsafe bundle file name: {name!r}")
    root = bundle.resolve()
    candidate = bundle / name
    if candidate.is_symlink():
        raise ValueError(f"symlink is not allowed in a bundle: {name!r}")
    resolved = candidate.resolve()
    if resolved.parent != root:
        raise ValueError(f"bundle file escapes the bundle directory: {name!r}")
    if must_exist and not resolved.is_file():
        raise ValueError(f"bundle file is missing or not regular: {name!r}")
    return resolved


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def is_safe_basename(name: str) -> bool:
    """Reject path traversal and separators in manifest/asset names."""

    return (
        bool(re.fullmatch(r"[A-Za-z0-9._+-]+", name))
        and ".." not in name
        and "/" not in name
        and "\\" not in name
    )


def archive_suffix_for_target(target: str) -> str:
    return ".zip" if TARGET_PLATFORM[target] == "windows" else ".tar.gz"


def archive_name_for(version: str, target: str) -> str:
    return f"boreas-{version}-{target}{archive_suffix_for_target(target)}"
