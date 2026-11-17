#!/usr/bin/env python3
"""Create a test-only, dual-signed default-prefix network-policy fixture.

The input private keys must already exist in the output directory. This is not
production provisioning and deliberately never copies private keys to fixture
materials. OpenSSL is selected by BOREAS_OPENSSL_BIN in the test environment.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

ED_KEY = "root-ed25519.pem"
ML_KEY = "root-mldsa65.pem"
TBS_FILE = "tbs.cbor"
ED_SIG = "ed25519.sig"
ML_SIG = "mldsa65.sig"
ED_DER = "root-ed25519.der"
ML_DER = "root-mldsa65.der"
EXPECTED_SIGNATURE_LENGTHS = {ED_SIG: 64, ML_SIG: 3309}


def _uint(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("integer is outside CBOR uint64 range")
    if value < 24:
        return bytes((value,))
    if value <= 0xFF:
        return bytes((0x18, value))
    if value <= 0xFFFF:
        return b"\x19" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\x1a" + value.to_bytes(4, "big")
    return b"\x1b" + value.to_bytes(8, "big")


def _head(major: int, value: int) -> bytes:
    encoded = _uint(value)
    return bytes(((major << 5) | encoded[0],)) + encoded[1:]


def _bytes(value: bytes) -> bytes:
    return _head(2, len(value)) + value


def _validate_net_id(net_id: bytes) -> None:
    if len(net_id) != 16 or net_id == bytes(16):
        raise ValueError("net-id must be a nonzero 16-byte value")


def fingerprint(net_id: bytes, ed_der: bytes, ml_der: bytes) -> bytes:
    _validate_net_id(net_id)
    if not ed_der or not ml_der:
        raise ValueError("invalid root pin public key DER")
    data = (b"BOREAS-NETWORK-ROOT-PIN-FINGERPRINT\0" + len(net_id).to_bytes(4, "big")
            + net_id + b"\x01" + len(ed_der).to_bytes(4, "big") + ed_der
            + b"\x41" + len(ml_der).to_bytes(4, "big") + ml_der)
    return hashlib.sha256(data).digest()


def encode_tbs(net_id: bytes, root_fp: bytes, sequence: int, issued: int, expires: int) -> bytes:
    _validate_net_id(net_id)
    if len(root_fp) != 32 or root_fp == bytes(32):
        raise ValueError("invalid root fingerprint")
    if sequence <= 0 or issued < 0 or expires <= issued:
        raise ValueError("invalid sequence or validity window")
    # Canonical NetworkPolicyCandidate, fixed default overlay 10.20.0.0/16.
    out = bytearray(_head(5, 11))
    for key, value in ((0, _uint(1)), (1, _uint(7)), (2, _bytes(net_id)),
                       (3, _bytes(b"network-root-v1")), (4, _uint(1)),
                       (5, _head(4, 1) + _uint(3)), (6, _uint(sequence)),
                       (7, _uint(issued)), (8, _uint(expires))):
        out += _uint(key) + value
    out += _uint(9) + _head(5, 5)
    out += _uint(0) + _bytes(net_id)
    out += _uint(1) + _bytes(bytes((10, 20, 0, 0)))
    out += _uint(2) + _uint(16)
    out += _uint(3) + _bytes(root_fp)
    out += _uint(4) + _uint(0)
    out += _uint(10) + _head(4, 0)
    return bytes(out)


def signature_input(tbs: bytes) -> bytes:
    if len(tbs) > 16 * 1024:
        raise ValueError("candidate is too large")
    return b"BOREAS-MGMT-OBJECT\0" + (1).to_bytes(2, "big") + b"\x07" + len(tbs).to_bytes(8, "big") + tbs


def _run(openssl: str, *args: str, pass_fds: tuple[int, ...] = ()) -> bytes:
    result = subprocess.run([openssl, *args], check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=False, pass_fds=pass_fds)
    if result.returncode != 0:
        # Never surface OpenSSL diagnostics or command arguments (which contain key paths).
        raise ValueError(f"pinned OpenSSL operation failed (exit {result.returncode})")
    return result.stdout


def _write_exclusive(path: Path, data: bytes, *, private: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        if private:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _open_private_key(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"unsafe operator key file: {path.name}")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError(f"operator key must have mode 0600: {path.name}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError(f"operator key must be owned by current user: {path.name}")
        raw = os.read(fd, 64 * 1024 + 1)
        if not raw or len(raw) > 64 * 1024:
            raise ValueError(f"invalid operator key file size: {path.name}")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise


def generate(out_dir: Path, net_id: bytes, sequence: int, issued: int, expires: int,
             openssl: str) -> None:
    out_fd = os.open(out_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    out_info = os.fstat(out_fd)
    if not stat.S_ISDIR(out_info.st_mode) or (hasattr(os, "getuid") and out_info.st_uid != os.getuid()):
        os.close(out_fd)
        raise ValueError("out-dir must be owned by the current user")
    out_dir = Path(f"/proc/self/fd/{out_fd}") if Path("/proc/self/fd").is_dir() else out_dir
    key_fds: list[int] = []
    scratch: Path | None = None
    try:
        if not Path("/proc/self/fd").is_dir():
            raise ValueError("this test fixture generator requires /proc/self/fd descriptor paths")
        dir_fd_path = Path(f"/proc/self/fd/{out_fd}")
        key_paths = [dir_fd_path / ED_KEY, dir_fd_path / ML_KEY]
        key_fds = [_open_private_key(path) for path in key_paths]
        fd_key_paths = [f"/proc/self/fd/{fd}" for fd in key_fds]
        if not all(Path(path).exists() for path in fd_key_paths):
            raise ValueError("this test fixture generator requires inherited descriptor paths")
        ed_der = _run(openssl, "pkey", "-in", fd_key_paths[0], "-pubout", "-outform", "DER", pass_fds=tuple((*key_fds, out_fd)))
        ml_der = _run(openssl, "pkey", "-in", fd_key_paths[1], "-pubout", "-outform", "DER", pass_fds=tuple((*key_fds, out_fd)))
        fp = fingerprint(net_id, ed_der, ml_der)
        tbs = encode_tbs(net_id, fp, sequence, issued, expires)
        signed = signature_input(tbs)
        scratch = out_dir / ".network-policy-signing-input.tmp"
        scratch_fd = os.open(scratch, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(scratch_fd, 0o600)
            with os.fdopen(scratch_fd, "wb", closefd=False) as stream:
                stream.write(signed)
                stream.flush()
                os.fsync(scratch_fd)
            scratch_path = f"/proc/self/fd/{scratch_fd}"
            ed_sig = _run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", fd_key_paths[0], "-in", scratch_path, pass_fds=tuple((*key_fds, out_fd, scratch_fd)))
            ml_sig = _run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", fd_key_paths[1], "-in", scratch_path, pass_fds=tuple((*key_fds, out_fd, scratch_fd)))
        finally:
            os.close(scratch_fd)
        if len(ed_sig) != EXPECTED_SIGNATURE_LENGTHS[ED_SIG] or len(ml_sig) != EXPECTED_SIGNATURE_LENGTHS[ML_SIG]:
            raise ValueError("OpenSSL returned invalid signature length")
        for name, data in ((TBS_FILE, tbs), (ED_SIG, ed_sig), (ML_SIG, ml_sig),
                           (ED_DER, ed_der), (ML_DER, ml_der)):
            _write_exclusive(out_dir / name, data)
    finally:
        if scratch is not None:
            try:
                scratch.unlink()
            except FileNotFoundError:
                pass
        for fd in key_fds:
            os.close(fd)
        os.close(out_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--net-id", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--issued-at-us", type=int, required=True)
    parser.add_argument("--expires-us", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        net_id = bytes.fromhex(args.net_id)
        if len(net_id) != 16:
            raise ValueError("--net-id must contain exactly 32 hex digits")
        openssl = os.environ.get("BOREAS_OPENSSL_BIN")
        if not openssl:
            raise ValueError("BOREAS_OPENSSL_BIN must name the pinned OpenSSL executable")
        generate(args.out_dir, net_id, args.sequence, args.issued_at_us,
                 args.expires_us, openssl)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"fixture generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
