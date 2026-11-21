#!/usr/bin/env python3
"""Test-only signed DNS material generator and netns client; no production keys."""
import hashlib
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time

from network_policy_test_fixture import _bytes, _head, _run, _uint

ZONE = b"private.boreas.test"


def array(*items):
    return _head(4, len(items)) + b"".join(items)


def mapping(*items):
    return _head(5, len(items)) + b"".join(_uint(i) + val for i, val in enumerate(items))


def generate(ca, policy, directory, pin, net_id):
    openssl = os.environ.get("BOREAS_OPENSSL_BIN") or "openssl"
    net = _bytes(bytes.fromhex(net_id))
    digest = _bytes(hashlib.sha256(policy.read_bytes()).digest())
    version = _uint(1)
    start = time.time_ns() // 1000
    # The NetworkPolicy fixture is issued before this one and lasts one hour.
    issued, expires = _uint(start), _uint(start + 300_000_000)
    key_id = _bytes(b"dns-authority-v1")
    ipv4 = _bytes(bytes((10, 20, 1, 1)))
    directory.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(dir=ca.parent) as scratch:
        scratch = Path(scratch)
        algs = ("ed25519", "mldsa65")
        root = tuple(ca / f"root.{alg}.key" for alg in algs)
        keys = tuple(scratch / f"{alg}.pem" for alg in algs)
        public = []
        for key, name in zip(keys, ("ED25519", "ML-DSA-65")):
            _run(openssl, "genpkey", "-algorithm", name, "-out", str(key))
            public.append(_bytes(_run(openssl, "pkey", "-in", str(key), "-pubout", "-outform", "DER")))
        service = mapping(version, net, digest, _uint(3), issued, expires,
                          array(array(_uint(1), _uint(1), _uint(4))))
        grant = mapping(net, digest, version, _uint(1), key_id, version, _uint(2), issued, expires,
                        mapping(public[0], _uint(65), public[1]))
        authority = mapping(net, digest, version, _bytes(ZONE), _uint(7), issued, expires, key_id,
                            array(mapping(_uint(1), ipv4, _bytes(bytes(16)))),
                            array(mapping(_bytes(b"core." + ZONE), _uint(1), ipv4)))
        for stem, typ, tbs, signers in (("service", 10, service, root), ("signer", 8, grant, root),
                                        ("authority", 9, authority, keys)):
            (directory / f"{stem}.tbs").write_bytes(tbs)
            message = b"BOREAS-MGMT-OBJECT\0\x00\x01" + bytes([typ]) + len(tbs).to_bytes(8, "big") + tbs
            msg = scratch / "message"
            msg.write_bytes(message)
            for alg, signer, size in zip(algs, signers, (64, 3309)):
                fmt = ("-keyform", "DER") if signers == root else ()
                sig = _run(openssl, "pkeyutl", "-sign", "-rawin", *fmt,
                           "-inkey", str(signer), "-in", str(msg))
                if len(sig) != size:
                    raise ValueError("invalid signature size")
                (directory / f"{stem}.{alg}.sig").write_bytes(sig)
        pin.write_bytes(b"".join(hashlib.sha256(tbs).digest() for tbs in (service, grant, authority)))


def query(server, port, name, rcode=None):
    qid = os.urandom(2)
    labels = b"".join(bytes([len(label)]) + label for label in name.split(b"."))
    question = labels + b"\0\0\x01\0\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("10.20.1.2", 0))
        client.connect((server, port))
        client.settimeout(2 if rcode is not None else 0.4)
        client.send(qid + b"\x01\x00\x00\x01" + bytes(6) + question)
        try:
            reply = client.recv(1400)
        except TimeoutError:
            if rcode is None:
                return
            raise
    if rcode is None:
        raise ValueError("unexpected DNS response")
    flags, qd, an, ns, ar = struct.unpack("!5H", reply[2:12])
    expected = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 60, 4) + bytes((10, 20, 1, 1))
    if (reply[:2] != qid or flags != (0x8500 | rcode) or (qd, an, ns, ar) != (1, int(rcode == 0), 0, 0)
            or reply[12:] != question + (expected if rcode == 0 else b"")):
        raise ValueError("DNS answer does not match signed fixture")


def probe():
    vip = "10.20.0.53"
    query(vip, 53, b"core." + ZONE, 0)
    query(vip, 53, b"missing." + ZONE, 3)
    query(vip, 53, b"private.boreas.test.invalid")
    query(vip, 54, b"core." + ZONE)
    query(vip, 53, b"core." + ZONE, 0)
    print("private_dns=verified_signed_a_nxdomain_and_out_of_scope_drop")


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        probe()
    else:
        ca, policy, directory, pin, net = sys.argv[1:]
        generate(Path(ca), Path(policy), Path(directory), Path(pin), net)
