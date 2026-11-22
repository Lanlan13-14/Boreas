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
CORE_VIP = bytes((10, 20, 1, 1))
EDGE_VIP = bytes((10, 20, 1, 2))
WIDE_RRSET = tuple(bytes((10, 20, 1, octet)) for octet in range(1, 33))


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
        claims = array(*(mapping(_uint(ip[3]), _bytes(ip), _bytes(bytes(16))) for ip in WIDE_RRSET))
        rrsets = ((b"core", (CORE_VIP,)), (b"pair", (CORE_VIP, EDGE_VIP)), (b"wide", WIDE_RRSET))
        records = array(*(mapping(_bytes(label + b"." + ZONE), _uint(1), _bytes(ip))
                          for label, addresses in rrsets for ip in addresses))
        authority = mapping(net, digest, version, _bytes(ZONE), _uint(7), issued, expires, key_id,
                            claims, records)
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


def opt(payload_size):
    return struct.pack("!BHHIH", 0, 41, payload_size, 0, 0)


def query(server, port, name, *, flags=None, addresses=(), qtype=1, edns=None):
    qid = os.urandom(2)
    labels = b"".join(bytes([len(label)]) + label for label in name.split(b"."))
    question = labels + b"\0" + struct.pack("!HH", qtype, 1)
    additional = b"" if edns is None else opt(edns)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("10.20.1.2", 0))
        client.connect((server, port))
        client.settimeout(2 if flags is not None else 0.4)
        client.send(qid + struct.pack("!5H", 0x0100, 1, 0, 0, bool(additional)) + question + additional)
        try:
            reply = client.recv(4097)
        except TimeoutError:
            if flags is None:
                return
            raise RuntimeError(f"private DNS: no reply for {name!r} port {port}") from None
    if flags is None:
        raise ValueError(f"private DNS: unexpected reply for {name!r} port {port}")
    a_rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
    answers = b"".join(a_rr + ip for ip in addresses)
    expected = (qid + struct.pack("!5H", flags, 1, len(addresses), 0, bool(additional))
                + question + answers + additional)
    if reply != expected:
        raise ValueError(f"private DNS: wrong wire reply for {name!r} type {qtype} EDNS {edns}; "
                         f"got {reply[:12].hex()} ({len(reply)} B), "
                         f"expected {expected[:12].hex()} ({len(expected)} B)")


def probe():
    vip = "10.20.0.53"
    query(vip, 53, b"core." + ZONE, flags=0x8500, addresses=(CORE_VIP,))
    query(vip, 53, b"missing." + ZONE, flags=0x8503)
    query(vip, 53, b"private.boreas.test.invalid")
    query(vip, 53, b"notprivate.boreas.test")
    query(vip, 54, b"core." + ZONE)
    query(vip, 53, b"PaIR." + ZONE, flags=0x8500, addresses=(CORE_VIP, EDGE_VIP))
    query(vip, 53, b"pair." + ZONE, flags=0x8500, qtype=28)
    print("private_dns=verified_signed_a_nxdomain_and_out_of_scope_drop", flush=True)

    # A conventional UDP limit cannot fit the complete signed set; no partial
    # answers, and no TCP or public fallback. A separate explicit EDNS query
    # to the same VIP fits the entire set in a single in-tunnel UDP packet.
    wide = b"wide." + ZONE
    query(vip, 53, wide, flags=0x8300)
    query(vip, 53, wide, flags=0x8300, edns=512)
    query(vip, 53, wide, flags=0x8500, addresses=WIDE_RRSET, edns=1232)
    print("private_dns_rrset=verified_complete_a_and_tc_without_partial_answers", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        probe()
    else:
        ca, policy, directory, pin, net = sys.argv[1:]
        generate(Path(ca), Path(policy), Path(directory), Path(pin), net)
