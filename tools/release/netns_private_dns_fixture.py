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
VIP = "10.20.0.53"
TCP_MAX_RRSET = tuple(bytes((10, 20, 1, octet)) for octet in range(1, 65))
LONG_OWNER_LABELS = b".".join((b"a" * 63, b"b" * 63, b"c" * 30))
CLIENT_TCP_MSS = 600


def array(*items):
    return _head(4, len(items)) + b"".join(items)


def mapping(*items):
    return _head(5, len(items)) + b"".join(_uint(i) + val for i, val in enumerate(items))


def generate(ca, policy, directory, pin, net_id, *, replica=False, public_forward=False):
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
        capabilities = 4 | (2 if public_forward else 0)
        replicas = [array(_uint(1), _uint(1), _uint(capabilities))]
        if replica:
            replicas.append(array(_uint(257), _uint(1), _uint(4)))
        service = mapping(version, net, digest, _uint(3), issued, expires, array(*replicas))
        grant = mapping(net, digest, version, _uint(1), key_id, version, _uint(2), issued, expires,
                        mapping(public[0], _uint(65), public[1]))
        claims = array(*(mapping(_uint(ip[3]), _bytes(ip), _bytes(bytes(16))) for ip in TCP_MAX_RRSET))
        rrsets = ((b"core", (CORE_VIP,)), (b"pair", (CORE_VIP, EDGE_VIP)), (b"wide", WIDE_RRSET),
                  (LONG_OWNER_LABELS, TCP_MAX_RRSET))
        records = array(*(mapping(_bytes(label + b"." + ZONE), _uint(1), _bytes(ip))
                          for label, addresses in rrsets for ip in addresses))
        authority = mapping(net, digest, version, _bytes(ZONE), _uint(7), issued, expires, key_id,
                            claims, records)
        if len(authority) > 16 * 1024:
            raise ValueError("DNS authority fixture exceeds the signed object cap")
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


def sign_replica_revocation(ca, net_id, output, node_id=257):
    """Fixture authority—not a production signing CLI."""
    openssl = os.environ.get("BOREAS_OPENSSL_BIN") or "openssl"
    now = time.time_ns() // 1000
    tbs = mapping(_uint(1), _bytes(bytes.fromhex(net_id)), _uint(1), _uint(node_id),
                  _uint(1), _bytes(b"identity-authority-v1"), _uint(1),
                  mapping(_bytes(b""), _uint(0), _uint(0)), _uint(1),
                  _uint(now), _uint(now + 120_000_000))
    message = b"BOREAS-AUTHORITY-REVOCATION\0\x00\x01\x01" + len(tbs).to_bytes(8, "big") + tbs
    with tempfile.TemporaryDirectory(dir=ca.parent) as scratch:
        source = Path(scratch) / "revocation-message"
        source.write_bytes(message)
        signatures = tuple(_run(openssl, "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                                "-inkey", str(ca / f"ia.{alg}.key"), "-in", str(source))
                           for alg in ("ed25519", "mldsa65"))
    if tuple(map(len, signatures)) != (64, 3309):
        raise ValueError("invalid identity revocation signature size")
    output.write_bytes(b"BRIR\0\0\0\x01" + b"".join(signatures) + tbs)


def opt(payload_size):
    return struct.pack("!BHHIH", 0, 41, payload_size, 0, 0)


def messages(name, flags=0x8500, addresses=(), qtype=1, edns=None):
    qid = os.urandom(2)
    labels = b"".join(bytes([len(label)]) + label for label in name.split(b"."))
    question = labels + b"\0" + struct.pack("!HH", qtype, 1)
    additional = b"" if edns is None else opt(edns)
    request = qid + struct.pack("!5H", 0x0100, 1, 0, 0, bool(additional)) + question + additional
    a_rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
    answers = b"".join(a_rr + ip for ip in addresses)
    expected = (qid + struct.pack("!5H", flags or 0, 1, len(addresses), 0, bool(additional))
                + question + answers + additional)
    return request, expected


def query(server, port, name, *, flags=None, addresses=(), qtype=1, edns=None):
    request, expected = messages(name, flags, addresses, qtype, edns)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("10.20.1.2", 0))
        client.connect((server, port))
        client.settimeout(2 if flags is not None else 0.4)
        client.send(request)
        try:
            reply = client.recv(4097)
        except TimeoutError:
            if flags is None:
                return
            raise RuntimeError(f"private DNS: no reply for {name!r} port {port}") from None
    if flags is None:
        raise ValueError(f"private DNS: unexpected reply for {name!r} port {port}")
    if reply != expected:
        raise ValueError(f"private DNS: wrong wire reply for {name!r} type {qtype} EDNS {edns}; "
                         f"got {reply[:12].hex()} ({len(reply)} B), "
                         f"expected {expected[:12].hex()} ({len(expected)} B)")


def probe():
    vip = VIP
    query(vip, 53, b"core." + ZONE, flags=0x8500, addresses=(CORE_VIP,))
    query(vip, 53, b"missing." + ZONE, flags=0x8503)
    query(vip, 53, b"private.boreas.test.invalid")
    query(vip, 53, b"notprivate.boreas.test")
    query(vip, 54, b"core." + ZONE)
    query(vip, 53, b"PaIR." + ZONE, flags=0x8500, addresses=(CORE_VIP, EDGE_VIP))
    query(vip, 53, b"pair." + ZONE, flags=0x8500, qtype=28)
    print("private_dns=verified_signed_a_nxdomain_and_out_of_scope_drop", flush=True)

    # A conventional UDP limit cannot fit the complete signed set; no partial
    # answers, and no automatic fallback in this client. An explicit EDNS query
    # to the same VIP fits the entire set in a single in-tunnel UDP packet.
    wide = b"wide." + ZONE
    query(vip, 53, wide, flags=0x8300)
    query(vip, 53, wide, flags=0x8300, edns=512)
    query(vip, 53, wide, flags=0x8500, addresses=WIDE_RRSET, edns=1232)
    print("private_dns_rrset=verified_complete_a_and_tc_without_partial_answers", flush=True)


def replica_tcp_probe():
    request, expected = messages(b"pair." + ZONE, addresses=(CORE_VIP, EDGE_VIP))
    with tcp_connect() as client:
        client.sendall(framed(request))
        receive_frame(client, expected)


def replica_old_tcp_probe(ready, promoted):
    request, expected = messages(b"pair." + ZONE, addresses=(CORE_VIP, EDGE_VIP))
    with tcp_connect() as client:
        client.sendall(framed(request))
        receive_frame(client, expected)
        ready.touch()
        until = time.monotonic() + 30
        while not promoted.exists():
            if time.monotonic() >= until:
                raise TimeoutError("backup promotion was not signaled")
            time.sleep(0.025)
        client.settimeout(1)
        another, _ = messages(b"pair." + ZONE)
        try:
            client.sendall(framed(another))
            result = client.recv(4096)
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            return
        if result:
            raise AssertionError("pre-promotion DNS TCP flow received bytes on the new replica")


def tcp_connect(timeout=3):
    client = socket.create_connection((VIP, 53), timeout=timeout, source_address=("10.20.1.2", 0))
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return client


def framed(payload):
    return struct.pack("!H", len(payload)) + payload


def receive_exact(client, length):
    out = bytearray()
    while len(out) < length:
        chunk = client.recv(length - len(out))
        if not chunk:
            raise EOFError("private DNS: EOF before full TCP frame")
        out.extend(chunk)
    return bytes(out)


def receive_frame(client, expected):
    size = struct.unpack("!H", receive_exact(client, 2))[0]
    if size != len(expected) or receive_exact(client, size) != expected:
        raise ValueError(f"private DNS: wrong framed response, length {size}, expected {len(expected)}")


def require_tcp_close_without_data(client):
    try:
        if client.recv(1) != b"":
            raise ValueError("private DNS: unexpected TCP response data")
    except ConnectionResetError:
        pass


def tcp_probe():
    owner = LONG_OWNER_LABELS + b"." + ZONE
    # This RRset exceeds both the 512-byte UDP limit and the route's
    # advertised TCP MSS. TCP must reassemble the entire signed RRset.
    query(VIP, 53, owner, flags=0x8300, edns=512)
    big, big_answer = messages(owner, addresses=TCP_MAX_RRSET)
    if len(framed(big_answer)) <= CLIENT_TCP_MSS:
        raise ValueError("private DNS: TCP fixture no longer exceeds the advertised MSS")
    nodata, nodata_answer = messages(b"pAiR." + ZONE, qtype=28)
    missing, missing_answer = messages(b"missing." + ZONE, flags=0x8503)
    with tcp_connect() as client:
        wire = framed(big)
        client.sendall(wire[:1])
        time.sleep(0.05)  # multi-segment length prefix (TCP_NODELAY)
        client.sendall(wire[1:] + framed(nodata) + framed(missing))
        client.shutdown(socket.SHUT_WR)
        for expected in (big_answer, nodata_answer, missing_answer):
            receive_frame(client, expected)
        if client.recv(1) != b"":
            raise ValueError("private DNS: expected clean TCP EOF after half-close")
    print("private_dns_tcp=verified_split_prefix_pipelining_full_rrset_and_fin", flush=True)

    with tcp_connect(timeout=15) as idle:
        for payload in (framed(messages(b"notprivate.boreas.test")[0]), b"\x10\x01"):
            with tcp_connect() as client:
                client.sendall(payload)
                require_tcp_close_without_data(client)
        # Wrong-port TCP never starts a DNS flow.
        try:
            with socket.create_connection((VIP, 54), timeout=0.4, source_address=("10.20.1.2", 0)):
                raise ValueError("private DNS: unexpected TCP/54 connection")
        except TimeoutError:
            pass
        # No client FIN or further traffic. The daemon must poll timers while idle.
        require_tcp_close_without_data(idle)
    with tcp_connect() as client:
        client.sendall(framed(missing))
        receive_frame(client, missing_answer)
    print("private_dns_tcp_denials=scope_frame_port_and_idle_timeout", flush=True)


def withdrawal_probe(ready, withdrawn):
    with tcp_connect() as client:
        request, response = messages(b"core." + ZONE, addresses=(CORE_VIP,))
        client.sendall(framed(request))
        receive_frame(client, response)
        ready.touch()
        until = time.monotonic() + 6
        while not withdrawn.exists():
            if time.monotonic() >= until:
                raise TimeoutError("Core pin withdrawal signal did not arrive")
            time.sleep(0.02)
        # No replacement circuit or alternate resolver. Linux may not wake
        # an existing TCP socket when the TUN disappears, so timeout is valid.
        try:
            client.sendall(framed(request))
            require_tcp_close_without_data(client)
        except (TimeoutError, OSError):
            pass
    print("private_dns_tcp_pin_withdrawal=no_later_dns_data_on_open_stream", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        probe()
        tcp_probe()
    elif len(sys.argv) == 4 and sys.argv[1] == "withdrawal":
        withdrawal_probe(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 5 and sys.argv[1] == "pool-revoke":
        sign_replica_revocation(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), node_id=2)
    elif len(sys.argv) == 5 and sys.argv[1] == "replica-revoke":
        sign_replica_revocation(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
    elif sys.argv[1:] == ["replica-udp"]:
        probe()
    elif sys.argv[1:] == ["replica-tcp"]:
        replica_tcp_probe()
    elif len(sys.argv) == 4 and sys.argv[1] == "replica-old-tcp":
        replica_old_tcp_probe(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        ca, policy, directory, pin, net, *flags = sys.argv[1:]
        if flags not in ([], ["--replica"], ["--public-forward"]):
            raise SystemExit("unsupported DNS fixture flags")
        generate(Path(ca), Path(policy), Path(directory), Path(pin), net,
                 replica="--replica" in flags, public_forward="--public-forward" in flags)
