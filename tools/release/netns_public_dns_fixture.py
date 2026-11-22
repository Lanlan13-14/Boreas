#!/usr/bin/env python3
"""Test-only DoH/DoT server and Edge probe; all network I/O stays in the fixture netns."""

import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

from netns_private_dns_fixture import (
    CORE_VIP, VIP, ZONE, framed, messages, query, receive_exact, receive_frame,
    require_tcp_close_without_data, tcp_connect,
)
from network_policy_test_fixture import _run

PORT = 18553
TLS_NAME = "dns.fixture.invalid"
HOST = f"{TLS_NAME}:{PORT}".encode()
ORIGIN = b"/dns-query"
PUBLIC = b"public.boreas-forward.net"
EXCLUDED = b"sensitive.boreas-forward.net"
LOOKALIKE = b"not" + EXCLUDED
WIDE = b"wide.boreas-forward.net"
BROKEN = b"broken.boreas-forward.net"
RESULT = bytes((192, 0, 2, 42))
WIDE_RESULT = tuple(bytes((192, 0, 2, n)) for n in range(1, 41))
EXPECTED = (PUBLIC, LOOKALIKE, PUBLIC, WIDE, BROKEN, WIDE, PUBLIC)


def prepare(mode, trust, directory):
    openssl = os.environ.get("BOREAS_OPENSSL_BIN") or "openssl"
    directory.mkdir(mode=0o700)
    for stem in ("root", "unrelated-root"):
        _run(openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-noenc", "-days", "1", "-subj", f"/CN=Boreas fixture {stem}",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(directory / f"{stem}.key"), "-out", str(directory / f"{stem}.pem"))
    root = directory / "root.pem"
    key = directory / "server.key"
    cert = directory / "server.pem"
    csr = directory / "server.csr"
    extensions = directory / "extensions.cnf"
    san = "wrong.fixture.invalid" if trust == "wrong-san" else TLS_NAME
    # Keep the CN correct even in the wrong-SAN case. Only the DNS SAN may match.
    _run(openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-noenc", "-subj", f"/CN={TLS_NAME}", "-keyout", str(key), "-out", str(csr))
    extensions.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                          f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{san}\n", encoding="ascii")
    _run(openssl, "x509", "-req", "-in", str(csr), "-CA", str(root), "-CAkey", str(directory / "root.key"),
         "-set_serial", "2", "-days", "1", "-extfile", str(extensions), "-out", str(cert))
    for name in ("root.key", "unrelated-root.key", "server.csr", "extensions.cnf"):
        (directory / name).unlink()
    ca = directory / "unrelated-root.pem" if trust == "wrong-ca" else root
    transport = "doh" if mode == "doh" else "tls-tcp"
    path = f'path = "{ORIGIN.decode()}"\n' if mode == "doh" else ""
    (directory / "upstream.toml").write_text(
        f'transport = "{transport}"\nendpoint = "127.0.0.1:{PORT}"\n'
        f'tls_name = "{TLS_NAME}"\nca_file = "{ca}"\n{path}'
        f'exclude_suffixes = ["{EXCLUDED.decode()}"]\n', encoding="ascii")


def read_query(client, mode):
    if mode == "dot":
        length = struct.unpack("!H", receive_exact(client, 2))[0]
        if not 17 <= length <= 4096:
            raise ValueError("invalid DoT request size")
        return receive_exact(client, length)
    with client.makefile("rb") as source:
        if source.readline(512) != b"POST " + ORIGIN + b" HTTP/1.1\r\n":
            raise ValueError("unexpected HTTP request line")
        fields = {}
        for _ in range(10):
            line = source.readline(1024)
            if line == b"\r\n":
                break
            name, value = line.split(b":", 1)
            if name.lower() in fields:
                raise ValueError("duplicate request field")
            fields[name.lower()] = value.strip()
        else:
            raise ValueError("too many request fields")
        if (fields.get(b"host") != HOST or fields.get(b"content-type") != b"application/dns-message"
                or fields.get(b"accept") != b"application/dns-message"):
            raise ValueError("incorrect DoH origin or media type")
        length = int(fields[b"content-length"])
        if not 17 <= length <= 4096:
            raise ValueError("invalid DoH request size")
        return source.read(length)


def load_name(body):
    if not 17 <= len(body) <= 4096 or body[2:12] != b"\x01\x00\x00\x01\0\0\0\0\0\0":
        raise ValueError("unexpected upstream DNS query")
    pos, labels = 12, []
    while pos < len(body) and body[pos]:
        length = body[pos]
        if length > 63 or pos + 1 + length >= len(body):
            raise ValueError("unexpected upstream DNS label")
        labels.append(body[pos + 1:pos + length + 1])
        pos += length + 1
    if body[pos:] != b"\0\0\x01\0\x01":
        raise ValueError("unexpected upstream DNS question framing")
    return b".".join(labels).lower()


def record(log, line):
    with log.open("ab") as evidence:
        evidence.write(line + b"\n")


def serve(mode, trust, directory):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "server.pem", directory / "server.key")
    context.set_servername_callback(lambda _, name, __: None if name == TLS_NAME else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
    if mode == "doh":
        context.set_alpn_protocols(["http/1.1"])
    log = directory / "wire.log"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", PORT))
        listener.listen(8)
        listener.settimeout(20)
        (directory / "ready").touch()
        exchanges = {"good": EXPECTED, "no-grant": ()}.get(trust, (None,))
        for expected in exchanges:
            raw, _ = listener.accept()
            record(log, b"connect")
            with raw:
                raw.settimeout(4)
                try:
                    client = context.wrap_socket(raw, server_side=True)
                except ssl.SSLError as exc:
                    expected_alert = {"wrong-ca": "TLSV1_ALERT_UNKNOWN_CA",
                                      "wrong-san": "SSLV3_ALERT_BAD_CERTIFICATE"}.get(trust)
                    if expected_alert is None or exc.reason != expected_alert:
                        raise
                    record(log, b"rejected-before-query")
                    continue
                with client:
                    if expected is None:
                        raise ValueError("invalid certificate completed the TLS handshake")
                    if mode == "doh" and client.selected_alpn_protocol() != "http/1.1":
                        raise ValueError("DoH did not negotiate HTTP/1.1")
                    body = read_query(client, mode)
                    name = load_name(body)
                    record(log, name)
                    if name != expected:
                        raise ValueError(f"unexpected upstream DNS question: {name!r}")
                    if name == BROKEN:
                        # Same-loopback redirect or over-limit DoT frame; neither permits retry.
                        client.sendall(b"HTTP/1.1 307 Redirect\r\nLocation: https://" + HOST + ORIGIN
                                       + b"\r\nContent-Length: 0\r\n\r\n" if mode == "doh" else b"\x10\x01")
                        continue
                    addresses = WIDE_RESULT if name == WIDE else (RESULT,)
                    a_rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                    response = (body[:2] + struct.pack("!5H", 0x8180, 1, len(addresses), 0, 0)
                                + body[12:] + b"".join(a_rr + ip for ip in addresses))
                    if mode == "doh":
                        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                                       + f"Content-Length: {len(response)}\r\n\r\n".encode() + response)
                    else:
                        client.sendall(framed(response))
        # Keep observing while the Edge finishes; reject a late retry as well.
        deadline = time.monotonic() + 6
        listener.settimeout(0.1)
        while not (directory / "probe-done").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("Edge probe did not finish")
            try:
                extra, _ = listener.accept()
            except TimeoutError:
                continue
            with extra:
                raise ValueError("unexpected upstream connection after expected exchanges")
        listener.settimeout(0.25)
        try:
            extra, _ = listener.accept()
        except TimeoutError:
            return
        with extra:
            raise ValueError("unexpected upstream retry")


def private_controls():
    query(VIP, 53, b"CoRe." + ZONE, flags=0x8500, addresses=(CORE_VIP,))
    query(VIP, 53, ZONE.upper(), flags=0x8500)  # Existing apex, no A RRset.
    query(VIP, 53, b"MiSsInG." + ZONE, flags=0x8503)


def probe(trust, directory):
    log = directory / "wire.log"
    private_controls()
    if trust == "good":
        for name in (EXCLUDED.upper(), b"child." + EXCLUDED, b"wpad", b"printer.local",
                     b"1.0.0.127.in-addr.arpa"):
            query(VIP, 53, name)
        with tcp_connect() as client:
            client.sendall(framed(messages(EXCLUDED)[0]))
            require_tcp_close_without_data(client)
    if log.exists():
        raise ValueError("private/special-use probe opened an upstream connection")
    if trust != "good":
        query(VIP, 53, PUBLIC, flags=0x8102)
        private_controls()  # Failure is a DNS SERVFAIL, not a dead tunnel or private authority.
        expected = [b"connect", b"rejected-before-query"]
    else:
        for name in (PUBLIC, LOOKALIKE, PUBLIC):  # The repeated public query is not cached.
            query(VIP, 53, name, flags=0x8180, addresses=(RESULT,))
        query(VIP, 53, WIDE, flags=0x8300)  # Whole-question TC, never a partial answer.
        query(VIP, 53, BROKEN, flags=0x8102)
        exchanges = (messages(WIDE, 0x8180, WIDE_RESULT), messages(b"absent." + ZONE, 0x8503),
                     messages(PUBLIC, 0x8180, (RESULT,)))
        with tcp_connect(timeout=5) as client:
            client.sendall(b"".join(framed(request) for request, _ in exchanges))
            client.shutdown(socket.SHUT_WR)
            for _, response in exchanges:
                receive_frame(client, response)
            if client.recv(1) != b"":
                raise ValueError("expected clean FIN after mixed pipelined replies")
        expected = [line for name in EXPECTED for line in (b"connect", name)]
    if log.read_bytes().splitlines() != expected:
        raise ValueError("unexpected upstream attempt, fallback, or private leakage")
    (directory / "probe-done").touch()


if __name__ == "__main__":
    action, mode, trust, path = sys.argv[1:]
    if mode not in ("doh", "dot") or trust not in ("good", "wrong-ca", "wrong-san", "no-grant"):
        raise ValueError("invalid fixture mode or certificate case")
    directory = Path(path)
    if action == "prepare":
        prepare(mode, trust, directory)
    elif action == "upstream":
        serve(mode, trust, directory)
    elif action == "probe":
        probe(trust, directory)
    else:
        raise ValueError("invalid fixture action")
