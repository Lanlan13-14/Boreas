#!/usr/bin/env python3
"""Bidirectional integrity and throughput probe for the netns overlay smoke.

Runs a receiver on the Core VIP and a sender on the Edge VIP. Only standard
library sockets are used; no host sysctl, route, or TLS setting is changed.
"""

import hashlib
import json
import socket
import sys
import time

CHUNK = bytes((index % 251 for index in range(64 * 1024)))
TOTAL_BYTES = 8 * 1024 * 1024
PORT = 18080
TIMEOUT_SECONDS = 30


def receiver() -> None:
    digest = hashlib.sha256()
    received = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("10.20.1.1", PORT))
        listener.listen(1)
        listener.settimeout(TIMEOUT_SECONDS)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(TIMEOUT_SECONDS)
            while True:
                data = connection.recv(len(CHUNK))
                if not data:
                    break
                digest.update(data)
                received += len(data)
            connection.sendall(digest.hexdigest().encode("ascii"))
    if received != TOTAL_BYTES:
        raise SystemExit(f"receiver got {received} bytes, expected {TOTAL_BYTES}")


def sender() -> None:
    digest = hashlib.sha256()
    started = time.monotonic()
    with socket.create_connection(("10.20.1.1", PORT), timeout=TIMEOUT_SECONDS) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        sent = 0
        while sent < TOTAL_BYTES:
            take = min(len(CHUNK), TOTAL_BYTES - sent)
            block = CHUNK[:take]
            connection.sendall(block)
            digest.update(block)
            sent += take
        connection.shutdown(socket.SHUT_WR)
        response = b""
        while len(response) < 64:
            part = connection.recv(64 - len(response))
            if not part:
                raise SystemExit("receiver closed before returning the digest")
            response += part
    elapsed = time.monotonic() - started
    if response.decode("ascii") != digest.hexdigest():
        raise SystemExit("overlay payload digest mismatch")
    if elapsed <= 0:
        raise SystemExit("invalid monotonic elapsed time")
    result = {
        "bytes": sent,
        "elapsed_seconds": round(elapsed, 6),
        "throughput_mbps": round(sent * 8 / elapsed / 1_000_000, 3),
        "sha256": digest.hexdigest(),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"receive", "send"}:
        raise SystemExit("usage: netns_overlay_perf.py receive|send")
    if sys.argv[1] == "receive":
        receiver()
    else:
        sender()
