#!/usr/bin/env python3
"""Bidirectional integrity and throughput probe for the netns overlay smoke.

Runs a receiver on the Core VIP and a sender on the Edge VIP. Only standard
library sockets are used; no host sysctl, route, or TLS setting is changed.

The sender's phase timings are diagnostic intervals inside the existing
end-to-end measurement. They are not a claim of payload-only steady-state
throughput; `throughput_mbps` keeps its original connect-through-digest
denominator and remains the smoke regression bound. A phase field is null when
that interval is not measurable, so a diagnostic problem never turns an
otherwise successful probe into a failure.
"""

import hashlib
import json
import math
import os
import socket
import sys
import time

CHUNK = bytes((index % 251 for index in range(64 * 1024)))
TOTAL_BYTES = int(os.environ.get("BOREAS_PERF_BYTES", str(8 * 1024 * 1024)))
if TOTAL_BYTES <= 0 or TOTAL_BYTES > 64 * 1024 * 1024:
    raise ValueError("BOREAS_PERF_BYTES must be in 1..=67108864")
PORT = 18080
TIMEOUT_SECONDS = 30


def _interval(start: float, end: float) -> float | None:
    """Return a finite, nonnegative monotonic interval, or None if unusable."""

    seconds = end - start
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return seconds


def _mbps(byte_count: int, seconds: float | None) -> float | None:
    """Return a finite, nonnegative interval rate, or None if unavailable."""

    if seconds is None or seconds <= 0:
        return None
    rate = byte_count * 8 / seconds / 1_000_000
    if not math.isfinite(rate) or rate < 0:
        return None
    return round(rate, 3)


def _rounded_seconds(seconds: float | None) -> float | None:
    """Round a measured interval for JSON, preserving None as unavailable."""

    return None if seconds is None else round(seconds, 6)


def receiver(local_ip: str) -> None:
    digest = hashlib.sha256()
    received = 0
    first_byte_at = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((local_ip, PORT))
        listener.listen(1)
        listener.settimeout(TIMEOUT_SECONDS)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(TIMEOUT_SECONDS)
            while True:
                data = connection.recv(len(CHUNK))
                if not data:
                    break
                if first_byte_at is None:
                    first_byte_at = time.monotonic()
                digest.update(data)
                received += len(data)
            finished = time.monotonic()
            connection.sendall(digest.hexdigest().encode("ascii"))
    first_byte_to_eof = None
    if first_byte_at is not None:
        first_byte_to_eof = _rounded_seconds(
            _interval(first_byte_at, finished)
        )
    # This diagnostic line is receiver-only and deliberately goes to stderr:
    # the smoke parses the sender's stdout as one JSON object.
    print(
        json.dumps(
            {
                "role": "receiver",
                "bytes": received,
                "first_byte_to_eof_seconds": first_byte_to_eof,
                "sha256": digest.hexdigest(),
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    if received != TOTAL_BYTES:
        raise SystemExit(f"receiver got {received} bytes, expected {TOTAL_BYTES}")


def sender(local_ip: str, peer_ip: str) -> None:
    digest = hashlib.sha256()
    started = time.monotonic()
    with socket.create_connection(
        (peer_ip, PORT), timeout=TIMEOUT_SECONDS, source_address=(local_ip, 0)
    ) as connection:
        connected = time.monotonic()
        connection.settimeout(TIMEOUT_SECONDS)
        sent = 0
        while sent < TOTAL_BYTES:
            take = min(len(CHUNK), TOTAL_BYTES - sent)
            block = CHUNK[:take]
            connection.sendall(block)
            digest.update(block)
            sent += take
        connection.shutdown(socket.SHUT_WR)
        sent_at = time.monotonic()
        response = b""
        while len(response) < 64:
            part = connection.recv(64 - len(response))
            if not part:
                raise SystemExit("receiver closed before returning the digest")
            response += part
    finished = time.monotonic()
    elapsed = finished - started
    if response.decode("ascii") != digest.hexdigest():
        raise SystemExit("overlay payload digest mismatch")
    if elapsed <= 0:
        raise SystemExit("invalid monotonic elapsed time")
    connect_seconds = _interval(started, connected)
    send_seconds = _interval(connected, sent_at)
    digest_seconds = _interval(sent_at, finished)
    result = {
        "bytes": sent,
        "connect_seconds": _rounded_seconds(connect_seconds),
        "digest_seconds": _rounded_seconds(digest_seconds),
        "elapsed_seconds": round(elapsed, 6),
        "payload_send_mbps": _mbps(sent, send_seconds),
        "send_seconds": _rounded_seconds(send_seconds),
        "sha256": digest.hexdigest(),
        "throughput_mbps": round(sent * 8 / elapsed / 1_000_000, 3),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in {"receive", "send"}:
        raise SystemExit("usage: netns_overlay_perf.py receive|send LOCAL_IP PEER_IP")
    if sys.argv[1] == "receive":
        receiver(sys.argv[2])
    else:
        sender(sys.argv[2], sys.argv[3])
