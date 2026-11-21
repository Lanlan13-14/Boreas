#!/usr/bin/env python3
"""Bounded IPv4/TCP integrity probe; run one instance in each fixture namespace."""

import hashlib
import socket
import sys

PORT = 18082
FLOWS = 4
TIMEOUT = 15
BYTES = 32 * 1024


def payload(origin, flow):
    return hashlib.shake_256(f"boreas-multi-active:{origin}:{flow}".encode()).digest(BYTES)


def read_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        block = conn.recv(size - len(result))
        if not block:
            raise ValueError("TCP flow ended before its payload was complete")
        result.extend(block)
    return result


def receive(listener, peer):
    seen = set()
    for _ in range(FLOWS):
        conn, addr = listener.accept()
        with conn:
            conn.settimeout(TIMEOUT)
            flow = read_exact(conn, 1)[0]
            if addr[0] != peer or not 0 <= flow < FLOWS or flow in seen:
                raise ValueError("incorrect source VIP or duplicate flow")
            data = read_exact(conn, BYTES)
            if data != payload(peer, flow):
                raise ValueError(f"flow {flow} payload mismatch")
            conn.sendall(hashlib.sha256(data).digest())
            seen.add(flow)


def send_all(local, peer):
    # Open all tuples before sending payloads so their independent application
    # TCP connections overlap even on a fast runner with no netem.
    from contextlib import ExitStack

    with ExitStack() as stack:
        connections = []
        for flow in range(FLOWS):
            conn = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.settimeout(TIMEOUT)
            conn.bind((local, 0))
            conn.connect((peer, PORT))
            connections.append(conn)
        for flow, conn in enumerate(connections):
            conn.sendall(bytes([flow]) + payload(local, flow))
        for flow, conn in enumerate(connections):
            if read_exact(conn, 32) != hashlib.sha256(payload(local, flow)).digest():
                raise ValueError(f"flow {flow} acknowledgement digest mismatch")


def main(mode, local, peer):
    if mode == "receive":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(TIMEOUT)
            listener.bind((local, PORT))
            listener.listen(FLOWS)
            receive(listener, peer)
    elif mode == "send":
        send_all(local, peer)
    else:
        raise ValueError("expected receive or send")
    print(f"multi_active_verified mode={mode} local={local} flows={FLOWS} payload_bytes={FLOWS * BYTES}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (OSError, TypeError, ValueError) as exc:
        raise SystemExit(f"multi-active probe: {exc}") from None
