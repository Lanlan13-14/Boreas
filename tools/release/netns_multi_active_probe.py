#!/usr/bin/env python3
"""Persistent TCP traffic across an owned underlay socket loss and replacement."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
from pathlib import Path
import socket
import sys
import time

PORT = 18082
TIMEOUT = 12
BYTES = 32 * 1024
LOST_CHALLENGE = 255


def payload(origin, flow, phase):
    seed = f"boreas-multi-active:{origin}:{flow}:{phase}".encode()
    return hashlib.shake_256(seed).digest(BYTES)


def read_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        block = conn.recv(size - len(result))
        if not block:
            raise ValueError("TCP flow ended before its payload was complete")
        result.extend(block)
    return result


def marker(work, name, value="ok\n"):
    path = work / name
    temporary = path.with_suffix(".tmp")
    temporary.write_text(value)
    temporary.replace(path)


def control(work, name):
    path = work / name
    deadline = time.monotonic() + 25
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise ValueError(f"timed out waiting for {name}")
        time.sleep(0.02)
    return int(path.read_text())


def serve_flow(conn, peer, expected_flow, original, work):
    with conn:
        conn.settimeout(30)
        while header := conn.recv(2):
            if len(header) == 1:
                header += read_exact(conn, 1)
            flow, phase = header
            if flow != expected_flow:
                raise ValueError(f"unexpected flow on the same TCP socket: {flow}")
            if phase == LOST_CHALLENGE:
                marker(work, "lost-delivered")
                raise ValueError("lost TCP flow was delivered after replacement")
            data = read_exact(conn, BYTES)
            if data != payload(peer, flow, phase):
                raise ValueError(f"flow {flow} phase {phase} payload mismatch")
            conn.sendall(hashlib.sha256(data).digest())
            if not original or phase == 2:
                return


def serve(local, peer, lanes, work):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(35)
        listener.bind((local, PORT))
        listener.listen(lanes)
        with ThreadPoolExecutor(max_workers=lanes * 2) as threads:
            futures = []
            connections = []
            for flow in range(lanes * 2):
                conn, addr = listener.accept()
                if addr[0] != peer:
                    conn.close()
                    raise ValueError("unexpected source VIP")
                connections.append(conn)
                futures.append(threads.submit(serve_flow, conn, peer, flow, flow < lanes, work))
            # Keep the original socket open throughout the negative assertion.
            lost = control(work, "degraded") - 1
            control(work, "finish")
            try:
                connections[lost].shutdown(socket.SHUT_RDWR)
            except OSError:
                if not futures[lost].done():
                    raise
            for future in futures:
                future.result(timeout=5)
            if (work / "lost-delivered").exists():
                raise ValueError("a lost original flow delivered application bytes")


def open_flow(stack, local, peer):
    conn = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(TIMEOUT)
    conn.bind((local, 0))
    conn.connect((peer, PORT))
    return conn


def exchange(conn, origin, flow, phase):
    data = payload(origin, flow, phase)
    conn.sendall(bytes([flow, phase]) + data)
    if read_exact(conn, 32) != hashlib.sha256(data).digest():
        raise ValueError(f"flow {flow} phase {phase} reply digest mismatch")


def exercise(local, peer, lanes, work):
    with ExitStack() as stack:
        # Only this endpoint initiates TCP. The initial SYNs advance the pool
        # cursor in ordinal order, with one persistent tuple per ready lane.
        original = [open_flow(stack, local, peer) for _ in range(lanes)]
        for flow, conn in enumerate(original):
            exchange(conn, local, flow, 0)
        marker(work, "baseline-done")
        lost = control(work, "degraded") - 1
        if not 0 <= lost < lanes:
            raise ValueError("invalid lost lane ordinal")
        for flow, conn in enumerate(original):
            if flow != lost:
                exchange(conn, local, flow, 1)
        marker(work, "degraded-done")
        control(work, "replaced")
        for flow, conn in enumerate(original):
            if flow != lost:
                exchange(conn, local, flow, 2)
        fresh = [open_flow(stack, local, peer) for _ in range(lanes)]
        for flow, conn in enumerate(fresh, start=lanes):
            exchange(conn, local, flow, 3)
        marker(work, "fresh-done")
        # No raw packets: write on the existing OS-owned socket, allowing
        # normal kernel retransmissions and demanding no delivery/reply.
        conn = original[lost]
        conn.sendall(bytes([lost, LOST_CHALLENGE]) + payload(local, lost, LOST_CHALLENGE))
        conn.settimeout(2)
        try:
            conn.recv(32)
        except TimeoutError:
            if (work / "lost-delivered").exists():
                raise ValueError("lost original TCP flow reached the server") from None
        else:
            raise ValueError("lost original TCP flow received data or EOF through the overlay")
        marker(work, "finish", "1\n")


def main(mode, local, peer, lanes, work):
    fn = {"serve": serve, "exercise": exercise}[mode]
    fn(local, peer, int(lanes), Path(work))
    print(f"multi_active_verified mode={mode} local={local} lanes={lanes}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise SystemExit(f"multi-active probe: {exc}") from None
