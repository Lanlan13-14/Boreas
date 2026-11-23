#!/usr/bin/env python3
"""Opt-in C-tier probe: fixed receiver windows, one TCP flow, bounded memory.

No thresholds in this helper replace the existing smoke gate. SHA-256 is
streamed for the entire connection; receiver windows exclude warm-up and
report the actual observation interval (including scheduler delay).
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

CHUNK = bytes(i % 251 for i in range(65536))
HEADER = struct.Struct("!4sddQ")
MAX_WINDOW = 60.0


def checked_seconds(value):
    value = float(value)
    if not math.isfinite(value) or not 0 < value <= 900:
        raise ValueError("seconds must be finite in (0,900]")
    return value


def summarize_windows(rows):
    if not rows:
        raise ValueError("no receiver windows")
    rates = []
    for row in rows:
        seconds, count = row["seconds"], row["bytes"]
        if not math.isfinite(seconds) or seconds <= 0 or count < 0:
            raise ValueError("invalid receiver window")
        rates.append(count * 8 / seconds / 1e6)
    return {"minimum_window_mbps": min(rates), "windows_mbps": rates,
            "all_windows_gigabit": all(rate >= 1000 for rate in rates)}


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError("truncated control message")
        result.extend(part)
    return bytes(result)


def receive(address, port, output, ready):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(1)
        listener.settimeout(20)
        Path(ready).touch()
        sock, peer = listener.accept()
        with sock:
            sock.settimeout(20)
            magic, warm, duration, limit = HEADER.unpack(exact(sock, HEADER.size))
            if magic != b"BSD1" or not (0 <= warm <= 60) or not (0 < duration <= 900) or limit > 10**10:
                raise ValueError("invalid bounded probe header")
            digest = hashlib.sha256()
            count, measured = 0, 0
            rows = []
            started = time.monotonic()
            measure_start = started + warm
            end = measure_start + duration
            window_start = measure_start
            last = started
            while True:
                data = sock.recv(65536)
                now = time.monotonic()
                if not data:
                    break
                digest.update(data)
                count += len(data)
                # Whole recv returns timestamped in each window; never claims
                # wire-arrival timestamps or subdivides an unobserved interval.
                if measure_start <= now < end:
                    measured += len(data)
                if now >= min(window_start + MAX_WINDOW, end) and window_start < end:
                    rows.append({"seconds": now-window_start, "bytes": measured,
                                 "scheduled_seconds": min(MAX_WINDOW, end-window_start)})
                    measured = 0
                    window_start = now
                last = now
            if window_start < end:
                rows.append({"seconds": max(last, time.monotonic())-window_start,
                             "bytes": measured, "scheduled_seconds": end-window_start})
            valid = count > 0 and last >= end and all(row["seconds"] > 0 for row in rows)
            result = {"schema": 1, "scope": "single-core-capacity-diagnostic-only",
                      "peer": peer[0], "bytes": count, "sha256": digest.hexdigest(),
                      "warmup_seconds": warm, "requested_seconds": duration,
                      "complete": valid, "receiver_windows": rows}
            if valid:
                result.update(summarize_windows(rows))
            payload = json.dumps(result, sort_keys=True).encode()
            sock.sendall(struct.pack("!I", len(payload)) + payload)
            Path(output).write_text(json.dumps(result, sort_keys=True) + "\n")
            if not valid:
                raise RuntimeError("receiver did not observe complete measurement duration")


def send(local, peer, port, warm, duration, rate, output):
    with socket.socket() as sock:
        sock.settimeout(20)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.bind((local, 0))
        sock.connect((peer, port))
        sock.sendall(HEADER.pack(b"BSD1", warm, duration, rate))
        digest = hashlib.sha256()
        count = 0
        started = time.monotonic()
        # Extra tail ensures the receiver observes the last measurement bound.
        deadline = started + warm + duration + 0.15
        while time.monotonic() < deadline:
            sock.sendall(CHUNK)
            digest.update(CHUNK)
            count += len(CHUNK)
            if rate:
                delay = started + count * 8 / rate - time.monotonic()
                if delay > 0:
                    time.sleep(min(delay, 1.0))
        sock.shutdown(socket.SHUT_WR)
        size, = struct.unpack("!I", exact(sock, 4))
        if size > 65536:
            raise ValueError("oversized receiver report")
        result = json.loads(exact(sock, size))
        if result["bytes"] != count or result["sha256"] != digest.hexdigest() or not result["complete"]:
            raise AssertionError("payload integrity/window completion mismatch")
        result["integrity"] = "sha256-and-exact-byte-count"
        Path(output).write_text(json.dumps(result, sort_keys=True) + "\n")


def proc_stat(text):
    fields = text[text.rindex(")")+2:].split()
    return {"user": int(fields[11]), "system": int(fields[12]),
            "starttime": int(fields[19]), "rss_pages": int(fields[21])}


def snapshot(pids):
    result = {"time": time.monotonic(), "processes": {}}
    for pid in pids:
        root = Path("/proc") / str(pid)
        proc = proc_stat((root/"stat").read_text())
        proc["exe"] = os.readlink(root/"exe")
        proc["threads"] = {}
        for tid in sorted(os.listdir(root/"task")):
            status = (root/"task"/tid/"status").read_text()
            affinity = next(line.split(":",1)[1].strip() for line in status.splitlines() if line.startswith("Cpus_allowed_list:"))
            stat = proc_stat((root/"task"/tid/"stat").read_text())
            stat["affinity"] = affinity
            proc["threads"][tid] = stat
        result["processes"][str(pid)] = proc
    for name in ["stat", "softirqs"]:
        result[name] = Path("/proc", name).read_text()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("receive")
    server.add_argument("address"); server.add_argument("port",type=int)
    server.add_argument("output"); server.add_argument("ready")
    client = sub.add_parser("send")
    for key in ["local","peer"]: client.add_argument(key)
    client.add_argument("port",type=int); client.add_argument("warm",type=float)
    client.add_argument("duration",type=checked_seconds); client.add_argument("rate",type=int)
    client.add_argument("output")
    sample = sub.add_parser("snapshot")
    sample.add_argument("output"); sample.add_argument("pids",type=int,nargs="+")
    args = vars(parser.parse_args()); mode=args.pop("mode")
    if mode == "snapshot": Path(args["output"]).write_text(json.dumps(snapshot(args["pids"]),sort_keys=True)+"\n")
    elif mode == "receive": receive(**args)
    else:
        if not 0 <= args["warm"] <= 60 or not 0 <= args["rate"] <= 10**10: raise ValueError("warm/rate bound")
        send(**args)

if __name__ == "__main__":
    main()
