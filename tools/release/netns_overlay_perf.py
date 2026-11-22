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

The overlay receiver also reports `first_second_bytes` and
`first_second_status` for one stream. Bytes are counted in whole nonempty
`recv` returns timestamped in [first nonempty return, first return + 1 s).
This is application-observed delivery, affected by read batching and receiver
scheduling, not wire arrival or sender goodput. `complete` means a later read
(possibly EOF) reached the deadline, not that the sender offered load for the
whole window. An earlier EOF gives `incomplete` with the observed byte count.
`no-payload` and `unavailable` (invalid clock sample while observing the
window) have null counts. Neither peer waits for the window. No cross-process
clock is used.

The `sample`/`summarize` modes are diagnostic-only. `sample` runs inside one
network namespace and periodically records `ss -tin` TCP_INFO for the underlay
pair plus `tc -s qdisc` and `ip -s link` counters; `summarize` turns that NDJSON
into bounded key=value evidence. They assert no threshold, change no probe byte,
deadline or gate, and never retry. Those TCP_INFO fields describe the underlay
outer-TLS socket, not overlay, E2E or application latency.

The `baseline-receive`/`baseline-send` modes run the same payload generator and
SHA-256 check over direct TCP on a distinct port. They are a separate diagnostic
for the caller's namespace(s), not part of the overlay probe, and they never
read the throughput gate. `compare` prints both denominators and ratios without
turning any overlay result green or red.

`multistream-receive`/`multistream-send` are a separate, same-candidate
application TCP probe. Each round holds the total measured payload constant,
primes every socket with a 64 KiB write, and starts measured bulk writes only
once all sockets in that direction have acknowledged the warm-up.
One receiver process per direction observes one [first payload recv, +1 s)
window for all its flows; different directions and rounds have separate clocks
and are never summed. Like the legacy diagnostic, observations count whole
recv returns (not wire arrivals), and EOF can close a window. The opt-in CLI
requires a complete window, but completeness does not prove sustained offered
load or enforce a speedup. Flows are application sockets, not TLS circuits.
"""

from contextlib import ExitStack
import hashlib
import json
import math
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time

CHUNK = bytes((index % 251 for index in range(64 * 1024)))
# Ordinary connectivity smoke uses a short payload. Longer performance
# experiments pass an explicit payload and matching fixture lifetime.
TOTAL_BYTES = int(os.environ.get("BOREAS_PERF_BYTES", str(8 * 1024 * 1024)))
if TOTAL_BYTES <= 0 or TOTAL_BYTES > 1024 * 1024 * 1024:
    raise ValueError("BOREAS_PERF_BYTES must be in 1..=1073741824")
PORT = 18080
TIMEOUT_SECONDS = float(os.environ.get("BOREAS_PERF_TIMEOUT_SECONDS", "120"))
if not math.isfinite(TIMEOUT_SECONDS) or TIMEOUT_SECONDS <= 0 or TIMEOUT_SECONDS > 900:
    raise ValueError("BOREAS_PERF_TIMEOUT_SECONDS must be in (0, 900]")

# Direct-TCP baseline bounds. The baseline is a separate, caller-invoked
# diagnostic: same payload generator and SHA-256 check, distinct port, fixed
# byte count, one attempt and the same 30 s socket timeout as the overlay probe.
# It reads the same BOREAS_PERF_BYTES value but never reads the throughput gate.
BASELINE_PORT = 18081
BASELINE_TIMEOUT_SECONDS = 30
BASELINE_SCOPE = "underlay-direct-tcp-baseline"
BASELINE_ACCEPTANCE = "never"

# Diagnostic sampler bounds. The sampler is a fixed-rate, self-terminating
# background reader; these are collection bounds, never acceptance windows.
TELEMETRY_INTERVAL_MS = 250
TELEMETRY_SLOW_EVERY = 4
TELEMETRY_MAX_SAMPLES = 240
TELEMETRY_MAX_SOCKETS_PER_SAMPLE = 32
TELEMETRY_COMMAND_TIMEOUT_SECONDS = 5


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


def _to_int(text: str | None) -> int | None:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _to_float(text: str | None) -> float | None:
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _rate_bps(text: str | None) -> float | None:
    """Parse an `ss` rate token such as `25473600bps` or `24.6Mbps`."""

    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kKmMgG]?)(?:bps)?", text or "")
    if match is None:
        return None
    value = _to_float(match.group(1))
    if value is None:
        return None
    scale = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9}[match.group(2).lower()]
    return value * scale


def _parse_tcp_info(record: dict, line: str) -> None:
    """Attach only the TCP_INFO fields the kernel actually printed."""

    tokens = line.split()
    if tokens and re.fullmatch(r"[a-z][a-z0-9_-]{0,15}", tokens[0]) and len(tokens) > 1 and tokens[1].startswith("wscale:"):
        record["congestion"] = tokens[0]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "app_limited":
            record["app_limited"] = True
            index += 1
            continue
        if token in ("delivery_rate", "pacing_rate", "send"):
            field = {
                "delivery_rate": "delivery_rate_bps",
                "pacing_rate": "pacing_rate_bps",
                "send": "send_rate_bps",
            }[token]
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            record[field] = _rate_bps(following)
            index += 2
            continue
        key, separator, value = token.partition(":")
        if separator:
            if key == "rtt":
                rtt, _, rttvar = value.partition("/")
                record["rtt_ms"] = _to_float(rtt)
                record["rttvar_ms"] = _to_float(rttvar) if rttvar else None
            elif key == "rto":
                record["rto_ms"] = _to_float(value)
            elif key == "cwnd":
                record["cwnd"] = _to_int(value)
            elif key == "ssthresh":
                record["ssthresh"] = _to_int(value)
            elif key == "retrans":
                current, _, total = value.partition("/")
                record["retrans_current"] = _to_int(current)
                record["retrans_total"] = _to_int(total if total else current)
            elif key == "bytes_acked":
                record["bytes_acked"] = _to_int(value)
            elif key == "bytes_received":
                record["bytes_received"] = _to_int(value)
            elif key in ("bytes_retrans", "notsent", "snd_wnd", "rcv_space"):
                record[key] = _to_int(value)
            elif key in ("busy", "rwnd_limited", "sndbuf_limited"):
                match = re.fullmatch(r"(\d+)ms(?:\(\d+(?:\.\d+)?%\))?", value)
                if match:
                    record[key + "_ms"] = int(match.group(1))
            elif key == "unacked":
                record["unacked"] = _to_int(value)
            elif key == "minrtt":
                record["minrtt_ms"] = _to_float(value)
        index += 1


def parse_ss_tcpinfo(text: str) -> list[dict]:
    """Parse `ss -tin` output into one record per socket row.

    Each non-indented socket row starts a record and the immediately following
    indented TCP_INFO row enriches it. Header rows, warnings and malformed
    tokens are ignored, so a parser gap can never invent a field or a socket.
    """

    records: list[dict] = []
    current: dict | None = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if current is not None:
                _parse_tcp_info(current, line)
            continue
        fields = line.split()
        if len(fields) < 5 or fields[0] == "State":
            current = None
            continue
        current = {"state": fields[0], "local": fields[3], "peer": fields[4]}
        records.append(current)
    return records


_QDISC_SENT = re.compile(
    r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+) requeues (\d+)\)"
)
_QDISC_BACKLOG = re.compile(r"backlog (\d+)b (\d+)p")


def parse_qdisc(text: str) -> dict:
    """Parse the counters printed by `tc -s qdisc show dev <device>`."""

    stats: dict = {}
    match = _QDISC_SENT.search(text or "")
    if match is not None:
        (
            stats["sent_bytes"],
            stats["sent_packets"],
            stats["dropped"],
            stats["overlimits"],
            stats["requeues"],
        ) = (int(value) for value in match.groups())
    match = _QDISC_BACKLOG.search(text or "")
    if match is not None:
        stats["backlog_bytes"], stats["backlog_packets"] = (
            int(value) for value in match.groups()
        )
    return stats


_LINK_DIRECTION = re.compile(r"^\s*(RX|TX):\s+bytes\s+packets")
_LINK_COUNTERS = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def parse_link(text: str) -> dict:
    """Parse the first RX/TX counter row of `ip -s link show <tun>`."""

    stats: dict = {}
    direction: str | None = None
    for line in (text or "").splitlines():
        header = _LINK_DIRECTION.match(line)
        if header is not None:
            direction = header.group(1).lower()
            continue
        if direction is None or not line.strip():
            continue
        values = _LINK_COUNTERS.match(line)
        if values is not None:
            fields = [int(value) for value in values.groups()]
            stats[direction + "_bytes"] = fields[0]
            stats[direction + "_packets"] = fields[1]
            stats[direction + "_errors"] = fields[2]
            stats[direction + "_dropped"] = fields[3]
        direction = None
    return stats


def _receive_stream(
    local_ip: str, port: int, timeout: float, *, measure_first_second: bool = False
) -> dict:
    """Receive one bounded stream and return its digest evidence."""

    digest = hashlib.sha256()
    received = 0
    first_byte_at = None
    first_second_status = "no-payload" if measure_first_second else None
    first_second_bytes = None
    last_observed_at = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((local_ip, port))
        listener.listen(1)
        listener.settimeout(timeout)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(timeout)
            while True:
                data = connection.recv(len(CHUNK))
                # Timestamp before hashing. After the window closes, only EOF
                # needs another timestamp for the existing duration diagnostic.
                if (
                    not data
                    or first_byte_at is None
                    or first_second_status == "incomplete"
                ):
                    observed_at = time.monotonic()
                    if data and first_byte_at is None:
                        first_byte_at = observed_at
                        if measure_first_second:
                            if math.isfinite(observed_at):
                                last_observed_at = observed_at
                                first_second_bytes = len(data)
                                first_second_status = "incomplete"
                            else:
                                first_second_status = "unavailable"
                    elif first_second_status == "incomplete":
                        window_elapsed = _interval(first_byte_at, observed_at)
                        if window_elapsed is None or observed_at < last_observed_at:
                            first_second_bytes = None
                            first_second_status = "unavailable"
                        elif window_elapsed >= 1.0:
                            first_second_status = "complete"
                        else:
                            first_second_bytes += len(data)
                            last_observed_at = observed_at
                if not data:
                    finished = observed_at
                    break
                digest.update(data)
                received += len(data)
            connection.sendall(digest.hexdigest().encode("ascii"))
    first_byte_to_eof = None
    if first_byte_at is not None:
        first_byte_to_eof = _rounded_seconds(_interval(first_byte_at, finished))
    result = {
        "role": "receiver",
        "bytes": received,
        "first_byte_to_eof_seconds": first_byte_to_eof,
        "sha256": digest.hexdigest(),
    }
    if measure_first_second:
        result.update(
            first_second_bytes=first_second_bytes,
            first_second_status=first_second_status,
        )
    return result


def _send_stream(
    local_ip: str,
    peer_ip: str,
    port: int,
    timeout: float,
    failure_label: str = "overlay",
) -> dict:
    """Send one bounded stream and verify the receiver's digest."""

    digest = hashlib.sha256()
    started = time.monotonic()
    with socket.create_connection(
        (peer_ip, port), timeout=timeout, source_address=(local_ip, 0)
    ) as connection:
        connected = time.monotonic()
        connection.settimeout(timeout)
        # The payload clock starts when the socket is ready to take bytes.
        # Reusing the connect timestamp keeps the interval count stable for the
        # probe's own tests and excludes only the handshake, not the send.
        first_byte_at = connected
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
                raise SystemExit(
                    f"{failure_label} receiver closed before returning the digest"
                )
            response += part
    finished = time.monotonic()
    elapsed = finished - started
    if response.decode("ascii") != digest.hexdigest():
        raise SystemExit(f"{failure_label} payload digest mismatch")
    if elapsed <= 0:
        raise SystemExit("invalid monotonic elapsed time")
    connect_seconds = _interval(started, connected)
    send_seconds = _interval(connected, sent_at)
    digest_seconds = _interval(sent_at, finished)
    # Steady rate is first byte to last byte. The connect and the digest
    # round trip are reported separately, so a long handshake cannot be
    # mistaken for a slow transfer and cannot hide one either.
    payload_seconds = _interval(first_byte_at, sent_at) if first_byte_at else None
    return {
        "bytes": sent,
        "connect_seconds": _rounded_seconds(connect_seconds),
        "digest_seconds": _rounded_seconds(digest_seconds),
        "elapsed_seconds": round(elapsed, 6),
        "payload_send_mbps": _mbps(sent, payload_seconds),
        "send_seconds": _rounded_seconds(send_seconds),
        "sha256": digest.hexdigest(),
        "throughput_mbps": round(sent * 8 / elapsed / 1_000_000, 3),
    }


def receiver(local_ip: str) -> None:
    result = _receive_stream(
        local_ip, PORT, TIMEOUT_SECONDS, measure_first_second=True
    )
    # This diagnostic line is receiver-only and deliberately goes to stderr:
    # the smoke parses the sender's stdout as one JSON object.
    print(json.dumps(result, sort_keys=True), file=sys.stderr)
    if result["bytes"] != TOTAL_BYTES:
        raise SystemExit(
            f"receiver got {result['bytes']} bytes, expected {TOTAL_BYTES}"
        )


def sender(local_ip: str, peer_ip: str) -> None:
    result = _send_stream(local_ip, peer_ip, PORT, TIMEOUT_SECONDS)
    print(json.dumps(result, sort_keys=True))


def _baseline_fields(role: str) -> dict:
    """Label a direct-TCP baseline result without inventing a gate."""

    return {
        "acceptance": BASELINE_ACCEPTANCE,
        "denominator": "connect-through-digest",
        "gate": "not-applicable",
        "payload_denominator": "connect-to-shutdown-write",
        "role": role,
        "scope": BASELINE_SCOPE,
    }


def baseline_receiver(local_ip: str) -> None:
    """Receive the direct-TCP baseline in the caller's namespace."""

    result = _receive_stream(local_ip, BASELINE_PORT, BASELINE_TIMEOUT_SECONDS)
    result.update(_baseline_fields("baseline-receiver"))
    print(json.dumps(result, sort_keys=True), file=sys.stderr)
    if result["bytes"] != TOTAL_BYTES:
        raise SystemExit(
            f"baseline receiver got {result['bytes']} bytes, "
            f"expected {TOTAL_BYTES}"
        )


def baseline_sender(local_ip: str, peer_ip: str) -> None:
    """Send the direct-TCP baseline in the caller's namespace."""

    result = _send_stream(
        local_ip,
        peer_ip,
        BASELINE_PORT,
        BASELINE_TIMEOUT_SECONDS,
        failure_label="baseline",
    )
    result.update(_baseline_fields("baseline-sender"))
    print(json.dumps(result, sort_keys=True))


MULTISTREAM_PORT = 18082
_MULTISTREAM_MAX_BYTES = 64 * 1024 * 1024
_MULTISTREAM_READY = b"ready"
_MULTISTREAM_PRIME = b"boreas-app-stream-v1:"
_MULTISTREAM_SECOND_NS = 1_000_000_000


class _SharedReceiverWindow:
    """One receiver-local clock and origin across every flow in this round."""

    def __init__(self, flows: int):
        self.start = None
        self.complete = False
        self.bytes = [0] * flows
        self.first = [None] * flows

    def observe(self, flow: int, size: int, at: int) -> None:
        if size and self.start is None:
            self.start = at
        if self.start is None:
            return
        offset = at - self.start
        if size and self.first[flow] is None:
            self.first[flow] = offset
        if offset >= _MULTISTREAM_SECOND_NS:
            self.complete = True
        elif size:
            self.bytes[flow] += size

    @property
    def status(self) -> str:
        if self.start is None:
            return "no-payload"
        return "complete" if self.complete else "incomplete"


def _multistream_remaining(deadline: int) -> float:
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0:
        raise TimeoutError("multistream round deadline expired")
    return remaining / _MULTISTREAM_SECOND_NS


def _multistream_read(connection: socket.socket, size: int, deadline: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        connection.settimeout(_multistream_remaining(deadline))
        part = connection.recv(size - len(data))
        if not part:
            raise ValueError("multistream control message truncated")
        data.extend(part)
    return bytes(data)


def _multistream_write(connection: socket.socket, data: bytes, deadline: int) -> None:
    connection.settimeout(_multistream_remaining(deadline))
    connection.sendall(data)


def _multistream_evidence(counts: list[int], hashes: list) -> tuple[dict, bytes]:
    # Domain-separated commitment to ordered (flow ID, exact byte count,
    # payload SHA-256) records. Both peers compute it independently; it is not
    # SHA-256 of arrival order or of a concatenation of the raw TCP payloads.
    frame = b"".join(
        struct.pack("!BQ32s", flow, count, digest.digest())
        for flow, (count, digest) in enumerate(zip(counts, hashes))
    )
    total = sum(counts)
    aggregate = hashlib.sha256(b"boreas-multistream-v1\0" + frame).digest()
    return {
        "scope": "same-candidate-overlay-application-tcp",
        "application_streams": len(counts),
        "warmup_bytes_per_flow": len(CHUNK),
        "bytes": total,
        "aggregate_sha256": aggregate.hex(),
        "flows": [
            {"id": flow, "bytes": count, "sha256": digest.hexdigest()}
            for flow, (count, digest) in enumerate(zip(counts, hashes))
        ],
    }, frame + struct.pack("!Q", total) + aggregate


def _multistream_payload(flow: int) -> memoryview:
    # Give each flow distinct content without allocating the whole transfer.
    return memoryview(CHUNK[flow:] + CHUNK[:flow])


def _multistream_transfer(
    connections: dict[int, socket.socket], per_flow: int, deadline: int, *, receive: bool
) -> tuple[dict, bytes]:
    flow_count = len(connections)
    counts = [0] * flow_count
    hashes = [hashlib.sha256() for _ in range(flow_count)]
    payloads = [_multistream_payload(flow) for flow in range(flow_count)]
    window = _SharedReceiverWindow(flow_count) if receive else None
    active = {connection: flow for flow, connection in connections.items()}
    for connection in active:
        connection.setblocking(False)
    while active:
        timeout = _multistream_remaining(deadline)
        reads, writes, _ = select.select(
            active if receive else [], [] if receive else active, [], timeout
        )
        if not (reads or writes):
            raise TimeoutError("multistream round deadline expired")
        # At most one chunk per ready socket in each pass. A single process
        # timestamps reads in observation order, without per-flow clocks.
        for connection in reads if receive else writes:
            _multistream_remaining(deadline)
            flow = active[connection]
            try:
                if receive:
                    data = connection.recv(min(len(CHUNK), per_flow - counts[flow] + 1))
                    window.observe(flow, len(data), time.monotonic_ns())
                    if not data:
                        if counts[flow] != per_flow:
                            raise ValueError(
                                f"multistream flow {flow} ended at {counts[flow]} bytes, "
                                f"expected {per_flow}"
                            )
                        del active[connection]
                        continue
                    taken = len(data)
                else:
                    offset = counts[flow] % len(CHUNK)
                    data = payloads[flow][offset:offset + per_flow - counts[flow]]
                    taken = connection.send(data)
                    if taken == 0:
                        raise ValueError(f"multistream flow {flow} made no send progress")
            except BlockingIOError:
                continue
            counts[flow] += taken
            if counts[flow] > per_flow:
                raise ValueError(f"multistream flow {flow} exceeded {per_flow} bytes")
            hashes[flow].update(data[:taken])
            if not receive and counts[flow] == per_flow:
                connection.shutdown(socket.SHUT_WR)
                del active[connection]
    result, evidence = _multistream_evidence(counts, hashes)
    if window is not None:
        result.update(
            first_second_bytes=sum(window.bytes) if window.start is not None else None,
            first_second_status=window.status,
            first_second_origin="first-payload-recv-across-flows",
            first_second_window_ns=_MULTISTREAM_SECOND_NS,
        )
        for flow, row in enumerate(result["flows"]):
            row["first_second_bytes"] = (
                window.bytes[flow] if window.start is not None else None
            )
            row["first_payload_offset_ns"] = window.first[flow]
    return result, evidence


def _multistream_verify(expected: bytes, reported: bytes) -> None:
    # The fixed-size read has already required the full frame. The trailer is
    # an eight-byte aggregate count followed by a 32-byte SHA-256 digest.
    if expected[:-40] != reported[:-40]:
        raise ValueError("multistream per-flow byte counts or SHA-256 mismatch")
    if expected[-40:-32] != reported[-40:-32]:
        raise ValueError("multistream aggregate byte count mismatch")
    if expected[-32:] != reported[-32:]:
        raise ValueError("multistream aggregate SHA-256 mismatch")


def _multistream_receive(local: str, flows: int, per_flow: int, deadline: int) -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((local, MULTISTREAM_PORT))
        listener.listen(flows)
        return _multistream_accept(listener, flows, per_flow, deadline)


def _multistream_accept(listener: socket.socket, flows: int, per_flow: int, deadline: int) -> dict:
    with ExitStack() as stack:
        connections = {}
        for _ in range(flows):
            listener.settimeout(_multistream_remaining(deadline))
            connection, _ = listener.accept()
            stack.enter_context(connection)
            prime = _multistream_read(connection, len(_MULTISTREAM_PRIME) + 1, deadline)
            flow = prime[-1]
            if prime[:-1] != _MULTISTREAM_PRIME or flow >= flows or flow in connections:
                raise ValueError("multistream invalid or duplicate flow ID")
            if _multistream_read(connection, len(CHUNK), deadline) != _multistream_payload(flow):
                raise ValueError(f"multistream flow {flow} warm-up mismatch")
            connections[flow] = connection
        # Finish priming all connections before any sender starts measured data.
        for connection in connections.values():
            _multistream_write(connection, _MULTISTREAM_READY, deadline)
        result, evidence = _multistream_transfer(connections, per_flow, deadline, receive=True)
        _multistream_write(connections[0], evidence, deadline)
        return result


def _multistream_send(local: str, peer: str, flows: int, per_flow: int, deadline: int) -> dict:
    with ExitStack() as stack:
        connections = {}
        for flow in range(flows):
            connection = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            connection.bind((local, 0))
            connection.settimeout(_multistream_remaining(deadline))
            connection.connect((peer, MULTISTREAM_PORT))
            connections[flow] = connection
        for flow, connection in connections.items():
            prime = _MULTISTREAM_PRIME + bytes([flow]) + bytes(_multistream_payload(flow))
            _multistream_write(connection, prime, deadline)
        for connection in connections.values():
            if _multistream_read(connection, len(_MULTISTREAM_READY), deadline) != _MULTISTREAM_READY:
                raise ValueError("multistream invalid ready acknowledgement")
        result, evidence = _multistream_transfer(connections, per_flow, deadline, receive=False)
        _multistream_verify(evidence, _multistream_read(connections[0], len(evidence), deadline))
        return result


def _multistream_cli(mode: str, args: list[str]) -> int:
    receive = mode == "multistream-receive"
    if len(args) != (2 if receive else 3) or args[0] not in ("1", "4"):
        peer_arg = "" if receive else " PEER_IPV4"
        raise SystemExit(f"usage: netns_overlay_perf.py {mode} 1|4 LOCAL_IPV4{peer_arg}")
    flows = int(args[0])
    try:
        for address in args[1:]:
            socket.inet_pton(socket.AF_INET, address)
        total = int(os.environ.get("BOREAS_MULTISTREAM_BYTES", str(32 * 1024 * 1024)))
        if not 4 <= total <= _MULTISTREAM_MAX_BYTES or total % 4:
            raise ValueError("BOREAS_MULTISTREAM_BYTES must be a multiple of four in 4..67108864")
        deadline = time.monotonic_ns() + int(TIMEOUT_SECONDS * _MULTISTREAM_SECOND_NS)
        if receive:
            result = _multistream_receive(args[1], flows, total // flows, deadline)
        else:
            result = _multistream_send(args[1], args[2], flows, total // flows, deadline)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"{mode}: {exc}") from None
    result["role"] = "receiver" if receive else "sender"
    print(json.dumps(result, sort_keys=True))
    if receive and result["first_second_status"] != "complete":
        raise SystemExit("multistream receiver did not observe a complete first-second window")
    return 0


def _run_bounded(argv: list[str], timeout: float) -> tuple[str | None, str | None]:
    """Run one read-only diagnostic command; never raise into the sampler."""

    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(0.2, min(TELEMETRY_COMMAND_TIMEOUT_SECONDS, timeout)),
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__
    if completed.returncode != 0:
        return completed.stdout, "exit-%d" % completed.returncode
    return completed.stdout, None


def _remaining_timeout(deadline: float) -> float:
    """Cap each command by the remaining sampler window, not just by 5 s."""

    return min(TELEMETRY_COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic())


def sampler(
    label: str,
    dev: str,
    tun: str,
    interval_ms: str | int,
    max_seconds: str | float,
    stop_path: str,
) -> int:
    """Bounded namespace-local underlay telemetry; diagnostic only.

    Runs inside one disposable namespace, so `ss`/`tc`/`ip` see only that
    namespace. Every tick records `ss -tin`; every fourth tick also records the
    underlay qdisc and TUN link counters. Missing tools, devices or sockets are
    recorded as absent evidence, never guessed. Hard bounds: 240 samples and 32
    socket records per sample, so one namespace writes well under 8 MiB of
    NDJSON; each command is `timeout`-capped and further capped by the remaining
    sampler window, so the process cannot outlive its deadline by more than one
    short tick.
    """

    interval_ms = max(1, min(int(interval_ms), 60_000))
    max_seconds = max(1.0, min(float(max_seconds), 600.0))
    interval = interval_ms / 1000.0
    max_samples = min(TELEMETRY_MAX_SAMPLES, max(2, int(max_seconds / interval) + 1))
    deadline = time.monotonic() + max_seconds
    samples = 0
    while True:
        tick = time.monotonic()
        row = {"t": round(tick, 6), "label": label}
        output, error = _run_bounded(["ss", "-tin"], _remaining_timeout(deadline))
        records = None if output is None else parse_ss_tcpinfo(output)
        if records is not None and len(records) > TELEMETRY_MAX_SOCKETS_PER_SAMPLE:
            row["ss_truncated"] = len(records) - TELEMETRY_MAX_SOCKETS_PER_SAMPLE
            records = records[:TELEMETRY_MAX_SOCKETS_PER_SAMPLE]
        row["ss"] = records
        row["ss_error"] = error
        if samples % TELEMETRY_SLOW_EVERY == 0:
            output, error = _run_bounded(
                ["tc", "-s", "qdisc", "show", "dev", dev],
                _remaining_timeout(deadline),
            )
            row["qdisc"] = parse_qdisc(output) if output else None
            row["qdisc_error"] = error
            output, error = _run_bounded(
                ["ip", "-s", "link", "show", tun], _remaining_timeout(deadline)
            )
            row["link"] = parse_link(output) if output else None
            row["link_error"] = error
        print(json.dumps(row, sort_keys=True), flush=True)
        samples += 1
        if samples >= max_samples or time.monotonic() >= deadline:
            break
        if os.path.exists(stop_path):
            break
        elapsed = time.monotonic() - tick
        if elapsed < interval:
            time.sleep(interval - elapsed)
    return 0


def _socket_map(row: dict) -> dict:
    sockets: dict = {}
    for record in row.get("ss") or []:
        if isinstance(record, dict) and record.get("local") and record.get("peer"):
            sockets[(record["local"], record["peer"])] = record
    return sockets


def _delta(first: dict, last: dict, field: str) -> int | None:
    if not isinstance(first, dict) or not isinstance(last, dict):
        return None
    before, after = first.get(field), last.get(field)
    if isinstance(before, int) and isinstance(after, int) and after >= before:
        return after - before
    return None


def _total_delta(first: dict, last: dict, keys: list, field: str) -> int | None:
    values = [_delta(first[key], last[key], field) for key in keys]
    if not values or any(value is None for value in values):
        return None
    return sum(values)


def _format(value: float | None, digits: int = 3) -> str:
    if value is None:
        return "unavailable"
    return f"{value:.{digits}f}"


def _plain(value: int | None) -> str:
    return "unavailable" if value is None else str(value)


def summarize(label: str, path: str) -> list[str]:
    """Render one sampler NDJSON file as key=value diagnostic evidence."""

    prefix = "underlay_telemetry_" + label
    rows: list[dict] = []
    unreadable = 0
    try:
        with open(path, encoding="utf-8") as source:
            for line in source:
                if not line.strip():
                    continue
                try:
                    parsed = json.loads(line)
                except ValueError:
                    # A truncated final line is possible if a sampler was
                    # terminated mid-write; it must not discard earlier samples.
                    unreadable += 1
                    continue
                if isinstance(parsed, dict):
                    rows.append(parsed)
    except OSError:
        return [
            prefix + "_status=unmeasured",
            prefix + "_detail=sampler-output-unreadable",
        ]
    if len(rows) < 2:
        return [
            prefix + "_status=unmeasured",
            prefix + "_detail=need-at-least-two-samples",
        ]
    timestamps = [
        row["t"]
        for row in rows
        if isinstance(row.get("t"), (int, float)) and not isinstance(row.get("t"), bool)
    ]
    if len(timestamps) < 2 or timestamps[-1] <= timestamps[0]:
        return [
            prefix + "_status=unmeasured",
            prefix + "_detail=invalid-sample-window",
        ]
    if all(row.get("ss") is None for row in rows) or (
        all(row.get("ss_error") for row in rows)
        and not any(row.get("ss") for row in rows)
    ):
        return [
            prefix + "_status=unmeasured",
            prefix + "_detail=ss-unavailable-in-namespace",
        ]

    window = timestamps[-1] - timestamps[0]
    socket_rows = [
        row for row in rows if isinstance(row.get("ss"), list) and row["ss"]
    ]
    states: list[str] = []
    observed: list = []
    first_socket_offset = None
    for row in rows:
        for record in row.get("ss") or []:
            if not isinstance(record, dict):
                continue
            key = (record.get("local"), record.get("peer"))
            if key not in observed:
                observed.append(key)
            state = record.get("state")
            if isinstance(state, str) and state not in states:
                states.append(state)
        if first_socket_offset is None and row.get("ss"):
            first_socket_offset = row["t"] - timestamps[0]
    lines = [
        prefix + "_status=measured",
        prefix + "_samples=%d" % len(rows),
        prefix + "_unreadable_lines=%d" % unreadable,
        prefix + "_window_seconds=%.3f" % window,
        prefix + "_ss_errors=%d" % sum(1 for row in rows if row.get("ss_error")),
        prefix
        + "_ss_truncated_records=%d"
        % sum(
            row["ss_truncated"]
            for row in rows
            if isinstance(row.get("ss_truncated"), int)
        ),
        prefix + "_sockets_observed=%d" % len(observed),
        prefix + "_states_seen=%s" % (",".join(states) if states else "unavailable"),
        prefix + "_first_socket_seconds=%s" % _format(first_socket_offset),
    ]
    if len(socket_rows) >= 2:
        first_row, last_row = socket_rows[0], socket_rows[-1]
        first_sockets, last_sockets = _socket_map(first_row), _socket_map(last_row)
        persistent = [key for key in first_sockets if key in last_sockets]
        socket_window = last_row["t"] - first_row["t"]
        lines.append(prefix + "_socket_window_seconds=%.3f" % socket_window)
        lines.append(prefix + "_persistent_sockets=%d" % len(persistent))
        if persistent and socket_window > 0:
            acked = _total_delta(first_sockets, last_sockets, persistent, "bytes_acked")
            received = _total_delta(
                first_sockets, last_sockets, persistent, "bytes_received"
            )
            retrans = _total_delta(
                first_sockets, last_sockets, persistent, "retrans_total"
            )
            retrans_bytes = _total_delta(first_sockets, last_sockets, persistent, "bytes_retrans")
            notsent_values: list[int] = []
            cwnd_values: list[int] = []
            rto_values: list[float] = []
            delivery_values: list[float] = []
            windows: list[int] = []
            receive_space: list[int] = []
            algorithms: set[str] = set()
            for row in socket_rows:
                sockets = _socket_map(row)
                for key in persistent:
                    record = sockets.get(key)
                    if not isinstance(record, dict):
                        continue
                    if isinstance(record.get("notsent"), int):
                        notsent_values.append(record["notsent"])
                    if isinstance(record.get("snd_wnd"), int):
                        windows.append(record["snd_wnd"])
                    if isinstance(record.get("rcv_space"), int):
                        receive_space.append(record["rcv_space"])
                    algorithm = record.get("congestion")
                    if isinstance(algorithm, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,15}", algorithm):
                        algorithms.add(algorithm)
                    if isinstance(record.get("cwnd"), int):
                        cwnd_values.append(record["cwnd"])
                    if isinstance(record.get("rto_ms"), (int, float)):
                        rto_values.append(record["rto_ms"])
                    if isinstance(record.get("delivery_rate_bps"), (int, float)):
                        delivery_values.append(record["delivery_rate_bps"])
            lines += [
                prefix + "_tx_bytes_acked_delta=" + _plain(acked),
                prefix + "_rx_bytes_received_delta=" + _plain(received),
                prefix
                + "_tx_mbps="
                + _format(None if acked is None else acked * 8 / socket_window / 1e6),
                prefix
                + "_rx_mbps="
                + _format(
                    None if received is None else received * 8 / socket_window / 1e6
                ),
                prefix + "_cwnd_min=" + _plain(min(cwnd_values) if cwnd_values else None),
                prefix + "_cwnd_max=" + _plain(max(cwnd_values) if cwnd_values else None),
                prefix + "_rto_max_ms=" + _format(max(rto_values) if rto_values else None),
                prefix + "_retrans_total_delta=" + _plain(retrans),
                prefix + "_bytes_retrans_delta=" + _plain(retrans_bytes),
                prefix + "_notsent_peak_bytes=" + _plain(max(notsent_values, default=None)),
                prefix + "_congestion=" + (",".join(sorted(algorithms)) or "unavailable"),
                prefix + "_snd_wnd_min_bytes=" + _plain(min(windows, default=None)),
                prefix + "_snd_wnd_max_bytes=" + _plain(max(windows, default=None)),
                prefix + "_rcv_space_max_bytes=" + _plain(max(receive_space, default=None)),
                *(
                    prefix + "_" + field + "_delta="
                    + _plain(_total_delta(first_sockets, last_sockets, persistent, field))
                    for field in ("busy_ms", "rwnd_limited_ms", "sndbuf_limited_ms")
                ),
                prefix
                + "_delivery_rate_max_mbps="
                + _format(max(delivery_values) / 1e6 if delivery_values else None),
            ]
        else:
            lines.append(prefix + "_socket_evidence=no-traffic-counter-delta")
    else:
        lines.append(prefix + "_socket_evidence=none-observed")

    qdisc_rows = [
        row["qdisc"]
        for row in rows
        if isinstance(row.get("qdisc"), dict) and row["qdisc"]
    ]
    if len(qdisc_rows) >= 2:
        first_q, last_q = qdisc_rows[0], qdisc_rows[-1]
        backlog = [
            q["backlog_bytes"]
            for q in qdisc_rows
            if isinstance(q.get("backlog_bytes"), int)
        ]
        lines += [
            prefix + "_qdisc_dropped_delta=" + _plain(_delta(first_q, last_q, "dropped")),
            prefix
            + "_qdisc_overlimits_delta="
            + _plain(_delta(first_q, last_q, "overlimits")),
            prefix
            + "_qdisc_requeues_delta="
            + _plain(_delta(first_q, last_q, "requeues")),
            prefix
            + "_qdisc_backlog_peak_bytes="
            + _plain(max(backlog) if backlog else None),
        ]
    else:
        lines.append(prefix + "_qdisc_evidence=unavailable")

    link_rows = [
        row["link"] for row in rows if isinstance(row.get("link"), dict) and row["link"]
    ]
    if len(link_rows) >= 2:
        first_l, last_l = link_rows[0], link_rows[-1]
        lines += [
            prefix + "_tun_rx_bytes_delta=" + _plain(_delta(first_l, last_l, "rx_bytes")),
            prefix + "_tun_tx_bytes_delta=" + _plain(_delta(first_l, last_l, "tx_bytes")),
            prefix
            + "_tun_rx_dropped_delta="
            + _plain(_delta(first_l, last_l, "rx_dropped")),
            prefix
            + "_tun_tx_dropped_delta="
            + _plain(_delta(first_l, last_l, "tx_dropped")),
        ]
    else:
        lines.append(prefix + "_tun_evidence=unavailable")
    lines.append(
        prefix
        + "_tun_absent_samples=%d"
        % sum(1 for row in rows if "link" in row and row.get("link") is None)
    )
    return lines


def _load_result(path: str) -> dict | None:
    """Load one sender JSON object; malformed or partial output is unavailable."""

    if path == "-":
        return None
    try:
        with open(path, encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _metric(result: dict | None, field: str) -> float | None:
    if result is None:
        return None
    value = result.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _byte_count(result: dict | None) -> int | None:
    if result is None:
        return None
    value = result.get("bytes")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    value = numerator / denominator
    return value if math.isfinite(value) else None


def _compare_label(label: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label) is None:
        raise SystemExit("compare labels must match [A-Za-z0-9_.-]{1,64}")
    return label


def compare(label: str, overlay_path: str, baseline_path: str) -> list[str]:
    """Compare one overlay result with one direct-TCP baseline result.

    Diagnostic only: no gate is read, no threshold is applied, and a missing or
    low baseline is reported as unmeasured rather than as an overlay pass.
    """

    label = _compare_label(label)
    prefix = "baseline_compare_" + label
    overlay = _load_result(overlay_path)
    baseline = _load_result(baseline_path)
    overlay_rate = _metric(overlay, "throughput_mbps")
    baseline_rate = _metric(baseline, "throughput_mbps")
    overlay_payload = _metric(overlay, "payload_send_mbps")
    baseline_payload = _metric(baseline, "payload_send_mbps")
    overlay_connect = _metric(overlay, "connect_seconds")
    overlay_send = _metric(overlay, "send_seconds")
    overlay_digest = _metric(overlay, "digest_seconds")
    overlay_elapsed = _metric(overlay, "elapsed_seconds")
    overlay_fixed = None
    if overlay_connect is not None and overlay_digest is not None:
        overlay_fixed = overlay_connect + overlay_digest
    overlay_bytes = _byte_count(overlay)
    baseline_bytes = _byte_count(baseline)
    if overlay_bytes is None or baseline_bytes is None:
        bytes_match = "unavailable"
    elif overlay_bytes == baseline_bytes:
        bytes_match = "yes"
    else:
        bytes_match = "no"
    return [
        "baseline_compare_source=perf-python-direct-tcp-baseline",
        "baseline_compare_scope=separate-denominator;diagnostic-only",
        "baseline_compare_acceptance=never",
        "overlay_gate=unchanged",
        prefix
        + "_overlay_status="
        + ("measured" if overlay_rate is not None else "unmeasured"),
        prefix
        + "_baseline_status="
        + ("measured" if baseline_rate is not None else "unmeasured"),
        prefix + "_overlay_bytes=" + _plain(overlay_bytes),
        prefix + "_baseline_bytes=" + _plain(baseline_bytes),
        prefix + "_bytes_match=" + bytes_match,
        prefix + "_overlay_throughput_mbps=" + _format(overlay_rate),
        prefix + "_overlay_payload_send_mbps=" + _format(overlay_payload),
        prefix + "_overlay_connect_seconds=" + _format(overlay_connect, 6),
        prefix + "_overlay_send_seconds=" + _format(overlay_send, 6),
        prefix + "_overlay_digest_seconds=" + _format(overlay_digest, 6),
        prefix + "_overlay_elapsed_seconds=" + _format(overlay_elapsed, 6),
        prefix
        + "_overlay_connect_plus_digest_share="
        + _format(_ratio(overlay_fixed, overlay_elapsed)),
        prefix
        + "_overlay_send_share="
        + _format(_ratio(overlay_send, overlay_elapsed)),
        prefix + "_baseline_throughput_mbps=" + _format(baseline_rate),
        prefix + "_baseline_payload_send_mbps=" + _format(baseline_payload),
        prefix
        + "_baseline_over_overlay_throughput_ratio="
        + _format(_ratio(baseline_rate, overlay_rate)),
        prefix
        + "_baseline_over_overlay_payload_ratio="
        + _format(_ratio(baseline_payload, overlay_payload)),
    ]


def _compare_cli(argv: list[str]) -> int:
    if len(argv) < 3 or len(argv) % 3 != 0:
        raise SystemExit(
            "usage: netns_overlay_perf.py compare "
            "LABEL OVERLAY_JSON BASELINE_JSON [LABEL ...]"
        )
    blocks = [
        "\n".join(compare(argv[index], argv[index + 1], argv[index + 2]))
        for index in range(0, len(argv), 3)
    ]
    print("\n".join(blocks))
    return 0


def _sampler_cli(argv: list[str]) -> int:
    if len(argv) != 6:
        raise SystemExit(
            "usage: netns_overlay_perf.py sample LABEL DEV TUN "
            "INTERVAL_MS MAX_SECONDS STOP_PATH"
        )
    label, dev, tun, interval_ms, max_seconds, stop_path = argv
    return sampler(label, dev, tun, interval_ms, max_seconds, stop_path)


def _summarize_cli(argv: list[str]) -> int:
    if not argv or len(argv) % 2 != 0:
        raise SystemExit(
            "usage: netns_overlay_perf.py summarize LABEL PATH [LABEL PATH ...]"
        )
    for index in range(0, len(argv), 2):
        print("\n".join(summarize(argv[index], argv[index + 1])))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] in {"multistream-receive", "multistream-send"}:
        raise SystemExit(_multistream_cli(sys.argv[1], sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "sample":
        raise SystemExit(_sampler_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "summarize":
        raise SystemExit(_summarize_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "compare":
        raise SystemExit(_compare_cli(sys.argv[2:]))
    if len(sys.argv) == 3 and sys.argv[1] == "baseline-receive":
        baseline_receiver(sys.argv[2])
        raise SystemExit(0)
    if len(sys.argv) == 4 and sys.argv[1] == "baseline-send":
        baseline_sender(sys.argv[2], sys.argv[3])
        raise SystemExit(0)
    if len(sys.argv) != 4 or sys.argv[1] not in {"receive", "send"}:
        raise SystemExit(
            "usage: netns_overlay_perf.py receive|send LOCAL_IP PEER_IP | "
            "baseline-receive LOCAL_IP | baseline-send LOCAL_IP PEER_IP | "
            "compare LABEL OVERLAY_JSON BASELINE_JSON"
        )
    if sys.argv[1] == "receive":
        receiver(sys.argv[2])
    else:
        sender(sys.argv[2], sys.argv[3])
