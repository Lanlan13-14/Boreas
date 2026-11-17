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

The `sample`/`summarize` modes are diagnostic-only. `sample` runs inside one
network namespace and periodically records `ss -tin` TCP_INFO for the underlay
pair plus `tc -s qdisc` and `ip -s link` counters; `summarize` turns that NDJSON
into bounded key=value evidence. They assert no threshold, change no probe byte,
deadline or gate, and never retry. Those TCP_INFO fields describe the underlay
outer-TLS socket, not overlay, E2E or application latency.
"""

import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import time

CHUNK = bytes((index % 251 for index in range(64 * 1024)))
TOTAL_BYTES = int(os.environ.get("BOREAS_PERF_BYTES", str(8 * 1024 * 1024)))
if TOTAL_BYTES <= 0 or TOTAL_BYTES > 64 * 1024 * 1024:
    raise ValueError("BOREAS_PERF_BYTES must be in 1..=67108864")
PORT = 18080
TIMEOUT_SECONDS = 30

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
            cwnd_values: list[int] = []
            rto_values: list[float] = []
            delivery_values: list[float] = []
            for row in socket_rows:
                sockets = _socket_map(row)
                for key in persistent:
                    record = sockets.get(key)
                    if not isinstance(record, dict):
                        continue
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
    if len(sys.argv) >= 2 and sys.argv[1] == "sample":
        raise SystemExit(_sampler_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "summarize":
        raise SystemExit(_summarize_cli(sys.argv[2:]))
    if len(sys.argv) != 4 or sys.argv[1] not in {"receive", "send"}:
        raise SystemExit("usage: netns_overlay_perf.py receive|send LOCAL_IP PEER_IP")
    if sys.argv[1] == "receive":
        receiver(sys.argv[2])
    else:
        sender(sys.argv[2], sys.argv[3])
