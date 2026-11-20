"""Contract tests for the netns overlay throughput probe.

Run only in GitHub Actions:
    python -m unittest discover -s tools/release -p 'test_*.py' -v

The tests use a fake clock/socket or a small real loopback transfer. They do
not create network namespaces, build Boreas, or claim performance evidence.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

import netns_overlay_perf


def _payload(total_bytes: int) -> bytes:
    repeats = total_bytes // len(netns_overlay_perf.CHUNK) + 1
    return (netns_overlay_perf.CHUNK * repeats)[:total_bytes]


class _FakeSenderConnection:
    def __init__(self) -> None:
        self.payload = bytearray()
        self.reply = b""
        self.timeout = None
        self.shutdown_how = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True
        return False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, block: bytes) -> None:
        self.payload.extend(block)
        self.reply = hashlib.sha256(self.payload).hexdigest().encode("ascii")

    def shutdown(self, how) -> None:
        self.shutdown_how = how

    def recv(self, size: int) -> bytes:
        part, self.reply = self.reply[:size], self.reply[size:]
        return part


class _FakeReceiverConnection:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.reply = b""
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        return chunk[:size]

    def sendall(self, block: bytes) -> None:
        self.reply += block


class _FakeListener:
    def __init__(self, connection: _FakeReceiverConnection) -> None:
        self.connection = connection
        self.address = None
        self.backlog = None
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def setsockopt(self, *args):
        return None

    def bind(self, address) -> None:
        self.address = address

    def listen(self, backlog: int) -> None:
        self.backlog = backlog

    def settimeout(self, value) -> None:
        self.timeout = value

    def accept(self):
        return self.connection, ("127.0.0.1", 12345)


class SenderPhaseTests(unittest.TestCase):
    def _run_sender(self, times, total_bytes: int = 64 * 1024):
        connection = _FakeSenderConnection()
        clock = mock.Mock()
        clock.monotonic.side_effect = list(times)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(netns_overlay_perf, "TOTAL_BYTES", total_bytes),
            mock.patch.object(netns_overlay_perf, "time", clock),
            mock.patch.object(
                netns_overlay_perf.socket,
                "create_connection",
                return_value=connection,
            ) as create_connection,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            netns_overlay_perf.sender("127.0.0.1", "127.0.0.2")
        return connection, create_connection, stdout.getvalue(), stderr.getvalue()

    def test_phase_fields_decompose_elapsed_and_keep_total_rate(self):
        total_bytes = 64 * 1024
        connection, create_connection, stdout, stderr = self._run_sender(
            [100.0, 100.25, 100.75, 101.0], total_bytes
        )
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertEqual(
            set(result),
            {
                "bytes",
                "connect_seconds",
                "digest_seconds",
                "elapsed_seconds",
                "payload_send_mbps",
                "send_seconds",
                "sha256",
                "throughput_mbps",
            },
        )
        self.assertEqual(result["bytes"], total_bytes)
        self.assertEqual(result["connect_seconds"], 0.25)
        self.assertEqual(result["send_seconds"], 0.5)
        self.assertEqual(result["digest_seconds"], 0.25)
        self.assertEqual(result["elapsed_seconds"], 1.0)
        self.assertAlmostEqual(
            result["connect_seconds"]
            + result["send_seconds"]
            + result["digest_seconds"],
            result["elapsed_seconds"],
            places=9,
        )
        self.assertEqual(
            result["throughput_mbps"],
            round(total_bytes * 8 / 1.0 / 1_000_000, 3),
        )
        self.assertEqual(
            result["payload_send_mbps"],
            round(total_bytes * 8 / 0.5 / 1_000_000, 3),
        )
        self.assertGreater(result["payload_send_mbps"], result["throughput_mbps"])
        self.assertEqual(
            result["sha256"], hashlib.sha256(_payload(total_bytes)).hexdigest()
        )
        self.assertEqual(bytes(connection.payload), _payload(total_bytes))
        self.assertEqual(connection.timeout, netns_overlay_perf.TIMEOUT_SECONDS)
        self.assertEqual(connection.shutdown_how, socket.SHUT_WR)
        self.assertTrue(connection.closed)
        create_connection.assert_called_once_with(
            ("127.0.0.2", netns_overlay_perf.PORT),
            timeout=netns_overlay_perf.TIMEOUT_SECONDS,
            source_address=("127.0.0.1", 0),
        )

    def test_zero_send_interval_marks_payload_rate_unavailable(self):
        total_bytes = 64 * 1024
        _, _, stdout, stderr = self._run_sender(
            [10.0, 10.1, 10.1, 10.3], total_bytes
        )
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertEqual(result["connect_seconds"], 0.1)
        self.assertEqual(result["send_seconds"], 0.0)
        self.assertEqual(result["digest_seconds"], 0.2)
        self.assertEqual(result["elapsed_seconds"], 0.3)
        self.assertIsNone(result["payload_send_mbps"])
        self.assertEqual(
            result["throughput_mbps"],
            round(total_bytes * 8 / 0.3 / 1_000_000, 3),
        )
        self.assertGreater(result["throughput_mbps"], 0)

    def test_nonfinite_phase_intervals_are_null_without_failing_total(self):
        total_bytes = 64 * 1024
        _, _, stdout, stderr = self._run_sender(
            [10.0, math.nan, 10.2, 10.3], total_bytes
        )
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertIsNone(result["connect_seconds"])
        self.assertIsNone(result["send_seconds"])
        self.assertEqual(result["digest_seconds"], 0.1)
        self.assertEqual(result["elapsed_seconds"], 0.3)
        self.assertIsNone(result["payload_send_mbps"])
        self.assertGreater(result["throughput_mbps"], 0)

    def test_negative_phase_interval_is_null_without_failing_total(self):
        total_bytes = 64 * 1024
        _, _, stdout, stderr = self._run_sender(
            [10.0, 9.5, 9.8, 10.4], total_bytes
        )
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertIsNone(result["connect_seconds"])
        self.assertEqual(result["send_seconds"], 0.3)
        self.assertEqual(result["digest_seconds"], 0.6)
        self.assertEqual(result["elapsed_seconds"], 0.4)
        self.assertEqual(
            result["payload_send_mbps"],
            round(total_bytes * 8 / 0.3 / 1_000_000, 3),
        )
        self.assertGreater(result["throughput_mbps"], 0)


class ReceiverDiagnosticTests(unittest.TestCase):
    def test_first_byte_to_eof_is_logged_to_stderr_only(self):
        payload = b"receiver-diagnostic" * 16
        connection = _FakeReceiverConnection([payload[:17], payload[17:]])
        listener = _FakeListener(connection)
        clock = mock.Mock()
        clock.monotonic.side_effect = [40.0, 40.75]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(netns_overlay_perf, "TOTAL_BYTES", len(payload)),
            mock.patch.object(netns_overlay_perf, "time", clock),
            mock.patch.object(
                netns_overlay_perf.socket, "socket", return_value=listener
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            netns_overlay_perf.receiver("127.0.0.1")
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(listener.address, ("127.0.0.1", netns_overlay_perf.PORT))
        self.assertEqual(listener.backlog, 1)
        self.assertEqual(listener.timeout, netns_overlay_perf.TIMEOUT_SECONDS)
        self.assertEqual(connection.timeout, netns_overlay_perf.TIMEOUT_SECONDS)
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(connection.reply, digest.encode("ascii"))
        log = json.loads(stderr.getvalue())
        self.assertEqual(log["role"], "receiver")
        self.assertEqual(log["bytes"], len(payload))
        self.assertEqual(log["first_byte_to_eof_seconds"], 0.75)
        self.assertEqual(log["sha256"], digest)


class _LoopbackServer(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.ready = threading.Event()
        self.port = None
        self.error = None
        self.received = 0
        self.sha256 = None

    def run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(5)
                self.port = listener.getsockname()[1]
                self.ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    digest = hashlib.sha256()
                    while True:
                        data = connection.recv(64 * 1024)
                        if not data:
                            break
                        digest.update(data)
                        self.received += len(data)
                    self.sha256 = digest.hexdigest()
                    connection.sendall(self.sha256.encode("ascii"))
        except BaseException as exc:  # re-raised by the test thread below
            self.error = exc
            self.ready.set()


class LoopbackProbeTests(unittest.TestCase):
    def test_real_loopback_sender_reports_finite_nonnegative_phases(self):
        total_bytes = 256 * 1024
        server = _LoopbackServer()
        server.start()
        self.assertTrue(server.ready.wait(5), "loopback server did not become ready")
        if server.error is not None:
            self.fail(f"loopback server failed before accept: {server.error!r}")

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with (
                mock.patch.object(netns_overlay_perf, "TOTAL_BYTES", total_bytes),
                mock.patch.object(netns_overlay_perf, "PORT", server.port),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                netns_overlay_perf.sender("127.0.0.1", "127.0.0.1")
        finally:
            server.join(5)
        self.assertFalse(server.is_alive(), "loopback server did not finish")
        if server.error is not None:
            self.fail(f"loopback server failed: {server.error!r}")

        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        expected_sha256 = hashlib.sha256(_payload(total_bytes)).hexdigest()
        self.assertEqual(result["bytes"], total_bytes)
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(server.received, total_bytes)
        self.assertEqual(server.sha256, expected_sha256)
        for field in (
            "connect_seconds",
            "send_seconds",
            "digest_seconds",
            "elapsed_seconds",
            "payload_send_mbps",
            "throughput_mbps",
        ):
            value = result[field]
            self.assertIsInstance(value, (int, float))
            self.assertNotIsInstance(value, bool)
            self.assertTrue(math.isfinite(value), field)
            self.assertGreaterEqual(value, 0, field)
        self.assertAlmostEqual(
            result["connect_seconds"]
            + result["send_seconds"]
            + result["digest_seconds"],
            result["elapsed_seconds"],
            delta=3e-6,
        )
        self.assertGreater(result["payload_send_mbps"], 0)
        expected_total = total_bytes * 8 / result["elapsed_seconds"] / 1_000_000
        self.assertTrue(
            math.isclose(result["throughput_mbps"], expected_total, rel_tol=0.01)
        )


class BaselineProbeTests(unittest.TestCase):
    def test_baseline_sender_uses_distinct_port_and_separate_denominator(self):
        total_bytes = 64 * 1024
        connection = _FakeSenderConnection()
        clock = mock.Mock()
        clock.monotonic.side_effect = [100.0, 100.25, 100.75, 101.0]
        stdout = io.StringIO()
        with (
            mock.patch.object(netns_overlay_perf, "TOTAL_BYTES", total_bytes),
            mock.patch.object(netns_overlay_perf, "time", clock),
            mock.patch.object(
                netns_overlay_perf.socket,
                "create_connection",
                return_value=connection,
            ) as create_connection,
            contextlib.redirect_stdout(stdout),
        ):
            netns_overlay_perf.baseline_sender("127.0.0.1", "127.0.0.2")
        result = json.loads(stdout.getvalue())
        self.assertNotEqual(
            netns_overlay_perf.BASELINE_PORT, netns_overlay_perf.PORT
        )
        self.assertEqual(result["role"], "baseline-sender")
        self.assertEqual(result["scope"], netns_overlay_perf.BASELINE_SCOPE)
        self.assertEqual(result["gate"], "not-applicable")
        self.assertEqual(result["acceptance"], "never")
        self.assertEqual(result["denominator"], "connect-through-digest")
        self.assertEqual(result["payload_denominator"], "connect-to-shutdown-write")
        self.assertEqual(result["bytes"], total_bytes)
        self.assertEqual(
            result["throughput_mbps"],
            round(total_bytes * 8 / 1.0 / 1_000_000, 3),
        )
        self.assertEqual(
            result["payload_send_mbps"],
            round(total_bytes * 8 / 0.5 / 1_000_000, 3),
        )
        self.assertEqual(
            result["sha256"], hashlib.sha256(_payload(total_bytes)).hexdigest()
        )
        self.assertEqual(connection.timeout, netns_overlay_perf.BASELINE_TIMEOUT_SECONDS)
        self.assertEqual(connection.shutdown_how, socket.SHUT_WR)
        create_connection.assert_called_once_with(
            ("127.0.0.2", netns_overlay_perf.BASELINE_PORT),
            timeout=netns_overlay_perf.BASELINE_TIMEOUT_SECONDS,
            source_address=("127.0.0.1", 0),
        )

    def test_baseline_receiver_logs_digest_without_a_gate(self):
        payload = b"baseline-receiver" * 16
        connection = _FakeReceiverConnection([payload[:17], payload[17:]])
        listener = _FakeListener(connection)
        clock = mock.Mock()
        clock.monotonic.side_effect = [40.0, 40.75]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(netns_overlay_perf, "TOTAL_BYTES", len(payload)),
            mock.patch.object(netns_overlay_perf, "time", clock),
            mock.patch.object(
                netns_overlay_perf.socket, "socket", return_value=listener
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            netns_overlay_perf.baseline_receiver("127.0.0.1")
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            listener.address, ("127.0.0.1", netns_overlay_perf.BASELINE_PORT)
        )
        self.assertEqual(
            listener.timeout, netns_overlay_perf.BASELINE_TIMEOUT_SECONDS
        )
        log = json.loads(stderr.getvalue())
        self.assertEqual(log["role"], "baseline-receiver")
        self.assertEqual(log["scope"], netns_overlay_perf.BASELINE_SCOPE)
        self.assertEqual(log["gate"], "not-applicable")
        self.assertEqual(log["acceptance"], "never")
        self.assertEqual(log["bytes"], len(payload))
        self.assertEqual(log["first_byte_to_eof_seconds"], 0.75)
        self.assertEqual(log["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(connection.reply, log["sha256"].encode("ascii"))


class BaselineBoundTests(unittest.TestCase):
    def test_baseline_port_is_distinct_and_timeout_is_bounded(self):
        self.assertNotEqual(
            netns_overlay_perf.BASELINE_PORT, netns_overlay_perf.PORT
        )
        self.assertGreater(netns_overlay_perf.BASELINE_PORT, 0)
        self.assertLessEqual(netns_overlay_perf.BASELINE_PORT, 65535)
        self.assertLessEqual(netns_overlay_perf.BASELINE_TIMEOUT_SECONDS, 30)
        self.assertEqual(netns_overlay_perf.BASELINE_ACCEPTANCE, "never")
        self.assertIn("baseline", netns_overlay_perf.BASELINE_SCOPE)


class BaselineCompareTests(unittest.TestCase):
    @staticmethod
    def _parse(lines):
        return dict(line.split("=", 1) for line in lines)

    def _write_json(self, payload):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        with handle:
            json.dump(payload, handle)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_compare_reports_both_denominators_and_never_gates(self):
        overlay = self._write_json(
            {
                "bytes": 1048576,
                "connect_seconds": 0.4,
                "digest_seconds": 0.9,
                "elapsed_seconds": 3.5,
                "send_seconds": 2.2,
                "throughput_mbps": 2.4,
                "payload_send_mbps": 3.8,
            }
        )
        baseline = self._write_json(
            {
                "bytes": 1048576,
                "throughput_mbps": 100.0,
                "payload_send_mbps": 120.0,
                "scope": netns_overlay_perf.BASELINE_SCOPE,
            }
        )
        values = self._parse(
            netns_overlay_perf.compare("edge_to_core", overlay, baseline)
        )
        self.assertEqual(values["baseline_compare_acceptance"], "never")
        self.assertEqual(values["overlay_gate"], "unchanged")
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_status"], "measured"
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_status"], "measured"
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_throughput_mbps"],
            "2.400",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_payload_send_mbps"],
            "3.800",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_connect_seconds"],
            "0.400000",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_send_seconds"],
            "2.200000",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_digest_seconds"],
            "0.900000",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_elapsed_seconds"],
            "3.500000",
        )
        self.assertEqual(
            values[
                "baseline_compare_edge_to_core_overlay_connect_plus_digest_share"
            ],
            "0.371",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_send_share"],
            "0.629",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_throughput_mbps"],
            "100.000",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_payload_send_mbps"],
            "120.000",
        )
        self.assertEqual(
            values[
                "baseline_compare_edge_to_core_baseline_over_overlay_throughput_ratio"
            ],
            "41.667",
        )
        self.assertEqual(
            values[
                "baseline_compare_edge_to_core_baseline_over_overlay_payload_ratio"
            ],
            "31.579",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_bytes_match"], "yes"
        )

    def test_compare_missing_baseline_is_unmeasured_not_green(self):
        overlay = self._write_json(
            {
                "bytes": 1048576,
                "throughput_mbps": 0.1,
                "payload_send_mbps": 0.2,
            }
        )
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            missing = handle.name
        values = self._parse(
            netns_overlay_perf.compare("edge_to_core", overlay, missing)
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_status"], "measured"
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_status"], "unmeasured"
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_throughput_mbps"],
            "0.100",
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_throughput_mbps"],
            "unavailable",
        )
        self.assertEqual(values["overlay_gate"], "unchanged")
        self.assertNotIn("pass", "\n".join(values.values()).lower())

    def test_compare_dash_marks_baseline_unmeasured(self):
        overlay = self._write_json(
            {
                "bytes": 1048576,
                "connect_seconds": 0.4,
                "digest_seconds": 0.9,
                "elapsed_seconds": 3.5,
                "send_seconds": 2.2,
                "throughput_mbps": 2.4,
            }
        )
        values = self._parse(
            netns_overlay_perf.compare("edge_to_core", overlay, "-")
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_overlay_status"], "measured"
        )
        self.assertEqual(
            values["baseline_compare_edge_to_core_baseline_status"], "unmeasured"
        )
        self.assertEqual(
            values[
                "baseline_compare_edge_to_core_overlay_connect_plus_digest_share"
            ],
            "0.371",
        )

    def test_compare_cli_returns_zero_for_a_low_overlay_result(self):
        overlay = self._write_json(
            {
                "bytes": 1048576,
                "throughput_mbps": 0.1,
                "payload_send_mbps": 0.2,
            }
        )
        baseline = self._write_json(
            {
                "bytes": 1048576,
                "throughput_mbps": 100.0,
                "payload_send_mbps": 120.0,
            }
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = netns_overlay_perf._compare_cli(
                ["edge_to_core", overlay, baseline]
            )
        self.assertEqual(status, 0)
        self.assertIn("overlay_gate=unchanged", stdout.getvalue())
        self.assertIn("baseline_compare_acceptance=never", stdout.getvalue())


class ProtocolConstantsTests(unittest.TestCase):
    def test_smoke_protocol_constants_are_unchanged(self):
        self.assertEqual(netns_overlay_perf.PORT, 18080)
        # The transfer has to outlast slow start on a 200 ms path, so the
        # socket timeout and the payload cap are larger than the original
        # 30 s / 64 MiB probe. Both stay bounded.
        self.assertEqual(netns_overlay_perf.TIMEOUT_SECONDS, 120)
        self.assertGreater(netns_overlay_perf.TOTAL_BYTES, 0)
        self.assertLessEqual(netns_overlay_perf.TOTAL_BYTES, 1024 * 1024 * 1024)


class UnderlayTcpInfoParserTests(unittest.TestCase):
    def test_parses_socket_and_continuation_fields(self):
        text = "\n".join(
            [
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                "ESTAB 0 0 192.0.2.1:8443 192.0.2.2:41234",
                "\t cubic wscale:7,7 rto:204 rtt:0.5/0.1 ato:40 mss:1360 cwnd:10 "
                "bytes_acked:12345 bytes_received:678 retrans:0/1 unacked:3 "
                "ssthresh:1846 app_limited delivery_rate 25473600bps",
                "ESTAB 0 0 192.0.2.1:8443 192.0.2.2:41235",
                "\t cubic rto:201 rtt:1.5/0.3 cwnd:27 bytes_acked:1 "
                "bytes_received:2 retrans:2/28 delivery_rate 24.6Mbps",
            ]
        )
        records = netns_overlay_perf.parse_ss_tcpinfo(text)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first["state"], "ESTAB")
        self.assertEqual(first["local"], "192.0.2.1:8443")
        self.assertEqual(first["peer"], "192.0.2.2:41234")
        self.assertEqual(first["rtt_ms"], 0.5)
        self.assertEqual(first["rttvar_ms"], 0.1)
        self.assertEqual(first["rto_ms"], 204.0)
        self.assertEqual(first["cwnd"], 10)
        self.assertEqual(first["ssthresh"], 1846)
        self.assertEqual(first["retrans_current"], 0)
        self.assertEqual(first["retrans_total"], 1)
        self.assertEqual(first["bytes_acked"], 12345)
        self.assertEqual(first["bytes_received"], 678)
        self.assertEqual(first["unacked"], 3)
        self.assertIs(first["app_limited"], True)
        self.assertEqual(first["delivery_rate_bps"], 25_473_600.0)
        self.assertEqual(records[1]["retrans_total"], 28)
        self.assertAlmostEqual(records[1]["delivery_rate_bps"], 24_600_000.0)

    def test_headers_and_stray_text_never_create_sockets(self):
        header = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        self.assertEqual(netns_overlay_perf.parse_ss_tcpinfo(header), [])
        self.assertEqual(netns_overlay_perf.parse_ss_tcpinfo(""), [])
        self.assertEqual(netns_overlay_perf.parse_ss_tcpinfo("ss: warning"), [])

    def test_syn_sent_socket_keeps_state_without_tcpinfo(self):
        text = "SYN-SENT 0 1 192.0.2.2:40123 192.0.2.1:8443\n"
        records = netns_overlay_perf.parse_ss_tcpinfo(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "SYN-SENT")
        self.assertEqual(records[0]["local"], "192.0.2.2:40123")
        self.assertEqual(records[0]["peer"], "192.0.2.1:8443")
        self.assertNotIn("cwnd", records[0])


class UnderlayCounterParserTests(unittest.TestCase):
    def test_parses_netem_qdisc_counters(self):
        text = (
            "qdisc netem 8001: root refcnt 2 limit 1000 delay 200ms "
            "loss 0.1% rate 100Mbit\n"
            " Sent 1048576 bytes 8123 pkt (dropped 4, overlimits 7 requeues 2)\n"
            " backlog 2048b 3p requeues 2\n"
        )
        stats = netns_overlay_perf.parse_qdisc(text)
        self.assertEqual(stats["sent_bytes"], 1048576)
        self.assertEqual(stats["sent_packets"], 8123)
        self.assertEqual(stats["dropped"], 4)
        self.assertEqual(stats["overlimits"], 7)
        self.assertEqual(stats["requeues"], 2)
        self.assertEqual(stats["backlog_bytes"], 2048)
        self.assertEqual(stats["backlog_packets"], 3)

    def test_parses_tun_link_counters(self):
        text = (
            "2: btun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1360 qdisc noqueue "
            "state UNKNOWN\n"
            "    link/none\n"
            "    RX:  bytes    packets errors dropped  missed   mcast\n"
            "      1048576     8123      0       3       0       0\n"
            "    TX:  bytes    packets errors dropped carrier collsns\n"
            "      2097152     9123      0       5       0       0\n"
        )
        stats = netns_overlay_perf.parse_link(text)
        self.assertEqual(stats["rx_bytes"], 1048576)
        self.assertEqual(stats["rx_packets"], 8123)
        self.assertEqual(stats["rx_dropped"], 3)
        self.assertEqual(stats["tx_bytes"], 2097152)
        self.assertEqual(stats["tx_packets"], 9123)
        self.assertEqual(stats["tx_dropped"], 5)

    def test_missing_device_output_yields_no_counters(self):
        self.assertEqual(netns_overlay_perf.parse_link(""), {})
        self.assertEqual(netns_overlay_perf.parse_qdisc(""), {})


class UnderlaySummarizeTests(unittest.TestCase):
    def _write_rows(self, rows):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".ndjson", delete=False, encoding="utf-8"
        )
        with handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    @staticmethod
    def _parse(lines):
        return dict(line.split("=", 1) for line in lines)

    def test_reports_per_socket_deltas_and_counter_trends(self):
        address = ("192.0.2.1:8443", "192.0.2.2:41234")
        samples = [(1000, 500, 10, 0), (2000, 1500, 20, 1), (4000, 2500, 40, 5)]
        rows = []
        for index, (acked, received, cwnd, retrans) in enumerate(samples):
            rows.append(
                {
                    "t": float(index),
                    "ss": [
                        {
                            "state": "ESTAB",
                            "local": address[0],
                            "peer": address[1],
                            "bytes_acked": acked,
                            "bytes_received": received,
                            "cwnd": cwnd,
                            "rto_ms": 200.0,
                            "retrans_total": retrans,
                            "delivery_rate_bps": 24_600_000.0,
                        }
                    ],
                    "ss_error": None,
                    "qdisc": {
                        "dropped": index * 2,
                        "overlimits": 0,
                        "requeues": index,
                        "backlog_bytes": 2048,
                    },
                    "link": {
                        "rx_bytes": index * 1000,
                        "tx_bytes": index * 2000,
                        "rx_dropped": index,
                        "tx_dropped": 0,
                    },
                }
            )
        values = self._parse(
            netns_overlay_perf.summarize("core", self._write_rows(rows))
        )
        self.assertEqual(values["underlay_telemetry_core_status"], "measured")
        self.assertEqual(values["underlay_telemetry_core_samples"], "3")
        self.assertEqual(values["underlay_telemetry_core_window_seconds"], "2.000")
        self.assertEqual(values["underlay_telemetry_core_sockets_observed"], "1")
        self.assertEqual(values["underlay_telemetry_core_states_seen"], "ESTAB")
        self.assertEqual(
            values["underlay_telemetry_core_first_socket_seconds"], "0.000"
        )
        self.assertEqual(
            values["underlay_telemetry_core_tx_bytes_acked_delta"], "3000"
        )
        self.assertEqual(
            values["underlay_telemetry_core_rx_bytes_received_delta"], "2000"
        )
        self.assertEqual(values["underlay_telemetry_core_tx_mbps"], "0.012")
        self.assertEqual(values["underlay_telemetry_core_rx_mbps"], "0.008")
        self.assertEqual(values["underlay_telemetry_core_cwnd_min"], "10")
        self.assertEqual(values["underlay_telemetry_core_cwnd_max"], "40")
        self.assertEqual(values["underlay_telemetry_core_rto_max_ms"], "200.000")
        self.assertEqual(values["underlay_telemetry_core_retrans_total_delta"], "5")
        self.assertEqual(
            values["underlay_telemetry_core_delivery_rate_max_mbps"], "24.600"
        )
        self.assertEqual(values["underlay_telemetry_core_qdisc_dropped_delta"], "4")
        self.assertEqual(values["underlay_telemetry_core_qdisc_requeues_delta"], "2")
        self.assertEqual(
            values["underlay_telemetry_core_qdisc_backlog_peak_bytes"], "2048"
        )
        self.assertEqual(values["underlay_telemetry_core_tun_rx_dropped_delta"], "2")
        self.assertEqual(values["underlay_telemetry_core_tun_tx_bytes_delta"], "4000")
        self.assertEqual(values["underlay_telemetry_core_tun_absent_samples"], "0")

    def test_startup_window_without_sockets_is_measured_absence(self):
        rows = [
            {
                "t": 0.0,
                "ss": [],
                "ss_error": None,
                "qdisc": None,
                "link": None,
                "link_error": "exit-1",
            },
            {
                "t": 0.25,
                "ss": [],
                "ss_error": None,
                "qdisc": None,
                "link": None,
                "link_error": "exit-1",
            },
        ]
        values = self._parse(
            netns_overlay_perf.summarize("edge", self._write_rows(rows))
        )
        self.assertEqual(values["underlay_telemetry_edge_status"], "measured")
        self.assertEqual(values["underlay_telemetry_edge_sockets_observed"], "0")
        self.assertEqual(
            values["underlay_telemetry_edge_states_seen"], "unavailable"
        )
        self.assertEqual(
            values["underlay_telemetry_edge_first_socket_seconds"], "unavailable"
        )
        self.assertEqual(
            values["underlay_telemetry_edge_socket_evidence"], "none-observed"
        )
        self.assertEqual(values["underlay_telemetry_edge_qdisc_evidence"], "unavailable")
        self.assertEqual(values["underlay_telemetry_edge_tun_evidence"], "unavailable")
        self.assertEqual(values["underlay_telemetry_edge_tun_absent_samples"], "2")

    def test_all_ss_errors_without_sockets_is_unmeasured(self):
        rows = [
            {"t": 0.0, "ss": [], "ss_error": "exit-1"},
            {"t": 0.25, "ss": [], "ss_error": "exit-1"},
        ]
        values = self._parse(
            netns_overlay_perf.summarize("core", self._write_rows(rows))
        )
        self.assertEqual(values["underlay_telemetry_core_status"], "unmeasured")
        self.assertEqual(
            values["underlay_telemetry_core_detail"], "ss-unavailable-in-namespace"
        )

    def test_unreadable_sampler_output_is_unmeasured(self):
        missing = os.path.join(tempfile.gettempdir(), "missing-underlay.ndjson")
        values = self._parse(netns_overlay_perf.summarize("core", missing))
        self.assertEqual(values["underlay_telemetry_core_status"], "unmeasured")
        self.assertEqual(
            values["underlay_telemetry_core_detail"], "sampler-output-unreadable"
        )

    def test_single_sample_is_unmeasured(self):
        rows = [{"t": 0.0, "ss": [], "ss_error": None}]
        values = self._parse(
            netns_overlay_perf.summarize("core", self._write_rows(rows))
        )
        self.assertEqual(values["underlay_telemetry_core_status"], "unmeasured")
        self.assertEqual(
            values["underlay_telemetry_core_detail"], "need-at-least-two-samples"
        )


class TelemetryBoundTests(unittest.TestCase):
    def test_sampler_bounds_are_finite_and_small(self):
        self.assertLessEqual(netns_overlay_perf.TELEMETRY_MAX_SAMPLES, 240)
        self.assertLessEqual(
            netns_overlay_perf.TELEMETRY_MAX_SOCKETS_PER_SAMPLE, 32
        )
        self.assertLessEqual(
            netns_overlay_perf.TELEMETRY_COMMAND_TIMEOUT_SECONDS, 5
        )
        # Coarse ceiling per namespace: 240 rows x 32 records x 1 KiB/record.
        self.assertLess(
            netns_overlay_perf.TELEMETRY_MAX_SAMPLES
            * netns_overlay_perf.TELEMETRY_MAX_SOCKETS_PER_SAMPLE
            * 1024,
            8 * 1024 * 1024,
        )

    def test_sampler_stops_at_cap_and_truncates_socket_records(self):
        clock = [0.0]

        def monotonic():
            clock[0] += 0.01
            return clock[0]

        sockets = "\n".join(
            "ESTAB 0 0 192.0.2.1:8443 192.0.2.2:%d" % (40000 + index)
            for index in range(33)
        )
        timeouts = []

        def fake_run(argv, timeout):
            timeouts.append(timeout)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(
                timeout, netns_overlay_perf.TELEMETRY_COMMAND_TIMEOUT_SECONDS
            )
            if argv[0] == "ss":
                return sockets, None
            return "", None

        stdout = io.StringIO()
        stop_path = os.path.join(tempfile.gettempdir(), "never-created-stop")
        with (
            mock.patch.object(netns_overlay_perf, "_run_bounded", side_effect=fake_run),
            mock.patch.object(netns_overlay_perf, "TELEMETRY_MAX_SAMPLES", 3),
            mock.patch.object(
                netns_overlay_perf.time, "monotonic", side_effect=monotonic
            ),
            mock.patch.object(netns_overlay_perf.time, "sleep"),
            contextlib.redirect_stdout(stdout),
        ):
            netns_overlay_perf.sampler(
                "core", "veth-core", "btun0", 250, 60, stop_path
            )
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(len(row["ss"]), 32)
            self.assertEqual(row["ss_truncated"], 1)
        self.assertEqual(
            timeouts[0], netns_overlay_perf.TELEMETRY_COMMAND_TIMEOUT_SECONDS
        )


if __name__ == "__main__":
    unittest.main()
