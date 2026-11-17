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
import socket
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


class ProtocolConstantsTests(unittest.TestCase):
    def test_smoke_protocol_constants_are_unchanged(self):
        self.assertEqual(netns_overlay_perf.PORT, 18080)
        self.assertEqual(netns_overlay_perf.TIMEOUT_SECONDS, 30)
        self.assertGreater(netns_overlay_perf.TOTAL_BYTES, 0)
        self.assertLessEqual(netns_overlay_perf.TOTAL_BYTES, 64 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
