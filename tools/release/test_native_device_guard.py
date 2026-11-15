"""Log-parser tests for real native device evidence.

Run only in GitHub Actions:
    python -m unittest discover -s tools/release -p 'test_*.py' -v

The fixtures reproduce the GitHub Actions timestamp prefixes, ANSI escapes and
nested ``--nocapture`` test-harness output seen in the real linux_device log.
"""

from __future__ import annotations

import unittest

import native_device_guard

LINUX_NESTED_PASS = """
2026-11-15T00:28:20.3340461Z \x1b[1m\x1b[92m     Running\x1b[0m tests/linux_device.rs
2026-11-15T00:28:20.3359675Z running 2 tests
2026-11-15T00:28:20.3420699Z test create_verify_mtu_multiqueue_and_auto_cleanup ... 
2026-11-15T00:28:20.3421148Z running 1 test
2026-11-15T00:28:20.3552159Z Cannot find device "btacd0"
2026-11-15T00:28:20.3554226Z test create_verify_mtu_multiqueue_and_auto_cleanup ... ok
2026-11-15T00:28:20.3554908Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s
2026-11-15T00:28:20.3559009Z ok
2026-11-15T00:28:20.3612124Z test real_l3_write_and_kernel_routed_reply ... 
2026-11-15T00:28:20.3612527Z running 1 test
2026-11-15T00:28:20.3768437Z test real_l3_write_and_kernel_routed_reply ... ok
2026-11-15T00:28:20.3777710Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
"""

LINUX_NESTED_FAILURE = """
2026-11-15T00:28:20.3359675Z running 2 tests
2026-11-15T00:28:20.3420699Z test create_verify_mtu_multiqueue_and_auto_cleanup ... 
2026-11-15T00:28:20.3554226Z test create_verify_mtu_multiqueue_and_auto_cleanup ... ok
2026-11-15T00:28:20.3554908Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s
2026-11-15T00:28:20.3612124Z test real_l3_write_and_kernel_routed_reply ... 
2026-11-15T00:28:20.3768437Z test real_l3_write_and_kernel_routed_reply ... FAILED
2026-11-15T00:28:20.3770061Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.02s
"""

LINUX_NESTED_SKIPPED = """
2026-11-15T00:28:20.3359675Z running 1 test
2026-11-15T00:28:20.3768437Z test create_verify_mtu_multiqueue_and_auto_cleanup ... ignored
2026-11-15T00:28:20.3770061Z test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""

WINDOWS_MARKER = "BOREAS_DEVICE_EVIDENCE platform=windows driver=wintun adapter=created packet_roundtrip=ok cleanup=ok"


class NativeDeviceGuardTests(unittest.TestCase):
    def test_nested_linux_pass_with_timestamps_and_ansi(self):
        report = native_device_guard.evaluate_text(
            LINUX_NESTED_PASS,
            "linux",
            [
                "create_verify_mtu_multiqueue_and_auto_cleanup",
                "real_l3_write_and_kernel_routed_reply",
            ],
            [],
            True,
        )
        self.assertEqual(report["result"], "passed", report["failures"])
        self.assertTrue(report["required_tests"]["real_l3_write_and_kernel_routed_reply"])

    def test_nested_linux_failure_is_rejected(self):
        report = native_device_guard.evaluate_text(
            LINUX_NESTED_FAILURE,
            "linux",
            ["real_l3_write_and_kernel_routed_reply"],
            [],
            True,
        )
        self.assertEqual(report["result"], "failed")
        self.assertTrue(any("FAILED" in failure for failure in report["failures"]))
        self.assertTrue(any("failed" in failure for failure in report["failures"]))

    def test_ignored_test_is_rejected(self):
        report = native_device_guard.evaluate_text(
            LINUX_NESTED_SKIPPED,
            "linux",
            ["create_verify_mtu_multiqueue_and_auto_cleanup"],
            [],
            True,
        )
        self.assertEqual(report["result"], "failed")
        self.assertTrue(any("ignored" in failure for failure in report["failures"]))

    def test_missing_required_test_is_rejected(self):
        report = native_device_guard.evaluate_text(
            LINUX_NESTED_PASS,
            "linux",
            ["some_test_that_did_not_run"],
            [],
            True,
        )
        self.assertEqual(report["result"], "failed")
        self.assertFalse(report["required_tests"]["some_test_that_did_not_run"])

    def test_windows_marker_is_required(self):
        log = (
            "running 1 test\n"
            "test real_wintun_device_packet_round_trip ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            + WINDOWS_MARKER
            + "\n"
        )
        accepted = native_device_guard.evaluate_text(
            log, "windows", ["real_wintun_device_packet_round_trip"], [WINDOWS_MARKER], True
        )
        self.assertEqual(accepted["result"], "passed", accepted["failures"])

        rejected = native_device_guard.evaluate_text(
            log.replace(WINDOWS_MARKER, ""),
            "windows",
            ["real_wintun_device_packet_round_trip"],
            [WINDOWS_MARKER],
            True,
        )
        self.assertEqual(rejected["result"], "failed")

    def test_require_tun_env_is_enforced(self):
        report = native_device_guard.evaluate_text(
            LINUX_NESTED_PASS,
            "linux",
            ["real_l3_write_and_kernel_routed_reply"],
            [],
            False,
        )
        self.assertEqual(report["result"], "failed")
        self.assertTrue(any("BOREAS_REQUIRE_TUN" in failure for failure in report["failures"]))


if __name__ == "__main__":
    unittest.main()
