#!/usr/bin/env python3
"""Fail-closed check that real packet-I/O device tests actually ran.

A cargo test process can exit successfully while silently skipping a device
test.  This guard parses the captured test log and requires:

  * at least one passed test;
  * zero failed and zero ignored tests;
  * every explicitly required test name to appear as ``... ok``;
  * every explicitly required evidence marker to be present.

The parser normalizes GitHub Actions timestamp prefixes and ANSI colour codes,
and accepts nested ``--nocapture`` output (an outer test spawning the same test
binary in a network namespace).  It is a log parser, not a substitute for a
real device test: the native workflows also require ``BOREAS_REQUIRE_TUN=1``
and fail when a driver or privilege is absent.

The marker contract is:

  Windows: ``BOREAS_DEVICE_EVIDENCE platform=windows driver=wintun
            adapter=created packet_roundtrip=ok cleanup=ok``

  macOS:   ``BOREAS_DEVICE_EVIDENCE platform=macos driver=utun
            adapter=created packet_roundtrip=ok cleanup=ok``

A guard report is crate-level device evidence, not a full VPN data-plane gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

MAX_LOG_BYTES = 64 * 1024 * 1024

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+"
)
# `gh run view --log` puts `<job>\t<step>\t` after the timestamp.
JOB_PREFIX_RE = re.compile(r"^[^\t]+\t[^\t]+\t")
RESULT_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;"
)
RUNNING_RE = re.compile(r"^running (\d+) tests?$")
# `--nocapture` lets the test print its evidence marker between `...` and
# `ok`. The marker is still required separately; this only recovers the name.
# `--nocapture` may print the evidence marker between `...` and `ok`.
# The line must still end at `ok`; a later `...` (an env dump, for example)
# is not a test result.
# The evidence marker may contain dots. A second cargo separator (` ... `)
# means this line is an env dump or another test, not this result.
# The evidence marker may contain dots. A second cargo separator (` ... `)
# means this line is an env dump or another test, not this result. The
# result itself must end at `ok`.
TEST_OK_RE = re.compile(r"^test ([^ ]+) \.\.\.(?: (?!.* \.\.\. ).*)?ok$")

DRIVER = {"windows": "wintun", "macos": "utun", "linux": "tun"}


def normalize_lines(text: str) -> list[str]:
    normalized = []
    for raw in text.splitlines():
        line = ANSI_RE.sub("", raw)
        line = TIMESTAMP_RE.sub("", line)
        line = JOB_PREFIX_RE.sub("", line)
        # GitHub's log exporter prefixes each captured line with a timestamp
        # and a space. A leading space left after that is indentation, not
        # part of cargo's test line.
        normalized.append(line.strip())
    return normalized


def evaluate_text(
    text: str,
    platform: str,
    require_tests: list[str],
    require_markers: list[str],
    require_tun_env: bool,
) -> dict:
    failures: list[str] = []
    report = {
        "schema": "boreas.native-device.evidence.v1",
        "channel": "development",
        "production_release": False,
        "production_claim": False,
        "platform": platform,
        "driver": DRIVER[platform],
        "require_tun_env": require_tun_env,
        "driver_test_executed": False,
        "test_runs": 0,
        "passed": 0,
        "failed": 0,
        "ignored": 0,
        "required_tests": {},
        "markers": {},
        "failures": failures,
        "scope_note": (
            "Crate-level native device evidence only. It is not a full VPN "
            "data-plane, routing, DNS, failover or release acceptance record."
        ),
    }

    if not text.strip():
        failures.append("test log is empty")
        report["result"] = "failed"
        return report
    if not require_tun_env:
        failures.append("BOREAS_REQUIRE_TUN must be '1' so tests cannot silently skip")

    lines = normalize_lines(text)
    normalized_text = "\n".join(lines)

    running = [
        int(match.group(1))
        for line in lines
        if (match := RUNNING_RE.match(line))
    ]
    report["test_runs"] = len(running)
    if not running:
        failures.append("no cargo 'running N tests' section found")

    results = [
        match.groups()
        for line in lines
        if (match := RESULT_RE.match(line))
    ]
    if not results:
        failures.append("no cargo 'test result:' line found")
    for status, passed, failed, ignored in results:
        report["passed"] += int(passed)
        report["failed"] += int(failed)
        report["ignored"] += int(ignored)
        if status != "ok":
            failures.append("a cargo test section reported FAILED")
        if int(failed) != 0:
            failures.append(f"a cargo test section reported {failed} failed test(s)")
        if int(ignored) != 0:
            failures.append(f"a cargo test section reported {ignored} ignored test(s)")

    if report["passed"] < 1:
        failures.append("no test actually passed")
    report["skipped_or_ignored"] = report["ignored"] != 0

    ok_tests = {
        match.group(1)
        for line in lines
        if (match := TEST_OK_RE.match(line))
    }
    # Windows `--nocapture` wraps after `...`, so the evidence and `ok`
    # land on the following lines. Pair a bare start with the next `ok`
    # before another test starts.
    pending = None
    for line in lines:
        if line.startswith("test ") and line.endswith(" ..."):
            pending = line[len("test ") : -len(" ...")]
        elif line == "ok" and pending is not None:
            ok_tests.add(pending)
            pending = None
        elif line.startswith("test "):
            pending = None
    for name in require_tests:
        present = name in ok_tests
        report["required_tests"][name] = present
        if not present:
            failures.append(f"required real-device test did not pass: {name}")

    for marker in require_markers:
        present = marker in normalized_text
        report["markers"][marker] = present
        if not present:
            failures.append(f"required device evidence marker is missing: {marker}")

    report["driver_test_executed"] = not failures
    report["result"] = "passed" if not failures else "failed"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=sorted(DRIVER))
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--require-test", action="append", default=[])
    parser.add_argument("--require-marker", action="append", default=[])
    args = parser.parse_args()

    try:
        with args.log.open("rb") as handle:
            data = handle.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise ValueError(f"log exceeds the {MAX_LOG_BYTES}-byte limit")
        text = data.decode("utf-8", errors="replace")
    except (OSError, ValueError) as error:
        report = {
            "schema": "boreas.native-device.evidence.v1",
            "channel": "development",
            "production_release": False,
            "production_claim": False,
            "platform": args.platform,
            "driver": DRIVER[args.platform],
            "driver_test_executed": False,
            "result": "failed",
            "failures": [f"cannot read test log: {error}"],
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"DEVICE EVIDENCE FAILED: {report['failures'][0]}", file=sys.stderr)
        return 1

    report = evaluate_text(
        text,
        args.platform,
        args.require_test,
        args.require_marker,
        os.environ.get("BOREAS_REQUIRE_TUN") == "1",
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if report["failures"]:
        for failure in report["failures"]:
            print(f"DEVICE EVIDENCE FAILED: {failure}", file=sys.stderr)
        return 1
    print(
        f"native {report['driver']} device evidence passed: "
        f"{report['passed']} test(s), 0 failed, 0 ignored"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
