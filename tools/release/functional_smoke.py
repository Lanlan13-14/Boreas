#!/usr/bin/env python3
"""Execute the built Boreas CLI and validate capability-report consistency.

This is a *functional* test of the shipped executable: it starts the binary,
reads its stdout/stderr and exit status, and parses the JSON it emits.  It is
explicitly **not** a VPN, TLS, TUN, routing, DNS, failover or data-plane test.

The assertions are intentionally capability-aware rather than pinned to the
current foundation build.  If a future runtime integrates a daemon, the CLI may
report ``daemon: true`` and a non-foundation status; this test then checks that
the report is internally consistent instead of demanding ``false`` everywhere.
What it always rejects is a report that claims no daemon while also claiming a
TLS backend or networking, or a live daemon while still claiming
``foundation_only``.

Exit code 0 means every required check passed.  Any deviation writes a
``failed`` report and exits 1.  The report always contains
``"vpn_data_plane_tested": false``.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path

from common import parse_json_text, utc_now_iso

CAPABILITY_FIELDS = ("daemon", "tls_backend", "networking")
OPTIONAL_CAPABILITY_FIELDS = ("phase0_complete",)


class CheckFailure(Exception):
    pass


def run_binary(binary: Path, arguments: list[str], timeout: int = 30):
    try:
        return subprocess.run(
            [str(binary), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except OSError as error:
        raise CheckFailure(f"could not execute {binary}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise CheckFailure(f"{binary} {' '.join(arguments)} timed out") from error


def parse_object(text: str, label: str) -> dict:
    stripped = text.strip()
    if not stripped:
        raise CheckFailure(f"{label}: stdout is empty")
    try:
        value = parse_json_text(stripped)
    except (ValueError, json.JSONDecodeError) as error:
        raise CheckFailure(f"{label}: stdout is not one strict JSON value: {error}") from error
    if not isinstance(value, dict):
        raise CheckFailure(f"{label}: stdout JSON is not an object")
    return value


def require_capability_booleans(document: dict, label: str) -> dict:
    observed = {}
    for field in CAPABILITY_FIELDS:
        if field not in document:
            raise CheckFailure(f"{label}: required capability field {field!r} is missing")
        value = document[field]
        if not isinstance(value, bool):
            raise CheckFailure(
                f"{label}: capability field {field!r} must be a JSON boolean"
            )
        observed[field] = value
    for field in OPTIONAL_CAPABILITY_FIELDS:
        if field not in document:
            observed[field] = None
            continue
        value = document[field]
        if not isinstance(value, bool):
            raise CheckFailure(
                f"{label}: capability field {field!r} must be a JSON boolean when present"
            )
        observed[field] = value
    return observed


def validate_capability_report(document: dict, label: str) -> dict:
    observed = require_capability_booleans(document, label)
    status = document.get("status")
    if not isinstance(status, str) or not status.strip():
        raise CheckFailure(f"{label}: non-empty status string is required")
    phase = document.get("phase")
    if phase is not None and not isinstance(phase, str):
        raise CheckFailure(f"{label}: phase must be a string when present")
    scope = document.get("scope")
    if scope is not None and (not isinstance(scope, str) or not scope.strip()):
        raise CheckFailure(f"{label}: scope must be a non-empty string when present")

    if observed["daemon"] is False:
        if observed["tls_backend"] is not False:
            raise CheckFailure(
                f"{label}: claims tls_backend without a daemon; that is inconsistent"
            )
        if observed["networking"] is not False:
            raise CheckFailure(
                f"{label}: claims networking without a daemon; that is inconsistent"
            )
    elif status == "foundation_only":
        raise CheckFailure(
            f"{label}: claims a live daemon while status is still 'foundation_only'"
        )

    return {
        "status": status,
        "phase": phase,
        "daemon": observed["daemon"],
        "tls_backend": observed["tls_backend"],
        "networking": observed["networking"],
        "phase0_complete": observed["phase0_complete"],
        "profile": "runtime-claimed" if observed["daemon"] else "foundation",
    }


def require_success(result, label: str) -> None:
    if result.returncode != 0:
        raise CheckFailure(
            f"{label}: expected exit 0, got {result.returncode}; stderr={result.stderr!r}"
        )
    if result.stderr.strip():
        raise CheckFailure(f"{label}: expected empty stderr, got {result.stderr!r}")


def check_named_report(binary: Path, arguments: list[str], label: str) -> dict:
    result = run_binary(binary, arguments)
    require_success(result, label)
    document = parse_object(result.stdout, label)
    return validate_capability_report(document, label)


def check_default(binary: Path) -> dict:
    result = run_binary(binary, [])
    require_success(result, "default")
    document = parse_object(result.stdout, "default")
    if document.get("command") == "status":
        observed = validate_status_report(document, "default status")
        observed["default_command"] = "status"
        return observed
    observed = validate_capability_report(document, "default")
    observed["default_command"] = "doctor"
    return observed


def validate_status_report(document: dict, label: str) -> dict:
    if document.get("command") != "status":
        raise CheckFailure(f"{label}: command field is not 'status'")
    daemon = document.get("daemon")
    if daemon not in ("connected", "not_connected"):
        raise CheckFailure(f"{label}: daemon must be 'connected' or 'not_connected'")
    security_mode = document.get("security_mode")
    if security_mode not in ("e2e-required", "hop-only"):
        raise CheckFailure(f"{label}: security_mode is not a known policy token")
    inbound_on = document.get("inbound_on")
    if not isinstance(inbound_on, bool):
        raise CheckFailure(f"{label}: inbound_on must be a boolean")
    for field in ("inbound_connections", "outbound_upstreams"):
        value = document.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CheckFailure(f"{label}: {field} must be a non-negative integer")
    if daemon == "not_connected":
        if inbound_on:
            raise CheckFailure(f"{label}: not_connected cannot report inbound_on")
        if document.get("outbound_upstreams") != 0:
            raise CheckFailure(f"{label}: not_connected cannot report upstreams")
        if document.get("inbound_connections") != 0:
            raise CheckFailure(f"{label}: not_connected cannot report inbound connections")
    return {
        "status": "status",
        "daemon": daemon,
        "security_mode": security_mode,
        "inbound_on": inbound_on,
        "profile": "status-report",
    }


def check_help(binary: Path) -> str:
    result = run_binary(binary, ["help"])
    if result.returncode != 0:
        raise CheckFailure(f"help: expected exit 0, got {result.returncode}")
    if "USAGE" not in result.stdout:
        raise CheckFailure("help: stdout does not contain a USAGE section")
    if not result.stdout.strip():
        raise CheckFailure("help: stdout is empty")
    return result.stdout


def check_unknown_command(binary: Path) -> None:
    result = run_binary(binary, ["definitely-not-a-boreas-command"])
    if result.returncode == 0:
        raise CheckFailure("unknown command: exited 0 instead of failing")
    if result.stdout.strip():
        raise CheckFailure("unknown command: wrote success-looking stdout")
    if "no daemon was started" not in result.stderr:
        raise CheckFailure(
            "unknown command: stderr must state that no daemon was started"
        )


def check_extra_argument(binary: Path) -> None:
    result = run_binary(binary, ["doctor", "unexpected"])
    if result.returncode == 0:
        raise CheckFailure("doctor with an extra argument: exited 0")
    if result.stdout.strip():
        raise CheckFailure("doctor with an extra argument: wrote stdout")


def check_status_if_advertised(binary: Path, help_text: str) -> dict:
    if "status" not in help_text:
        return {"status_command": "not_advertised"}
    result = run_binary(binary, ["status", "--json"])
    if result.returncode != 0:
        raise CheckFailure(
            "help advertises 'status' but 'status --json' failed with exit "
            f"{result.returncode}: {result.stderr!r}"
        )
    document = parse_object(result.stdout, "status --json")
    observed = validate_status_report(document, "status --json")
    observed["status_command"] = "tested"
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    report = {
        "schema": "boreas.development.functional-smoke.v2",
        "channel": "development",
        "production_release": False,
        "vpn_data_plane_tested": False,
        "assertion_profile": "capability-consistency-v2",
        "target": args.target,
        "binary": str(args.binary),
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "checked_at": utc_now_iso(),
        "checks": [],
        "observed_capabilities": {},
        "capabilities": {},
        "limitations": [
            "This test executes the CLI process and validates self-reported capability consistency.",
            "It does not start a daemon, establish TLS/WSS, create a TUN/Wintun/utun adapter, install routes, serve DNS or transfer packets.",
            "Workspace TLS/TUN code, if present, is not exercised here; no production VPN gate is claimed.",
        ],
    }

    if not args.binary.is_file():
        report["result"] = "failed"
        report["failures"] = [f"binary does not exist or is not a file: {args.binary}"]
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"FAIL: {report['failures'][0]}", file=sys.stderr)
        return 1

    failures: list[str] = []
    observations: dict[str, dict] = {}

    named_checks = [
        ("doctor", ["doctor"]),
        ("self-check", ["self-check"]),
    ]
    for name, arguments in named_checks:
        try:
            observations[name] = check_named_report(args.binary, arguments, name)
            report["checks"].append({"name": name, "result": "passed"})
        except CheckFailure as error:
            failures.append(str(error))
            report["checks"].append(
                {"name": name, "result": "failed", "detail": str(error)}
            )

    try:
        observations["default"] = check_default(args.binary)
        report["checks"].append({"name": "default", "result": "passed"})
    except CheckFailure as error:
        failures.append(str(error))
        report["checks"].append(
            {"name": "default", "result": "failed", "detail": str(error)}
        )

    help_text = ""
    for name, check in (
        ("help", check_help),
        ("unknown-command", check_unknown_command),
        ("extra-argument", check_extra_argument),
    ):
        try:
            value = check(args.binary)
            report["checks"].append({"name": name, "result": "passed"})
            if name == "help" and isinstance(value, str):
                help_text = value
        except CheckFailure as error:
            failures.append(str(error))
            report["checks"].append(
                {"name": name, "result": "failed", "detail": str(error)}
            )

    if not failures:
        try:
            report["capabilities"].update(
                check_status_if_advertised(args.binary, help_text)
            )
        except CheckFailure as error:
            failures.append(str(error))

    # doctor and self-check must not contradict each other.
    comparable = {
        name: observations[name]
        for name in ("doctor", "self-check")
        if name in observations
    }
    if len(comparable) == 2:
        doctor = comparable["doctor"]
        self_check = comparable["self-check"]
        for field in (
            "status",
            "daemon",
            "tls_backend",
            "networking",
            "phase0_complete",
        ):
            if doctor.get(field) != self_check.get(field):
                failures.append(
                    f"doctor and self-check disagree on {field!r}: "
                    f"{doctor.get(field)!r} vs {self_check.get(field)!r}"
                )
        report["observed_capabilities"] = doctor
    elif comparable:
        report["observed_capabilities"] = next(iter(comparable.values()))

    report["result"] = "passed" if not failures else "failed"
    report["failures"] = failures
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"functional CLI capability smoke passed for {args.target} (not a VPN test)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
