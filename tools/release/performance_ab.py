#!/usr/bin/env python3
"""Compare two already-built, exact-commit Boreas binaries in GitHub Actions."""

import csv
import hashlib
import math
import os
from pathlib import Path
import re
import subprocess
import sys


# Identical to the strict 200 ms one-way profile: 400 ms configured base RTT.
PROFILE = {
    "BOREAS_NETEM_RTT_MS": "200",  # netem adds this on EACH egress device
    "BOREAS_NETEM_LOSS_PERCENT": "0.1",
    "BOREAS_NETEM_RATE_MBIT": "100",
    "BOREAS_MAX_PING_MS": "415",
    "BOREAS_MIN_THROUGHPUT_MBPS": "3",
    "BOREAS_PERF_BYTES": "67108864",
    "BOREAS_PERF_TIMEOUT_SECONDS": "120",  # existing probe socket timeout
    "BOREAS_NETNS_EDGE_LIFETIME_SECONDS": "230",
}
DIRECTIONS = ("edge_to_core", "core_to_edge")
PHASES = ("connect_seconds", "send_seconds", "digest_seconds", "payload_send_mbps")


def number(fields, key):
    try:
        value = float(fields[key])
    except (KeyError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ARCH") == "X64"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    ):
        raise SystemExit("Run only on a GitHub-hosted Linux x64 Actions runner")
    shas = sys.argv[1:]
    if len(shas) != 2 or shas[0] == shas[1] or not all(re.fullmatch(r"[0-9a-f]{40}", x) for x in shas):
        raise SystemExit("Usage: performance_ab.py BASELINE_SHA CANDIDATE_SHA (distinct full SHAs)")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    evidence = temp / "ab-evidence"
    release = Path(__file__).resolve().parent
    harness = release / "netns_daemon_smoke.sh"
    binaries = temp / "ab-binaries"
    if binaries.is_symlink() or not binaries.is_dir():
        raise SystemExit("Missing same-run build output directory")
    inputs = dict(zip(("baseline", "candidate"), shas))
    manifest = (evidence / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    if len(manifest) != 2:
        raise SystemExit("Expected a two-binary build manifest")

    def checked_binary(sha):
        path = binaries / f"boreas-{sha}"
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise SystemExit(f"Missing regular versioned executable: {path.name}")
        if f"{sha256(path)}  {path.name}" not in manifest:
            raise SystemExit(f"Binary hash differs from build manifest: {path.name}")
        return path

    for sha in shas:
        checked_binary(sha)
    fixture = temp / "ab-policy-fixture"
    if not fixture.is_dir() or fixture.is_symlink():
        raise SystemExit("Missing shared signed policy fixture")
    with (evidence / "profile.txt").open("x", encoding="utf-8") as out:
        print("scope=DEVELOPMENT_DIAGNOSTIC_ONLY", "configured_base_rtt_ms=400",
              "pair_order=AB,BA", "sample_guard_seconds=270", *(
                  f"{key}={value}" for key, value in PROFILE.items()
              ), sep="\n", file=out)
        for name in (harness.name, "netns_overlay_perf.py", Path(__file__).name):
            print(f"{sha256(release / name)}  {name}", file=out)

    # A fresh namespace/PKI per invocation; no broad `sudo -E` or inherited knobs.
    command = ["sudo", "-n", "/usr/bin/env", "-i",
               "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
               f"BOREAS_POLICY_FIXTURE_DIR={fixture}",
               f"OPENSSL_CONF={temp / 'ab-openssl/ssl/openssl.cnf'}",
               *(f"{key}={value}" for key, value in PROFILE.items()),
               "/usr/bin/timeout", "--kill-after=10s", "270s", "/usr/bin/bash", str(harness)]
    columns = ["pair", "position", "variant", "sha", "direction", "smoke_exit",
               "base_rtt_ms", "ping_avg_ms", "ping_max_ms", "ping_loss_percent",
               "daemon_launch_to_connected_ms", *PHASES, "completion_seconds_approx",
               "completion_mbps"]
    samples = {}
    failed = False
    with (evidence / "samples.csv").open("x", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        for pair, order in enumerate((("baseline", "candidate"), ("candidate", "baseline")), 1):
            for position, variant in enumerate(order, 1):
                sha = inputs[variant]
                binary = checked_binary(sha)
                log = evidence / f"pair-{pair}-{position}-{variant}.log"
                print(f"Pair {pair}, position {position}: {variant} {sha}", flush=True)
                with log.open("xb") as raw:
                    result = subprocess.run([*command, str(binary)], stdout=raw, stderr=subprocess.STDOUT,
                                            check=False)
                if result.returncode != 0:
                    failed = True
                print(f"Smoke exit={result.returncode}; raw={log.name}", flush=True)
                fields = dict(line.split("=", 1) for line in log.read_text(errors="replace").splitlines()
                              if re.fullmatch(r"[a-z_]+=[^\r\n]*", line))
                for direction in DIRECTIONS:
                    phase = {key: number(fields, f"overlay_{direction}_{key}") for key in PHASES}
                    parts = [phase[key] for key in PHASES[:3]]
                    completion_mbps = number(fields, f"overlay_throughput_{direction}_mbps")
                    # The harness only publishes these probe metrics after all
                    # four workers finish (including both digest verifications).
                    completion = (round(sum(parts), 6) if completion_mbps is not None
                                  and all(part is not None for part in parts) else None)
                    row = dict(pair=pair, position=position, variant=variant, sha=sha, direction=direction,
                               smoke_exit=result.returncode, base_rtt_ms=number(fields, "netem_effective_rtt_ms"),
                               ping_avg_ms=number(fields, "overlay_ping_average_ms"),
                               ping_max_ms=number(fields, "overlay_ping_max_ms"),
                               ping_loss_percent=number(fields, "overlay_ping_loss_percent"),
                               daemon_launch_to_connected_ms=number(fields, "stage_edge_launch_to_connected_elapsed_ms")
                               if fields.get("stage_edge_launch_to_connected_result") == "success" else None,
                               **phase, completion_seconds_approx=completion, completion_mbps=completion_mbps)
                    # A successful smoke without its expected evidence is not a successful A/B sample.
                    if result.returncode == 0 and (row["base_rtt_ms"] != 400 or completion is None
                                                   or row["ping_avg_ms"] is None):
                        print(f"Incomplete evidence: {log.name} {direction}", file=sys.stderr)
                        failed = True
                    writer.writerow(row)
                    samples[pair, direction, variant] = row
                out.flush()

    with (evidence / "paired-deltas.csv").open("x", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["pair", "direction", "baseline_smoke_exit", "candidate_smoke_exit",
                         "candidate_minus_baseline_connect_s", "candidate_minus_baseline_completion_s_approx",
                         "candidate_minus_baseline_completion_mbps"])
        for pair in (1, 2):
            for direction in DIRECTIONS:
                a = samples[pair, direction, "baseline"]
                b = samples[pair, direction, "candidate"]
                deltas = [round(b[key] - a[key], 6) if a[key] is not None and b[key] is not None else None
                          for key in ("connect_seconds", "completion_seconds_approx", "completion_mbps")]
                writer.writerow([pair, direction, a["smoke_exit"], b["smoke_exit"], *deltas])
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
