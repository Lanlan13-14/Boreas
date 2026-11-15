#!/usr/bin/env python3
"""Verify that a Linux release binary is fully static and matches its target.

"Fully static" here means the produced executable has no ``PT_INTERP``
program header and no ``DT_NEEDED`` entries.  A static-PIE may legitimately
retain a ``DYNAMIC`` segment for relocations, so the presence of that segment
alone is not a failure; an ELF interpreter or a needed shared library is.

The check is deliberately performed on the *release binary that is packaged*,
not on an intermediate object.  It is Linux-only and is invoked by
``.github/workflows/platforms.yml`` on native x86_64 and aarch64 runners.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import archive_suffix_for_target, sha256_file, utc_now_iso

EXPECTED_MACHINE = {
    "x86_64-unknown-linux-musl": "Advanced Micro Devices X86-64",
    "aarch64-unknown-linux-musl": "AArch64",
}


class StaticCheckFailure(Exception):
    pass


def run_tool(arguments: list[str]) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
    )


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise StaticCheckFailure(f"required tool is not installed: {name}")
    return path


def parse_readelf_header(output: str) -> dict:
    fields = {}
    for line in output.splitlines():
        match = re.match(r"\s*(Class|Type|Machine):\s*([^\s(]+)", line)
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def needed_libraries(dynamic_output: str) -> list[str]:
    needed = []
    for line in dynamic_output.splitlines():
        match = re.search(r"\(NEEDED\)\s+Shared library:\s*\[(.+?)\]", line)
        if match:
            needed.append(match.group(1))
    return needed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=sorted(EXPECTED_MACHINE))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    report = {
        "schema": "boreas.development.static-linkage.v1",
        "channel": "development",
        "production_release": False,
        "target": args.target,
        "binary": str(args.binary),
        "checked_at": utc_now_iso(),
        "fully_static": False,
        "failures": [],
    }

    try:
        if not args.binary.is_file():
            raise StaticCheckFailure(f"binary is not a regular file: {args.binary}")
        readelf = require_tool("readelf")
        file_tool = require_tool("file")

        header = run_tool([readelf, "-h", str(args.binary)])
        if header.returncode != 0:
            raise StaticCheckFailure(f"readelf -h failed: {header.stderr.strip()}")
        fields = parse_readelf_header(header.stdout)
        expected_machine = EXPECTED_MACHINE[args.target]
        if fields.get("Class") != "ELF64":
            raise StaticCheckFailure(f"expected ELF64, got {fields.get('Class')!r}")
        if fields.get("Machine") != expected_machine:
            raise StaticCheckFailure(
                f"expected machine {expected_machine!r}, got {fields.get('Machine')!r}"
            )
        if fields.get("Type") not in ("EXEC", "DYN"):
            raise StaticCheckFailure(f"unexpected ELF type {fields.get('Type')!r}")

        programs = run_tool([readelf, "-l", str(args.binary)])
        if programs.returncode != 0:
            raise StaticCheckFailure(f"readelf -l failed: {programs.stderr.strip()}")
        if re.search(r"^\s*INTERP\s+", programs.stdout, re.MULTILINE):
            raise StaticCheckFailure("ELF contains a PT_INTERP program header")

        dynamic = run_tool([readelf, "-d", str(args.binary)])
        needed = needed_libraries(dynamic.stdout) if dynamic.returncode == 0 else []
        if needed:
            raise StaticCheckFailure(
                "ELF declares shared-library dependencies: " + ", ".join(needed)
            )

        description = run_tool([file_tool, "-b", str(args.binary)])
        if description.returncode != 0:
            raise StaticCheckFailure(f"file failed: {description.stderr.strip()}")
        description_text = description.stdout.strip()
        lowered = description_text.lower()
        if "static" not in lowered and "static-pie" not in lowered:
            raise StaticCheckFailure(
                f"file does not describe a static executable: {description_text!r}"
            )

        report.update(
            {
                "fully_static": True,
                "elf_class": fields.get("Class"),
                "elf_type": fields.get("Type"),
                "machine": fields.get("Machine"),
                "file_description": description_text,
                "elf_interpreter": None,
                "needed_libraries": needed,
                "sha256": sha256_file(args.binary),
                "size": args.binary.stat().st_size,
                "archive_suffix": archive_suffix_for_target(args.target),
            }
        )
    except StaticCheckFailure as error:
        report["failures"].append(str(error))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if report["failures"]:
        for failure in report["failures"]:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        f"fully static {args.target} executable verified "
        f"(no PT_INTERP, no DT_NEEDED): {report['file_description']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
