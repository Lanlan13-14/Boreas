#!/usr/bin/env python3
"""Check release-note structure only; this is not release or production approval.

Emoji screening uses explicit reviewed Unicode blocks/code points plus variation
selector and format-control rejection. It is intentionally not a complete Unicode
emoji-property database. Ordinary non-ASCII text and punctuation are allowed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

SCHEMA = "boreas.release-notes-validation.v1"
MAX_NOTES_BYTES = 256 * 1024
REQUIRED = {
    "security": ("security", "安全"),
    "compatibility": ("compatibility and migration", "compatibility", "兼容性", "兼容与迁移"),
    "known_limitations": ("known limitations", "known limitations and risks", "已知限制", "已知局限"),
    "evidence": ("verification evidence", "evidence", "验证证据", "证据"),
    "artifacts": ("artifacts and supply chain", "artifacts", "产物与供应链", "产物"),
    "rollback": ("upgrade and rollback", "rollback", "升级与回滚", "回滚"),
}
CHANNELS = {
    "development": "development", "dev": "development", "开发": "development",
    "draft": "draft", "草稿": "draft",
    "prerelease": "prerelease", "pre-release": "prerelease", "预发布": "prerelease",
    "production": "production", "stable": "production", "生产": "production",
}
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def has_emoji(text: str) -> bool:
    # Deliberate explicit ranges: broad pictograph/symbol blocks, regional flags,
    # and commonly emoji-presented symbols. Do not infer from ASCII/non-ASCII.
    for ch in text:
        cp = ord(ch)
        if cp in (0xFE0F, 0x20E3):  # emoji variation selector and keycap mark
            return True
        if (0x1F000 <= cp <= 0x1FAFF or 0x1FC00 <= cp <= 0x1FFFD
                or 0x1F1E6 <= cp <= 0x1F1FF or 0x2600 <= cp <= 0x27BF):
            return True
        if cp in {0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139,
                  0x3030, 0x303D, 0x3297, 0x3299}:
            return True
    return False


def normalized_heading(value: str) -> str:
    return " ".join(re.sub(r"[`*_]", "", value).strip().casefold().split())


def _identity_fields(text: str, names: tuple[str, ...]) -> list[str]:
    pattern = re.compile(r"(?im)^\s*(?:-\s*)?(?:" + "|".join(names) + r")\s*:\s*([^\r\n]*)")
    return [match.group(1).strip() for match in pattern.finditer(text)]


def _section_body(text: str, heading_match: re.Match[str], next_start: int) -> str:
    body = text[heading_match.end():next_start]
    # Ignore Markdown list prefixes and common template placeholder forms.
    lines = []
    for line in body.splitlines():
        line = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", "", line).strip()
        if not line or re.fullmatch(r"(?:<[^>]*>|\[.*\]|\.\.\.|TODO|TBD|N/?A)", line, re.I):
            continue
        if re.search(r"<[^>]+>|\[[^]]*(?:fill|todo|tbd|placeholder)[^]]*\]", line, re.I):
            line = re.sub(r"<[^>]+>|\[[^]]*(?:fill|todo|tbd|placeholder)[^]]*\]", "", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def validate(text: str) -> list[str]:
    errors: list[str] = []
    if "\ufeff" in text:
        errors.append("UTF-8 BOM is not permitted")
    for index, ch in enumerate(text):
        category = unicodedata.category(ch)
        if (category == "Cc" and ch not in "\r\n\t") or category == "Cf":
            errors.append(f"terminal/control character U+{ord(ch):04X} at offset {index}")
            break
    if has_emoji(text):
        errors.append("emoji characters are not permitted")

    headings = list(re.finditer(r"(?m)^##\s+(.+?)\s*#*\s*$", text))
    normalized = [normalized_heading(match.group(1)) for match in headings]
    for name, aliases in REQUIRED.items():
        matches = [i for i, heading in enumerate(normalized) if heading in aliases]
        if not matches:
            errors.append(f"missing required section: {name}")
        elif not any(_section_body(text, headings[i], headings[i + 1].start() if i + 1 < len(headings) else len(text)) for i in matches):
            errors.append(f"empty or unfilled required section: {name}")

    title_matches = re.findall(r"(?m)^#\s+(.+?)\s*$", text)
    if len(title_matches) != 1:
        errors.append("exactly one software-version title is required")
    else:
        title = title_matches[0]
        match = re.fullmatch(r"Boreas\s+(" + SEMVER.pattern + r")(?:\s+[—–-].*)?", title, re.I)
        if not match:
            errors.append("title must include Boreas and a valid SemVer software version")
        elif match.group(1).lstrip("vV") == "1.11.0":
            errors.append("design baseline v1.11.0 must not be presented as a software version")

    channels = _identity_fields(text, ("channel", "渠道"))
    sources = _identity_fields(text, ("source commit", "source sha", "源码提交"))
    if len(channels) != 1:
        errors.append("exactly one channel field is required")
    if len(sources) != 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", sources[0] if sources else ""):
        errors.append("source commit must be exactly one full 40-hex SHA")
    if len(channels) == 1:
        channel = CHANNELS.get(channels[0].casefold())
        if channel is None:
            errors.append("channel must be one of development, draft, prerelease, production, or their documented exact aliases")
        elif channel in {"development", "draft", "prerelease"} and not re.search(
            r"(?i)(?:non[- ]production|非生产|仅供开发|仅限开发)", text
        ):
            errors.append("non-production channel requires an explicit non-production marker")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notes", type=Path, help="Markdown release notes")
    parser.add_argument("--json", action="store_true", help="emit stable JSON result")
    args = parser.parse_args(argv)
    try:
        with args.notes.open("rb") as stream:
            raw = stream.read(MAX_NOTES_BYTES + 1)
        if len(raw) > MAX_NOTES_BYTES:
            raise ValueError("notes exceed the 256 KiB limit")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("UTF-8 BOM is not permitted")
        text = raw.decode("utf-8", errors="strict")
        errors = validate(text)
    except (OSError, UnicodeError, ValueError) as exc:
        errors = [f"cannot read notes: {str(exc) if isinstance(exc, ValueError) else type(exc).__name__}"]
    result = {"schema": SCHEMA, "valid": not errors, "errors": errors}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    elif errors:
        for error in errors:
            print(error, file=sys.stderr)
    else:
        print("release notes structure valid; no production acceptance implied")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
