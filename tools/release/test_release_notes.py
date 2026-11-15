"""Policy examples for release-note structure; run via Actions unittest discovery.

No test here proves signatures, evidence truth, production gates, or acceptance.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_release_notes as notes


class ReleaseNotesTests(unittest.TestCase):
    def good(self, channel="development", title="Boreas 0.1.0-dev.1 — Development prerelease"):
        return f"""# {title}

Channel: {channel}
Source commit: {'a' * 40}
This is non-production; architecture baseline v1.11.0 is a design revision.

## Added
- Added an example.
## Changed
- No behavior change.
## Fixed
- No fix claimed.
## Security
- Reviewed scope; no new security claim.
## Compatibility and migration
- No CLI/API/schema change; migration not applicable.
## Known limitations
- No daemon/data plane; not a VPN feature claim.
## Verification evidence
- Actions evidence status is pending review.
## Artifacts and supply chain
- Unsigned development archives; integrity is not authenticity.
## Upgrade and rollback
- Do not install as production; recovery is manual.
"""

    def test_minimal_complete_note_is_valid(self):
        self.assertEqual(notes.validate(self.good()), [])

    def test_chinese_punctuation_and_ordinary_numeric_key_are_allowed(self):
        text = self.good().replace("Reviewed scope; no new security claim.", "安全范围已审阅：无新增声明。普通中文，标点；key 1: value")
        self.assertEqual(notes.validate(text), [])

    def test_rejects_keycap_emoji_with_and_without_variation_selector(self):
        for keycap in ("1\ufe0f\u20e3", "1\u20e3"):
            with self.subTest(keycap=keycap):
                self.assertTrue(any("emoji" in error for error in notes.validate(self.good() + "\n" + keycap)))

    def test_rejects_emoji_and_terminal_controls(self):
        for addition in ("\nLaunch 🚀", "\nStar ★", "\nInjected\x1b[31mterminal", "\nBidi\u202eoverride"):
            with self.subTest(addition=addition):
                self.assertTrue(notes.validate(self.good() + addition))

    def test_missing_and_empty_or_placeholder_sections_are_rejected(self):
        variants = (
            self.good().replace("## Known limitations\n- No daemon/data plane; not a VPN feature claim.\n", ""),
            self.good().replace("- No daemon/data plane; not a VPN feature claim.", "- <fill in>"),
            self.good().replace("- No daemon/data plane; not a VPN feature claim.", "- TBD"),
        )
        for text in variants:
            self.assertTrue(any("known_limitations" in e for e in notes.validate(text)))

    def test_rejects_design_revision_in_title_but_allows_body_baseline(self):
        self.assertEqual(notes.validate(self.good()), [])
        title = "Boreas 1.11.0 — Development prerelease"
        self.assertTrue(any("design baseline" in e for e in notes.validate(self.good(title=title))))

    def test_title_requires_valid_software_semver(self):
        for title in ("Boreas release", "Boreas 0.1", "Boreas 01.2.3"):
            with self.subTest(title=title):
                self.assertTrue(any("SemVer" in e for e in notes.validate(self.good(title=title))))

    def test_channel_is_exact_and_identity_fields_unique(self):
        cases = (
            self.good().replace("Channel: development", "Channel: developmentx"),
            self.good().replace("Channel: development", "Channel: dev; production"),
            self.good().replace("Channel: development", "Channel: development\nChannel: draft"),
            self.good().replace("Source commit: " + "a" * 40, "Source commit: " + "a" * 40 + "\nSource commit: " + "b" * 40),
        )
        for text in cases:
            self.assertTrue(notes.validate(text))

    def test_requires_full_source_and_nonproduction_marker(self):
        short = self.good().replace("Source commit: " + "a" * 40, "Source commit: abcdef")
        self.assertTrue(any("source commit" in e for e in notes.validate(short)))
        no_marker = self.good().replace("This is non-production;", "This is")
        self.assertTrue(any("non-production" in e for e in notes.validate(no_marker)))

    def test_utf8_bom_invalid_utf8_and_size_limit_fail_in_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.md"
            for payload in (b"\xef\xbb\xbf" + self.good().encode(), b"\xff", b" " * (notes.MAX_NOTES_BYTES + 1)):
                with self.subTest(size=len(payload)):
                    path.write_bytes(payload)
                    output = []
                    with patch("builtins.print", side_effect=lambda value: output.append(value)):
                        code = notes.main([str(path), "--json"])
                    self.assertEqual(code, 1)
                    self.assertEqual(json.loads(output[0])["valid"], False)

    def test_cli_json_valid_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.md"
            path.write_text(self.good(), encoding="utf-8")
            output = []
            with patch("builtins.print", side_effect=lambda value: output.append(value)):
                code = notes.main([str(path), "--json"])
            self.assertEqual(code, 0)
            result = json.loads(output[0])
            self.assertEqual(result, {"schema": notes.SCHEMA, "valid": True, "errors": []})

    def test_cli_read_error_json_is_stable(self):
        output = []
        with patch("builtins.print", side_effect=lambda value: output.append(value)):
            code = notes.main(["missing-release-notes-file", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output[0])["schema"], notes.SCHEMA)


if __name__ == "__main__":
    unittest.main()
