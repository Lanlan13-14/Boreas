"""Read production evidence from a reviewed main snapshot, never the candidate tree."""

import importlib.util
import re
import subprocess
from pathlib import Path

LEDGER_PATH = "docs/engineering/release-evidence/gates.json"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")

# Load the fixed policy verifier adjacent to these tools, not a candidate or
# caller-supplied executable. The caller must use a trusted tooling checkout.
_policy_path = Path(__file__).resolve().parents[1] / "gates" / "verify.py"
_spec = importlib.util.spec_from_file_location("boreas_gate_policy", _policy_path)
gate_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate_policy)


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"Git {args[0]} failed (exit {result.returncode})")
    return result.stdout


def load_ledger(repo: Path, candidate: str, source: str) -> bytes:
    """Use the trusted checkout's HEAD as the pinned protected-main anchor."""
    for label, sha in (("candidate commit", candidate), ("ledger commit", source)):
        if not COMMIT_RE.fullmatch(sha):
            raise ValueError(f"{label} must be a full lowercase 40-hex SHA-1")
        if _git(repo, "cat-file", "-t", sha) != b"commit\n":
            raise ValueError(f"{label} must identify a commit object")
    if source == candidate:
        raise ValueError("ledger commit must not be the candidate commit")
    try:
        _git(repo, "merge-base", "--is-ancestor", candidate, source)
    except ValueError as error:
        raise ValueError("ledger commit must descend from the candidate commit") from error
    if source.encode("ascii") not in _git(repo, "rev-list", "--first-parent", "HEAD", "--").splitlines():
        raise ValueError("ledger commit is not on the trusted main first-parent history")

    # Read the exact raw committed blob. No checkout filters, symlinks, working
    # tree edits, artifact files, or caller-selected paths participate.
    entry = _git(repo, "ls-tree", "--full-tree", "-z", source, "--", LEDGER_PATH)
    match = re.fullmatch(
        rb"100644 blob ([0-9a-f]{40})\t" + re.escape(LEDGER_PATH.encode()) + rb"\x00", entry,
    )
    if not match:
        raise ValueError(f"ledger commit must contain a regular 100644 blob at {LEDGER_PATH}")
    parent_entry = _git(repo, "ls-tree", "--full-tree", "-z", f"{source}^1", "--", LEDGER_PATH)
    if entry == parent_entry:
        raise ValueError("ledger source must introduce or update the reviewed ledger on main")
    oid = match[1].decode("ascii")
    size = int(_git(repo, "cat-file", "-s", oid))
    if not 0 < size <= gate_policy.MAX_LEDGER_BYTES:
        raise ValueError("gate ledger is empty or exceeds 1 MiB")
    return _git(repo, "cat-file", "blob", oid)


def verify_ledger(raw: bytes, candidate: str) -> list[str]:
    """Validate the same bytes whose digest is bound by the promotion manifest."""
    try:
        return gate_policy.verify(gate_policy.parse_ledger(raw), candidate)
    except (AttributeError, ValueError, RecursionError) as error:
        return [f"invalid gate ledger: {error}"]
