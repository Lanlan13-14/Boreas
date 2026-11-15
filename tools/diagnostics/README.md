# diagnostics — redacted environment collector

Collects a small, repeatable support/preflight bundle per master plan
v1.11.0 §10.3 (preflight) and §10.4 (redacted diagnostics): OS/arch/kernel,
existing seccomp state, resource limits, an open-fd **count by type** for
the collecting shell, output-filesystem space, toolchain versions,
presence (never values) of a few relevant environment variables, and —
with `--boreas-bin` — the binary's SHA-256, size, ELF header summary,
dynamic-interpreter presence and dynamic-dependency sonames.

## Usage

```sh
sh tools/diagnostics/collect-diagnostics.sh \
    --out /tmp/diag --boreas-bin ./boreas --self-test
cat /tmp/diag/diagnostics.txt
cat /tmp/diag/SHA256SUMS
```

Exit codes: `0` bundle written and redaction scan clean; `1` redaction
scan hit or self-test failure (bundle deleted, fail-closed); `2` required
tool missing or output directory unusable; `3` usage error.

## Redaction contract

- Never reads private keys, certificates, configuration files, log files,
  other processes' arguments, or environment **values**.
- Hostname, username and `$HOME` are replaced with placeholders in every
  section (including third-party version output, which can embed build
  paths).
- fd targets are never printed — only counts by type (socket/pipe/other).
- `ldd` output is reduced to sonames; resolved paths are stripped.
- After writing, the bundle is scanned for PEM private-key markers, TLS
  key-log labels (`CLIENT_TRAFFIC_SECRET`, `CLIENT_RANDOM`, …) and long
  unlabelled hex/base64 blobs. Any hit deletes the bundle and exits `1`.
  The binary's own labelled SHA-256 line is the only long hex string
  allowed.
- `--self-test` plants a PEM marker and a long hex blob into copies of
  the bundle and requires the scan patterns to match, and requires a
  non-empty `--out` to be refused.

## Honest limits

- Limits and fd counts describe **this collecting shell**, not a running
  Boreas daemon. A daemon's real limits come from its service unit (§10.5)
  and must be collected from `/proc/<daemon-pid>/` by a future,
  separately-reviewed mode — not inferred from this bundle.
- A clean redaction scan means "no known secret-shaped pattern matched",
  not a proof that arbitrary free text is safe. The collector avoids the
  problem by never ingesting logs or configs in the first place; keep it
  that way.
- This script is not the §10.4 console "export redacted bundle" feature
  and does not talk to the management socket.
