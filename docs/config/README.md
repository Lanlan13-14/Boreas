# Config parser, `config-check`, `config-migrate` and `config-save-candidate`

`crates/boreas-cli/src/config.rs` is a typed TOML model with fail-closed static policy validation, exposed through three commands:

```
boreas config-check   <path>   # validate, print redacted JSON
boreas config-migrate <path>   # print the canonical version = 2 document
boreas config-save-candidate --config <path> --primary <host:port> [--backup <host:port>] --confirm SAVE
                               # Linux only: write an endpoint-only candidate; never applied
```

None of these commands starts a daemon, opens a socket, reads the private key or trust-anchor contents, resolves an endpoint, authenticates a peer, or establishes TLS. `config-check` success means "the document matches the declared schema and static policy" — nothing more. `config-migrate` writes only to stdout. `config-save-candidate` reads the source, revalidates only the changed endpoints, and writes only an `[uplink]` fragment under the per-user candidate directory; it never applies or replaces the source configuration.

## Two schemas, always by explicit version

The layout is chosen by the document's `version` key and is never guessed:

| `version` | Layout | Status |
|---|---|---|
| `2` | canonical §5.5-aligned: `[node]`, `[paths]`, `[uplink]`, `[limits]`, `[dns]` | current |
| `1` | earlier slice-local: `[network]`, `[identity]`, `[security]`, `[paths]`, `[transport]`, `[features]` | legacy, accepted and reported as migrated |
| absent / other | — | rejected (`SchemaVersionRequired` / `UnsupportedSchemaVersion`) |

A legacy document is never silently treated as current: `config-check` reports `"schema":"legacy-v1","migrated":true`, and the operator is expected to run `config-migrate`, review, and install the result. The shipped examples are [`config.example.toml`](./config.example.toml) (v2) and [`config.legacy-v1.example.toml`](./config.legacy-v1.example.toml) (v1); unit tests parse both, and re-parse the migrated output as v2.

Migration refuses to lose information rather than approximating:

- a legacy uplink with a path/query/fragment → `LegacyUplinkNeedsRewrite` (dropping it would change where the tunnel dials);
- more than two legacy uplinks → `TooManyLegacyUplinks` (use the v2 `[uplink]` section);
- a non-`wss://` scheme → `LegacyUplinkNeedsRewrite`.

Legacy `transport.uplinks[0]` becomes `[uplink].primary` (port defaults to `443`), `uplinks[1]` becomes `backup`, `[features]` maps onto `[limits]`, and `paths`/`probe_paths` take the §5.5 defaults (4 / 1).

## `config-save-candidate`: Linux-only endpoint fragment, never applied

`config-save-candidate` persists a reviewed endpoint change as a **candidate**. It does not install, merge, replace, apply, reload, connect, or start a daemon. It is implemented on Linux only; with a valid source document, Windows and macOS exit 2 with `candidate saving is supported only on Linux` and create nothing.

```
boreas config-save-candidate \
  --config /etc/boreas/config.toml \
  --primary edge.example.net:443 \
  [--backup backup.example.net:443] \
  --confirm SAVE
```

`--config`, `--primary` and `--confirm SAVE` are mandatory; `--backup` is optional. `SAVE` is compared as an exact string: lowercase, surrounding whitespace, prefixes, a missing `--confirm`, or duplicate/unknown arguments fail before any write. The CLI never prompts and never reads stdin for confirmation, so a non-interactive invocation cannot hang waiting for input.

The source is read through the same bounded contract as `config-check` (64 KiB, regular file, mode `0600`, owner root/effective user, final symlink/reparse point refused). The changed endpoints are revalidated by `Config::validate` under `NO_RUNTIME`, so existing identity/slot, security mode/suite, path, limits, DNS capability and non-default `overlay_prefix` refusals still apply. The command does not read key, trust-anchor or state contents, resolve or dial an endpoint, or authenticate anything.

Only an `[uplink]` fragment is written: `primary`, optional `backup`, the source document's existing `paths`/`probe_paths`, and a comment saying the candidate is not applied. It is **not** a complete `version = 2` document — it omits `version`, `[node]`, `[paths]`, limits and DNS — so it cannot be dropped in as a replacement for the active configuration. The command never edits or replaces the source file, and the source's key/root/state references remain unchanged.

Destination contract (Linux):

- If `XDG_CONFIG_HOME` is set, it must be an absolute, **already existing** per-user config root, owned by the effective UID; a relative or unsafe value is refused and there is **no fallback** to `$HOME/.config`. The candidate goes under `$XDG_CONFIG_HOME/boreas/candidates/`.
- If `XDG_CONFIG_HOME` is unset, `$HOME/.config` must be absolute and already exist under the same checks; the candidate goes under `$HOME/.config/boreas/candidates/`.
- Every path component must be a real directory (no symlinks), owned by the effective user or root, and not group/world-writable; the selected root itself must be owned by the effective UID. The selected root is never created by this command.
- Missing `boreas/` and `candidates/` directories below that verified root are auto-created with mode `0700` (and synced). If they already exist, they must be real, current-user-owned directories with mode exactly `0700`; unsafe ones are refused, never chmod-repaired.
- The filename is generated (`uplink-<pid>-<UTC nanoseconds>-<nonce>.toml`), never caller-supplied. It is created exclusively with mode `0600` and no-follow semantics, synced before success, and never overwrites or truncates an existing file; collisions retry a bounded number of times.

Success prints one JSON object and exits 0:

```json
{"saved":true,"applied":false,"candidate":"uplink-<pid>-<timestamp>-<nonce>.toml"}
```

`applied` is always `false`; there is no apply/reload path. `candidate` is a sanitized basename only, not an absolute path. A failure exits 2 and never reports success. If writing has begun, it attempts to remove the partial file and sync the directory; cleanup is best-effort, so a crash or power loss can leave partial state, and newly created `boreas/`/`candidates/` directories may remain.

The console (`boreas-easy` / `boreas console`) remains preview-only: it can edit and preview `[uplink]` endpoints, but it has no save action, and a typed `SAVE` does not write anything. It directs the user to copy the preview and review it outside the console.

## Schema (canonical, `version = 2`)

Required: `version`, `[node]`, `[paths]`, `[uplink]`. Optional: `[limits]`, `[dns]`; every switch defaults off. Unknown keys are rejected at every level.

| Section | Key | Rule |
|---|---|---|
| — | `version` | `2` (canonical) or `1` (legacy) |
| `[node]` | `net_id` | Exactly 32 hex digits (16 bytes) |
| `[node]` | `overlay_prefix` | Optional, defaults to `10.20.0.0/16`; only that default is currently accepted by config validation; custom-prefix API is candidate-only |
| `[node]` | `role` | `core` \| `edge` (model also knows `enrollment`, refused by this schema) |
| `[node]` | `home_core_id` | `1..=16` |
| `[node]` | `vip_octet` | Core: exactly `1`; Edge: `2..=251` |
| `[node]` | `node_id` | `< 4096` and exactly `((home_core_id - 1) << 8) \| vip_octet` |
| `[node]` | `identity_generation` | `>= 1` |
| `[node]` | `security_mode` | `e2e-required` (default) \| `hop-only` |
| `[node]` | `suite` | `pq768` (default); `pq1024` refused until its PoC is accepted |
| `[paths]` | `identity_key` | Absolute; contents never read |
| `[paths]` | `roots` | Non-empty; one string or a list; every entry absolute; contents never read |
| `[paths]` | `state_dir` | Absolute; never created |
| `[uplink]` | `primary` / `backup` | `host:port`; non-empty host, port `1..=65535`, no userinfo/path/query/fragment; IPv6 literals not modelled |
| `[uplink]` | `paths` | `1..=8` (slice-local bound, not a capacity claim) |
| `[uplink]` | `probe_paths` | `0` or `1` |
| `[limits]` | `default_route` | Must be `false` in this release (§1.1 item 6) |
| `[limits]` | `allow_edges` | Only valid with `role = "core"` |
| `[limits]` | `ipv6` / `advertise_routes` / `accept_routes` / `edge_direct` | Accepted as intent; runtime-gated |
| `[dns]` | `listen_vip` | IP literal (a VIP this node owns, not a bind address) |
| `[dns]` | `zone` | Non-empty suffix, `<= 253` bytes, no whitespace/control |
| `[dns]` | `tcp` | Requires a runtime that reports the TCP DNS capability |

Range checks run before derived-value comparisons, so `node_id = 5000` reports an out-of-range slot instead of a mismatch. Nothing is defaulted to a "working" value and no invalid document is silently repaired.

## Overlay prefix: candidate API, not completed runtime support

The candidate `boreas_pki::OverlayPrefix` policy/derivation API accepts only canonical RFC1918 IPv4 `/16` networks: `10.x.0.0/16`, `172.16.0.0/16` through `172.31.0.0/16`, and `192.168.0.0/16`. It rejects public addresses (including `1.1.1.1`), CGNAT `100.64.0.0/10` and its `/16` subsets, loopback/link-local/multicast/reserved ranges, IPv6, nonzero host bits, whitespace, and other mask lengths. It never masks or silently repairs an input. `/16` preserves the existing two-octet base + home-Core + host layout; this is a deliberate layout restriction, not a claim that every other mask lacks enough addresses.

The reserved service address derives as `base.0.53`; Core slots use `base.<1..16>.1`, and each of those sixteen Core blocks retains 250 Edge slots (`.2` through `.251`). NodeID encoding is unchanged. `expected_vip_in` and `NodeIdentity::validate_in` are candidate policy APIs only; the latter is **not** a cryptographic signature-verification or negotiation API. Its expected prefix must be trusted independently, never learned from the identity being checked or an unauthenticated handshake. Existing `expected_vip` / `validate` callers keep their `10.20.0.0/16` behavior.

The v2 schema names the field `[node].overlay_prefix`; legacy v1 names it `[network].overlay_prefix`. Omission and explicit `10.20.0.0/16` are equivalent. JSON summaries and v2 migration output include it, and a prefix change is a high-risk network rebinding. However, **all non-default prefixes are explicitly refused with `CustomOverlayPrefixUnavailable`**, in both schemas and by direct `Config::validate`, even when current runtime capability bits are all enabled. Structurally invalid prefixes instead return `InvalidOverlayPrefix`. Thus `config-check`, migration and daemon config loading cannot silently accept a custom prefix while the runtime still signs/uses `10.20` VIPs. No custom runtime support is claimed by these unit tests.

Before this refusal can be lifted, trusted genesis/network-policy binding, identity issuance and cryptographic verification, peer negotiation, local signed-VIP/config matching, TUN/routes, DNS, and packet/session paths must consistently consume and enforce the same prefix. End-to-end signed positive/negative and mismatched-network evidence is required; merely adding a capability boolean or deriving a prefix from a peer VIP is not sufficient. This slice does not change daemon, main, TUI, protocol or packet-path code.

## `[dns].tcp` is capability-gated, not schema-banned

`Config::parse_toml` / `Config::read_file` take [`RuntimeCapabilities`]. `[dns].tcp = true` is refused only when `capabilities.dns_tcp` is false, and the error names the missing integration rather than calling the field illegal. In this binary `runtime_capabilities()` returns `NO_RUNTIME`, because:

- `crates/boreas-tunnel` currently exposes only in-process session APIs (`LinkClient::connect`, `LinkServer::accept`) — no status snapshot and no `/run/boreas/control.sock`;
- `boreas_dns::TcpDnsSupport` is authoritative and currently reports `Unsupported` (the `pub mod tcp` driver is a prototype awaiting runtime integration).

When the tunnel crate publishes `runtime_capabilities()`, `main.rs` must forward it verbatim. Unit tests flip the same document from rejected to accepted by changing only the capability value, which proves the gate is capability-driven.

## Resource limits and safe file handling

| Limit | Value / behavior |
|---|---|
| Maximum document size | 64 KiB, enforced **in `parse_toml`** (API boundary, so in-memory callers are bounded too) and again around the file read (`metadata().len()` + `take(MAX + 1)`) |
| Accepted file type | Regular files only (`NotRegularFile`) |
| Unix open | `O_NOFOLLOW \| O_NONBLOCK \| O_CLOEXEC`: a FIFO cannot block the caller, and a final-component symlink is refused as `SymlinkNotAllowed` |
| Unix metadata | All checks run on the **file descriptor** (`fstat`), removing the path-based TOCTOU window |
| Unix permissions | Mode `0600`: any group/world bit is refused before reading |
| Unix owner | Must be root or the effective user (`WrongOwner`) |
| Windows | Opened with `FILE_FLAG_OPEN_REPARSE_POINT`; a reparse point is refused. NTFS ACLs are **not** inspected — stated, not implied |
| I/O performed | One open plus one bounded read of the given path; no key, root, state or network access |
| Output | Redacted JSON or one error line; key path, roots, state dir and endpoints are replaced with `[REDACTED]` |

Known bounds of the mitigation: `O_NOFOLLOW` only refuses a symlinked **final component**; intermediate directory symlinks are still resolved by the kernel, and full `RESOLVE_NO_SYMLINKS` behavior would require Linux `openat2` and is not implemented. Parser diagnostics are collapsed to `ParseFailed`, so raw TOML source lines (which may embed secrets) are never echoed. `net_id` is reported in full because it is a public genesis identifier.

## High-risk transitions

`security_transition_requires_high_risk` flags changes to the security mode, suite, network binding, role, permanent slot (`home_core_id`, `vip_octet`, `node_id`), identity generation, key reference or trust anchors. `authorize_security_transition` then requires the literal phrase `HOP-ONLY` for a downgrade to hop-only and `TRUST-ROOT-CHANGE` for any other high-risk rebinding, followed by an audit record and a full session disconnect (§1.3, §5.5).

No daemon, session manager or audit log integrates this API yet, and neither config command ever applies a transition. The contract is covered by unit tests with recording stubs, including the ordering assertion that a missing phrase produces zero audit records and zero disconnects.

## Verification status (evidence boundary)

Formal acceptance is GitHub Actions only; this page performed no local compiler, test-runner, formatter or package-manager execution. Earlier local work on this slice — including the recorded local `cargo`/`rustfmt` attempt — is not acceptance evidence. The candidate-save slice is evidenced at the exact commit [`0295cf8`](https://github.com/Lanlan13-14/Boreas/commit/0295cf86b08261aa57a8fecd3c21fb17be618692): Rust workflow [43972354816](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354816) and TLS workflow [43972354900](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354900) succeeded. That is evidence for the candidate-save/private-directory tests at that SHA only — not for the current branch tip, any later commit, an all-green release, or a production/security gate. The native security workflow for that commit ([43972354797](https://github.com/Lanlan13-14/Boreas/actions/runs/43972354797)) did not pass and remains blocked; no `v0.1.0-pre.4` has been published. Unverified at the time of writing for this tree:

- The overlay slice adds no registry package: `boreas-pki` becomes an unconditional backend-free CLI dependency, and `openssl-inner-tls` still explicitly enables its crypto backend. The existing lock already lists that CLI dependency plus the serde/TOML dependencies; no lock refresh is expected for this slice. This is static inspection, not proof of `--locked` resolution; Actions must verify it.
- Rustfmt formatting was applied by hand, not by `cargo fmt`.
- No `G-CRYPTO`, `G-UI` or other §11 gate is asserted. `G-UI` still requires narrow-terminal, non-TTY, `NO_COLOR`, unavailable-DSR, dangerous-operation confirmation, and log/terminal-injection evidence; the status screen remains a one-shot 10-line box, not the §10.4.1 77x18 interactive TUI.
- `config-check` is not daemon startup, not a key or trust-anchor loader, and not proof that any referenced file exists safely.