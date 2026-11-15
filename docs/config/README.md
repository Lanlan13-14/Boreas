# Config parser, `config-check` and `config-migrate`

`crates/boreas-cli/src/config.rs` is a typed TOML model with fail-closed static policy validation, exposed through two commands:

```
boreas config-check   <path>   # validate, print redacted JSON
boreas config-migrate <path>   # print the canonical version = 2 document
```

Neither command starts a daemon, opens a socket, reads the private key or trust-anchor contents, resolves an endpoint, authenticates a peer, or establishes TLS. `config-check` success means "the document matches the declared schema and static policy" — nothing more. `config-migrate` writes only to stdout.

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

## Schema (canonical, `version = 2`)

Required: `version`, `[node]`, `[paths]`, `[uplink]`. Optional: `[limits]`, `[dns]`; every switch defaults off. Unknown keys are rejected at every level.

| Section | Key | Rule |
|---|---|---|
| — | `version` | `2` (canonical) or `1` (legacy) |
| `[node]` | `net_id` | Exactly 32 hex digits (16 bytes) |
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

Produced without any local compiler, test runner or package-manager invocation, by explicit project policy; every compile/test/format/lint result must come from GitHub Actions. Unverified at the time of writing:

- `cargo check/clippy/test --workspace --locked` cannot resolve until `Cargo.lock` gains `serde_derive`, `serde_core`, `serde_spanned`, `toml_datetime`, `toml_parser`, `toml_writer` and `winnow` (`.github/workflows/refresh-lock.yml` exists for this). `libc 0.2.191` is already in the lock, so the Unix open flags add no new package.
- Rustfmt formatting was applied by hand, not by `cargo fmt`.
- No `G-CRYPTO`, `G-UI` or other §11 gate is asserted. `G-UI` still requires narrow-terminal, non-TTY, `NO_COLOR`, unavailable-DSR, dangerous-operation confirmation, and log/terminal-injection evidence; the status screen remains a one-shot 10-line box, not the §10.4.1 77x18 interactive TUI.
- `config-check` is not daemon startup, not a key or trust-anchor loader, and not proof that any referenced file exists safely.