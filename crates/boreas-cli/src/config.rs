//! Typed, fail-closed configuration model, schema migration and static policy.
//!
//! Two document layouts are understood, and the layout is never guessed:
//!
//! - `version = 2` — the canonical layout aligned with master plan §5.5
//!   (`[node]`, `[paths]`, `[uplink]`, `[limits]`, `[dns]`).
//! - `version = 1` — the earlier slice-local layout (`[network]`, `[identity]`,
//!   `[security]`, `[paths]`, `[transport]`, `[features]`). It is accepted only
//!   when the document says so explicitly, is reported as migrated in every
//!   output, and can be converted to the canonical layout with
//!   `boreas config-migrate` (stdout only; nothing is rewritten on disk).
//!
//! A document without a `version` key is rejected instead of being assigned a
//! default, so an operator can never unknowingly keep drifting on the old shape.
//!
//! This module parses and validates bounded TOML only. It does not start a
//! daemon, open sockets, resolve endpoints, load key or trust-anchor contents,
//! authenticate peers, or establish TLS. Secret-bearing values are never
//! rendered: key path, trust anchors, state directory and uplink endpoints are
//! replaced in every diagnostic.
//!
//! Capability-gated fields (`[dns].tcp`) are decided by [`RuntimeCapabilities`]
//! supplied by the caller — never by a schema-level ban — so the check follows
//! the actual integration state of the runtime.

use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Hard upper bound on an accepted document, enforced at the API boundary.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Permanent `NodeID` slot space (§3.2): 12 bits, `0..=4095`.
const NODE_ID_LIMIT: u16 = 4096;

/// Slice-local bound on `[uplink].paths`; it is not a capacity claim (§8.1
/// budgets still have to be measured) and must be re-derived when Phase 1
/// publishes its resource envelope.
const MAX_UPLINK_PATHS: u8 = 8;

/// Default active-connection count from the §5.5 template.
const DEFAULT_UPLINK_PATHS: u8 = 4;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Security mode (§1.3). The default is the production policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// Explicit, audited downgrade: forwarding cores can read business plaintext.
    HopOnly,
    /// Production default: relays see circuit metadata and E2E ciphertext only.
    #[default]
    E2eRequired,
}

impl SecurityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HopOnly => "hop-only",
            Self::E2eRequired => "e2e-required",
        }
    }
}

/// Cryptographic suite. It must never be downgraded after network creation (§5.5).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    #[default]
    Pq768,
    Pq1024,
}

impl CryptoSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pq768 => "pq768",
            Self::Pq1024 => "pq1024",
        }
    }
}

/// Node role. `enrollment-service` exists in the model because §2.2 separates
/// identity issuance from forwarding, but this generic node schema does not
/// provision it. Both the §5.5 spelling (`enrollment`) and this crate's canonical
/// spelling parse.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Core,
    Edge,
    #[serde(alias = "enrollment")]
    EnrollmentService,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Edge => "edge",
            Self::EnrollmentService => "enrollment",
        }
    }
}

/// Declared schema version of the document that produced this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaVersion {
    /// Legacy slice-local layout; accepted but always reported as migrated.
    LegacyV1,
    /// Canonical §5.5-aligned layout.
    V2,
}

impl SchemaVersion {
    pub fn as_u32(self) -> u32 {
        match self {
            Self::LegacyV1 => 1,
            Self::V2 => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LegacyV1 => "legacy-v1",
            Self::V2 => "v2",
        }
    }
}

/// Capability facts reported by the running runtime. The CLI never invents them:
/// with no daemon integrated, every capability is false and capability-gated
/// configuration is refused with an explanation naming the missing integration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeCapabilities {
    /// A daemon polls `boreas-dns`'s bounded smoltcp TCP DNS endpoint.
    pub dns_tcp: bool,
    /// A control socket exists that can serve a live status snapshot.
    pub control_socket: bool,
    /// An E2E relay path exists (Phase 5).
    pub e2e_relay: bool,
}

impl RuntimeCapabilities {
    /// No runtime is integrated into this binary yet.
    pub const NO_RUNTIME: Self = Self {
        dns_tcp: false,
        control_socket: false,
        e2e_relay: false,
    };

    /// Capabilities of a runtime that reports everything §1.3 requires.
    pub const FULL: Self = Self {
        dns_tcp: true,
        control_socket: true,
        e2e_relay: true,
    };
}

// ---------------------------------------------------------------------------
// Normalized model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub schema: SchemaVersion,
    pub network: NetworkConfig,
    pub identity: IdentityConfig,
    pub security: SecurityConfig,
    pub paths: PathsConfig,
    pub uplinks: UplinkConfig,
    pub limits: LimitsConfig,
    pub dns: Option<DnsConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Exactly 32 hexadecimal digits (16 bytes), the network genesis parameter.
    pub net_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityConfig {
    pub role: NodeRole,
    /// Core slot, `1..=16` (§3.2).
    pub home_core_id: u8,
    /// Host octet inside the core's VIP /16.
    pub vip_octet: u8,
    /// Permanent node identifier; must equal the slot encoding below.
    pub node_id: u16,
    /// Monotonic identity generation; `0` is never valid.
    pub identity_generation: u64,
    /// Absolute path reference only; contents are never read here.
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub mode: SecurityMode,
    #[serde(default)]
    pub suite: CryptoSuite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathsConfig {
    /// Trust-anchor files; each absolute. Contents are not loaded here.
    pub roots: Vec<PathBuf>,
    /// Durable state directory; absolute. It is not created here.
    pub state_dir: PathBuf,
}

/// §5.5 `[uplink]`: one primary endpoint, an optional backup, and bounded
/// path counts. Endpoints are `host:port` (the §5.5 form); the runtime is
/// responsible for turning them into `wss://` URLs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UplinkConfig {
    pub primary: String,
    pub backup: Option<String>,
    pub paths: u8,
    pub probe_paths: u8,
}

/// §5.5 `[limits]`, plus the §1.1 `edge_direct` switch, all defaulting off.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub advertise_routes: bool,
    #[serde(default)]
    pub accept_routes: bool,
    #[serde(default)]
    pub edge_direct: bool,
    /// Core-only admission of edges; meaningless (and refused) for other roles.
    #[serde(default)]
    pub allow_edges: bool,
    /// Whole-network default-route egress; refused in this release (§1.1 item 6).
    #[serde(default)]
    pub default_route: bool,
}

/// §5.5 `[dns]`. `tcp` is a *requested* capability validated against
/// [`RuntimeCapabilities::dns_tcp`]; it is not a schema-level ban.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub listen_vip: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub tcp: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Static validation failures. Variant names are diagnostic codes; [`fmt::Display`]
/// carries the human-readable, secret-free message the CLI prints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    SchemaVersionRequired,
    UnsupportedSchemaVersion,
    InvalidNetId,
    InvalidNodeId,
    InvalidHomeCoreId,
    InvalidVipOctet,
    EnrollmentRoleNotProvisionable,
    NodeIdMismatch,
    InvalidGeneration,
    PrivateKeyPathNotAbsolute,
    RootsRequired,
    RootPathNotAbsolute,
    StatePathNotAbsolute,
    InvalidEndpoint,
    InvalidPathCount,
    InvalidProbePaths,
    Pq1024Disabled,
    DefaultRouteUnsupported,
    AllowEdgesRequiresCore,
    InvalidDnsListenVip,
    InvalidDnsZone,
    DnsTcpUnavailable,
    TooManyLegacyUplinks,
    LegacyUplinkNeedsRewrite,
    ReadFailed,
    NotRegularFile,
    SymlinkNotAllowed,
    WrongOwner,
    TooLarge,
    ParseFailed,
    UnsafePermissions,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SchemaVersionRequired => {
                "the document must declare `version = 1` (legacy) or `version = 2` (current)"
            }
            Self::UnsupportedSchemaVersion => {
                "unsupported `version`; only 1 (legacy) and 2 (current) are understood"
            }
            Self::InvalidNetId => {
                "network net_id must be exactly 32 hexadecimal digits (16 bytes)"
            }
            Self::InvalidNodeId => "node_id is outside the permanent 12-bit slot range (0..=4095)",
            Self::InvalidHomeCoreId => "home_core_id must be within 1..=16",
            Self::InvalidVipOctet => "vip_octet is not valid for the configured role",
            Self::EnrollmentRoleNotProvisionable => {
                "role `enrollment` cannot be provisioned by the generic node schema"
            }
            Self::NodeIdMismatch => "node_id must equal ((home_core_id - 1) << 8) | vip_octet",
            Self::InvalidGeneration => "identity_generation must be at least 1",
            Self::PrivateKeyPathNotAbsolute => "identity key path must be absolute",
            Self::RootsRequired => "at least one trust-anchor root is required",
            Self::RootPathNotAbsolute => "every trust-anchor root path must be absolute",
            Self::StatePathNotAbsolute => "state_dir must be absolute",
            Self::InvalidEndpoint => {
                "uplink endpoint must be `host:port` with a non-empty host, no userinfo, no path, and port 1..=65535"
            }
            Self::InvalidPathCount => "uplink.paths must be within 1..=8",
            Self::InvalidProbePaths => "uplink.probe_paths must be 0 or 1",
            Self::Pq1024Disabled => {
                "suite pq1024 is disabled until its separate PoC and review are accepted"
            }
            Self::DefaultRouteUnsupported => {
                "limits.default_route is not supported by this release"
            }
            Self::AllowEdgesRequiresCore => "limits.allow_edges is only meaningful for role `core`",
            Self::InvalidDnsListenVip => "dns.listen_vip must be an IP address literal",
            Self::InvalidDnsZone => "dns.zone must be a non-empty domain suffix without whitespace",
            Self::DnsTcpUnavailable => {
                "dns.tcp requires a runtime that polls the bounded TCP DNS endpoint; no integrated runtime reported that capability"
            }
            Self::TooManyLegacyUplinks => {
                "legacy `transport.uplinks` accepts at most two entries (primary and backup); split the rest into the v2 `[uplink]` section"
            }
            Self::LegacyUplinkNeedsRewrite => {
                "legacy uplink URLs must be `wss://host[:port]` with no path, query or fragment before migration; rewrite them as v2 `[uplink]` endpoints"
            }
            Self::ReadFailed => "configuration file could not be read",
            Self::NotRegularFile => "configuration path is not a regular file",
            Self::SymlinkNotAllowed => {
                "configuration path is a symbolic link or reparse point; pass the real file"
            }
            Self::WrongOwner => {
                "configuration file is not owned by root or the current user"
            }
            Self::TooLarge => "configuration file exceeds the 64 KiB limit",
            Self::ParseFailed => {
                "configuration is not valid TOML or does not match the declared schema"
            }
            Self::UnsafePermissions => {
                "configuration file is group- or world-accessible; expected mode 0600"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Raw documents
// ---------------------------------------------------------------------------

/// Minimal probe used only to read the declared schema version before the
/// version-specific deserialization. It deliberately ignores every other key.
/// A non-integer `version` fails to deserialize here and is reported as a schema
/// mismatch; a missing one is reported separately.
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    version: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Document {
    version: u32,
    node: V2Node,
    paths: V2Paths,
    uplink: V2Uplink,
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    dns: Option<DnsConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Node {
    net_id: String,
    role: String,
    home_core_id: u8,
    vip_octet: u8,
    node_id: u16,
    identity_generation: u64,
    #[serde(default)]
    security_mode: SecurityMode,
    #[serde(default)]
    suite: CryptoSuite,
}

/// §5.5 shows a single anchor path; a list is accepted because root rotation
/// needs more than one. One string and a one-element list mean the same thing.
#[derive(Deserialize)]
#[serde(untagged)]
enum RootsInput {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl RootsInput {
    fn into_vec(self) -> Vec<PathBuf> {
        match self {
            Self::One(path) => vec![path],
            Self::Many(paths) => paths,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Paths {
    identity_key: PathBuf,
    roots: RootsInput,
    state_dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Uplink {
    primary: String,
    #[serde(default)]
    backup: Option<String>,
    #[serde(default = "default_uplink_paths")]
    paths: u8,
    #[serde(default = "default_probe_paths")]
    probe_paths: u8,
}

fn default_uplink_paths() -> u8 {
    DEFAULT_UPLINK_PATHS
}

fn default_probe_paths() -> u8 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDocument {
    version: u32,
    network: LegacyNetwork,
    identity: LegacyIdentity,
    #[serde(default)]
    security: SecurityConfig,
    paths: LegacyPaths,
    transport: LegacyTransport,
    #[serde(default)]
    features: LegacyFeatures,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyNetwork {
    net_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyIdentity {
    role: NodeRole,
    home_core_id: u8,
    vip_octet: u8,
    node_id: u16,
    identity_generation: u64,
    private_key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPaths {
    roots: Vec<PathBuf>,
    state_dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTransport {
    uplinks: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyFeatures {
    #[serde(default)]
    ipv6: bool,
    #[serde(default)]
    advertise_routes: bool,
    #[serde(default)]
    accept_routes: bool,
    #[serde(default)]
    edge_direct: bool,
    #[serde(default)]
    default_route: bool,
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

impl Config {
    /// Parse a TOML document, honor its declared schema version, and validate
    /// it against the supplied runtime capabilities.
    ///
    /// The size bound is enforced here, not only in [`Config::read_file`], so
    /// every caller is bounded — including a future control-socket path that
    /// hands over an in-memory string.
    pub fn parse_toml(input: &str, capabilities: RuntimeCapabilities) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        // A tiny probe first: the layout is chosen by the declared version, never
        // guessed, and an absent version is an error rather than a default.
        let probe: VersionProbe = toml::from_str(input).map_err(|_| ConfigError::ParseFailed)?;
        let Some(version) = probe.version else {
            return Err(ConfigError::SchemaVersionRequired);
        };
        let config = match version {
            1 => {
                let raw: LegacyDocument =
                    toml::from_str(input).map_err(|_| ConfigError::ParseFailed)?;
                if raw.version != 1 {
                    return Err(ConfigError::UnsupportedSchemaVersion);
                }
                Self::migrate_legacy(raw)?
            }
            2 => {
                let raw: V2Document = toml::from_str(input).map_err(|_| ConfigError::ParseFailed)?;
                if raw.version != 2 {
                    return Err(ConfigError::UnsupportedSchemaVersion);
                }
                Self::from_v2(raw)?
            }
            _ => return Err(ConfigError::UnsupportedSchemaVersion),
        };
        config.validate(capabilities)?;
        Ok(config)
    }

    fn from_v2(raw: V2Document) -> Result<Self, ConfigError> {
        // §5.5 spells the third role `enrollment`; the shared parser accepts
        // both spellings, so map the raw string explicitly here.
        let role = match raw.node.role.as_str() {
            "core" => NodeRole::Core,
            "edge" => NodeRole::Edge,
            "enrollment" | "enrollment-service" => NodeRole::EnrollmentService,
            _ => return Err(ConfigError::ParseFailed),
        };
        Ok(Self {
            schema: SchemaVersion::V2,
            network: NetworkConfig {
                net_id: raw.node.net_id,
            },
            identity: IdentityConfig {
                role,
                home_core_id: raw.node.home_core_id,
                vip_octet: raw.node.vip_octet,
                node_id: raw.node.node_id,
                identity_generation: raw.node.identity_generation,
                private_key: raw.paths.identity_key,
            },
            security: SecurityConfig {
                mode: raw.node.security_mode,
                suite: raw.node.suite,
            },
            paths: PathsConfig {
                roots: raw.paths.roots.into_vec(),
                state_dir: raw.paths.state_dir,
            },
            uplinks: UplinkConfig {
                primary: raw.uplink.primary,
                backup: raw.uplink.backup,
                paths: raw.uplink.paths,
                probe_paths: raw.uplink.probe_paths,
            },
            limits: raw.limits,
            dns: raw.dns,
        })
    }

    /// Explicit legacy migration. Nothing is guessed: an old document that
    /// cannot be mapped without losing information is refused with an
    /// instruction to rewrite the affected field.
    fn migrate_legacy(raw: LegacyDocument) -> Result<Self, ConfigError> {
        let mut endpoints: Vec<String> = Vec::with_capacity(raw.transport.uplinks.len());
        for url in &raw.transport.uplinks {
            endpoints.push(legacy_wss_to_endpoint(url)?);
        }
        if endpoints.is_empty() {
            return Err(ConfigError::InvalidEndpoint);
        }
        if endpoints.len() > 2 {
            return Err(ConfigError::TooManyLegacyUplinks);
        }
        let primary = endpoints[0].clone();
        let backup = endpoints.get(1).cloned();
        Ok(Self {
            schema: SchemaVersion::LegacyV1,
            network: NetworkConfig {
                net_id: raw.network.net_id,
            },
            identity: IdentityConfig {
                role: raw.identity.role,
                home_core_id: raw.identity.home_core_id,
                vip_octet: raw.identity.vip_octet,
                node_id: raw.identity.node_id,
                identity_generation: raw.identity.identity_generation,
                private_key: raw.identity.private_key,
            },
            security: SecurityConfig {
                mode: raw.security.mode,
                suite: raw.security.suite,
            },
            paths: PathsConfig {
                roots: raw.paths.roots,
                state_dir: raw.paths.state_dir,
            },
            uplinks: UplinkConfig {
                primary,
                backup,
                paths: DEFAULT_UPLINK_PATHS,
                probe_paths: 1,
            },
            limits: LimitsConfig {
                ipv6: raw.features.ipv6,
                advertise_routes: raw.features.advertise_routes,
                accept_routes: raw.features.accept_routes,
                edge_direct: raw.features.edge_direct,
                allow_edges: false,
                default_route: raw.features.default_route,
            },
            dns: None,
        })
    }

    /// Read a bounded configuration file through a single safe open.
    ///
    /// Unix: `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, so a FIFO cannot block the
    /// caller and the final path component cannot be a symlink; all checks then
    /// run on the *file descriptor's* metadata (`fstat`), which removes the
    /// path-based TOCTOU window. Owner must be root or the effective user, and
    /// mode must be `0600` (§5.5).
    ///
    /// Windows: the file is opened without following reparse points, and a
    /// reparse point is refused. NTFS ACLs are not inspected; that is stated
    /// rather than implied.
    pub fn read_file(
        path: &Path,
        capabilities: RuntimeCapabilities,
    ) -> Result<Self, ConfigError> {
        let file = open_no_follow(path)?;
        let metadata = file.metadata().map_err(|_| ConfigError::ReadFailed)?;
        if !metadata.file_type().is_file() {
            #[cfg(unix)]
            if metadata.file_type().is_symlink() {
                return Err(ConfigError::SymlinkNotAllowed);
            }
            return Err(ConfigError::NotRegularFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigError::UnsafePermissions);
            }
            let owner = metadata.uid();
            // SAFETY: `geteuid` is a pure getter with no arguments and no
            // preconditions; it cannot fail and has no side effects.
            let effective_uid = unsafe { libc::geteuid() };
            if owner != 0 && owner != effective_uid {
                return Err(ConfigError::WrongOwner);
            }
        }
        if metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(ConfigError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_CONFIG_BYTES as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::ReadFailed)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let input = std::str::from_utf8(&bytes).map_err(|_| ConfigError::ParseFailed)?;
        Self::parse_toml(input, capabilities)
    }

    /// Machine-readable summary. Secret-bearing values are replaced; `net_id` is
    /// a public genesis identifier and the path counts are not secret.
    pub fn redacted_json(&self) -> String {
        let (backup_present, probe_paths) = (self.uplinks.backup.is_some(), self.uplinks.probe_paths);
        let dns = match &self.dns {
            None => "\"dns\":null".to_string(),
            Some(dns) => format!(
                "\"dns\":{{\"configured\":true,\"tcp\":{},\"listen_vip\":{},\"zone\":{}}}",
                dns.tcp,
                dns.listen_vip.is_some(),
                dns.zone.is_some()
            ),
        };
        format!(
            concat!(
                "{{\"valid\":true,\"schema_version\":{},\"schema\":\"{}\",\"migrated\":{},",
                "\"net_id\":\"{}\",\"role\":\"{}\",\"home_core_id\":{},",
                "\"node_id\":{},\"identity_generation\":{},\"security_mode\":\"{}\",",
                "\"suite\":\"{}\",\"uplink\":{{\"backup\":{},\"paths\":{},\"probe_paths\":{}}},",
                "\"limits\":{{\"ipv6\":{},\"advertise_routes\":{},\"accept_routes\":{},",
                "\"edge_direct\":{},\"allow_edges\":{},\"default_route\":{}}},",
                "{},",
                "\"identity_key\":\"[REDACTED]\",\"roots\":\"[REDACTED]\",",
                "\"state_dir\":\"[REDACTED]\",\"endpoints\":\"[REDACTED]\"}}"
            ),
            self.schema.as_u32(),
            self.schema.label(),
            self.schema == SchemaVersion::LegacyV1,
            self.network.net_id,
            self.identity.role.as_str(),
            self.identity.home_core_id,
            self.identity.node_id,
            self.identity.identity_generation,
            self.security.mode.as_str(),
            self.security.suite.as_str(),
            backup_present,
            self.uplinks.paths,
            probe_paths,
            self.limits.ipv6,
            self.limits.advertise_routes,
            self.limits.accept_routes,
            self.limits.edge_direct,
            self.limits.allow_edges,
            self.limits.default_route,
            dns,
        )
    }

    /// Canonical `version = 2` TOML for this value. Used by `config-migrate` to
    /// print an explicit migration; the file on disk is never modified.
    pub fn to_v2_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("# Generated by `boreas config-migrate`; review before installing.\n");
        out.push_str(&format!(
            "# Source schema: version {} ({}).\n",
            self.schema.as_u32(),
            self.schema.label()
        ));
        out.push_str("version = 2\n\n[node]\n");
        out.push_str(&format!("net_id = {}\n", toml_string(&self.network.net_id)));
        out.push_str(&format!("role = {}\n", toml_string(self.identity.role.as_str())));
        out.push_str(&format!("home_core_id = {}\n", self.identity.home_core_id));
        out.push_str(&format!("vip_octet = {}\n", self.identity.vip_octet));
        out.push_str(&format!("node_id = {}\n", self.identity.node_id));
        out.push_str(&format!(
            "identity_generation = {}\n",
            self.identity.identity_generation
        ));
        out.push_str(&format!(
            "security_mode = {}\n",
            toml_string(self.security.mode.as_str())
        ));
        out.push_str(&format!("suite = {}\n\n[paths]\n", toml_string(self.security.suite.as_str())));
        out.push_str(&format!(
            "identity_key = {}\n",
            toml_string(&path_text(&self.identity.private_key))
        ));
        let roots: Vec<String> = self
            .paths
            .roots
            .iter()
            .map(|root| toml_string(&path_text(root)))
            .collect();
        out.push_str(&format!("roots = [{}]\n", roots.join(", ")));
        out.push_str(&format!(
            "state_dir = {}\n\n[uplink]\n",
            toml_string(&path_text(&self.paths.state_dir))
        ));
        out.push_str(&format!("primary = {}\n", toml_string(&self.uplinks.primary)));
        if let Some(backup) = &self.uplinks.backup {
            out.push_str(&format!("backup = {}\n", toml_string(backup)));
        }
        out.push_str(&format!(
            "paths = {}\nprobe_paths = {}\n\n[limits]\n",
            self.uplinks.paths, self.uplinks.probe_paths
        ));
        out.push_str(&format!(
            "ipv6 = {}\nadvertise_routes = {}\naccept_routes = {}\nedge_direct = {}\nallow_edges = {}\ndefault_route = {}\n",
            self.limits.ipv6,
            self.limits.advertise_routes,
            self.limits.accept_routes,
            self.limits.edge_direct,
            self.limits.allow_edges,
            self.limits.default_route
        ));
        if let Some(dns) = &self.dns {
            out.push_str("\n[dns]\n");
            if let Some(vip) = &dns.listen_vip {
                out.push_str(&format!("listen_vip = {}\n", toml_string(vip)));
            }
            if let Some(zone) = &dns.zone {
                out.push_str(&format!("zone = {}\n", toml_string(zone)));
            }
            out.push_str(&format!("tcp = {}\n", dns.tcp));
        }
        out
    }

    /// Validate required security-critical identifiers and policy. Existence,
    /// permissions, key encoding and trust-chain validity are later runtime jobs.
    pub fn validate(&self, capabilities: RuntimeCapabilities) -> Result<(), ConfigError> {
        if self.network.net_id.len() != 32
            || !self.network.net_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ConfigError::InvalidNetId);
        }
        let identity = &self.identity;
        if !(1..=16).contains(&identity.home_core_id) {
            return Err(ConfigError::InvalidHomeCoreId);
        }
        if identity.node_id >= NODE_ID_LIMIT {
            return Err(ConfigError::InvalidNodeId);
        }
        let role_octet_valid = match identity.role {
            NodeRole::Core => identity.vip_octet == 1,
            NodeRole::Edge => (2..=251).contains(&identity.vip_octet),
            NodeRole::EnrollmentService => {
                return Err(ConfigError::EnrollmentRoleNotProvisionable);
            }
        };
        if !role_octet_valid {
            return Err(ConfigError::InvalidVipOctet);
        }
        // §3.2 permanent slot encoding; a declared ID that drifts from it is a
        // configuration error, never silently repaired.
        let expected_node_id =
            ((u16::from(identity.home_core_id) - 1) << 8) | u16::from(identity.vip_octet);
        if identity.node_id != expected_node_id {
            return Err(ConfigError::NodeIdMismatch);
        }
        if identity.identity_generation == 0 {
            return Err(ConfigError::InvalidGeneration);
        }
        if !identity.private_key.is_absolute() {
            return Err(ConfigError::PrivateKeyPathNotAbsolute);
        }
        if self.paths.roots.is_empty() {
            return Err(ConfigError::RootsRequired);
        }
        if self.paths.roots.iter().any(|path| !path.is_absolute()) {
            return Err(ConfigError::RootPathNotAbsolute);
        }
        if !self.paths.state_dir.is_absolute() {
            return Err(ConfigError::StatePathNotAbsolute);
        }
        if !valid_endpoint(&self.uplinks.primary) {
            return Err(ConfigError::InvalidEndpoint);
        }
        if let Some(backup) = &self.uplinks.backup
            && !valid_endpoint(backup)
        {
            return Err(ConfigError::InvalidEndpoint);
        }
        if !(1..=MAX_UPLINK_PATHS).contains(&self.uplinks.paths) {
            return Err(ConfigError::InvalidPathCount);
        }
        if self.uplinks.probe_paths > 1 {
            return Err(ConfigError::InvalidProbePaths);
        }
        if self.security.suite == CryptoSuite::Pq1024 {
            return Err(ConfigError::Pq1024Disabled);
        }
        if self.limits.default_route {
            return Err(ConfigError::DefaultRouteUnsupported);
        }
        if self.limits.allow_edges && self.identity.role != NodeRole::Core {
            return Err(ConfigError::AllowEdgesRequiresCore);
        }
        if let Some(dns) = &self.dns {
            if let Some(vip) = &dns.listen_vip
                && vip.parse::<IpAddr>().is_err()
            {
                return Err(ConfigError::InvalidDnsListenVip);
            }
            if let Some(zone) = &dns.zone
                && !valid_zone(zone)
            {
                return Err(ConfigError::InvalidDnsZone);
            }
            if dns.tcp && !capabilities.dns_tcp {
                return Err(ConfigError::DnsTcpUnavailable);
            }
        }
        Ok(())
    }

    /// True when moving from `self` to `next` changes a high-risk binding: the
    /// security mode, the network binding, the permanent identity slot, the
    /// identity generation, the key reference, the trust anchors, or the suite.
    /// Such a change is not a failover action (§1.3, §5.5).
    pub fn security_transition_requires_high_risk(&self, next: &Self) -> bool {
        self.security.mode != next.security.mode
            || self.security.suite != next.security.suite
            || self.network.net_id != next.network.net_id
            || self.identity.role != next.identity.role
            || self.identity.home_core_id != next.identity.home_core_id
            || self.identity.vip_octet != next.identity.vip_octet
            || self.identity.node_id != next.identity.node_id
            || self.identity.identity_generation != next.identity.identity_generation
            || self.identity.private_key != next.identity.private_key
            || self.paths.roots != next.paths.roots
    }

    /// Redacted diagnostic representation, kept for future logging.
    #[allow(
        dead_code,
        reason = "redacted Debug view is exercised by tests; the CLI uses redacted_json"
    )]
    pub fn redacted(&self) -> RedactedConfig<'_> {
        RedactedConfig(self)
    }
}

/// Open a path without following a final-component symlink/reparse point and
/// without blocking on a FIFO. `O_NONBLOCK` has no effect on regular files.
fn open_no_follow(path: &Path) -> Result<File, ConfigError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the link itself, never its target.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|error| classify_open_error(&error))
}

/// Map an open failure onto the narrowest honest diagnostic. `ELOOP` means the
/// final component was a symlink and `O_NOFOLLOW` refused to traverse it.
fn classify_open_error(error: &std::io::Error) -> ConfigError {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return ConfigError::SymlinkNotAllowed;
    }
    let _ = error;
    ConfigError::ReadFailed
}

/// Validate a `host:port` endpoint in the §5.5 form. No resolution, no dialling.
fn valid_endpoint(value: &str) -> bool {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || value.contains('@')
        || value.contains('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
    {
        return false;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    // Bare IPv6 literals need brackets in this form, which this slice does not
    // model; reject rather than silently mis-parse.
    if host.contains(':') {
        return false;
    }
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Convert one legacy `wss://host[:port]` uplink into a `host:port` endpoint.
/// Anything carrying a path, query or fragment is refused: dropping it silently
/// would change where the tunnel dials.
fn legacy_wss_to_endpoint(url: &str) -> Result<String, ConfigError> {
    let Some(rest) = url.strip_prefix("wss://") else {
        return Err(ConfigError::LegacyUplinkNeedsRewrite);
    };
    if rest.is_empty() || rest.contains('@') || rest.contains('\\') {
        return Err(ConfigError::LegacyUplinkNeedsRewrite);
    }
    let authority = match rest.find(['/', '?', '#']) {
        Some(index) => {
            let (authority, tail) = rest.split_at(index);
            if tail != "/" {
                return Err(ConfigError::LegacyUplinkNeedsRewrite);
            }
            authority
        }
        None => rest,
    };
    let endpoint = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:443")
    };
    if !valid_endpoint(&endpoint) {
        return Err(ConfigError::LegacyUplinkNeedsRewrite);
    }
    Ok(endpoint)
}

/// A DNS zone suffix: non-empty, bounded, no whitespace or control characters.
fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 253
        && !zone
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path_text(path: &Path) -> String {
    // Display is lossy only for non-UTF-8 paths, which are already rejected by
    // the UTF-8 document requirement; this is a rendering helper, not identity.
    path.to_string_lossy().into_owned()
}

pub struct RedactedConfig<'a>(&'a Config);

#[allow(
    dead_code,
    reason = "redacted Debug view is exercised by tests; the CLI uses redacted_json"
)]
impl fmt::Debug for RedactedConfig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config = self.0;
        f.debug_struct("Config")
            .field("schema", &config.schema.label())
            .field("network", &config.network)
            .field(
                "identity",
                &format_args!(
                    "role={}, node_id={}, identity_generation={}, private_key=[REDACTED PATH]",
                    config.identity.role.as_str(),
                    config.identity.node_id,
                    config.identity.identity_generation
                ),
            )
            .field("security", &config.security)
            .field(
                "roots",
                &format_args!(
                    "{} trust anchor path(s) [PATHS REDACTED]",
                    config.paths.roots.len()
                ),
            )
            .field("state_dir", &"[REDACTED PATH]")
            .field(
                "uplink",
                &format_args!(
                    "backup={}, paths={}, probe_paths={} [ENDPOINTS REDACTED]",
                    config.uplinks.backup.is_some(),
                    config.uplinks.paths,
                    config.uplinks.probe_paths
                ),
            )
            .field("limits", &config.limits)
            .field("dns", &config.dns)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// High-risk transitions
// ---------------------------------------------------------------------------

/// Persist a security-transition audit record.
#[allow(
    dead_code,
    reason = "no daemon integrates transitions yet; the contract is tested directly"
)]
pub trait SecurityAudit {
    type Error;
    fn record_security_transition(&mut self, old: &Config, new: &Config) -> Result<(), Self::Error>;
}

/// Drop every established session so a changed trust model cannot apply to old
/// connections.
#[allow(
    dead_code,
    reason = "no daemon integrates transitions yet; the contract is tested directly"
)]
pub trait SessionDisconnect {
    type Error;
    fn disconnect_all_sessions(&mut self) -> Result<(), Self::Error>;
}

#[allow(
    dead_code,
    reason = "no daemon integrates transitions yet; the contract is tested directly"
)]
#[derive(Debug, Eq, PartialEq)]
pub enum TransitionError<E> {
    ConfirmationRequired,
    Audit(E),
    Disconnect(E),
}

/// Authorize a high-risk transition: explicit confirmation phrase, an audit
/// record, and a full session disconnect must all happen before the new
/// configuration may take effect (§1.3, §5.5). No standalone boolean authorizes
/// the change, and this function never itself reloads or applies a configuration.
#[allow(
    dead_code,
    reason = "no daemon loads or applies configuration yet; the contract is tested directly"
)]
pub fn authorize_security_transition<A: SecurityAudit, D: SessionDisconnect>(
    old: &Config,
    new: &Config,
    confirmation: Option<&str>,
    audit: &mut A,
    disconnect: &mut D,
) -> Result<(), TransitionError<A::Error>>
where
    D: SessionDisconnect<Error = A::Error>,
{
    if !old.security_transition_requires_high_risk(new) {
        return Ok(());
    }
    let downgrades_to_hop_only =
        new.security.mode != old.security.mode && new.security.mode == SecurityMode::HopOnly;
    let required_phrase = if downgrades_to_hop_only {
        "HOP-ONLY"
    } else {
        "TRUST-ROOT-CHANGE"
    };
    if confirmation != Some(required_phrase) {
        return Err(TransitionError::ConfirmationRequired);
    }
    audit
        .record_security_transition(old, new)
        .map_err(TransitionError::Audit)?;
    disconnect
        .disconnect_all_sessions()
        .map_err(TransitionError::Disconnect)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute fixture root valid on the host family. TOML basic strings
    /// interpret backslashes, so Windows uses forward slashes (`C:/...`).
    #[cfg(windows)]
    const TEST_BASE: &str = "C:/boreas-tests";
    #[cfg(not(windows))]
    const TEST_BASE: &str = "/boreas-tests";

    const NO_CAPS: RuntimeCapabilities = RuntimeCapabilities::NO_RUNTIME;

    fn v2_toml() -> String {
        format!(
            r#"
version = 2
[node]
net_id = "0123456789abcdef0123456789abcdef"
role = "core"
home_core_id = 2
vip_octet = 1
node_id = 257
identity_generation = 1
[paths]
identity_key = "{TEST_BASE}/identity.key"
roots = ["{TEST_BASE}/roots.cbor"]
state_dir = "{TEST_BASE}/state"
[uplink]
primary = "hub-us-c.example.net:443"
backup = "hub-us-d.example.net:443"
paths = 4
probe_paths = 1
"#
        )
    }

    fn legacy_toml() -> String {
        format!(
            r#"
version = 1
[network]
net_id = "0123456789abcdef0123456789abcdef"
[identity]
role = "core"
home_core_id = 2
vip_octet = 1
node_id = 257
identity_generation = 1
private_key = "{TEST_BASE}/identity.key"
[paths]
roots = ["{TEST_BASE}/roots.cbor"]
state_dir = "{TEST_BASE}/state"
[transport]
uplinks = ["wss://core.example.net"]
[features]
ipv6 = false
"#
        )
    }

    fn parse(input: &str) -> Result<Config, ConfigError> {
        Config::parse_toml(input, NO_CAPS)
    }

    #[test]
    fn size_bound_is_enforced_at_the_api_boundary() {
        let oversized = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert_eq!(parse(&oversized), Err(ConfigError::TooLarge));
        // Just under the bound fails for a different reason, proving the bound
        // itself (not a parse accident) produced TooLarge above.
        let boundary = format!("{}{}", "x".repeat(MAX_CONFIG_BYTES - 1), "\n");
        assert_eq!(parse(&boundary), Err(ConfigError::ParseFailed));
    }

    #[test]
    fn schema_version_is_required_and_validated() {
        assert_eq!(
            parse(&v2_toml().replace("version = 2\n", "")),
            Err(ConfigError::SchemaVersionRequired)
        );
        assert_eq!(
            parse(&v2_toml().replace("version = 2", "version = 3")),
            Err(ConfigError::UnsupportedSchemaVersion)
        );
        assert_eq!(
            parse(&v2_toml().replace("version = 2", "version \"2\"")),
            Err(ConfigError::ParseFailed)
        );
        // Declared version must match the body: a v2 body under version = 1
        // cannot be read as a legacy document.
        assert_eq!(
            parse(&v2_toml().replace("version = 2", "version = 1")),
            Err(ConfigError::ParseFailed)
        );
    }

    #[test]
    fn canonical_v2_document_validates_and_defaults() {
        let config = parse(&v2_toml()).unwrap();
        assert_eq!(config.schema, SchemaVersion::V2);
        assert_eq!(config.security.mode, SecurityMode::E2eRequired);
        assert_eq!(config.security.suite, CryptoSuite::Pq768);
        assert_eq!(config.limits, LimitsConfig::default());
        assert!(config.dns.is_none());
        assert!(!config.redacted_json().contains("\"migrated\":true"));
    }

    #[test]
    fn v2_optional_sections_and_partial_limits_parse() {
        let with_limits = format!("{}[limits]\nipv6 = true\n", v2_toml());
        let config = parse(&with_limits).unwrap();
        assert!(config.limits.ipv6);
        assert!(!config.limits.allow_edges);

        let with_dns = format!("{}[dns]\nlisten_vip = \"10.20.0.53\"\nzone = \".boreas\"\n", v2_toml());
        let config = parse(&with_dns).unwrap();
        let dns = config.dns.as_ref().unwrap();
        assert_eq!(dns.zone.as_deref(), Some(".boreas"));
        assert!(!dns.tcp);
    }

    #[test]
    fn roots_accept_one_string_or_a_list() {
        let single = v2_toml().replace(
            &format!("roots = [\"{TEST_BASE}/roots.cbor\"]"),
            &format!("roots = \"{TEST_BASE}/roots.cbor\""),
        );
        assert_eq!(parse(&single).unwrap().paths.roots.len(), 1);
        let double = v2_toml().replace(
            &format!("roots = [\"{TEST_BASE}/roots.cbor\"]"),
            &format!("roots = [\"{TEST_BASE}/roots.cbor\", \"{TEST_BASE}/roots2.cbor\"]"),
        );
        assert_eq!(parse(&double).unwrap().paths.roots.len(), 2);
    }

    #[test]
    fn legacy_document_is_accepted_but_explicitly_migrated() {
        let config = parse(&legacy_toml()).unwrap();
        assert_eq!(config.schema, SchemaVersion::LegacyV1);
        assert_eq!(config.uplinks.primary, "core.example.net:443");
        assert!(config.uplinks.backup.is_none());
        assert_eq!(config.uplinks.paths, DEFAULT_UPLINK_PATHS);
        let json = config.redacted_json();
        assert!(json.contains("\"migrated\":true"), "{json}");
        assert!(json.contains("\"schema\":\"legacy-v1\""));
    }

    #[test]
    fn legacy_migration_refuses_lossy_input() {
        // A path on the URL would be dropped by a silent migration.
        let with_path = legacy_toml().replace(
            "wss://core.example.net",
            "wss://core.example.net/boreas/edge",
        );
        assert_eq!(parse(&with_path), Err(ConfigError::LegacyUplinkNeedsRewrite));

        let three = legacy_toml().replace(
            "uplinks = [\"wss://core.example.net\"]",
            "uplinks = [\"wss://a.example.net\", \"wss://b.example.net\", \"wss://c.example.net\"]",
        );
        assert_eq!(parse(&three), Err(ConfigError::TooManyLegacyUplinks));

        let plaintext = legacy_toml().replace("wss://core.example.net", "https://core.example.net");
        assert_eq!(parse(&plaintext), Err(ConfigError::LegacyUplinkNeedsRewrite));
    }

    #[test]
    fn migration_output_is_reparseable_as_v2() {
        let legacy = parse(&legacy_toml()).unwrap();
        let migrated = legacy.to_v2_toml();
        assert!(migrated.starts_with("# Generated by"));
        assert!(migrated.contains("version = 2"));
        let reparsed = parse(&migrated).expect("migrated document must validate as v2");
        assert_eq!(reparsed.schema, SchemaVersion::V2);
        assert_eq!(reparsed.identity.node_id, legacy.identity.node_id);
        assert_eq!(reparsed.uplinks.primary, legacy.uplinks.primary);
        assert_eq!(reparsed.limits, legacy.limits);
    }

    #[test]
    fn validation_fails_closed_on_invalid_mandatory_values() {
        let mut config = parse(&v2_toml()).unwrap();
        config.network.net_id = "short".into();
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::InvalidNetId));

        let mut config = parse(&v2_toml()).unwrap();
        config.uplinks.paths = 0;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::InvalidPathCount));

        let mut config = parse(&v2_toml()).unwrap();
        config.uplinks.probe_paths = 2;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::InvalidProbePaths));

        let mut config = parse(&v2_toml()).unwrap();
        config.security.suite = CryptoSuite::Pq1024;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::Pq1024Disabled));

        let mut config = parse(&v2_toml()).unwrap();
        config.limits.default_route = true;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::DefaultRouteUnsupported));
    }

    #[test]
    fn endpoints_must_be_host_port() {
        for accepted in ["core.example.net:443", "10.20.0.1:8443", "hub-us-c.example.net:1"] {
            let document = v2_toml().replace(
                "primary = \"hub-us-c.example.net:443\"",
                &format!("primary = \"{accepted}\""),
            );
            assert_eq!(parse(&document).map(|_| ()), Ok(()), "rejected {accepted}");
        }
        for rejected in [
            "",
            "core.example.net",
            "wss://core.example.net:443",
            "core.example.net:0",
            "core.example.net:70000",
            "user:pass@core.example.net:443",
            "core.example.net:443/path",
            "::1:443",
            " core.example.net:443",
        ] {
            let document = v2_toml().replace(
                "primary = \"hub-us-c.example.net:443\"",
                &format!("primary = \"{rejected}\""),
            );
            assert_eq!(parse(&document), Err(ConfigError::InvalidEndpoint), "accepted {rejected}");
        }
    }

    #[test]
    fn node_id_follows_the_permanent_slot_encoding() {
        let mut config = parse(&v2_toml()).unwrap();
        config.identity.node_id = 1;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::NodeIdMismatch));

        let mut config = parse(&v2_toml()).unwrap();
        config.identity.node_id = 5000;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::InvalidNodeId));

        let mut config = parse(&v2_toml()).unwrap();
        config.identity.home_core_id = 17;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::InvalidHomeCoreId));

        let mut edge = parse(&v2_toml()).unwrap();
        edge.identity.role = NodeRole::Edge;
        edge.identity.vip_octet = 1;
        assert_eq!(edge.validate(NO_CAPS), Err(ConfigError::InvalidVipOctet));

        let mut edge = parse(&v2_toml()).unwrap();
        edge.identity.role = NodeRole::Edge;
        edge.identity.vip_octet = 27;
        edge.identity.node_id = 257 + 26;
        assert_eq!(edge.validate(NO_CAPS), Ok(()));

        let mut enrollment = parse(&v2_toml()).unwrap();
        enrollment.identity.role = NodeRole::EnrollmentService;
        assert_eq!(
            enrollment.validate(NO_CAPS),
            Err(ConfigError::EnrollmentRoleNotProvisionable)
        );
    }

    #[test]
    fn allow_edges_is_core_only() {
        let mut config = parse(&v2_toml()).unwrap();
        config.limits.allow_edges = true;
        assert_eq!(config.validate(NO_CAPS), Ok(()));
        config.identity.role = NodeRole::Edge;
        config.identity.vip_octet = 2;
        config.identity.node_id = ((2u16 - 1) << 8) | 2;
        assert_eq!(config.validate(NO_CAPS), Err(ConfigError::AllowEdgesRequiresCore));
    }

    #[test]
    fn dns_tcp_follows_capability_not_a_schema_ban() {
        let document = format!("{}[dns]\ntcp = true\n", v2_toml());
        // Capability absent: refuse, and name the missing integration.
        assert_eq!(parse(&document), Err(ConfigError::DnsTcpUnavailable));
        // Capability present: the exact same document is accepted.
        let config = Config::parse_toml(&document, RuntimeCapabilities::FULL).unwrap();
        assert!(config.dns.as_ref().unwrap().tcp);
        assert!(config.redacted_json().contains("\"tcp\":true"));
    }

    #[test]
    fn dns_values_are_sanity_checked() {
        let bad_vip = format!("{}[dns]\nlisten_vip = \"not-an-ip\"\n", v2_toml());
        assert_eq!(parse(&bad_vip), Err(ConfigError::InvalidDnsListenVip));
        let bad_zone = format!("{}[dns]\nzone = \"has space\"\n", v2_toml());
        assert_eq!(parse(&bad_zone), Err(ConfigError::InvalidDnsZone));
    }

    #[test]
    fn relative_paths_are_rejected() {
        let document = v2_toml().replace(
            &format!("\"{TEST_BASE}/identity.key\""),
            "\"relative/identity.key\"",
        );
        assert_eq!(parse(&document), Err(ConfigError::PrivateKeyPathNotAbsolute));
    }

    #[test]
    fn redacted_output_does_not_leak_paths_or_endpoints() {
        let config = parse(&v2_toml()).unwrap();
        let json = config.redacted_json();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"identity_key\":\"[REDACTED]\""));
        assert!(json.contains("\"endpoints\":\"[REDACTED]\""));
        assert!(!json.contains("identity.key"));
        assert!(!json.contains("hub-us-c.example.net"));

        let debug = format!("{:?}", config.redacted());
        assert!(!debug.contains("identity.key"));
        assert!(!debug.contains("hub-us-c.example.net"));
        assert!(!debug.contains("roots.cbor"));
    }

    /// The shipped canonical example must stay parseable by the command that
    /// ships with it. It is Unix-oriented (`/etc/...`), so checked on Unix hosts.
    #[cfg(unix)]
    #[test]
    fn shipped_v2_example_stays_in_sync_with_the_schema() {
        let example = Config::parse_toml(
            include_str!("../../../docs/config/config.example.toml"),
            NO_CAPS,
        )
        .expect("docs/config/config.example.toml must validate");
        assert_eq!(example.schema, SchemaVersion::V2);
        assert_eq!(example.identity.node_id, 1);
        assert!(!example.limits.default_route);
    }

    /// The shipped legacy example documents what `version = 1` looks like and
    /// must still migrate cleanly.
    #[cfg(unix)]
    #[test]
    fn shipped_legacy_example_migrates() {
        let legacy = Config::parse_toml(
            include_str!("../../../docs/config/config.legacy-v1.example.toml"),
            NO_CAPS,
        )
        .expect("legacy example must migrate");
        assert_eq!(legacy.schema, SchemaVersion::LegacyV1);
        let reparsed = Config::parse_toml(&legacy.to_v2_toml(), NO_CAPS).unwrap();
        assert_eq!(reparsed.schema, SchemaVersion::V2);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_even_when_the_target_is_valid() {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("boreas-link-{}-{unique}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let real = dir.join("real.toml");
        fs::write(&real, v2_toml()).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.toml");
        symlink(&real, &link).unwrap();

        assert_eq!(
            Config::read_file(&link, NO_CAPS),
            Err(ConfigError::SymlinkNotAllowed)
        );
        // The target itself still passes.
        assert_eq!(
            Config::read_file(&real, NO_CAPS).map(|config| config.schema),
            Ok(SchemaVersion::V2)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_refused_without_reading() {
        use std::fs;
        let dir = std::env::temp_dir().join(format!("boreas-dir-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Config::read_file(&dir, NO_CAPS),
            Err(ConfigError::NotRegularFile)
        );
        let _ = fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_files_are_refused_but_0600_passes() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("boreas-mode-{}-{unique}.toml", std::process::id()));
        fs::write(&path, v2_toml()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            Config::read_file(&path, NO_CAPS),
            Err(ConfigError::UnsafePermissions)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::read_file(&path, NO_CAPS).is_ok());
        let _ = fs::remove_file(&path);
    }

    #[derive(Default)]
    struct Recorder {
        audited: usize,
        disconnected: usize,
    }

    impl SecurityAudit for Recorder {
        type Error = &'static str;
        fn record_security_transition(
            &mut self,
            _old: &Config,
            _new: &Config,
        ) -> Result<(), Self::Error> {
            self.audited += 1;
            Ok(())
        }
    }

    impl SessionDisconnect for Recorder {
        type Error = &'static str;
        fn disconnect_all_sessions(&mut self) -> Result<(), Self::Error> {
            self.disconnected += 1;
            Ok(())
        }
    }

    #[test]
    fn high_risk_transition_needs_phrase_audit_and_disconnect() {
        let old = parse(&v2_toml()).unwrap();
        let mut new = parse(&v2_toml()).unwrap();
        new.security.mode = SecurityMode::HopOnly;
        let mut audit = Recorder::default();
        let mut disconnect = Recorder::default();

        assert_eq!(
            authorize_security_transition(&old, &new, None, &mut audit, &mut disconnect),
            Err(TransitionError::ConfirmationRequired)
        );
        assert_eq!(audit.audited, 0);
        assert_eq!(disconnect.disconnected, 0);

        assert_eq!(
            authorize_security_transition(
                &old,
                &new,
                Some("TRUST-ROOT-CHANGE"),
                &mut audit,
                &mut disconnect
            ),
            Err(TransitionError::ConfirmationRequired)
        );

        assert_eq!(
            authorize_security_transition(
                &old,
                &new,
                Some("HOP-ONLY"),
                &mut audit,
                &mut disconnect
            ),
            Ok(())
        );
        assert_eq!(audit.audited, 1);
        assert_eq!(disconnect.disconnected, 1);
    }

    #[test]
    fn identity_rebinding_uses_the_trust_root_phrase() {
        let old = parse(&v2_toml()).unwrap();
        let mut new = parse(&v2_toml()).unwrap();
        new.identity.node_id = 258;
        let mut audit = Recorder::default();
        let mut disconnect = Recorder::default();
        assert_eq!(
            authorize_security_transition(
                &old,
                &new,
                Some("HOP-ONLY"),
                &mut audit,
                &mut disconnect
            ),
            Err(TransitionError::ConfirmationRequired)
        );
        assert_eq!(
            authorize_security_transition(
                &old,
                &new,
                Some("TRUST-ROOT-CHANGE"),
                &mut audit,
                &mut disconnect
            ),
            Ok(())
        );
    }

    #[test]
    fn unrelated_edits_need_no_confirmation() {
        let old = parse(&v2_toml()).unwrap();
        let mut new = parse(&v2_toml()).unwrap();
        new.limits.ipv6 = true;
        let mut audit = Recorder::default();
        let mut disconnect = Recorder::default();
        assert_eq!(
            authorize_security_transition(&old, &new, None, &mut audit, &mut disconnect),
            Ok(())
        );
        assert_eq!(audit.audited, 0);
    }
}