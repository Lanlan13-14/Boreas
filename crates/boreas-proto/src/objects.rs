//! Candidate typed management-object CBOR schemas. This module is exported but remains non-frozen.
//! No cryptography, signing-key policy, certificate parsing, or signature verification is implemented.
pub const MAX_OBJECT_LEN: usize = 16 * 1024;
pub const MAX_SCOPE_LEN: usize = 1024;
pub const MAX_NEIGHBORS: usize = 15;
pub const MAX_EXTENSIONS: usize = 32;
pub const MAX_EXTENSION_VALUE: usize = 2048;
pub const SIGNATURE_DOMAIN: &[u8] = b"BOREAS-MGMT-OBJECT\0";
const SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectType {
    NodeIdentity = 1,
    AttachmentLease = 2,
    CoreLsa = 3,
    RouteGrant = 4,
    DirectGrant = 5,
    StatusSnapshot = 6,
}
impl TryFrom<u64> for ObjectType {
    type Error = Error;
    fn try_from(v: u64) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::NodeIdentity),
            2 => Ok(Self::AttachmentLease),
            3 => Ok(Self::CoreLsa),
            4 => Ok(Self::RouteGrant),
            5 => Ok(Self::DirectGrant),
            6 => Ok(Self::StatusSnapshot),
            _ => Err(Error::UnknownObjectType),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extension {
    pub id: u64,
    pub critical: bool,
    pub value: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NodeRole {
    Edge = 1,
    Core = 2,
    EnrollmentService = 3,
}
impl TryFrom<u64> for NodeRole {
    type Error = Error;
    fn try_from(v: u64) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Edge),
            2 => Ok(Self::Core),
            3 => Ok(Self::EnrollmentService),
            _ => Err(Error::InvalidField("node role")),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MldsaParameterSet {
    Mldsa65 = 1,
    Mldsa87 = 2,
}
impl TryFrom<u64> for MldsaParameterSet {
    type Error = Error;
    fn try_from(v: u64) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Mldsa65),
            2 => Ok(Self::Mldsa87),
            _ => Err(Error::InvalidField("ML-DSA parameter set")),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    pub net_id: [u8; 16],
    pub node_id: u16,
    pub home_core_id: u8,
    pub vip: [u8; 4],
    pub vip6: [u8; 16],
    pub role: NodeRole,
    pub mldsa_parameter_set: MldsaParameterSet,
    pub identity_pub_mldsa: Vec<u8>,
    /// Node Ed25519 management-signing public key (raw 32 bytes).
    /// TLS authentication remains ML-DSA; this key binds the management
    /// Ed25519 signature required alongside ML-DSA.
    pub identity_pub_ed25519: [u8; 32],
    pub identity_generation: u64,
    pub not_before: u64,
    pub expires: u64,
    pub scope: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentLease {
    pub node_id: u16,
    pub identity_generation: u64,
    pub attach_generation: u64,
    pub target_core_id: u8,
    pub not_before: u64,
    pub expires: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neighbor {
    pub peer_core_id: u8,
    pub rtt_p50_ms: u16,
    pub loss_ppm: u32,
    pub path_type: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreLsa {
    pub core_id: u8,
    pub core_generation: u64,
    pub seq: u64,
    pub neighbors: Vec<Neighbor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteGrant {
    pub subject_node_id: u16,
    pub prefix: Vec<u8>,
    pub prefix_len: u8,
    pub metric: u16,
    pub ha_group: Vec<u8>,
    pub seq: u64,
    pub expires: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    Ip(Vec<u8>),
    Hostname(Vec<u8>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectGrant {
    pub subject_node_id: u16,
    pub endpoint: Endpoint,
    pub port: u16,
    pub sni: Vec<u8>,
    pub expires: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    pub issued_at: u64,
    pub next_update: u64,
    pub sequence: u64,
    pub revocations: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectBody {
    NodeIdentity(NodeIdentity),
    AttachmentLease(AttachmentLease),
    CoreLsa(CoreLsa),
    RouteGrant(RouteGrant),
    DirectGrant(DirectGrant),
    StatusSnapshot(StatusSnapshot),
}
impl ObjectBody {
    pub fn object_type(&self) -> ObjectType {
        match self {
            Self::NodeIdentity(_) => ObjectType::NodeIdentity,
            Self::AttachmentLease(_) => ObjectType::AttachmentLease,
            Self::CoreLsa(_) => ObjectType::CoreLsa,
            Self::RouteGrant(_) => ObjectType::RouteGrant,
            Self::DirectGrant(_) => ObjectType::DirectGrant,
            Self::StatusSnapshot(_) => ObjectType::StatusSnapshot,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectIdentity {
    Node(u16),
    Core(u8),
    Network,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementObject {
    pub net_id: [u8; 16],
    pub issuer_key_id: Vec<u8>,
    pub issuer_generation: u64,
    pub subject_identity: SubjectIdentity,
    pub seq: u64,
    pub issued_at: u64,
    pub expires: u64,
    pub extensions: Vec<Extension>,
    pub body: ObjectBody,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    Truncated,
    TrailingBytes,
    UnsupportedCbor,
    NonCanonical,
    DuplicateOrUnknownField,
    UnknownObjectType,
    UnknownCriticalExtension(u64),
    InvalidField(&'static str),
    ObjectTypeMismatch,
    LengthOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum V {
    U(u64),
    B(Vec<u8>),
    A(Vec<V>),
    M(Vec<(u64, V)>),
}
fn u(v: u64) -> V {
    V::U(v)
}
fn b(v: &[u8]) -> V {
    V::B(v.to_vec())
}
fn arr(v: Vec<V>) -> V {
    V::A(v)
}
fn map(v: Vec<(u64, V)>) -> V {
    V::M(v)
}
fn enc_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8)
    } else if n <= 255 {
        out.extend([m | 24, n as u8])
    } else if n <= 65535 {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes())
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes())
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes())
    }
}
fn encode(v: &V, out: &mut Vec<u8>) {
    match v {
        V::U(n) => enc_head(0, *n, out),
        V::B(x) => {
            enc_head(2, x.len() as u64, out);
            out.extend(x)
        }
        V::A(xs) => {
            enc_head(4, xs.len() as u64, out);
            for x in xs {
                encode(x, out)
            }
        }
        V::M(xs) => {
            enc_head(5, xs.len() as u64, out);
            for (k, v) in xs {
                encode(&u(*k), out);
                encode(v, out)
            }
        }
    }
}
fn parse(data: &[u8]) -> Result<V, Error> {
    let mut p = Reader { d: data, i: 0 };
    let v = p.item(0)?;
    if p.i != data.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}
struct Reader<'a> {
    d: &'a [u8],
    i: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let e = self.i.checked_add(n).ok_or(Error::LengthOverflow)?;
        let x = self.d.get(self.i..e).ok_or(Error::Truncated)?;
        self.i = e;
        Ok(x)
    }
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        Ok(match ai {
            0..=23 => ai as u64,
            24 => {
                let n = self.take(1)?[0] as u64;
                if n < 24 {
                    return Err(Error::NonCanonical);
                }
                n
            }
            25 => {
                let x = self.take(2)?;
                let n = u16::from_be_bytes([x[0], x[1]]) as u64;
                if n <= 255 {
                    return Err(Error::NonCanonical);
                }
                n
            }
            26 => {
                let x = self.take(4)?;
                let n = u32::from_be_bytes(x.try_into().unwrap()) as u64;
                if n <= 65535 {
                    return Err(Error::NonCanonical);
                }
                n
            }
            27 => {
                let x = self.take(8)?;
                let n = u64::from_be_bytes(x.try_into().unwrap());
                if n <= u32::MAX as u64 {
                    return Err(Error::NonCanonical);
                }
                n
            }
            _ => return Err(Error::UnsupportedCbor),
        })
    }
    fn item(&mut self, depth: usize) -> Result<V, Error> {
        if depth > 32 {
            return Err(Error::TooLarge);
        }
        let h = *self.take(1)?.first().unwrap();
        let major = h >> 5;
        let n = self.arg(h & 31)?;
        match major {
            0 => Ok(V::U(n)),
            2 => Ok(V::B(
                self.take(usize::try_from(n).map_err(|_| Error::LengthOverflow)?)?
                    .to_vec(),
            )),
            4 => {
                if n > MAX_OBJECT_LEN as u64 || n as usize > self.d.len().saturating_sub(self.i) {
                    return Err(Error::TooLarge);
                }
                let mut xs = Vec::new();
                for _ in 0..n {
                    xs.push(self.item(depth + 1)?)
                }
                Ok(V::A(xs))
            }
            5 => {
                if n > 64 || n as usize > self.d.len().saturating_sub(self.i) / 2 {
                    return Err(Error::TooLarge);
                }
                let mut xs = Vec::new();
                let mut prev = None;
                for _ in 0..n {
                    let key = match self.item(depth + 1)? {
                        V::U(k) => k,
                        _ => return Err(Error::InvalidField("map key")),
                    };
                    if prev.is_some_and(|p| key <= p) {
                        return Err(Error::NonCanonical);
                    }
                    prev = Some(key);
                    xs.push((key, self.item(depth + 1)?))
                }
                Ok(V::M(xs))
            }
            _ => Err(Error::UnsupportedCbor),
        }
    }
}
fn get(m: &[(u64, V)], k: u64) -> Result<&V, Error> {
    m.iter()
        .find(|(x, _)| *x == k)
        .map(|x| &x.1)
        .ok_or(Error::InvalidField("required field missing"))
}
fn num(v: &V) -> Result<u64, Error> {
    if let V::U(n) = v {
        Ok(*n)
    } else {
        Err(Error::InvalidField("unsigned integer"))
    }
}
fn bytes<const N: usize>(v: &V) -> Result<[u8; N], Error> {
    if let V::B(x) = v {
        x.as_slice()
            .try_into()
            .map_err(|_| Error::InvalidField("fixed byte string length"))
    } else {
        Err(Error::InvalidField("byte string"))
    }
}
fn blob(v: &V, cap: usize) -> Result<Vec<u8>, Error> {
    if let V::B(x) = v {
        if x.len() > cap {
            return Err(Error::TooLarge);
        }
        Ok(x.clone())
    } else {
        Err(Error::InvalidField("byte string"))
    }
}
fn check_fields(m: &[(u64, V)], max: u64) -> Result<(), Error> {
    if m.iter().any(|(k, _)| *k > max) || m.len() != (max as usize + 1) {
        Err(Error::DuplicateOrUnknownField)
    } else {
        Ok(())
    }
}

fn body_value(body: &ObjectBody) -> Result<V, Error> {
    Ok(match body {
        ObjectBody::NodeIdentity(x) => map(vec![
            (0, b(&x.net_id)),
            (1, u(x.node_id as u64)),
            (2, u(x.home_core_id as u64)),
            (3, b(&x.vip)),
            (4, b(&x.vip6)),
            (5, u(x.role as u64)),
            (6, u(x.mldsa_parameter_set as u64)),
            (7, b(&x.identity_pub_mldsa)),
            (8, u(x.identity_generation)),
            (9, u(x.not_before)),
            (10, u(x.expires)),
            (11, b(&x.identity_pub_ed25519)),
            (12, b(&x.scope)),
        ]),
        ObjectBody::AttachmentLease(x) => map(vec![
            (0, u(x.node_id as u64)),
            (1, u(x.identity_generation)),
            (2, u(x.attach_generation)),
            (3, u(x.target_core_id as u64)),
            (4, u(x.not_before)),
            (5, u(x.expires)),
        ]),
        ObjectBody::CoreLsa(x) => map(vec![
            (0, u(x.core_id as u64)),
            (1, u(x.core_generation)),
            (2, u(x.seq)),
            (
                3,
                arr(x
                    .neighbors
                    .iter()
                    .map(|n| {
                        arr(vec![
                            u(n.peer_core_id as u64),
                            u(n.rtt_p50_ms as u64),
                            u(n.loss_ppm as u64),
                            u(n.path_type as u64),
                        ])
                    })
                    .collect()),
            ),
        ]),
        ObjectBody::RouteGrant(x) => map(vec![
            (0, u(x.subject_node_id as u64)),
            (1, b(&x.prefix)),
            (2, u(x.prefix_len as u64)),
            (3, u(x.metric as u64)),
            (4, b(&x.ha_group)),
            (5, u(x.seq)),
            (6, u(x.expires)),
        ]),
        ObjectBody::DirectGrant(x) => {
            let (kind, data) = match &x.endpoint {
                Endpoint::Ip(v) => (1, v),
                Endpoint::Hostname(v) => (2, v),
            };
            map(vec![
                (0, u(x.subject_node_id as u64)),
                (1, u(kind)),
                (2, b(data)),
                (3, u(x.port as u64)),
                (4, b(&x.sni)),
                (5, u(x.expires)),
            ])
        }
        ObjectBody::StatusSnapshot(x) => map(vec![
            (0, u(x.issued_at)),
            (1, u(x.next_update)),
            (2, u(x.sequence)),
            (3, b(&x.revocations)),
        ]),
    })
}
fn parse_body(ty: ObjectType, v: &V) -> Result<ObjectBody, Error> {
    let V::M(m) = v else {
        return Err(Error::InvalidField("body map"));
    };
    Ok(match ty {
        ObjectType::NodeIdentity => {
            check_fields(m, 12)?;
            ObjectBody::NodeIdentity(NodeIdentity {
                net_id: bytes(get(m, 0)?)?,
                node_id: u16::try_from(num(get(m, 1)?)?)
                    .map_err(|_| Error::InvalidField("node_id"))?,
                home_core_id: u8::try_from(num(get(m, 2)?)?)
                    .map_err(|_| Error::InvalidField("home_core_id"))?,
                vip: bytes(get(m, 3)?)?,
                vip6: bytes(get(m, 4)?)?,
                role: NodeRole::try_from(num(get(m, 5)?)?)?,
                mldsa_parameter_set: MldsaParameterSet::try_from(num(get(m, 6)?)?)?,
                identity_pub_mldsa: blob(get(m, 7)?, 8192)?,
                identity_generation: num(get(m, 8)?)?,
                not_before: num(get(m, 9)?)?,
                expires: num(get(m, 10)?)?,
                identity_pub_ed25519: bytes(get(m, 11)?)?,
                scope: blob(get(m, 12)?, MAX_SCOPE_LEN)?,
            })
        }
        ObjectType::AttachmentLease => {
            check_fields(m, 5)?;
            ObjectBody::AttachmentLease(AttachmentLease {
                node_id: u16::try_from(num(get(m, 0)?)?)
                    .map_err(|_| Error::InvalidField("node_id"))?,
                identity_generation: num(get(m, 1)?)?,
                attach_generation: num(get(m, 2)?)?,
                target_core_id: u8::try_from(num(get(m, 3)?)?)
                    .map_err(|_| Error::InvalidField("target_core_id"))?,
                not_before: num(get(m, 4)?)?,
                expires: num(get(m, 5)?)?,
            })
        }
        ObjectType::CoreLsa => {
            check_fields(m, 3)?;
            let V::A(ns) = get(m, 3)? else {
                return Err(Error::InvalidField("neighbors"));
            };
            if ns.len() > MAX_NEIGHBORS {
                return Err(Error::TooLarge);
            }
            let mut neighbors = Vec::new();
            for n in ns {
                let V::A(a) = n else {
                    return Err(Error::InvalidField("neighbor tuple"));
                };
                if a.len() != 4 {
                    return Err(Error::InvalidField("neighbor tuple"));
                }
                neighbors.push(Neighbor {
                    peer_core_id: u8::try_from(num(&a[0])?)
                        .map_err(|_| Error::InvalidField("peer_core_id"))?,
                    rtt_p50_ms: u16::try_from(num(&a[1])?)
                        .map_err(|_| Error::InvalidField("rtt"))?,
                    loss_ppm: u32::try_from(num(&a[2])?)
                        .map_err(|_| Error::InvalidField("loss"))?,
                    path_type: u8::try_from(num(&a[3])?)
                        .map_err(|_| Error::InvalidField("path_type"))?,
                })
            }
            ObjectBody::CoreLsa(CoreLsa {
                core_id: u8::try_from(num(get(m, 0)?)?)
                    .map_err(|_| Error::InvalidField("core_id"))?,
                core_generation: num(get(m, 1)?)?,
                seq: num(get(m, 2)?)?,
                neighbors,
            })
        }
        ObjectType::RouteGrant => {
            check_fields(m, 6)?;
            let prefix = blob(get(m, 1)?, 16)?;
            if prefix.len() != 4 && prefix.len() != 16 {
                return Err(Error::InvalidField("prefix length"));
            }
            let prefix_len =
                u8::try_from(num(get(m, 2)?)?).map_err(|_| Error::InvalidField("prefix_len"))?;
            if prefix_len as usize > prefix.len() * 8 {
                return Err(Error::InvalidField("prefix_len"));
            }
            ObjectBody::RouteGrant(RouteGrant {
                subject_node_id: u16::try_from(num(get(m, 0)?)?)
                    .map_err(|_| Error::InvalidField("subject"))?,
                prefix,
                prefix_len,
                metric: u16::try_from(num(get(m, 3)?)?)
                    .map_err(|_| Error::InvalidField("metric"))?,
                ha_group: blob(get(m, 4)?, 64)?,
                seq: num(get(m, 5)?)?,
                expires: num(get(m, 6)?)?,
            })
        }
        ObjectType::DirectGrant => {
            check_fields(m, 5)?;
            let kind = num(get(m, 1)?)?;
            let data = blob(get(m, 2)?, 253)?;
            let endpoint = match kind {
                1 if data.len() == 4 || data.len() == 16 => Endpoint::Ip(data),
                2 if !data.is_empty() => Endpoint::Hostname(data),
                _ => return Err(Error::InvalidField("endpoint")),
            };
            ObjectBody::DirectGrant(DirectGrant {
                subject_node_id: u16::try_from(num(get(m, 0)?)?)
                    .map_err(|_| Error::InvalidField("subject"))?,
                endpoint,
                port: u16::try_from(num(get(m, 3)?)?).map_err(|_| Error::InvalidField("port"))?,
                sni: blob(get(m, 4)?, 253)?,
                expires: num(get(m, 5)?)?,
            })
        }
        ObjectType::StatusSnapshot => {
            check_fields(m, 3)?;
            let issued_at = num(get(m, 0)?)?;
            let next_update = num(get(m, 1)?)?;
            if next_update <= issued_at || next_update - issued_at > 86_400_000_000 {
                return Err(Error::InvalidField("snapshot time window"));
            }
            ObjectBody::StatusSnapshot(StatusSnapshot {
                issued_at,
                next_update,
                sequence: num(get(m, 2)?)?,
                revocations: blob(get(m, 3)?, MAX_OBJECT_LEN)?,
            })
        }
    })
}
fn known_extension(_id: u64) -> bool {
    false
}
fn subject_value(subject: &SubjectIdentity) -> V {
    match subject {
        SubjectIdentity::Node(id) => arr(vec![u(1), u(*id as u64)]),
        SubjectIdentity::Core(id) => arr(vec![u(2), u(*id as u64)]),
        SubjectIdentity::Network => arr(vec![u(3)]),
    }
}
fn parse_subject(v: &V) -> Result<SubjectIdentity, Error> {
    let V::A(a) = v else {
        return Err(Error::InvalidField("subject identity"));
    };
    match a.as_slice() {
        [kind, id] if num(kind)? == 1 => Ok(SubjectIdentity::Node(
            u16::try_from(num(id)?).map_err(|_| Error::InvalidField("node subject"))?,
        )),
        [kind, id] if num(kind)? == 2 => Ok(SubjectIdentity::Core(
            u8::try_from(num(id)?).map_err(|_| Error::InvalidField("core subject"))?,
        )),
        [kind] if num(kind)? == 3 => Ok(SubjectIdentity::Network),
        _ => Err(Error::InvalidField("subject identity")),
    }
}
fn prefix_host_bits_zero(prefix: &[u8], prefix_len: u8) -> bool {
    let full = prefix_len as usize / 8;
    let rem = prefix_len as usize % 8;
    if rem != 0
        && prefix
            .get(full)
            .is_some_and(|b| b & ((1u8 << (8 - rem)) - 1) != 0)
    {
        return false;
    }
    let start = full + usize::from(rem != 0);
    prefix
        .get(start..)
        .is_some_and(|tail| tail.iter().all(|b| *b == 0))
}
pub(crate) fn valid_node_id(node_id: u16) -> bool {
    let core = (node_id >> 8) + 1;
    let octet = (node_id & 0xff) as u8;
    (1..=16).contains(&core) && (octet == 1 || (2..=251).contains(&octet))
}
fn validate_context(x: &ManagementObject) -> Result<(), Error> {
    if x.issuer_key_id.is_empty()
        || x.issuer_key_id.len() > 64
        || x.issuer_generation == 0
        || x.expires <= x.issued_at
    {
        return Err(Error::InvalidField("common envelope bounds"));
    }
    match &x.body {
        ObjectBody::NodeIdentity(body) => {
            if body.net_id != x.net_id
                || x.subject_identity != SubjectIdentity::Node(body.node_id)
                || x.seq != body.identity_generation
                || x.issued_at != body.not_before
                || x.expires != body.expires
                || body.home_core_id == 0
                || body.home_core_id > 16
                || body.node_id != ((((body.home_core_id as u16) - 1) << 8) | body.vip[3] as u16)
                || body.vip[0] != 10
                || body.vip[1] != 20
                || !match body.role {
                    NodeRole::Core => body.vip[2] == body.home_core_id && body.vip[3] == 1,
                    NodeRole::Edge => {
                        body.vip[2] == body.home_core_id && (2..=251).contains(&body.vip[3])
                    }
                    NodeRole::EnrollmentService => body.vip[2] == 0 && body.vip[3] != 0,
                }
                || body.identity_generation == 0
                || body.expires <= body.not_before
                || body.scope.len() > MAX_SCOPE_LEN
                || body.identity_pub_mldsa.is_empty()
                || body.identity_pub_mldsa.len() > 8192
                || body.identity_pub_ed25519 == [0; 32]
            {
                return Err(Error::InvalidField(
                    "NodeIdentity common/body mismatch or bound",
                ));
            }
        }
        ObjectBody::AttachmentLease(body) => {
            if !valid_node_id(body.node_id)
                || x.subject_identity != SubjectIdentity::Node(body.node_id)
                || x.seq != body.attach_generation
                || x.issued_at != body.not_before
                || x.expires != body.expires
                || body.target_core_id == 0
                || body.target_core_id > 16
                || body.identity_generation == 0
                || body.attach_generation == 0
                || body.expires <= body.not_before
            {
                return Err(Error::InvalidField(
                    "AttachmentLease common/body mismatch or bounds",
                ));
            }
        }
        ObjectBody::CoreLsa(body) => {
            if x.subject_identity != SubjectIdentity::Core(body.core_id)
                || x.seq != body.seq
                || body.core_id == 0
                || body.core_id > 16
                || body.core_generation == 0
                || body.seq == 0
                || body.neighbors.len() > MAX_NEIGHBORS
                || body.neighbors.iter().any(|n| {
                    n.peer_core_id == 0
                        || n.peer_core_id > 16
                        || n.peer_core_id == body.core_id
                        || !(1..=2).contains(&n.path_type)
                        || n.loss_ppm > 1_000_000
                })
                || {
                    let mut ids = body
                        .neighbors
                        .iter()
                        .map(|n| n.peer_core_id)
                        .collect::<Vec<_>>();
                    ids.sort_unstable();
                    ids.windows(2).any(|w| w[0] == w[1])
                }
            {
                return Err(Error::InvalidField(
                    "CoreLsa common/body mismatch or bounds",
                ));
            }
        }
        ObjectBody::RouteGrant(body) => {
            if !valid_node_id(body.subject_node_id)
                || x.subject_identity != SubjectIdentity::Node(body.subject_node_id)
                || x.seq != body.seq
                || x.expires != body.expires
                || body.prefix.len() != 4 && body.prefix.len() != 16
                || body.prefix_len as usize > body.prefix.len() * 8
                || body.ha_group.len() > 64
                || !prefix_host_bits_zero(&body.prefix, body.prefix_len)
            {
                return Err(Error::InvalidField(
                    "RouteGrant common/body mismatch or bounds",
                ));
            }
        }
        ObjectBody::DirectGrant(body) => {
            if !valid_node_id(body.subject_node_id)
                || x.subject_identity != SubjectIdentity::Node(body.subject_node_id)
                || x.expires != body.expires
                || body.port == 0
                || body.sni.len() > 253
            {
                return Err(Error::InvalidField(
                    "DirectGrant common/body mismatch or bounds",
                ));
            }
            match &body.endpoint {
                Endpoint::Ip(ip) if ip.len() != 4 && ip.len() != 16 => {
                    return Err(Error::InvalidField("DirectGrant IP length"));
                }
                Endpoint::Hostname(host) => {
                    let Ok(name) = std::str::from_utf8(host) else {
                        return Err(Error::InvalidField("DirectGrant hostname UTF-8"));
                    };
                    if name.is_empty()
                        || host.len() > 253
                        || name.starts_with('.')
                        || name.ends_with('.')
                        || name.split('.').any(|label| {
                            label.is_empty()
                                || label.len() > 63
                                || label.starts_with('-')
                                || label.ends_with('-')
                                || !label
                                    .bytes()
                                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                        })
                    {
                        return Err(Error::InvalidField("DirectGrant hostname"));
                    }
                }
                _ => {}
            }
        }
        ObjectBody::StatusSnapshot(body) => {
            if x.subject_identity != SubjectIdentity::Network
                || x.seq != body.sequence
                || x.issued_at != body.issued_at
                || x.expires != body.next_update
                || body.next_update <= body.issued_at
                || body.next_update - body.issued_at > 86_400_000_000
                || body.revocations.len() > MAX_OBJECT_LEN
            {
                return Err(Error::InvalidField(
                    "StatusSnapshot common/body mismatch or bounds",
                ));
            }
        }
    }
    Ok(())
}
fn envelope_value(x: &ManagementObject) -> Result<V, Error> {
    validate_context(x)?;
    if x.issuer_key_id.is_empty()
        || x.issuer_key_id.len() > 64
        || x.extensions.len() > MAX_EXTENSIONS
    {
        return Err(Error::TooLarge);
    }
    let mut ex = x.extensions.clone();
    ex.sort_by_key(|e| e.id);
    if ex.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(Error::DuplicateOrUnknownField);
    }
    for e in &ex {
        if e.value.len() > MAX_EXTENSION_VALUE {
            return Err(Error::TooLarge);
        }
        if e.critical && !known_extension(e.id) {
            return Err(Error::UnknownCriticalExtension(e.id));
        }
    }
    Ok(map(vec![
        (0, u(SCHEMA_VERSION)),
        (1, u(x.body.object_type() as u64)),
        (2, b(&x.net_id)),
        (3, b(&x.issuer_key_id)),
        (4, u(x.issuer_generation)),
        (5, subject_value(&x.subject_identity)),
        (6, u(x.seq)),
        (7, u(x.issued_at)),
        (8, u(x.expires)),
        (9, body_value(&x.body)?),
        (
            10,
            arr(ex
                .iter()
                .map(|e| arr(vec![u(e.id), u(e.critical as u64), b(&e.value)]))
                .collect()),
        ),
    ]))
}
pub fn encode_tbs(x: &ManagementObject) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode(&envelope_value(x)?, &mut out);
    if out.len() > MAX_OBJECT_LEN {
        return Err(Error::TooLarge);
    }
    Ok(out)
}
/// Parse for typed inspection; caller must keep `data` and pass those exact bytes to signature_input.
/// This function does not return a re-encoded substitute for the signed input.
pub fn decode_tbs(data: &[u8]) -> Result<ManagementObject, Error> {
    if data.len() > MAX_OBJECT_LEN {
        return Err(Error::TooLarge);
    }
    let v = parse(data)?;
    let V::M(m) = v else {
        return Err(Error::InvalidField("envelope map"));
    };
    check_fields(&m, 10)?;
    if num(get(&m, 0)?)? != SCHEMA_VERSION {
        return Err(Error::InvalidField("schema_version"));
    }
    let ty = ObjectType::try_from(num(get(&m, 1)?)?)?;
    let mut extensions = Vec::new();
    let V::A(a) = get(&m, 10)? else {
        return Err(Error::InvalidField("extensions"));
    };
    if a.len() > MAX_EXTENSIONS {
        return Err(Error::TooLarge);
    }
    let mut last = None;
    for e in a {
        let V::A(t) = e else {
            return Err(Error::InvalidField("extension tuple"));
        };
        if t.len() != 3 {
            return Err(Error::InvalidField("extension tuple"));
        }
        let id = num(&t[0])?;
        if last.is_some_and(|p| id <= p) {
            return Err(Error::NonCanonical);
        }
        last = Some(id);
        let critical = match num(&t[1])? {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidField("critical bool")),
        };
        if critical && !known_extension(id) {
            return Err(Error::UnknownCriticalExtension(id));
        }
        extensions.push(Extension {
            id,
            critical,
            value: blob(&t[2], MAX_EXTENSION_VALUE)?,
        })
    }
    let body = parse_body(ty, get(&m, 9)?)?;
    if body.object_type() != ty {
        return Err(Error::ObjectTypeMismatch);
    }
    let object = ManagementObject {
        net_id: bytes(get(&m, 2)?)?,
        issuer_key_id: blob(get(&m, 3)?, 64)?,
        issuer_generation: num(get(&m, 4)?)?,
        subject_identity: parse_subject(get(&m, 5)?)?,
        seq: num(get(&m, 6)?)?,
        issued_at: num(get(&m, 7)?)?,
        expires: num(get(&m, 8)?)?,
        extensions,
        body,
    };
    validate_context(&object)?;
    Ok(object)
}
/// Construct the exact domain-separated message to be signed. Caller retains and verifies original TBS bytes.
pub fn signature_input(
    raw_tbs: &[u8],
    object_type: ObjectType,
    schema_version: u16,
) -> Result<Vec<u8>, Error> {
    if raw_tbs.len() > MAX_OBJECT_LEN {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 2 + 1 + 8 + raw_tbs.len());
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.push(object_type as u8);
    out.extend_from_slice(&(raw_tbs.len() as u64).to_be_bytes());
    out.extend_from_slice(raw_tbs);
    Ok(out)
}
// Candidate object id rule is SHA-256(raw_tbs); hashing is deferred to a reviewed crypto/integration layer.
// object_id is external metadata, never a field in the TBS, so this rule is not self-referential.

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURES: &str =
        include_str!("../../../docs/protocol/vectors/management-objects-candidate-v1.json");
    fn fixture_entry(id: &str) -> String {
        let marker = format!("\"id\": \"{id}\"");
        let at = FIXTURES.find(&marker).expect("fixture id present");
        let start = FIXTURES[..at].rfind('{').expect("fixture object start");
        let end = FIXTURES[at..].find('}').expect("fixture object end") + at + 1;
        FIXTURES[start..end].to_owned()
    }
    fn fixture_field(id: &str, field: &str) -> String {
        let entry = fixture_entry(id);
        let marker = format!("\"{field}\"");
        let at = entry.find(&marker).expect("fixture field present") + marker.len();
        let value = entry[at..]
            .trim_start()
            .strip_prefix(':')
            .expect("field colon")
            .trim_start();
        let value = value.strip_prefix('\"').expect("string fixture field");
        value[..value.find('\"').expect("fixture string terminator")].to_owned()
    }
    fn decode_hex(hex: &str) -> Vec<u8> {
        let digit = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("bad fixture hex"),
        };
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "odd fixture hex length");
        pairs
            .iter()
            .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
            .collect()
    }
    fn fixture_hex(id: &str) -> Vec<u8> {
        decode_hex(&fixture_field(id, "raw_tbs_hex"))
    }

    // ------------------------------------------------------------------
    // G-FRAME/SS5.3 supplemental adversarial coverage for the candidate
    // typed-object codec. Focus: truncation/mutation sweeps and size
    // bounds. No new wire rules are asserted beyond the candidate docs.
    // ------------------------------------------------------------------

    const POSITIVE_IDS: [&str; 6] = [
        "node-identity-minimal-valid",
        "attachment-lease-minimal-valid",
        "core-lsa-minimal-valid",
        "route-grant-minimal-valid",
        "direct-grant-minimal-valid",
        "status-snapshot-minimal-valid",
    ];

    #[test]
    fn every_proper_prefix_of_valid_tbs_rejects() {
        // Truncation sweep: no prefix of a valid object may decode (a
        // shorter valid object sharing the prefix would be a type
        // confusion hazard), and none may panic.
        for id in POSITIVE_IDS {
            let raw = fixture_hex(id);
            decode_tbs(&raw).unwrap_or_else(|e| panic!("{id} fixture must decode: {e:?}"));
            for n in 0..raw.len() {
                assert!(
                    decode_tbs(&raw[..n]).is_err(),
                    "{id}: prefix {n}/{} must reject",
                    raw.len()
                );
            }
            // Trailing garbage: one extra byte of each flavour.
            for extra in [0x00u8, 0xFF, 0x81, b'X'] {
                let mut longer = raw.clone();
                longer.push(extra);
                assert_eq!(
                    decode_tbs(&longer),
                    Err(Error::TrailingBytes),
                    "{id}: trailing {extra:#04x}"
                );
            }
        }
    }

    #[test]
    fn hostile_size_bounds_fail_before_semantics() {
        // 16 KiB TBS cap (SS5.3): exactly-at data passes the size gate and
        // then fails as CBOR/schema; one byte over fails as TooLarge.
        assert_eq!(
            MAX_OBJECT_LEN,
            16 * 1024,
            "SS5.3 single-object cap candidate"
        );
        assert_eq!(
            decode_tbs(&vec![0x00; MAX_OBJECT_LEN + 1]),
            Err(Error::TooLarge)
        );
        assert_ne!(
            decode_tbs(&vec![0x00; MAX_OBJECT_LEN]),
            Err(Error::TooLarge),
            "at-cap input reaches the parser"
        );
        assert!(decode_tbs(&vec![0x00; MAX_OBJECT_LEN]).is_err());
        // signature_input enforces the same cap on caller-retained bytes.
        assert_eq!(
            signature_input(&vec![0; MAX_OBJECT_LEN + 1], ObjectType::NodeIdentity, 1),
            Err(Error::TooLarge)
        );
        assert!(signature_input(&vec![0; MAX_OBJECT_LEN], ObjectType::NodeIdentity, 1).is_ok());
        // Empty input is truncated CBOR, never an empty object.
        assert_eq!(decode_tbs(&[]), Err(Error::Truncated));
    }

    #[test]
    fn hostile_root_shapes_and_majors_reject() {
        // Root must be a map with unsigned-int keys only; every other
        // major type / shape rejects with a deterministic category.
        assert_eq!(
            decode_tbs(&[0x80]),
            Err(Error::InvalidField("envelope map"))
        ); // []
        assert_eq!(
            decode_tbs(&[0x00]),
            Err(Error::InvalidField("envelope map"))
        ); // 0
        assert_eq!(
            decode_tbs(&[0x40]),
            Err(Error::InvalidField("envelope map"))
        ); // h''
        assert_eq!(decode_tbs(&[0x20]), Err(Error::UnsupportedCbor)); // -1: major 1 unsupported
        assert_eq!(decode_tbs(&[0x61, b'a']), Err(Error::UnsupportedCbor)); // text unsupported
        assert_eq!(decode_tbs(&[0xC0, 0x00]), Err(Error::UnsupportedCbor)); // tag
        assert_eq!(decode_tbs(&[0xF5]), Err(Error::UnsupportedCbor)); // true
        assert_eq!(decode_tbs(&[0xBF, 0xFF]), Err(Error::UnsupportedCbor)); // indefinite map
        assert_eq!(
            decode_tbs(&[0xA1, 0x61, b'a', 0x00]),
            Err(Error::UnsupportedCbor),
            "text map key: major-3 item itself is unsupported before key typing"
        );
        // Duplicate and out-of-order envelope keys are non-canonical.
        assert_eq!(
            decode_tbs(&[0xA2, 0x00, 0x00, 0x00, 0x00]),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            decode_tbs(&[0xA2, 0x01, 0x00, 0x00, 0x00]),
            Err(Error::NonCanonical)
        );
        // Empty map: missing all required fields.
        assert_eq!(decode_tbs(&[0xA0]), Err(Error::DuplicateOrUnknownField));
    }

    #[test]
    fn hostile_depth_and_flat_size_bombs_reject() {
        // Deep nesting: reader caps at depth > 32 (TooLarge category).
        let mut deep_arrays = vec![0x81; 64];
        deep_arrays.push(0);
        assert_eq!(decode_tbs(&deep_arrays), Err(Error::TooLarge));
        let mut deep_arrays = vec![0x81; 33];
        deep_arrays.push(0);
        assert_eq!(decode_tbs(&deep_arrays), Err(Error::TooLarge));
        // 32-deep is within the reader cap, then fails as schema (not a map).
        let mut within = vec![0x81; 32];
        within.push(0);
        assert_eq!(
            decode_tbs(&within),
            Err(Error::InvalidField("envelope map"))
        );
        // Map with absurd declared entry count rejects as TooLarge without
        // iterating it.
        assert_eq!(
            decode_tbs(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0]),
            Err(Error::TooLarge)
        );
        // Array count header alone is truncated, not pre-allocated.
        assert!(decode_tbs(&[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        // Huge declared byte-string length rejects (truncated/overflow).
        assert!(
            decode_tbs(&[
                0xA1, 0x00, 0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ])
            .is_err()
        );
    }

    #[test]
    fn single_byte_mutation_never_panics_and_stays_deterministic() {
        // Every position x every replacement byte on the smallest fixture:
        // decode twice, require identical outcomes (determinism), and when
        // a mutation happens to still decode, its re-encoding must equal
        // the mutated input (the parser never "repairs" signed bytes).
        let raw = fixture_hex("core-lsa-minimal-valid");
        for pos in 0..raw.len() {
            for replacement in 0u16..=255 {
                let mut mutated = raw.clone();
                mutated[pos] = replacement as u8;
                let first = decode_tbs(&mutated);
                assert_eq!(
                    first,
                    decode_tbs(&mutated),
                    "non-deterministic at pos {pos}"
                );
                if let Ok(obj) = first {
                    assert_eq!(
                        encode_tbs(&obj).unwrap(),
                        mutated,
                        "pos {pos}: accepted mutation must round-trip exactly"
                    );
                }
            }
        }
    }

    #[test]
    fn encode_side_bounds_fail_closed() {
        // Typed values that violate candidate caps must fail to encode,
        // not silently emit an object its own decoder would reject.
        let baseline = decode_tbs(&fixture_hex("core-lsa-minimal-valid")).unwrap();
        assert_eq!(
            encode_tbs(&baseline).unwrap(),
            fixture_hex("core-lsa-minimal-valid")
        );
        // issuer_key_id empty / over 64.
        let mut o = baseline.clone();
        o.issuer_key_id = vec![];
        assert!(encode_tbs(&o).is_err());
        let mut o = baseline.clone();
        o.issuer_key_id = vec![7; 65];
        assert_eq!(
            encode_tbs(&o),
            Err(Error::InvalidField("common envelope bounds"))
        );
        // Too many extensions.
        let mut o = baseline.clone();
        o.extensions = (0..(MAX_EXTENSIONS as u64 + 1))
            .map(|i| Extension {
                id: i,
                critical: false,
                value: vec![],
            })
            .collect();
        assert_eq!(encode_tbs(&o), Err(Error::TooLarge));
        // Unknown critical extension on encode.
        let mut o = baseline.clone();
        o.extensions = vec![Extension {
            id: 99,
            critical: true,
            value: vec![],
        }];
        assert_eq!(encode_tbs(&o), Err(Error::UnknownCriticalExtension(99)));
        // Duplicate extension ids.
        let mut o = baseline;
        o.extensions = vec![
            Extension {
                id: 5,
                critical: false,
                value: vec![],
            },
            Extension {
                id: 5,
                critical: false,
                value: vec![1],
            },
        ];
        assert_eq!(encode_tbs(&o), Err(Error::DuplicateOrUnknownField));
    }
    #[test]
    fn positive_fixed_tbs_vectors_round_trip_exact_bytes() {
        for (id, ty) in [
            ("node-identity-minimal-valid", ObjectType::NodeIdentity),
            (
                "attachment-lease-minimal-valid",
                ObjectType::AttachmentLease,
            ),
            ("core-lsa-minimal-valid", ObjectType::CoreLsa),
            ("route-grant-minimal-valid", ObjectType::RouteGrant),
            ("direct-grant-minimal-valid", ObjectType::DirectGrant),
            ("status-snapshot-minimal-valid", ObjectType::StatusSnapshot),
        ] {
            let raw = fixture_hex(id);
            let object = decode_tbs(&raw).expect(id);
            assert_eq!(object.body.object_type(), ty);
            assert_eq!(encode_tbs(&object).unwrap(), raw, "fixture {id}");
        }
    }
    fn fixture_error(id: &str) -> String {
        let marker = format!("\"id\": \"{id}\"");
        let item = FIXTURES.find(&marker).expect("fixture id present");
        let object_start = FIXTURES[..item].rfind('{').expect("fixture object start");
        let object_end = FIXTURES[item..].find('}').expect("fixture object end") + item + 1;
        let tail = &FIXTURES[object_start..object_end];
        let field = "\"expected_error\": \"";
        let start = tail.find(field).expect("negative fixture error category") + field.len();
        let value = &tail[start..];
        value[..value.find('\"').expect("quoted error")].to_owned()
    }
    #[test]
    fn negative_fixed_tbs_vectors_match_error_categories() {
        for id in [
            "node-identity-cross-net-mismatch",
            "node-identity-common-sequence-mismatch",
            "cross-type-body",
            "empty-issuer-key-id",
            "unknown-critical-extension",
            "cbor-root-not-map",
            "tbs-trailing-byte",
            "tbs-nonshortest-map-length",
            "tbs-indefinite-map",
        ] {
            let err = decode_tbs(&fixture_hex(id)).expect_err(id);
            let expected = fixture_error(id);
            let category_matches = match expected.as_str() {
                "invalid_field" => matches!(
                    err,
                    Error::InvalidField(_)
                        | Error::DuplicateOrUnknownField
                        | Error::ObjectTypeMismatch
                ),
                "trailing_bytes" => err == Error::TrailingBytes,
                "noncanonical" => err == Error::NonCanonical,
                "unsupported_cbor" => err == Error::UnsupportedCbor,
                "unknown_critical_extension" => matches!(err, Error::UnknownCriticalExtension(_)),
                _ => false,
            };
            assert!(category_matches, "{id}: expected {expected}, got {err:?}");
        }
    }
    #[test]
    fn signature_domain_fixed_vector() {
        let object_type = ObjectType::NodeIdentity;
        let raw = fixture_hex("signature-domain-raw-three-bytes");
        let got = signature_input(&raw, object_type, 1).unwrap();
        let expected = fixture_field("signature-domain-raw-three-bytes", "expected_hex");
        let expected: Vec<u8> = expected
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                let d = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                d(p[0]) * 16 + d(p[1])
            })
            .collect();
        assert_eq!(got, expected);
    }
}
