//! G-DNS-shaped checks against the public DNS surfaces.
//!
//! `boreas_tunnel::dns_runtime::DnsUdpRuntime` is the packet responder, but an
//! integration test cannot construct one: [`DnsUdpRuntime::try_new`] requires a
//! [`boreas_tunnel::PeerIdentity`] whose policy context is `pub(crate)`.
//! Feeding it a verified token from outside the crate is therefore impossible
//! without changing `src/`.
//!
//! What *is* public, once `openssl-inner-tls` links `boreas-pki`:
//!
//! * [`boreas_pki::dns_authority::VerifiedDnsAuthority::verify`] accepts a
//!   dual-signed authority and rejects one whose `now` is outside the window;
//! * the verified token exposes the zone, VIP, and A record;
//! * [`boreas_dns::AuthoritativeDns`] answers an in-zone A query with that
//!   address and refuses a name outside the zone (it does not recurse).
//!
//! No UDP socket is opened. This file is not a `G-DNS` pass.

#![cfg(feature = "openssl-inner-tls")]

use std::net::{IpAddr, Ipv4Addr};

use boreas_dns::{AuthoritativeDns, SourceAuthorization, Zone};
use boreas_pki::dns_authority::{DnsSignerPin, VerifiedDnsAuthority};
use boreas_pki::{NetworkRootPin, verify_network_policy};
use boreas_proto::dns_authority::{
    DnsAuthority, DnsRecordEntry, DnsSignerGrant, DnsVipClaim, MLDSA_PARAMETER_SET_65, TYPE_A,
};
use boreas_proto::network_policy::NetworkPolicyCandidate;
use boreas_proto::objects::MldsaParameterSet;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;

const NET: [u8; 16] = [0x44; 16];
const ZONE: &str = "b.example";
const OWNER: &str = "edge.b.example";
const VIP: Ipv4Addr = Ipv4Addr::new(10, 20, 3, 7);
const LOCAL_NODE: u16 = 0x0207;
const NOW: u64 = 1_500;

struct Material {
    raw_tbs: Vec<u8>,
    ed25519: Vec<u8>,
    mldsa: Vec<u8>,
    signer: DnsSignerPin,
    policy: boreas_pki::VerifiedNetworkContext,
}

fn sign(ed: &PKey<Private>, pq: &PKey<Private>, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ed_signer = Signer::new_without_digest(ed).unwrap();
    let ed_signature = ed_signer.sign_oneshot_to_vec(message).unwrap();
    let mut pq_signer = Signer::new_without_digest(pq).unwrap();
    let pq_signature = pq_signer.sign_oneshot_to_vec(message).unwrap();
    (ed_signature, pq_signature)
}

fn keys(seed: u8) -> (PKey<Private>, PKey<Private>) {
    (
        PKey::generate_ed25519().unwrap(),
        PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
    )
}

fn material() -> Material {
    let (root_ed, root_pq) = keys(41);
    let root = NetworkRootPin::provisioned(
        NET,
        root_ed.public_key_to_der().unwrap(),
        MldsaParameterSet::Mldsa65,
        root_pq.public_key_to_der().unwrap(),
    )
    .unwrap();
    let candidate = NetworkPolicyCandidate {
        net_id: NET,
        root_key_fingerprint: root.fingerprint().unwrap(),
        overlay_base: [10, 20, 0, 0],
        version: 1,
        seq: 1,
        issued_at: 1_000,
        expires: 2_000,
    };
    let policy_raw = candidate.encode_tbs().unwrap();
    let policy_message = NetworkPolicyCandidate::signature_input(&policy_raw).unwrap();
    let (policy_ed, policy_pq) = sign(&root_ed, &root_pq, &policy_message);
    let policy = verify_network_policy(&policy_raw, &policy_ed, &policy_pq, &root, NET, NOW)
        .unwrap()
        .require_default_runtime()
        .unwrap();

    let (signer_ed, signer_pq) = keys(42);
    let grant = DnsSignerGrant {
        net_id: NET,
        policy_digest: policy.policy_digest(),
        signer_generation: 1,
        sequence: 1,
        not_before: 1_000,
        expires: 2_000,
        ed25519_public_key_der: signer_ed.public_key_to_der().unwrap(),
        mldsa_parameter_set: MLDSA_PARAMETER_SET_65,
        mldsa_public_key_der: signer_pq.public_key_to_der().unwrap(),
    };
    let grant_raw = grant.encode_tbs().unwrap();
    let grant_message = DnsSignerGrant::signature_input(&grant_raw).unwrap();
    let (grant_ed, grant_pq) = sign(&root_ed, &root_pq, &grant_message);
    let signer =
        DnsSignerPin::verify_grant(&grant_raw, &grant_ed, &grant_pq, &root, &policy, NOW).unwrap();

    let authority = DnsAuthority {
        net_id: NET,
        policy_digest: policy.policy_digest(),
        sequence: 2,
        issued_at: 1_000,
        expires: 1_900,
        zone: ZONE.as_bytes().to_vec(),
        vips: vec![DnsVipClaim {
            node_id: LOCAL_NODE,
            ipv4: VIP.octets(),
            ipv6: [0; 16],
        }],
        records: vec![DnsRecordEntry {
            owner: OWNER.as_bytes().to_vec(),
            record_type: TYPE_A,
            address: VIP.octets().to_vec(),
        }],
    };
    let raw_tbs = authority.encode_tbs().unwrap();
    let message = DnsAuthority::signature_input(&raw_tbs).unwrap();
    let (ed25519, mldsa) = sign(&signer_ed, &signer_pq, &message);
    Material {
        raw_tbs,
        ed25519,
        mldsa,
        signer,
        policy,
    }
}

fn verify_at(
    material: &Material,
    now: u64,
) -> Result<VerifiedDnsAuthority, boreas_pki::dns_authority::Error> {
    VerifiedDnsAuthority::verify(
        &material.raw_tbs,
        &material.ed25519,
        &material.mldsa,
        &material.signer,
        &material.policy,
        now,
    )
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        message.push(u8::try_from(label.len()).unwrap());
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

fn rcode(message: &[u8]) -> u8 {
    message[3] & 0x0f
}

fn answer_a(message: &[u8]) -> Option<Ipv4Addr> {
    let answers = u16::from_be_bytes([message[6], message[7]]);
    if answers == 0 {
        return None;
    }
    // Question name is uncompressed; skip it, then qtype/qclass, then the
    // answer name (a compression pointer in this responder) and the A rdata.
    let mut index = 12usize;
    while message.get(index).copied()? != 0 {
        index += 1 + usize::from(message[index]);
    }
    index += 1 + 4;
    if message.get(index)? & 0xc0 != 0xc0 {
        return None;
    }
    index += 2;
    let kind = u16::from_be_bytes([message[index], message[index + 1]]);
    let rdlength = u16::from_be_bytes([message[index + 8], message[index + 9]]);
    if kind != TYPE_A || rdlength != 4 {
        return None;
    }
    let start = index + 10;
    let octets: [u8; 4] = message.get(start..start + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

fn resolver_from(authority: &VerifiedDnsAuthority) -> AuthoritativeDns {
    let mut zone = Zone::new(authority.zone()).unwrap();
    for record in authority.records() {
        assert_eq!(record.record_type, TYPE_A);
        let octets: [u8; 4] = record.address.as_slice().try_into().unwrap();
        zone.add_address(&record.owner, IpAddr::V4(Ipv4Addr::from(octets)))
            .unwrap();
    }
    let source = IpAddr::V4(authority.vips()[0].ipv4);
    AuthoritativeDns::new(zone, SourceAuthorization::new([source]), 512).unwrap()
}

#[test]
fn verified_authority_answers_in_zone_a_and_refuses_outside_names() {
    let signed = material();
    let authority = verify_at(&signed, NOW).unwrap();
    assert!(authority.is_fresh_at(NOW));
    assert_eq!(authority.zone(), ZONE);
    assert_eq!(authority.vips()[0].ipv4, VIP);
    assert_eq!(authority.records()[0].owner, OWNER);

    let resolver = resolver_from(&authority);
    let source = IpAddr::V4(VIP);
    let inside = resolver
        .respond_udp(source, &query(OWNER, TYPE_A))
        .unwrap()
        .expect("in-zone answer");
    assert_eq!(rcode(&inside), 0);
    assert_eq!(answer_a(&inside), Some(VIP));

    let outside = resolver
        .respond_udp(source, &query("other.example", TYPE_A))
        .unwrap()
        .expect("refusal, not silence and not a recursive answer");
    assert_eq!(rcode(&outside), 5);
    assert_eq!(answer_a(&outside), None);
    assert_eq!(u16::from_be_bytes([outside[6], outside[7]]), 0);
}

#[test]
fn expired_dns_authority_is_rejected_by_verify_and_by_freshness() {
    let signed = material();
    let fresh = verify_at(&signed, NOW).unwrap();
    let (_from, until) = fresh.freshness();
    assert!(until > NOW);
    assert!(!fresh.is_fresh_at(until));
    assert!(verify_at(&signed, until).is_err());
    assert!(verify_at(&signed, fresh.validity().0.saturating_sub(1)).is_err());
}
