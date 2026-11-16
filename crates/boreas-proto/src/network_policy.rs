//! Isolated NetworkPolicy candidate bytes. Does not extend `objects::ObjectType` or enable prefixes.
use crate::objects::SIGNATURE_DOMAIN;

pub const MAX_TBS_LEN: usize = 16 * 1024;
pub const CANDIDATE_OBJECT_TYPE: u8 = 7;
pub const ISSUER_KEY_ID: &[u8] = b"network-root-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicyCandidate {
    pub net_id: [u8; 16],
    pub root_key_fingerprint: [u8; 32],
    pub overlay_base: [u8; 4],
    pub version: u64,
    pub seq: u64,
    pub issued_at: u64,
    pub expires: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    Invalid(&'static str),
}

impl NetworkPolicyCandidate {
    pub fn validate(&self) -> Result<(), Error> {
        if self.net_id == [0; 16] {
            return Err(Error::Invalid("net_id"));
        }
        if self.root_key_fingerprint == [0; 32] {
            return Err(Error::Invalid("root fingerprint"));
        }
        let [a, b, c, d] = self.overlay_base;
        if c != 0
            || d != 0
            || !(a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168))
        {
            return Err(Error::Invalid("RFC1918 canonical /16"));
        }
        if self.version != 1 {
            return Err(Error::Invalid("schema version"));
        }
        if self.seq == 0 {
            return Err(Error::Invalid("sequence"));
        }
        if self.issued_at >= self.expires {
            return Err(Error::Invalid("time window"));
        }
        Ok(())
    }

    /// Encode the candidate management TBS exactly per the candidate contract.
    pub fn encode_tbs(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        map(&mut out, 11);
        uint(&mut out, 0); uint(&mut out, 1);
        uint(&mut out, 1); uint(&mut out, 7);
        uint(&mut out, 2); bytes(&mut out, &self.net_id);
        uint(&mut out, 3); bytes(&mut out, ISSUER_KEY_ID);
        uint(&mut out, 4); uint(&mut out, 1);
        uint(&mut out, 5); array(&mut out, 1); uint(&mut out, 3);
        uint(&mut out, 6); uint(&mut out, self.seq);
        uint(&mut out, 7); uint(&mut out, self.issued_at);
        uint(&mut out, 8); uint(&mut out, self.expires);
        uint(&mut out, 9); map(&mut out, 5);
        uint(&mut out, 0); bytes(&mut out, &self.net_id);
        uint(&mut out, 1); bytes(&mut out, &self.overlay_base);
        uint(&mut out, 2); uint(&mut out, 16);
        uint(&mut out, 3); bytes(&mut out, &self.root_key_fingerprint);
        uint(&mut out, 4); uint(&mut out, 0);
        uint(&mut out, 10); array(&mut out, 0);
        if out.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Parse the complete canonical TBS. Caller retains and verifies these exact bytes.
    pub fn decode_tbs(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_TBS_LEN {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { b: raw, i: 0 };
        r.container(5, 11)?;
        r.key(0)?;
        if r.uint()? != 1 { return Err(Error::Invalid("schema version")); }
        r.key(1)?;
        if r.uint()? != 7 { return Err(Error::Invalid("candidate type")); }
        r.key(2)?;
        let net_id = r.fixed::<16>()?;
        r.key(3)?;
        if r.blob()? != ISSUER_KEY_ID { return Err(Error::Invalid("issuer")); }
        r.key(4)?;
        if r.uint()? != 1 { return Err(Error::Invalid("issuer generation")); }
        r.key(5)?;
        r.container(4, 1)?;
        if r.uint()? != 3 { return Err(Error::Invalid("subject")); }
        r.key(6)?;
        let seq = r.uint()?;
        r.key(7)?;
        let issued_at = r.uint()?;
        r.key(8)?;
        let expires = r.uint()?;
        r.key(9)?;
        r.container(5, 5)?;
        r.key(0)?;
        if r.fixed::<16>()? != net_id { return Err(Error::Invalid("body net_id mismatch")); }
        r.key(1)?;
        let overlay_base = r.fixed::<4>()?;
        r.key(2)?;
        if r.uint()? != 16 { return Err(Error::Invalid("prefix length")); }
        r.key(3)?;
        let root_key_fingerprint = r.fixed::<32>()?;
        r.key(4)?;
        if r.uint()? != 0 { return Err(Error::Invalid("flags")); }
        r.key(10)?;
        r.container(4, 0)?;
        if r.i != raw.len() { return Err(Error::Invalid("trailing bytes")); }
        let value = Self { net_id, root_key_fingerprint, overlay_base, version: 1, seq, issued_at, expires };
        value.validate()?;
        Ok(value)
    }

    /// Domain-separated bytes; candidate type 7 is explicit, never cast to ObjectType.
    pub fn signature_input(raw_tbs: &[u8]) -> Result<Vec<u8>, Error> {
        if raw_tbs.len() > MAX_TBS_LEN { return Err(Error::TooLarge); }
        let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 11 + raw_tbs.len());
        out.extend_from_slice(SIGNATURE_DOMAIN);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(CANDIDATE_OBJECT_TYPE);
        out.extend_from_slice(&(raw_tbs.len() as u64).to_be_bytes());
        out.extend_from_slice(raw_tbs);
        Ok(out)
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 { out.push(major << 5 | n as u8); }
    else if n <= 255 { out.extend([major << 5 | 24, n as u8]); }
    else if n <= 65535 { out.push(major << 5 | 25); out.extend_from_slice(&(n as u16).to_be_bytes()); }
    else if n <= u32::MAX as u64 { out.push(major << 5 | 26); out.extend_from_slice(&(n as u32).to_be_bytes()); }
    else { out.push(major << 5 | 27); out.extend_from_slice(&n.to_be_bytes()); }
}
fn uint(out: &mut Vec<u8>, n: u64) { head(out, 0, n); }
fn map(out: &mut Vec<u8>, n: u64) { head(out, 5, n); }
fn array(out: &mut Vec<u8>, n: u64) { head(out, 4, n); }
fn bytes(out: &mut Vec<u8>, b: &[u8]) { head(out, 2, b.len() as u64); out.extend_from_slice(b); }

struct Reader<'a> { b: &'a [u8], i: usize }
impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let value = *self.b.get(self.i).ok_or(Error::Invalid("truncated"))?;
        self.i += 1;
        Ok(value)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.i.checked_add(n).ok_or(Error::Invalid("length overflow"))?;
        let bytes = self.b.get(self.i..end).ok_or(Error::Invalid("truncated"))?;
        self.i = end;
        Ok(bytes)
    }
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        let (value, width) = match ai {
            0..=23 => (ai as u64, 0),
            24 => (self.byte()? as u64, 1),
            25 => { let b = self.take(2)?; (u16::from_be_bytes([b[0], b[1]]) as u64, 2) }
            26 => { let b = self.take(4)?; (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4) }
            27 => { let b = self.take(8)?; let mut a = [0; 8]; a.copy_from_slice(b); (u64::from_be_bytes(a), 8) }
            _ => return Err(Error::Invalid("indefinite/reserved")),
        };
        if (width == 1 && value < 24) || (width == 2 && value <= 255)
            || (width == 4 && value <= 65535) || (width == 8 && value <= u32::MAX as u64)
        { return Err(Error::Invalid("noncanonical integer/length")); }
        Ok(value)
    }
    fn item(&mut self, major: u8) -> Result<u64, Error> {
        let h = self.byte()?;
        if h >> 5 != major { return Err(Error::Invalid("wrong CBOR type")); }
        self.arg(h & 31)
    }
    fn uint(&mut self) -> Result<u64, Error> { self.item(0) }
    fn key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected { Ok(()) } else { Err(Error::Invalid("field order/unknown/duplicate key")) }
    }
    fn container(&mut self, major: u8, expected: u64) -> Result<(), Error> {
        if self.item(major)? == expected { Ok(()) } else { Err(Error::Invalid("map/array size; nonempty extension rejected")) }
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.item(2)?).map_err(|_| Error::TooLarge)?;
        self.take(n)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.blob()?;
        if b.len() != N { return Err(Error::Invalid("fixed byte length")); }
        let mut out = [0; N];
        out.copy_from_slice(b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|v| u8::from_str_radix(v, 16).expect("hex vector")).collect()
    }
    fn sample() -> NetworkPolicyCandidate {
        NetworkPolicyCandidate {
            net_id: [1; 16], root_key_fingerprint: [2; 32], overlay_base: [10, 20, 0, 0],
            version: 1, seq: 1, issued_at: 10, expires: 20,
        }
    }
    const POSITIVE_TBS: &str = concat!(
        "ab 00 01 01 07 02 50 ",
        "01 01 01 01 01 01 01 01 ",
        "01 01 01 01 01 01 01 01 ",
        "03 4f 6e 65 74 77 6f 72 6b 2d 72 6f 6f 74 2d 76 31 ",
        "04 01 05 81 03 06 01 07 0a 08 14 09 a5 00 50 ",
        "01 01 01 01 01 01 01 01 ",
        "01 01 01 01 01 01 01 01 ",
        "01 44 0a 14 00 00 02 10 03 58 20 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "02 02 02 02 02 02 02 02 ",
        "04 00 0a 80",
    );

    #[test]
    fn independent_fixed_tbs_and_signature_vector() {
        let raw = hex(POSITIVE_TBS);
        assert_eq!(raw.len(), 118);
        assert_eq!(NetworkPolicyCandidate::decode_tbs(&raw).unwrap(), sample());
        assert_eq!(sample().encode_tbs().unwrap(), raw);
        let mut expected = b"BOREAS-MGMT-OBJECT\0\x00\x01\x07\0\0\0\0\0\0\0\x76".to_vec();
        expected.extend_from_slice(&raw);
        assert_eq!(NetworkPolicyCandidate::signature_input(&raw).unwrap(), expected);
    }

    #[test]
    fn rejects_canonical_negative_vectors_and_contract_mutations() {
        let base = hex(POSITIVE_TBS);
        // Non-shortest map length; duplicate envelope key; unknown envelope key.
        assert!(NetworkPolicyCandidate::decode_tbs(&hex("b8 0b")).is_err());
        let mut duplicate = base.clone();
        assert_eq!(duplicate[5], 0x02); // envelope key 2
        duplicate[5] = 0x01; // repeats key 1
        assert!(NetworkPolicyCandidate::decode_tbs(&duplicate).is_err());
        let mut unknown = base.clone();
        assert_eq!(unknown[116], 0x0a); // final envelope key 10
        unknown[116] = 0x0b; // unknown key; no truncation involved
        assert!(NetworkPolicyCandidate::decode_tbs(&unknown).is_err());
        // Contract's extensions field is an array and MUST be empty: real nonempty array item.
        let mut extension = base.clone();
        assert_eq!(&extension[extension.len()-1..], &[0x80]);
        extension.pop(); extension.push(0x81); extension.push(0x00);
        assert!(NetworkPolicyCandidate::decode_tbs(&extension).is_err());
        // Alter issuer byte and body net_id byte while retaining valid CBOR shapes.
        let mut issuer = base.clone();
        assert_eq!(issuer[25], b'n');
        issuer[25] ^= 1;
        assert!(NetworkPolicyCandidate::decode_tbs(&issuer).is_err());
        let mut mismatch = base.clone();
        assert_eq!(mismatch[55], 0x01);
        mismatch[55] = 0x02; // body net_id only; envelope net_id remains valid/nonzero
        assert!(NetworkPolicyCandidate::decode_tbs(&mismatch).is_err());
        for (index, old, value) in [
            (3usize, 0x01, 0x18), // noncanonical encoding of key 1
            (34, 0x6f, 0x18), // issuer blob content
            (43, 0x81, 0x82), // subject array has wrong length
            (44, 0x03, 0x0b), // wrong subject value
            (45, 0x06, 0x00), // out-of-order/duplicate envelope key
        ] {
            let mut bad = base.clone();
            assert_eq!(bad[index], old, "mutation offset {index}");
            bad[index] = value;
            assert!(NetworkPolicyCandidate::decode_tbs(&bad).is_err());
        }
        let mut trailing = base; trailing.push(0);
        assert!(NetworkPolicyCandidate::decode_tbs(&trailing).is_err());
    }

    #[test]
    fn rejects_invalid_values_and_size() {
        for (field, expected) in [
            ("host bits", { let mut x=sample(); x.overlay_base=[10,20,0,1]; x }),
            ("time", { let mut x=sample(); x.expires=x.issued_at; x }),
            ("schema", { let mut x=sample(); x.version=2; x }),
            ("sequence", { let mut x=sample(); x.seq=0; x }),
            ("zero net", { let mut x=sample(); x.net_id=[0;16]; x }),
            ("zero root", { let mut x=sample(); x.root_key_fingerprint=[0;32]; x }),
        ] { let _ = field; assert!(expected.encode_tbs().is_err()); }
        assert_eq!(NetworkPolicyCandidate::decode_tbs(&vec![0; MAX_TBS_LEN + 1]), Err(Error::TooLarge));
        assert_eq!(NetworkPolicyCandidate::signature_input(&vec![0; MAX_TBS_LEN + 1]), Err(Error::TooLarge));
    }
}
