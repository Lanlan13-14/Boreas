use super::*;
use openssl::pkey::{Id, KeyType, PKey, Private};
use openssl::sign::Signer;

const BASE: &str = "https://updates.example.test:8443/candidate";
const ARCH: &str = "x86_64-unknown-linux-musl";
const ISSUED: u64 = 1;
const EXPIRES: u64 = 60;
const MANIFEST: &str = r#"{
    "product":"boreas", "manifest_version":1, "sequence":7,
    "published_at":"1970-01-01T00:00:00Z", "issued_at":"1970-01-01T00:00:01Z",
    "expires":"1970-01-01T00:01:00Z", "min_compatible_state":"boreas-node-state-v1",
    "signing_key_id":"fixture-root", "assets":[{
        "name":"boreas-linux-x86_64", "arch":"x86_64-unknown-linux-musl", "size":42,
        "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "url":"https://artifact.example.test/never-request"
    }]
}"#;

struct Fixture {
    feed: Feed,
    ed: PKey<Private>,
    pq: PKey<Private>,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        Self {
            feed: Feed::new(BASE).unwrap(),
            ed: PKey::private_key_from_raw_bytes(&[seed; 32], Id::ED25519).unwrap(),
            pq: PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap(),
        }
    }

    fn trust(&self, min_sequence: u64) -> Trust {
        Trust {
            root: ReleaseRoot::new(
                "fixture-root",
                self.ed.public_key_to_der().unwrap(),
                self.pq.public_key_to_der().unwrap(),
            ).unwrap(),
            min_sequence,
        }
    }

    fn bodies(&self, manifest: &str) -> [Vec<u8>; 3] {
        let sign = |key: &PKey<Private>| {
            Signer::new_without_digest(key)
                .unwrap()
                .sign_oneshot_to_vec(manifest.as_bytes())
                .unwrap()
        };
        [manifest.as_bytes().to_vec(), sign(&self.ed), sign(&self.pq)]
    }

    fn check(&self, bodies: [Vec<u8>; 3], trust: Trust, arch: &str, now: u64) -> Result<Receipt, Error> {
        let deadline = Instant::now() + TOTAL;
        let mut replies = [
            (&self.feed.manifest, MAX_MANIFEST_BYTES, JSON),
            (&self.feed.ed25519, ED25519_SIGNATURE_BYTES, BINARY),
            (&self.feed.mldsa65, ML_DSA_65_SIGNATURE_BYTES, BINARY),
        ].into_iter().zip(bodies);
        let result = discover(&self.feed, trust, arch, deadline, |url, max, accept, until| {
            let ((expected_url, expected_max, expected_accept), body) = replies.next().expect("unexpected GET");
            assert_eq!((url, max, accept, until), (expected_url.as_str(), expected_max, expected_accept, deadline));
            Ok(body)
        }, || Ok(now));
        if result.is_ok() {
            assert!(replies.next().is_none());
        }
        result
    }
}

#[test]
fn authenticates_exact_manifest_and_reports_metadata_only() {
    let fixture = Fixture::new(1);
    let receipt = fixture.check(fixture.bodies(MANIFEST), fixture.trust(7), ARCH, ISSUED).unwrap();
    assert_eq!(receipt.sequence, 7);
    assert_eq!(receipt.expires, "1970-01-01T00:01:00Z");
    assert_eq!(receipt.arch, ARCH);
    assert_eq!(receipt.asset, "boreas-linux-x86_64");
    let digest: String = openssl::sha::sha256(MANIFEST.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(receipt.manifest_sha256, digest);
}

#[test]
fn requires_both_signatures_exact_bytes_and_local_root() {
    let fixture = Fixture::new(1);
    for index in 0..3 {
        let mut bodies = fixture.bodies(MANIFEST);
        if index == 0 {
            // Even a valid JSON whitespace addition invalidates the signature.
            bodies[index].push(b'\n');
        } else {
            bodies[index][0] ^= 1;
        }
        assert_eq!(fixture.check(bodies, fixture.trust(1), ARCH, ISSUED).unwrap_err(), Error::Manifest);
    }
    let other = Fixture::new(2);
    assert_eq!(fixture.check(fixture.bodies(MANIFEST), other.trust(1), ARCH, ISSUED).unwrap_err(), Error::Manifest);
    for malformed in [
        MANIFEST.replace("fixture-root", "other-id"),
        MANIFEST.replace("\"sequence\":7", "\"sequence\":7,\"sequence\":7"),
        r#"{"product":"boreas","schema":1,"stable":null,"prerelease":"v99.0.0-pre.1"}"#.into(),
    ] {
        assert_eq!(fixture.check(fixture.bodies(&malformed), fixture.trust(1), ARCH, ISSUED).unwrap_err(), Error::Manifest);
    }
}

#[test]
fn enforces_freshness_floor_native_target_and_schema() {
    let fixture = Fixture::new(1);
    for (arch, now, floor, error) in [
        (ARCH, ISSUED - 1, 1, Error::Clock),
        (ARCH, EXPIRES, 1, Error::Policy),
        (ARCH, ISSUED, 8, Error::Policy),
        ("aarch64-unknown-linux-musl", ISSUED, 1, Error::Policy),
    ] {
        assert_eq!(fixture.check(fixture.bodies(MANIFEST), fixture.trust(floor), arch, now).unwrap_err(), error);
    }
    let (prefix, rest) = MANIFEST.split_once("\"assets\":[").unwrap();
    let (asset, suffix) = rest.split_once(']').unwrap();
    let second = asset.replace("boreas-linux-x86_64", "second-asset");
    let duplicate = format!("{prefix}\"assets\":[{asset},{second}]{suffix}");
    for rejected in [
        MANIFEST.replace("1970-01-01T00:01:00Z", "1970-05-01T00:00:00Z"),
        MANIFEST.replace(DAEMON_STATE_SCHEMA, "other-state"),
        MANIFEST.replace("\"size\":42", &format!("\"size\":{}", MAX_ELF_BYTES + 1)),
        duplicate,
    ] {
        assert_eq!(fixture.check(fixture.bodies(&rejected), fixture.trust(1), ARCH, ISSUED).unwrap_err(), Error::Policy);
    }
}

#[test]
fn stops_on_transport_error_or_short_signature_and_never_falls_back() {
    let fixture = Fixture::new(1);
    let [manifest, _, _] = fixture.bodies(MANIFEST);
    let deadline = Instant::now() + TOTAL;
    for reject in [Issue::Http(302), Issue::Http(404), Issue::TooLarge, Issue::Timeout] {
        let mut calls = 0;
        let result = discover(&fixture.feed, fixture.trust(1), ARCH, deadline, |url, _, _, _| {
            calls += 1;
            if calls == 1 {
                assert_eq!(url, fixture.feed.manifest);
                Ok(manifest.clone())
            } else {
                assert_eq!(url, fixture.feed.ed25519);
                Err(reject)
            }
        }, || panic!("must fail before freshness check"));
        assert_eq!(result.unwrap_err(), Error::Request(Object::Ed25519, reject));
        assert_eq!(calls, 2);
    }
    let result = discover(&fixture.feed, fixture.trust(1), ARCH, Instant::now(), |_, _, _, _| {
        panic!("deadline already elapsed")
    }, || panic!("no verification after timeout"));
    assert_eq!(result.unwrap_err(), Error::Request(Object::Manifest, Issue::Timeout));
    for (index, object) in [(1, Object::Ed25519), (2, Object::MlDsa65)] {
        let mut bodies = fixture.bodies(MANIFEST);
        bodies[index].pop();
        assert_eq!(fixture.check(bodies, fixture.trust(1), ARCH, ISSUED).unwrap_err(), Error::SignatureLength(object));
    }
}

#[test]
fn feed_requires_strict_https_and_uses_fixed_metadata_names() {
    let feed = Feed::new(&format!("{BASE}/")).unwrap();
    assert_eq!(feed.manifest, format!("{BASE}/release-manifest.json"));
    assert_eq!(feed.ed25519, format!("{BASE}/release-manifest.ed25519.sig"));
    assert_eq!(feed.mldsa65, format!("{BASE}/release-manifest.mldsa65.sig"));
    for bad in [
        "http://example.test", "file:///tmp/manifest", "https://", "https://user@example.test",
        "https://example.test/a?b=c", "https://example.test/a#x", "https://example.test/a/../b",
        "https://example.test/a/%2e", "https://example.test/a\nb", "https://example.test:0/b",
        "https://example.test:99999/b",
    ] {
        assert!(matches!(Feed::new(bad), Err(Error::Feed)), "{bad:?}");
    }
}

#[test]
fn trust_inputs_are_bounded_regular_files_with_local_ownership() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // The CI checkout (unlike /tmp) has non-group-writable ancestry. No host
    // trust files, environment overrides, Internet, or production keys needed.
    let parent = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = parent.join(format!(".signed-update-test-{}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700).create(&path).unwrap();
    let dir = Cleanup(path);
    // SAFETY: geteuid only queries the effective UID.
    let uid = unsafe { libc::geteuid() };
    let fixture = Fixture::new(1);
    for (name, bytes) in [
        ("key-id", b"fixture-root\n".to_vec()),
        ("min-sequence", b"7\n".to_vec()),
        ("ed25519.der", fixture.ed.public_key_to_der().unwrap()),
        ("mldsa65.der", fixture.pq.public_key_to_der().unwrap()),
    ] {
        let file = dir.0.join(name);
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(Trust::load(&dir.0, uid).unwrap().min_sequence, 7);
    let floor = dir.0.join("min-sequence");
    for malformed in ["0\n", "+7\n", "07\n", "7", "7\n8\n", "18446744073709551616\n"] {
        fs::write(&floor, malformed).unwrap();
        assert!(matches!(Trust::load(&dir.0, uid), Err(Error::Trust)));
    }
    fs::write(&floor, b"7\n").unwrap();
    fs::set_permissions(&floor, fs::Permissions::from_mode(0o622)).unwrap();
    assert!(matches!(Trust::load(&dir.0, uid), Err(Error::Trust)));
    fs::remove_file(&floor).unwrap();
    symlink(dir.0.join("key-id"), &floor).unwrap();
    assert!(matches!(Trust::load(&dir.0, uid), Err(Error::Trust)));
    fs::remove_file(&floor).unwrap();
    fs::write(&floor, b"7\n").unwrap();
    fs::write(dir.0.join("ed25519.der"), [0; MAX_ED25519_PUBLIC_KEY_DER_BYTES + 1]).unwrap();
    assert!(matches!(Trust::load(&dir.0, uid), Err(Error::Trust)));
}
