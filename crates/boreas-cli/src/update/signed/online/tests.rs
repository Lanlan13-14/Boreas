use super::super::tests::{ARCH, EXPIRES, Fixture, ISSUED, MANIFEST};
use super::*;

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn elf() -> Vec<u8> {
    let mut image = vec![0; 120];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    // ELF64 little-endian x86-64 ET_EXEC, with a single PT_LOAD. Never executed.
    image[16..20].copy_from_slice(&[2, 0, 62, 0]);
    image[20] = 1;
    image[32] = 64;
    image[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
    image[64] = 1;
    image[68] = 5;
    image[96] = 120;
    image[104] = 120;
    image[112] = 8;
    image
}

fn manifest_for(artifact: &[u8]) -> String {
    MANIFEST.replace("\"size\":42", &format!("\"size\":{}", artifact.len())).replace(&"a".repeat(64), &sha256(artifact))
}

fn sample(
    fixture: &Fixture,
    metadata: [Vec<u8>; 3],
    approval: &str,
    asset: Result<Vec<u8>, Issue>,
    size: usize,
    finished_at: u64,
) -> (Result<Bundle, Rejected>, usize) {
    let deadline = Instant::now() + BUDGET;
    let mut bodies = metadata.into_iter();
    let mut asset = Some(asset);
    let mut times = [ISSUED, finished_at].into_iter();
    let mut requests = 0;
    let bundle = download(
        &fixture.feed, fixture.trust(1), (ARCH, Machine::X86_64), approval, deadline,
        |url, max, accept, until| {
            assert_eq!(until, deadline);
            requests += 1;
            match requests {
                1 => assert_eq!(url, fixture.feed.manifest),
                2 => assert_eq!(url, fixture.feed.ed25519),
                3 => assert_eq!(url, fixture.feed.mldsa65),
                4 => {
                    assert_eq!(url, "https://artifact.example.test/never-request");
                    assert_eq!((max, accept), (size, BINARY));
                    return asset.take().unwrap();
                }
                _ => panic!("unexpected extra/fallback request"),
            }
            Ok(bodies.next().unwrap())
        },
        || Ok(times.next().unwrap()),
    );
    (bundle, requests)
}

#[test]
fn no_artifact_request_before_both_signatures_and_exact_operator_approval() {
    let fixture = Fixture::new(1);
    let artifact = elf();
    let manifest = manifest_for(&artifact);
    let approval = sha256(manifest.as_bytes());
    for i in [1, 2] {
        let mut metadata = fixture.bodies(&manifest);
        metadata[i][0] ^= 1;
        let (result, requests) = sample(&fixture, metadata, &approval, Ok(artifact.clone()), artifact.len(), ISSUED);
        assert_eq!(result.unwrap_err(), Rejected::Metadata(Error::Manifest));
        assert_eq!(requests, 3);
    }
    // A separately signed but different candidate is not approved by this pin.
    let replacement = manifest.replace("\"sequence\":7", "\"sequence\":8");
    let (result, requests) = sample(&fixture, fixture.bodies(&replacement), &approval, Ok(artifact.clone()), artifact.len(), ISSUED);
    assert_eq!(result.unwrap_err(), Rejected::Approval);
    assert_eq!(requests, 3);
}

#[test]
fn rejects_redirect_timeout_wrong_size_digest_elf_and_expiry_before_handoff() {
    let fixture = Fixture::new(1);
    let artifact = elf();
    let manifest = manifest_for(&artifact);
    let approval = sha256(manifest.as_bytes());
    let mut wrong_hash = artifact.clone();
    wrong_hash[119] ^= 1;
    for (body, clock, rejected) in [
        (Err(Issue::Http(302)), ISSUED, Rejected::ArtifactRequest(Issue::Http(302))),
        (Err(Issue::Timeout), ISSUED, Rejected::ArtifactRequest(Issue::Timeout)),
        (Err(Issue::TooLarge), ISSUED, Rejected::ArtifactRequest(Issue::TooLarge)),
        (Ok(artifact[..50].to_vec()), ISSUED, Rejected::ArtifactIdentity),
        (Ok(wrong_hash), ISSUED, Rejected::ArtifactIdentity),
        (Ok(artifact.clone()), EXPIRES, Rejected::Metadata(Error::Policy)),
    ] {
        let (result, requests) = sample(&fixture, fixture.bodies(&manifest), &approval, body, artifact.len(), clock);
        assert_eq!(result.unwrap_err(), rejected);
        assert_eq!(requests, 4);
    }
    for wrong_elf in [b"not an ELF".to_vec(), {
        let mut arm = elf();
        arm[18] = 183;
        arm
    }] {
        let manifest = manifest_for(&wrong_elf);
        let approval = sha256(manifest.as_bytes());
        let size = wrong_elf.len();
        let (result, _) = sample(&fixture, fixture.bodies(&manifest), &approval, Ok(wrong_elf), size, ISSUED);
        assert_eq!(result.unwrap_err(), Rejected::ArtifactElf);
    }
}

#[test]
fn prepares_exact_nonexecutable_inputs_for_existing_apply_then_removes_spool() {
    let fixture = Fixture::new(1);
    let artifact = elf();
    let manifest = manifest_for(&artifact);
    let approval = sha256(manifest.as_bytes());
    let metadata = fixture.bodies(&manifest);
    let (result, requests) = sample(&fixture, metadata.clone(), &approval, Ok(artifact.clone()), artifact.len(), ISSUED);
    let bundle = result.unwrap();
    assert_eq!(requests, 4);
    let path = {
        let spool = Spool::create(&std::env::temp_dir()).unwrap();
        assert_eq!(fs::metadata(&spool.0).unwrap().mode() & 0o777, 0o700);
        // SAFETY: getegid only queries the current process's effective group.
        let gid = unsafe { libc::getegid() };
        let args = spool.prepare(&bundle, gid, &approval).unwrap();
        assert_eq!(args.len(), 7);
        assert_eq!(args[0], "apply");
        assert_eq!(args[1], "--confirm-manifest-sha256");
        assert_eq!(args[2], approval);
        let [raw, ed, pq] = metadata;
        for ((file, name), bytes) in args[3..].iter().zip(NAMES).zip([raw, artifact, ed, pq]) {
            assert_eq!(Path::new(file), spool.0.join(name));
            assert_eq!(fs::read(file).unwrap(), bytes);
            assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
        }
        assert_eq!(fs::metadata(&spool.0).unwrap().mode() & 0o777, 0o750);
        // Immutable names / create_new refuse any attempt to replace the files.
        assert!(spool.prepare(&bundle, gid, &approval).is_err());
        spool.0.clone()
    };
    assert!(!path.exists());
}
