# Production evidence gate

Run the verifier in GitHub Actions:

```sh
python -m unittest discover -s tools/gates -p 'test_*.py' -v
python tools/release/production_promotion.py --check-ledger \
  --commit "$CANDIDATE_SHA" --ledger-commit "$REVIEWED_MAIN_LEDGER_SHA"
```

The working status file `docs/engineering/gates.json` is not an authorization
input. The production ledger must instead be a regular blob at
`docs/engineering/release-evidence/gates.json` in a later, independently
reviewed commit on main’s first-parent history. Run the provenance check from
the trusted main tooling checkout; do not run it from the candidate. Development artifacts may be uploaded
without claiming production readiness. Never change an open gate to accepted
because a build, a doctor command, or a simulator alone passed.

For every accepted gate, record the exact candidate commit, immutable Actions
run URL, reproducible command, environment, expected and observed results,
reviewer, UTC recording time and report SHA-256. Preserve the underlying reports
and negative samples. All five native platform entries require real packet I/O
and functional execution; Linux entries additionally require static-linkage
inspection. The independent review entry must identify the organization, scope,
report and unresolved high/critical finding count. An optional disabled suite
such as pq1024 remains unavailable until its separate evidence is reviewed.

This script checks **metadata consistency only**. It does not download reports,
verify a report signature, prove an auditor is independent, validate a run's
actual result or cryptographically authorize a release. A malicious writer can
fabricate metadata. Protected-branch review, an independent release approver,
retained evidence and offline ReleaseRoot dual signatures remain necessary.
No production signing private key belongs in Actions secrets. The ledger cannot
replace the artifact authenticity verifier or the independent security audit.

Freeze the exact candidate before building it and collecting evidence. A
subsequent ledger update must not move the candidate; the signed outer promotion
manifest binds the raw reviewed ledger bytes using `gate_ledger_sha256`. No local compilation or test execution is authorized by this file.
