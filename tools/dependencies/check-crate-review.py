"""Actions-only checker for the reviewed dependency decisions.

It answers one question: do the recorded decisions in
tools/dependencies/crates-review.json still match the crate manifests, the
committed Cargo.lock and (with --verify-candidates) the upstream registry
metadata that justified each decision?

It never edits a manifest or the lock. A failing decision is reported as a
concrete finding; it is not converted into a skip, and no green result here means
"no vulnerability" -- it only means the recorded decision is still accurate.
"""
import json
import os
import re
from pathlib import Path
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / 'tools/dependencies/crates-review.json'
LOCK = ROOT / 'Cargo.lock'
OUT = ROOT / 'dependency-reports'

SEMVER = re.compile(r'^(\d+)\.(\d+)\.(\d+)$')
RELEASE = re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?$')
REQ = re.compile(r'^([\^~=]?)(\d+)(?:\.(\d+))?(?:\.(\d+))?$')


def parse_semver(value):
    match = SEMVER.fullmatch(value.strip()) if isinstance(value, str) else None
    return tuple(map(int, match.groups())) if match else None


def parse_release(value):
    """Rust `rust-version` values may carry two components, e.g. `1.100`."""
    match = RELEASE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def requirement_allows(requirement, version):
    """Cargo-compatible check for the simple requirements recorded in reviews."""
    parsed = parse_semver(version)
    match = REQ.fullmatch(requirement.strip()) if isinstance(requirement, str) else None
    if parsed is None or match is None:
        raise ValueError('cannot compare requirement {!r} with version {!r}'.format(requirement, version))
    operator, major, minor, patch = match.groups()
    major = int(major)
    minor = int(minor) if minor is not None else None
    patch = int(patch) if patch is not None else None
    if operator == '=':
        wanted = tuple(part for part in (major, minor, patch) if part is not None)
        return parsed[:len(wanted)] == wanted
    if operator == '~':
        lower = (major, minor or 0, patch or 0)
        upper = (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
    else:  # '^' and bare requirements share caret semantics
        lower = (major, minor or 0, patch or 0)
        if major > 0:
            upper = (major + 1, 0, 0)
        elif minor:
            upper = (0, minor + 1, 0)
        elif patch is not None:
            upper = (0, 0, patch + 1)
        else:
            upper = (0, 1, 0)
    return lower <= parsed < upper


def manifest_dependency(manifest_path, crate):
    """Find (requirement, features, section) for one dependency in a manifest."""
    data = tomllib.loads(Path(manifest_path).read_text(encoding='utf-8'))
    sections = [('dependencies', data)]
    sections.extend(('target ' + name, section) for name, section in data.get('target', {}).items())
    found = []
    for label, section in sections:
        for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            for alias, spec in section.get(kind, {}).items():
                spec = {'version': spec} if isinstance(spec, str) else spec
                name = spec.get('package', alias)
                if name == crate:
                    found.append({'section': label + '.' + kind, 'requirement': spec.get('version'), 'features': list(spec.get('features', []))})
    return found


def lock_versions(crate):
    lock = tomllib.loads(LOCK.read_text(encoding='utf-8'))
    return [package['version'] for package in lock['package']
            if package['name'] == crate and package.get('source', '').startswith('registry+')]


def validate_review(review):
    """Schema and justification checks that need no network."""
    errors, notes = [], []
    decisions = set(review['decisions'])
    for entry in review['crates']:
        crate = entry.get('crate', '<unnamed>')
        decision = entry.get('decision')
        decision_text = decision if isinstance(decision, str) else ''
        if decision not in decisions:
            # Report the unknown enum but keep checking the rest of the entry:
            # one bad field must not hide independent defects such as an
            # unparseable candidate or a missing justification.
            errors.append('{}: unknown decision {!r}'.format(crate, decision))
        if not str(entry.get('adopted', '')).startswith('='):
            errors.append('{}: adopted pin must be an exact `=version` requirement'.format(crate))
        candidate = parse_semver(entry.get('candidate', ''))
        if candidate is None:
            errors.append('{}: candidate {!r} is not a stable x.y.z release; record BLOCKED/CANDIDATE_UPSTREAM_UNAVAILABLE with the reason instead of an unpinned name'.format(crate, entry.get('candidate')))
        if decision != 'ADOPTED' and len(entry.get('reason', '').strip()) < 40:
            errors.append('{}: a non-adopted decision needs a substantive recorded reason'.format(crate))
        if decision_text.startswith('BLOCKED') and not entry.get('blocking_evidence'):
            errors.append('{}: a blocking decision needs machine-checkable blocking_evidence, otherwise the block cannot be re-verified'.format(crate))
        if decision == 'ADOPTED' and entry.get('candidate') != entry.get('adopted', '').lstrip('='):
            notes.append('{}: ADOPTED but candidate {!r} differs from the adopted pin'.format(crate, entry.get('candidate')))
    return errors, notes


def validate_repository(review):
    """Compare the review record with the manifests and the committed lock."""
    errors = []
    for entry in review['crates']:
        crate = entry['crate']
        found = manifest_dependency(ROOT / entry['manifest'], crate)
        if len(found) != 1:
            errors.append('{}: expected exactly one declaration in {}, found {}'.format(crate, entry['manifest'], len(found)))
            continue
        requirement = found[0]['requirement']
        if requirement != entry['adopted']:
            errors.append('{}: {} declares {} but the review records {}'.format(crate, entry['manifest'], requirement, entry['adopted']))
        expected_features = entry.get('preconditions', {}).get('adopted_features')
        if expected_features is not None:
            if sorted(expected_features) != sorted(found[0]['features']):
                errors.append('{}: enabled features changed; review the candidate feature availability before editing preconditions'.format(crate))
        versions = lock_versions(crate)
        if len(versions) != 1:
            errors.append('{}: committed lock must resolve exactly one registry version, found {}'.format(crate, versions))
        elif versions[0] != entry['adopted'].lstrip('='):
            errors.append('{}: committed lock holds {} but the review records {}'.format(crate, versions[0], entry['adopted']))
    return errors


def fetch_json(url, name):
    headers = {'User-Agent': 'Boreas-crate-review-audit', 'Accept': 'application/json'}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        raw = response.read()
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_bytes(raw)
    return json.loads(raw)


def verify_candidates(review):
    """Re-check each recorded candidate and blocker against crates.io metadata."""
    errors = []
    for entry in review['crates']:
        crate = entry['crate']
        candidate = entry.get('candidate')
        if parse_semver(candidate) is None:
            continue
        try:
            data = fetch_json('https://crates.io/api/v1/crates/{}/{}'.format(crate, candidate), crate + '-' + candidate + '.json')['version']
            if data.get('num') != candidate:
                errors.append('{}: registry returned version {!r} for candidate {!r}'.format(crate, data.get('num'), candidate))
            if data.get('yanked'):
                errors.append('{}: candidate {} is yanked; the recorded decision is stale'.format(crate, candidate))
            if str(entry.get('decision', '')).startswith('CANDIDATE'):
                # MSRV and feature availability only gate an upgrade that the
                # review claims is adoptable; a blocked candidate is not adopted.
                owner_manifest = tomllib.loads((ROOT / entry['manifest']).read_text(encoding='utf-8'))
                owner_msrv = parse_release(owner_manifest.get('package', {}).get('rust-version'))
                candidate_msrv = parse_release(data.get('rust_version'))
                if candidate_msrv is None:
                    errors.append('{}: candidate {} declares no rust-version, so the MSRV precondition cannot be verified'.format(crate, candidate))
                elif owner_msrv is not None and candidate_msrv > owner_msrv:
                    errors.append('{}: candidate {} requires rustc {} above the owning crate minimum {}'.format(crate, candidate, data.get('rust_version'), owner_manifest['package']['rust-version']))
                expected_features = entry.get('preconditions', {}).get('adopted_features')
                if expected_features is not None:
                    missing = [feature for feature in expected_features if feature not in data.get('features', {})]
                    if missing:
                        errors.append('{}: candidate {} lacks enabled feature(s) {}'.format(crate, candidate, ', '.join(missing)))
        except Exception as exc:
            errors.append('{}: candidate metadata query failed: {}: {}'.format(crate, type(exc).__name__, exc))

        evidence = entry.get('blocking_evidence')
        if not evidence:
            continue
        try:
            dependencies = fetch_json(evidence['api'], crate + '-blocker.json')['dependencies']
            matches = [dependency for dependency in dependencies if dependency.get('crate_id') == crate]
            if len(matches) != 1:
                errors.append('{}: blocking evidence no longer resolves: {} dependency entries from {}'.format(crate, len(matches), evidence['consumer']))
                continue
            requirement = matches[0]['req']
            if requirement != evidence['consumer_requirement']:
                errors.append('{}: {} now requires {} instead of {}; re-review the block'.format(crate, evidence['consumer'], requirement, evidence['consumer_requirement']))
            if requirement_allows(requirement, candidate):
                errors.append('{}: blocker resolved -- {} {} accepts candidate {}; the recorded block must be re-reviewed instead of silently kept'.format(
                    crate, evidence['consumer'], evidence['consumer_version'], candidate))
        except Exception as exc:
            errors.append('{}: blocking evidence query failed: {}: {}'.format(crate, type(exc).__name__, exc))
    return errors


def self_test():
    failures = 0
    requirement_cases = [
        ('^0.1', '0.3.1', False),
        ('^0.1', '0.1.1', True),
        ('^0.3', '0.3.1', True),
        ('~0.3', '0.3.9', True),
        ('~0.3', '0.4.0', False),
        ('^1.2', '1.9.0', True),
        ('=0.1.1', '0.1.1', True),
        ('=0.1.1', '0.1.2', False),
        ('0.1', '0.3.1', False),
    ]
    lattice_failures = 0
    for requirement, version, expected in requirement_cases:
        actual = requirement_allows(requirement, version)
        if actual != expected:
            lattice_failures += 1
            print('FAIL - requirement_allows({!r}, {!r}) returned {}'.format(requirement, version, actual))
    failures += lattice_failures
    if not lattice_failures:
        print('ok - requirement lattice ({} cases)'.format(len(requirement_cases)))

    review = json.loads(REVIEW.read_text(encoding='utf-8'))
    errors, _ = validate_review(review)
    if errors:
        failures += 1
        print('FAIL - the committed review record is invalid: {}'.format(errors))
    else:
        print('ok - the committed review record passes schema/justification checks')

    broken = {'decisions': review['decisions'], 'crates': [
        {'crate': 'example', 'manifest': 'crates/boreas-tun/Cargo.toml', 'adopted': '0.1.0', 'candidate': '0.2.0', 'decision': 'BLOCKED_TYPE_IDENTITY', 'reason': 'x'},
        {'crate': 'example2', 'manifest': 'crates/boreas-tun/Cargo.toml', 'adopted': '=0.1.0', 'candidate': 'next', 'decision': 'MADE_UP'},
    ]}
    errors, _ = validate_review(broken)
    expected_fragments = ['exact `=version`', 'substantive recorded reason', 'machine-checkable blocking_evidence', 'is not a stable x.y.z', 'unknown decision']
    missing = [fragment for fragment in expected_fragments if not any(fragment in error for error in errors)]
    if missing:
        failures += 1
        print('FAIL - broken review fixture did not report {}: {}'.format(missing, errors))
    else:
        print('ok - broken review fixture is rejected on every documented ground')

    unknown_only = {'decisions': review['decisions'], 'crates': [
        {'crate': 'example3', 'manifest': 'crates/boreas-tun/Cargo.toml', 'adopted': '0.1.0', 'candidate': 'next', 'decision': 'MADE_UP', 'reason': 'x' * 64},
    ]}
    errors, _ = validate_review(unknown_only)
    expected_fragments = ['unknown decision', 'is not a stable x.y.z']
    missing = [fragment for fragment in expected_fragments if not any(fragment in error for error in errors)]
    if missing:
        failures += 1
        print('FAIL - unknown decision suppressed independent findings {}: {}'.format(missing, errors))
    else:
        print('ok - unknown decision does not suppress independent candidate errors')

    if failures:
        print('FAIL - {} crate-review fixture case(s) failed'.format(failures))
        return 1
    print('Crate-review fixture evidence only; no candidate is adopted or endorsed by this check.')
    return 0


def main(argv):
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        print('Run this checker only in GitHub Actions; local execution is prohibited.', file=sys.stderr)
        return 2
    if '--self-test' in argv:
        return self_test()
    review = json.loads(REVIEW.read_text(encoding='utf-8'))
    errors, notes = validate_review(review)
    errors.extend(validate_repository(review))
    if '--verify-candidates' in argv:
        errors.extend(verify_candidates(review))

    OUT.mkdir(exist_ok=True)
    (OUT / 'crate-review.json').write_text(json.dumps({'reviewed_at': review['reviewed_at'], 'notes': notes, 'errors': errors}, indent=2), encoding='utf-8')
    lines = ['# Reviewed dependency decisions (not a vulnerability waiver)', '', 'Reviewed: ' + review['reviewed_at'], '',
             '| Crate | Adopted | Candidate | Decision |', '| --- | --- | --- | --- |']
    lines.extend('| {crate} | {adopted} | {candidate} | {decision} |'.format(**entry) for entry in review['crates'])
    lines += ['', '## Notes', *(['- ' + note for note in notes] or ['- none'])]
    lines += ['', '## Blocking findings', *(['- ' + error for error in errors] or ['- none'])]
    text = '\n'.join(lines) + '\n'
    (OUT / 'crate-review.md').write_text(text, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(text)
    print(text)
    for error in errors:
        print('::error title=Dependency review::' + error.replace('\n', ' '))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
