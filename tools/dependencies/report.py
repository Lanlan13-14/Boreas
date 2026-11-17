"""Actions-only dependency intelligence; stdlib only, never resolves or edits Cargo.lock."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'dependency-reports'


def fetch(url, name, github=False):
    headers = {'User-Agent': 'Boreas-dependency-audit', 'Accept': 'application/json'}
    if github and os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        raw = response.read()
        link = response.headers.get('Link', '')
    (OUT / name).write_bytes(raw)
    if 'rel="next"' in link:
        raise RuntimeError('Paginated response requires review; refusing incomplete report: ' + url)
    return raw


def version(value):
    # Ignore build metadata, not prerelease markers: spec-1.1.0 is NOT a prerelease.
    # None means "not comparable", never "old": callers must block on None instead
    # of ordering it, because `tuple < None` raises TypeError and used to abort the
    # whole native OpenSSL review.
    if not isinstance(value, str):
        return None
    core = value.split('+', 1)[0]
    if '-' in core or not re.fullmatch(r'\d+\.\d+\.\d+', core):
        return None
    return tuple(map(int, core.split('.')))


def openssl_version(value):
    # OpenSSL labels patch releases with trailing letters inside a branch
    # (1.1.1 -> 1.1.1a -> 1.1.1zk). Those reviewed bounds are comparable and must
    # not be dropped; anything else (draft names, git snapshots) is None and
    # therefore blocking rather than silently skipped.
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)([a-z]{0,2})', value.strip())
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    rank = 0
    for letter in suffix:
        rank = rank * 26 + (ord(letter) - ord('a') + 1)
    return (int(major), int(minor), int(patch), rank)


def supported_release_branches(releases):
    """Normalize release versions to branch keys used for support comparison."""
    return {parsed[:2] for release in releases
            if (parsed := openssl_version(release)) is not None}


def affected_range_findings(pin, ranges):
    # One blocking finding per reviewed range that contains `pin`. A bound this
    # tool cannot order is reported as a blocking finding instead of raising:
    # fail closed, keep the message actionable, and never lose the other ranges.
    findings = []
    pinned = openssl_version(pin)
    if pinned is None:
        return ['Native OpenSSL pin is not a comparable release: ' + repr(pin)]
    for affected in ranges:
        minimum = openssl_version(affected.get('minimum'))
        fixed = openssl_version(affected.get('fixed'))
        if minimum is None or fixed is None:
            findings.append(
                'Native OpenSSL affected range is not comparable, manual review required: minimum={!r} fixed={!r} cves={}'.format(
                    affected.get('minimum'), affected.get('fixed'), ', '.join(affected.get('cves', []))))
            continue
        if minimum <= pinned < fixed:
            findings.append('Native OpenSSL {} affected: {}; fixed {}'.format(
                pin, ', '.join(affected.get('cves', [])), affected.get('fixed')))
    return findings


def describe(exc):
    return type(exc).__name__ + ': ' + str(exc)


def check_openssl(policy, errors):
    """Run every native OpenSSL review check independently.

    Each remote query is isolated so a failure is reported with its own concrete
    exception and the remaining checks still run. The previous single
    try/except collapsed everything after the first error into one
    "query incomplete" line, which could hide a real CVE or digest mismatch
    behind an unrelated parsing bug.
    """
    configuration = policy['configuration_review']
    outcome = {'pins': {}, 'notice_dates': [], 'supported_releases': [], 'latest_release_pointer': None}

    if configuration['status'] != 'APPROVED_WITH_ACTIONS_EVIDENCE':
        errors.append('Native OpenSSL configuration review remains blocking: ' + configuration['status'])

    pins = {}
    for workflow in sorted((ROOT / '.github/workflows').glob('*.yml')):
        workflow_text = workflow.read_text()
        found = re.findall(r'^\s+OPENSSL_VERSION:\s*[\'"]?(\d+\.\d+\.\d+)', workflow_text, re.M)
        if not found:
            continue
        workflow_name = str(workflow.relative_to(ROOT))
        pins[workflow_name] = found
        digests = re.findall(r'^\s+OPENSSL_SHA256:\s*[\'"]?([0-9a-f]{64})[\'"]?\s*$', workflow_text, re.M)
        if len(found) != 1 or len(digests) != 1:
            errors.append('Native OpenSSL workflow pin/digest ambiguous or absent: ' + workflow_name)
        elif found[0] == policy['version'] and digests[0] != configuration['release_sha256']:
            errors.append('Native OpenSSL workflow digest differs from reviewed release: ' + workflow_name)
    outcome['pins'] = pins
    if not pins:
        errors.append('Native OpenSSL workflow pins absent; the native gate cannot be evaluated')
    elif any(v != policy['version'] for values in pins.values() for v in values):
        errors.append('Native OpenSSL pin changed: update explicit security review evidence')

    # Cargo audit does not cover native libssl. New upstream security notices must
    # cause human review even if GitHub's latest release pointer is lagging.
    notices = []
    try:
        html = fetch('https://openssl-library.org/news/vulnerabilities/', 'openssl-vulnerabilities.html').decode()
        notices = sorted(set(re.findall(r'/news/secadv/(\d{8})\.txt', html)))
        if not notices:
            raise RuntimeError('No security notice dates parsed; upstream format changed')
    except Exception as exc:
        errors.append('Native OpenSSL security-notice query failed: ' + describe(exc))
    outcome['notice_dates'] = notices

    supported = set()
    try:
        downloads = fetch('https://openssl-library.org/source/', 'openssl-downloads.html').decode()
        supported = set(re.findall(r'releases/download/openssl-(\d+\.\d+\.\d+)/', downloads))
        if not supported or 'out of support' not in downloads.lower():
            raise RuntimeError('Cannot parse supported release table; manual review required')
    except Exception as exc:
        errors.append('Native OpenSSL supported-release query failed: ' + describe(exc))
    outcome['supported_releases'] = sorted(supported)

    supported_branches = supported_release_branches(supported)
    for pin in sorted({v for values in pins.values() for v in values}):
        parsed = openssl_version(pin)
        if parsed is None:
            errors.append('Native OpenSSL pin is not a comparable release: ' + pin)
            continue
        if supported_branches and parsed[:2] not in supported_branches:
            errors.append('Native OpenSSL ' + pin + ' branch is unsupported/unanalysed; security migration blocked pending supported patched backend')
        errors.extend(affected_range_findings(pin, policy['affected_ranges']))
    if not supported_branches:
        errors.append('Native OpenSSL supported-branch check did not run: the pin is unreviewed, not approved')

    new = [notice for notice in notices if notice > policy['reviewed_through_notice']]
    if new:
        errors.append('Native OpenSSL security notices need review: ' + ', '.join(new))

    try:
        release = json.loads(fetch('https://api.github.com/repos/openssl/openssl/releases/latest', 'openssl-latest.json', True))
        outcome['latest_release_pointer'] = release['tag_name']
        pinned_release = json.loads(fetch('https://api.github.com/repos/openssl/openssl/releases/tags/openssl-' + policy['version'], 'openssl-pinned-release.json', True))
        archive_name = 'openssl-' + policy['version'] + '.tar.gz'
        archives = [asset for asset in pinned_release.get('assets', []) if asset['name'] == archive_name]
        if (pinned_release.get('tag_name') != 'openssl-' + policy['version']
                or pinned_release.get('draft') is not False
                or pinned_release.get('prerelease') is not False
                or len(archives) != 1
                or archives[0].get('digest') != 'sha256:' + configuration['release_sha256']):
            errors.append('Native OpenSSL official release metadata/digest does not match reviewed stable archive')
    except Exception as exc:
        errors.append('Native OpenSSL official release metadata query failed: ' + describe(exc))

    (OUT / 'openssl.json').write_text(json.dumps({
        'pins': outcome['pins'],
        'latest_release_pointer': outcome['latest_release_pointer'],
        'supported_releases': outcome['supported_releases'],
        'notice_dates': outcome['notice_dates'],
        'policy': policy,
        'unreviewed_notices': new,
    }, indent=2))


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Run this tool only in GitHub Actions; local build/test/resolve is prohibited.')
    OUT.mkdir(exist_ok=True)
    errors, stale, rows = [], [], []
    queried = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lock_bytes = (ROOT / 'Cargo.lock').read_bytes()
    lock = tomllib.loads(lock_bytes.decode())
    packages = lock['package']
    direct = {}
    for manifest in sorted((ROOT / 'crates').glob('*/Cargo.toml')):
        data = tomllib.loads(manifest.read_text(encoding='utf-8'))
        sections = [data]
        sections.extend(data.get('target', {}).values())
        for section in sections:
            for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for alias, spec in section.get(kind, {}).items():
                    spec = {'version': spec} if isinstance(spec, str) else spec
                    if 'path' in spec:
                        continue
                    if 'git' in spec:
                        raise RuntimeError('Git dependency requires explicit source review: ' + alias)
                    name = spec.get('package', alias)
                    direct.setdefault(name, []).append({'manifest': str(manifest.relative_to(ROOT)), 'requirement': spec.get('version'), 'kind': kind})
    for name, declarations in sorted(direct.items()):
        try:
            api = 'https://crates.io/api/v1/crates/' + urllib.parse.quote(name)
            data = json.loads(fetch(api, name + '-registry.json'))
            candidates = [v for v in data['versions'] if not v['yanked'] and version(v['num']) is not None]
            latest = max(candidates, key=lambda v: version(v['num']))
            locked = [p['version'] for p in packages if p['name'] == name and p.get('source', '').startswith('registry+')]
            if not locked:
                raise RuntimeError('Direct dependency absent from committed lock')
            old = any(version(v) is None or version(v) < version(latest['num']) for v in locked)
            if old:
                stale.append(name)
            for locked_version in locked:
                affect = urllib.parse.quote(name + '@' + locked_version, safe='')
                url = 'https://api.github.com/advisories?ecosystem=rust&per_page=100&affects=' + affect
                advisories = json.loads(fetch(url, name + '-' + locked_version.replace('+', '_') + '-advisories.json', True))
                if not isinstance(advisories, list):
                    raise RuntimeError('Invalid GitHub advisory response')
                active = [a for a in advisories if not a.get('withdrawn_at')]
                if active:
                    errors.append(name + '@' + locked_version + ': ' + ', '.join(a['ghsa_id'] for a in active))
            rows.append({'name': name, 'declarations': declarations, 'locked': locked, 'latest_stable': latest['num'], 'latest_rust_version': latest.get('rust_version'), 'outdated': old, 'source': api})
        except Exception as exc:
            errors.append(name + ': query incomplete: ' + describe(exc))
    # Native libssl is not covered by Cargo audit, so the reviewed pin, the
    # applicable CVE ranges, the notice dates and the official release metadata
    # are each checked independently in check_openssl().
    try:
        policy = json.loads((ROOT / 'tools/dependencies/openssl-review.json').read_text())
        check_openssl(policy, errors)
    except Exception as exc:
        errors.append('Native OpenSSL review aborted before completion: ' + describe(exc))
    if os.environ.get('FAIL_ON_OUTDATED') == '1' and stale:
        errors.append('Strict freshness policy: ' + ', '.join(stale))
    result = {'queried_at_utc': queried, 'lock_sha256': hashlib.sha256(lock_bytes).hexdigest(), 'dependencies': rows, 'outdated': stale, 'failures': errors, 'warning': 'Latest does not mean vulnerability-free. Empty advisory results are not a safety proof.'}
    (OUT / 'report.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    lines = ['# Dependency intelligence', '', 'Queried (UTC): ' + queried, '', '| Crate | Locked | Latest non-yanked stable | Outdated |', '| --- | --- | --- | --- |']
    lines.extend('| {name} | {locked} | {latest_stable} | {outdated} |'.format(
        locked=', '.join(row['locked']), **{k: v for k, v in row.items() if k != 'locked'}) for row in rows)
    review = json.loads((ROOT / 'tools/dependencies/openssl-review.json').read_text())
    configuration = review['configuration_review']
    lines += ['', '## Exact native OpenSSL configuration review (NOT a waiver)',
              '- Status: ' + configuration['status'],
              '- Reviewed release: ' + review['version'] + '; SHA-256: ' + configuration['release_sha256'],
              '- Required options: ' + ' '.join(configuration['required_options'])]
    for config in configuration['configurations']:
        lines.append('- {workflow}: {target}; {compiler}; extra options: {options}'.format(
            **config, options=' '.join(config['extra_options']) or '(none)'))
    lines += ['- Evidence boundary: ' + configuration['evidence']]
    candidate = review.get('pinned_candidate') or {}
    availability = review.get('fixed_release_availability') or {}
    if candidate:
        lines += ['', '## Pinned native candidate (NOT an approval)',
                  '- Gate: ' + str(candidate.get('gate')),
                  '- Measured results: ' + str(candidate.get('measured_results')),
                  '- Fixed release {} available: {}'.format(
                      availability.get('wanted_fixed_version', 'unknown'), availability.get('available'))]
    lines += ['', '## Native OpenSSL CVE applicability (not exploitability proof)', *['- ' + cve + ': ' + note for cve, note in review['applicability'].items()]]
    lines += ['', '## Blocking findings', *['- ' + e.replace('\n', ' ') for e in errors], '', result['warning']]
    text = '\n'.join(lines) + '\n'
    (OUT / 'report.md').write_text(text, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(text)
    print(text)
    # Surface each finding as a workflow annotation as well: a failed gate must
    # name the concrete cause in the Actions UI, not only inside an artifact.
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        for failure in errors:
            print('::error title=Dependency gate::' + failure.replace('\n', ' '))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
