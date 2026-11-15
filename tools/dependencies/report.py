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
    core = value.split('+', 1)[0]
    if '-' in core or not re.fullmatch(r'\d+\.\d+\.\d+', core):
        return None
    return tuple(map(int, core.split('.')))


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
            errors.append(name + ': query incomplete: ' + str(exc))
    # Cargo audit does not cover native libssl. New upstream security notices must
    # cause human review even if GitHub's latest release pointer is lagging.
    try:
        html = fetch('https://openssl-library.org/news/vulnerabilities/', 'openssl-vulnerabilities.html').decode()
        notices = sorted(set(re.findall(r'/news/secadv/(\d{8})\.txt', html)))
        if not notices:
            raise RuntimeError('No security notice dates parsed; upstream format changed')
        policy = json.loads((ROOT / 'tools/dependencies/openssl-review.json').read_text())
        pins = {}
        for workflow in sorted((ROOT / '.github/workflows').glob('*.yml')):
            found = re.findall(r'^\s+OPENSSL_VERSION:\s*[\'"]?(\d+\.\d+\.\d+)', workflow.read_text(), re.M)
            if found:
                pins[str(workflow.relative_to(ROOT))] = found
        if not pins:
            raise RuntimeError('No OpenSSL workflow pins found')
        if any(v != policy['version'] for values in pins.values() for v in values):
            errors.append('Native OpenSSL pin changed: update explicit security review evidence')
        downloads = fetch('https://openssl-library.org/source/', 'openssl-downloads.html').decode()
        supported = set(re.findall(r'releases/download/openssl-(\d+\.\d+\.\d+)/', downloads))
        if not supported or 'out of support' not in downloads.lower():
            raise RuntimeError('Cannot parse supported release table; manual review required')
        supported_branches = {version(v)[:2] for v in supported}
        for pin in {v for values in pins.values() for v in values}:
            if version(pin)[:2] not in supported_branches:
                errors.append('Native OpenSSL ' + pin + ' branch is unsupported/unanalysed; security migration blocked pending supported patched backend')
            for affected in policy['affected_ranges']:
                if version(affected['minimum']) <= version(pin) < version(affected['fixed']):
                    errors.append('Native OpenSSL ' + pin + ' affected: ' + ', '.join(affected['cves']) + '; fixed ' + affected['fixed'])
        new = [n for n in notices if n > policy['reviewed_through_notice']]
        if new:
            errors.append('Native OpenSSL security notices need review: ' + ', '.join(new))
        release = json.loads(fetch('https://api.github.com/repos/openssl/openssl/releases/latest', 'openssl-latest.json', True))
        fetch('https://api.github.com/repos/openssl/openssl/releases/tags/openssl-' + policy['version'], 'openssl-pinned-release.json', True)
        (OUT / 'openssl.json').write_text(json.dumps({'pins': pins, 'latest_release_pointer': release['tag_name'], 'notice_dates': notices, 'policy': policy, 'unreviewed_notices': new}, indent=2))
    except Exception as exc:
        errors.append('Native OpenSSL query incomplete: ' + str(exc))
    if os.environ.get('FAIL_ON_OUTDATED') == '1' and stale:
        errors.append('Strict freshness policy: ' + ', '.join(stale))
    result = {'queried_at_utc': queried, 'lock_sha256': hashlib.sha256(lock_bytes).hexdigest(), 'dependencies': rows, 'outdated': stale, 'failures': errors, 'warning': 'Latest does not mean vulnerability-free. Empty advisory results are not a safety proof.'}
    (OUT / 'report.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    lines = ['# Dependency intelligence', '', 'Queried (UTC): ' + queried, '', '| Crate | Locked | Latest non-yanked stable | Outdated |', '| --- | --- | --- | --- |']
    lines.extend('| {name} | {locked} | {latest_stable} | {outdated} |'.format(**r) for r in rows)
    review = json.loads((ROOT / 'tools/dependencies/openssl-review.json').read_text())
    lines += ['', '## Native OpenSSL CVE applicability (not exploitability proof)', *['- ' + cve + ': ' + note for cve, note in review['applicability'].items()]]
    lines += ['', '## Blocking findings', *['- ' + e.replace('\n', ' ') for e in errors], '', result['warning']]
    text = '\n'.join(lines) + '\n'
    (OUT / 'report.md').write_text(text, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(text)
    print(text)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
