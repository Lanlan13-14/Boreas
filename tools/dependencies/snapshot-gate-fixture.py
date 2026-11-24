"""Network-free exact snapshot gate checks; called only by Actions fixture."""
import copy
import json
from pathlib import Path
import tempfile
from unittest.mock import patch


def check_snapshot_gate(report, review, check):
    new_cves = {'CVE-2026-84786', 'CVE-2026-107494', 'CVE-2026-121482', 'CVE-2026-84785'}
    for branch in ['4.1.0', '4.0.3', '3.5.9']:
        findings = report.affected_range_findings(branch, review['affected_ranges'])
        check(branch + ' still blocks on all new CVEs',
              all(cve in ' '.join(findings) for cve in new_cves))
    check('DANE affects 3.0 and 1.1.1 but not 1.0.2', all(
        ('CVE-2026-84786' in ' '.join(report.affected_range_findings(v, review['affected_ranges']))) == expected
        for v, expected in [('3.0.23', True), ('1.1.1zj', True), ('1.0.2zs', False)]))
    current = review['fixed_commit']
    old = '941390af2ac35f41d2f95bb0bac823dbf0700845'
    def run_case(commit=None, digest=None, missing=False, future=False):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / '.github/workflows').mkdir(parents=True)
            (root / 'reports').mkdir()
            (root / '.github/workflows/tls.yml').write_text(
                'env:\n  OPENSSL_VERSION: ' + current['version'] + '\n  OPENSSL_COMMIT: '
                + (commit or current['sha']) + '\n  OPENSSL_SHA256: '
                + (digest or current['archive_sha256']) + '\n')
            def fetch(url, _name, github=False):
                if 'vulnerabilities/' in url:
                    return ('/news/secadv/20261124.txt ' + ('/news/secadv/20990101.txt' if future else '')).encode()
                if url.endswith('/source/'):
                    return b'out of support releases/download/openssl-4.1.0/'
                if '/compare/' in url:
                    fixes = current['fixes'][1:] if missing else current['fixes']
                    return json.dumps({'status':'ahead', 'commits':[{'sha':s} for s in fixes]}).encode()
                if url.endswith('/releases/latest'):
                    return b'{"tag_name":"openssl-4.1.0"}'
                if '/releases/tags/' in url:
                    return json.dumps({'tag_name':'openssl-' + review['version'], 'draft':False,
                        'prerelease':False, 'assets':[{'name':'openssl-' + review['version'] + '.tar.gz',
                        'digest':'sha256:' + review['configuration_review']['release_sha256']}]}).encode()
                raise AssertionError('unexpected fetch ' + url)
            errors=[]
            with patch.object(report, 'ROOT', root), patch.object(report, 'OUT', root/'reports'), patch.object(report, 'fetch', fetch):
                report.check_openssl(copy.deepcopy(review), errors)
            return errors
    check('exact reviewed snapshot and all fixes are accepted by metadata checks', run_case() == [])
    check('old reviewed snapshot is no longer accepted', any('not the reviewed fix commit' in e for e in run_case(commit=old)))
    check('wrong archive digest fails closed', any('digest differs' in e for e in run_case(digest='0'*64)))
    check('missing an old fix still fails closed', any('does not contain' in e for e in run_case(missing=True)))
    check('future notice still requires a new review', any('20990101' in e for e in run_case(future=True)))
