"""Actions-only fixture for the native OpenSSL review logic in report.py.

It never touches the network and never writes outside a temporary directory: it
imports report.py and drives the pure decision functions that crashed the gate.

The regression it covers: `version()` returned None for the reviewed legacy
bounds `1.1.1zk` and `1.0.2zt`, and the caller compared `(4, 1, 0) < None`, which
raised TypeError. The whole native OpenSSL review then collapsed into a single
"query incomplete" line, so the real CVE findings, the notice-date check and the
release-metadata check never ran.
"""
import json
import os
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import report  # noqa: E402  (path setup must precede the import)

FAILURES = []


def check(label, condition, detail=''):
    if condition:
        print('ok - ' + label)
    else:
        FAILURES.append(label + (': ' + detail if detail else ''))
        print('FAIL - ' + label + (': ' + detail if detail else ''))


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        print('Run this fixture only in GitHub Actions; local execution is prohibited.', file=sys.stderr)
        return 2

    review = json.loads((TOOLS / 'openssl-review.json').read_text(encoding='utf-8'))
    ranges = review['affected_ranges']

    # 1. None is "not comparable", never "old", and must not raise.
    check('version(None) is not comparable', report.version(None) is None)
    check('version of a non-string is not comparable', report.version(4.1) is None)
    check('legacy letter release is not a strict semver crate version', report.version('1.1.1zk') is None)
    check('build metadata is ignored', report.version('1.2.3+local') == (1, 2, 3))

    # 2. OpenSSL patch letters are ordered inside a branch.
    ordered = ['1.1.1', '1.1.1a', '1.1.1z', '1.1.1za', '1.1.1zk']
    parsed = [report.openssl_version(value) for value in ordered]
    check('every reviewed OpenSSL-style release parses', all(value is not None for value in parsed), str(parsed))
    check('patch letters order monotonically', parsed == sorted(parsed), str(parsed))
    check('4.1.0 sorts after 3.6.5', report.openssl_version('4.1.0') > report.openssl_version('3.6.5'))
    check('draft names stay uncomparable', report.openssl_version('4.1.1-dev') is None)

    # 3. Every reviewed range bound must be orderable, otherwise the gate would
    #    fall back to manual review on every run.
    unparsed = [affected for affected in ranges
                if report.openssl_version(affected.get('minimum')) is None
                or report.openssl_version(affected.get('fixed')) is None]
    check('all reviewed affected-range bounds are comparable', not unparsed, str(unparsed))

    # 4. The pinned release is still inside exactly one reviewed affected range
    #    and the finding names the CVEs -- this is the blocking result, not a pass.
    pinned = review['version']
    findings = report.affected_range_findings(pinned, ranges)
    check('pinned release still produces a blocking finding', len(findings) == 1, str(findings))
    if findings:
        missing = [cve for cve in ranges[0]['cves'] if cve not in findings[0]]
        check('the finding names every reviewed CVE', not missing, str(missing))
        check('the finding states the fixed release', ranges[0]['fixed'] in findings[0])

    # 5. Ordering works on both sides of the range without raising.
    check('a fixed release is outside the range', report.affected_range_findings('4.1.1', ranges) == [])
    check('a later release is outside the range', report.affected_range_findings('4.0.5', ranges) == [])
    check('an earlier patch of the same branch is inside the range',
          len(report.affected_range_findings('4.0.3', ranges)) == 1)

    # 6. An unorderable bound blocks instead of being skipped or raising.
    future = [{'minimum': '4.1.0', 'fixed': 'next-branch', 'cves': ['CVE-EXAMPLE']}]
    future_findings = report.affected_range_findings(pinned, future)
    check('an unorderable bound is a blocking finding', len(future_findings) == 1 and 'manual review required' in future_findings[0], str(future_findings))
    check('an unorderable pin is a blocking finding', 'not a comparable release' in report.affected_range_findings(None, ranges)[0])
    check('an unorderable pin does not raise', report.affected_range_findings('not-a-release', ranges) != [])

    if FAILURES:
        print('\nFAIL - {} assertion(s) failed'.format(len(FAILURES)))
        for failure in FAILURES:
            print('  - ' + failure)
        return 1
    print('\nReport-logic fixture: native OpenSSL review ordering is total and still blocking.')
    print('Logic evidence only; it is not Actions evidence for any OpenSSL build.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
