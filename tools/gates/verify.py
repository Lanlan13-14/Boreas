"""Fail-closed production evidence verification; execute tests only in Actions.

This checks evidence metadata, not whether an audit or a measurement is true.
A release approver must review the immutable linked reports independently.
"""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

REQUIRED = (
    'G-CRYPTO', 'G-FRAME', 'G-DATA', 'G-RESOURCE', 'G-PERF',
    'G-ENROLL', 'G-AUTHZ', 'G-REVOKE', 'G-DOS', 'G-TUN', 'G-MTU',
    'G-DNS', 'G-SANDBOX', 'G-UPGRADE', 'G-CONVERGE', 'G-PREFIX',
    'G-FAILOVER', 'G-SUPPLY', 'G-UI', 'G-E2E', 'G-NO-DOWNGRADE',
    'G-E2E-COST', 'G-EXTERNAL-REVIEW', 'G-OPERATIONS',
)
PLATFORMS = ('linux-x86_64-static', 'linux-aarch64-static', 'windows-x86_64',
             'macos-x86_64', 'macos-aarch64')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


MAX_LEDGER_BYTES = 1024 * 1024


def parse_ledger(raw):
    if len(raw) > MAX_LEDGER_BYTES:
        raise ValueError('ledger exceeds 1 MiB')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)


def read_ledger(path):
    with Path(path).open('rb') as handle:
        return parse_ledger(handle.read(MAX_LEDGER_BYTES + 1))


def immutable_actions_url(value):
    if not isinstance(value, str):
        return False
    u = urlparse(value)
    return (u.scheme == 'https' and u.netloc == 'github.com'
            and not u.query and not u.fragment
            and re.fullmatch(r'/Lanlan13-14/Boreas/actions/runs/[1-9][0-9]*', u.path))


def verify(ledger, commit):
    errors = []
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        return ['release commit must be a full lowercase SHA-1']
    if not isinstance(ledger, dict) or ledger.get('schema_version') != 1:
        return ['unsupported gate ledger schema']
    if ledger.get('release_commit') != commit:
        errors.append('ledger release_commit does not match candidate')
    if ledger.get('production_approved') is not True:
        errors.append('production approval is absent')
    if ledger.get('blocking_findings') != []:
        errors.append('blocking findings must be an explicit empty list')
    gates = ledger.get('gates', {})
    if not isinstance(gates, dict):
        return errors + ['gates must be an object']
    for name in REQUIRED:
        gate = gates.get(name)
        if not isinstance(gate, dict) or gate.get('status') != 'accepted':
            errors.append(f'{name}: not accepted')
            continue
        records = gate.get('evidence')
        if not isinstance(records, list) or not records:
            errors.append(f'{name}: no evidence')
            continue
        for item in records:
            if not isinstance(item, dict):
                errors.append(f'{name}: invalid evidence record')
                continue
            if item.get('commit') != commit:
                errors.append(f'{name}: evidence belongs to another commit')
            for field in ('command', 'environment', 'expected', 'observed', 'reviewer'):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    errors.append(f'{name}: missing {field}')
            if not immutable_actions_url(item.get('actions_run')):
                errors.append(f'{name}: missing immutable Actions run URL')
            if not re.fullmatch(r'[0-9a-f]{64}', str(item.get('report_sha256', ''))):
                errors.append(f'{name}: report SHA-256 absent')
            if item.get('outcome') != 'pass':
                errors.append(f'{name}: evidence did not pass')
            try:
                date = dt.datetime.fromisoformat(item.get('recorded_at', '').replace('Z', '+00:00'))
                if date.utcoffset() != dt.timedelta(0):
                    raise ValueError('not UTC')
            except (ValueError, TypeError):
                errors.append(f'{name}: recorded_at must be UTC ISO-8601')
        if name == 'G-EXTERNAL-REVIEW':
            review = gate.get('independent_review', {})
            if not isinstance(review, dict) or review.get('independent') is not True:
                errors.append(f'{name}: independent audit absent')
            else:
                for field in ('organization', 'scope', 'report_url', 'report_sha256'):
                    if not isinstance(review.get(field), str) or not review[field].strip():
                        errors.append(f'{name}: missing audit {field}')
                if review.get('open_high_or_critical') != 0:
                    errors.append(f'{name}: unresolved audit findings')
    platform_records = ledger.get('platforms', {})
    for name in PLATFORMS:
        record = platform_records.get(name, {}) if isinstance(platform_records, dict) else {}
        if not isinstance(record, dict) or record.get('commit') != commit or record.get('functional_test') != 'pass':
            errors.append(f'{name}: exact-commit native functional evidence absent')
            continue
        if not immutable_actions_url(record.get('actions_run')):
            errors.append(f'{name}: Actions run absent')
        if record.get('native_execution') is not True or record.get('real_packet_io') is not True:
            errors.append(f'{name}: native real packet I/O not demonstrated')
        if name.endswith('-static') and record.get('static_linkage') is not True:
            errors.append(f'{name}: static linkage not demonstrated')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    try:
        errors = verify(read_ledger(args.ledger), args.commit)
    except (ValueError, OSError, RecursionError) as exc:
        errors = [f'invalid ledger: {exc}']
    if errors:
        for error in errors:
            print(f'RELEASE BLOCKED: {error}', file=sys.stderr)
        return 1
    print('Evidence metadata accepted; independent release approval remains required.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
