"""Actions-only audit of GitHub Actions pins in .github/workflows.

Every `uses:` reference must resolve to the exact reviewed commit recorded in
tools/dependencies/action-pins.json, and the trailing comment must start with the
reviewed version tag so a reviewer can read the intent without resolving a hash.
Floating tags and branches are tolerated only up to the frozen ceiling in
tools/dependencies/action-pins-inventory.json; that ceiling may shrink but never
grow, and nothing in it is described as security-reviewed.

stdlib only. It never edits a workflow, never resolves Cargo state and never
claims that a tag is safe: it proves the pins still match the reviewed record and
that no unreviewed reference appeared.
"""
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github/workflows'
REGISTRY = ROOT / 'tools/dependencies/action-pins.json'
INVENTORY = ROOT / 'tools/dependencies/action-pins-inventory.json'
OUT = ROOT / 'dependency-reports'

USES = re.compile(r'^\s*(?:-\s+)?uses:\s*(?P<target>[^\s#]+)(?:\s+#\s*(?P<comment>.*?))?\s*$')
USES_KEY = re.compile(r'^\s*(?:-\s+)?uses\s*:')
FLOW_USES = re.compile(r'^\s*-\s*\{[^}]*\buses\s*:')
BLOCK_SCALAR = re.compile(r'^\s*(?:-\s+)?(?!uses\s*:)[A-Za-z0-9_.-]+:\s*[|>][-+]?\d?\s*(?:#.*)?$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')


def parse_workflow(path):
    """Return every `uses:` entry of one workflow file with its 1-based line.

    A line that starts a malformed `uses:` key, or a flow-style mapping that
    carries one, is returned separately: such a reference would otherwise
    smuggle an unaudited action past this audit. Text inside a YAML block
    scalar (`run: |`, `script: >-`, ...) is deliberately skipped -- a shell or
    script line that merely contains `uses:` is not an action reference, and
    treating it as one produced both false `unparseable` failures and false
    unreviewed-action findings.
    """
    entries, unparsed = [], []
    block_indent = None
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        stripped = line.lstrip(' ')
        indent = len(line) - len(stripped)
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue
            block_indent = None
        if BLOCK_SCALAR.match(line):
            block_indent = indent
            continue
        match = USES.match(line)
        if not match:
            if USES_KEY.match(line) or FLOW_USES.match(line):
                unparsed.append(number)
            continue
        target = match.group('target')
        comment = match.group('comment') or ''
        if target.startswith('./'):
            # Local composite action: it lives in this repository and is not a
            # third-party supply-chain pin.
            continue
        if '@' not in target:
            entries.append({'line': number, 'target': target, 'action': target, 'ref': '', 'comment': comment})
            continue
        action, ref = target.rsplit('@', 1)
        entries.append({'line': number, 'target': target, 'action': action, 'ref': ref, 'comment': comment})
    return entries, unparsed


def audit(workflows_dir, actions, inventory):
    """Static audit; returns blocking errors, recorded debt and accepted pins."""
    ceilings = {(entry['workflow'], entry['uses']): entry['max_occurrences'] for entry in inventory}
    errors, reviewed, debt = [], [], []
    floating = Counter()
    first_line = {}

    workflows_dir = Path(workflows_dir)
    files = sorted(workflows_dir.glob('*.yml'))
    if not files:
        return {'errors': ['No workflow files found under ' + str(workflows_dir)], 'reviewed': [], 'debt': []}
    for path in files:
        label = '.github/workflows/' + path.name
        entries, unparsed = parse_workflow(path)
        for number in unparsed:
            errors.append('{}:{}: unparseable `uses:` reference; keep it on its own line so this audit can resolve it'.format(label, number))
        for entry in entries:
            where = '{}:{}'.format(label, entry['line'])
            if COMMIT.match(entry['ref']):
                record = actions.get(entry['action'])
                if record is None:
                    errors.append(where + ': unreviewed action ' + entry['action'] + '; record a reviewed commit in action-pins.json first')
                    continue
                if entry['ref'] != record['commit']:
                    errors.append('{}: {} is pinned to {} but the reviewed commit is {} ({})'.format(
                        where, entry['action'], entry['ref'], record['commit'], record['reviewed_version']))
                    continue
                if not entry['comment'].startswith(record['reviewed_version']):
                    errors.append('{}: {} pin lacks a comment starting with {} (found {!r})'.format(
                        where, entry['action'], record['reviewed_version'], entry['comment']))
                    continue
                reviewed.append({'where': where, 'action': entry['action'], 'version': record['reviewed_version'], 'commit': entry['ref']})
                continue
            key = (label, entry['target'])
            floating[key] += 1
            first_line.setdefault(key, entry['line'])

    for key, count in sorted(floating.items()):
        label, target = key
        ceiling = ceilings.get(key)
        where = '{}:{}'.format(label, first_line[key])
        if ceiling is None:
            errors.append('{}: {} is not a reviewed commit and is absent from action-pins-inventory.json; pin it to the reviewed commit'.format(where, target))
        elif count > ceiling:
            errors.append('{}: {} appears {} times but the frozen inventory ceiling is {}; pin the added reference instead of raising the ceiling'.format(
                where, target, count, ceiling))
        else:
            debt.append({'workflow': label, 'uses': target, 'occurrences': count, 'ceiling': ceiling, 'first_line': first_line[key]})

    # A recorded ceiling whose references disappeared does not block: paying the
    # debt down is the intended direction.
    for (label, target), ceiling in sorted(ceilings.items()):
        if (label, target) not in floating:
            debt.append({'workflow': label, 'uses': target, 'occurrences': 0, 'ceiling': ceiling, 'first_line': None, 'settled': True})
    return {'errors': errors, 'reviewed': reviewed, 'debt': debt}


def fetch_json(url):
    headers = {'User-Agent': 'Boreas-action-pin-audit', 'Accept': 'application/vnd.github+json'}
    token = os.environ.get('GH_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        return json.loads(response.read())


def major_version(text):
    match = re.match(r'^v?(\d+)', text or '')
    return int(match.group(1)) if match else None


def verify_remote(actions):
    """Re-resolve every reviewed version against the official GitHub API."""
    errors, notes = [], []
    for name, record in sorted(actions.items()):
        try:
            resolved = fetch_json(record['ref_api']).get('object', {}).get('sha')
            if resolved != record['commit']:
                if record.get('ref_kind') == 'branch':
                    # A rolling branch moving does not change the code behind the
                    # pinned commit, so this is a re-review reminder, not a
                    # finding: nothing unaudited starts executing.
                    notes.append('{}: {} advanced to {}; the pinned {} is still the reviewed snapshot, re-review to adopt the newer tip'.format(
                        name, record['reviewed_version'], resolved, record['commit']))
                    continue
                errors.append('{}: {} now resolves to {} but the reviewed commit is {}; re-review that action version before using it'.format(
                    name, record['reviewed_version'], resolved, record['commit']))
                continue
            if record.get('tags_api'):
                tags = fetch_json(record['tags_api'])
                latest = tags[0]['name'] if isinstance(tags, list) and tags else None
                if latest is None:
                    errors.append('{}: official tag list is empty or unreadable; the reviewed pin cannot be confirmed as the latest stable release'.format(name))
                elif major_version(latest) is not None and major_version(latest) > major_version(record['reviewed_version']):
                    errors.append('{}: newer stable release line {} exists; the reviewed {} pin is outdated'.format(name, latest, record['reviewed_version']))
                else:
                    notes.append('{}: reviewed {} matches the current stable line (latest tag {})'.format(name, record['reviewed_version'], latest))
            else:
                notes.append('{}: reviewed {} branch commit {} confirmed'.format(name, record['reviewed_version'], record['commit']))
        except Exception as exc:
            errors.append('{}: remote verification failed: {}: {}'.format(name, type(exc).__name__, exc))
    return errors, notes


def report(result, remote_notes):
    OUT.mkdir(exist_ok=True)
    payload = {'reviewed_pins': result['reviewed'], 'unpinned_debt': result['debt'], 'remote_notes': remote_notes, 'errors': result['errors']}
    (OUT / 'action-pins.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
    active = [entry for entry in result['debt'] if not entry.get('settled')]
    lines = ['# Workflow action pin audit (not a security review of the actions)', '',
             '- Reviewed pins accepted: {}'.format(len(result['reviewed'])),
             '- Workflows still on floating refs (recorded debt, not reviewed): {}'.format(len(active)),
             '', '| Workflow | Workflow ref | Occurrences | Frozen ceiling |', '| --- | --- | --- | --- |']
    lines.extend('| {workflow} | {uses} | {occurrences} | {ceiling} |'.format(**entry) for entry in active)
    lines += ['', '## Remote pin re-verification', *(['- ' + note for note in remote_notes] or ['- not requested'])]
    lines += ['', '## Blocking findings', *(['- ' + error.replace('\n', ' ') for error in result['errors']] or ['- none'])]
    text = '\n'.join(lines) + '\n'
    (OUT / 'action-pins.md').write_text(text, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(text)
    print(text)


def self_test():
    """Fixture for the classifier; no network, no repository mutation."""
    actions = {
        'actions/checkout': {'reviewed_version': 'v7', 'commit': 'a' * 40},
        'actions/upload-artifact': {'reviewed_version': 'v7', 'commit': 'b' * 40},
    }
    inventory = [{'workflow': '.github/workflows/legacy.yml', 'uses': 'actions/checkout@v7', 'max_occurrences': 2}]
    cases = [
        ('pinned_ok', ['      - uses: actions/checkout@' + 'a' * 40 + ' # v7'], []),
        ('pinned_with_input', ['      - uses: actions/upload-artifact@' + 'b' * 40 + ' # v7'], []),
        ('floating_within_ceiling', ['      - uses: actions/checkout@v7'], []),
        ('floating_growth', ['      - uses: actions/checkout@v7'] * 3, ['frozen inventory ceiling is 2']),
        ('unlisted_floating', ['      - uses: actions/setup-python@v7'], ['absent from action-pins-inventory.json']),
        ('unreviewed_action', ['      - uses: evil/action@' + 'c' * 40 + ' # v1'], ['unreviewed action evil/action']),
        ('wrong_commit', ['      - uses: actions/checkout@' + 'd' * 40 + ' # v7'], ['but the reviewed commit is']),
        ('missing_comment', ['      - uses: actions/checkout@' + 'a' * 40], ['lacks a comment starting with v7']),
        ('short_sha', ['      - uses: actions/checkout@3d3c42e'], ['absent from action-pins-inventory.json']),
        ('local_action_ignored', ['      - uses: ./.github/actions/local'], []),
        ('pinned_comment_with_pipe', ['      - uses: actions/checkout@' + 'a' * 40 + ' # v7: |'], []),
        ('script_text_ignored', ['      - name: note', '        run: |', '          echo "uses: actions/checkout@v7"', '          uses: evil/action@' + 'e' * 40], []),
        ('malformed_uses_key', ['      - uses:'], ['unparseable `uses:` reference']),
        ('uses_block_value_rejected', ['      - uses: |'], ['absent from action-pins-inventory.json']),
        ('flow_style_ref', ['      - {uses: actions/checkout@v7}'], ['unparseable `uses:` reference']),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as work:
        base = Path(work) / '.github' / 'workflows'
        base.mkdir(parents=True)
        for name, lines, expected in cases:
            for stale in base.glob('*.yml'):
                stale.unlink()
            (base / ('legacy.yml' if name.startswith('floating') else 'case.yml')).write_text('jobs:\n  j:\n    steps:\n' + '\n'.join(lines) + '\n', encoding='utf-8')
            result = audit(base, actions, inventory)
            errors = ' | '.join(result['errors'])
            if expected:
                missing = [fragment for fragment in expected if fragment not in errors]
                if missing:
                    failures += 1
                    print('FAIL - {}: expected {} in {!r}'.format(name, missing, errors))
                else:
                    print('ok - {}'.format(name))
            elif result['errors']:
                failures += 1
                print('FAIL - {}: unexpected errors {!r}'.format(name, errors))
            else:
                print('ok - {}'.format(name))
    if failures:
        print('FAIL - {} action-pin fixture case(s) failed'.format(failures))
        return 1
    print('Action-pin fixture: {} cases passed (pins, floating ceilings, unreviewed actions, comment drift).'.format(len(cases)))
    print('Fixture evidence only; no action is endorsed by this check.')
    return 0


def main(argv):
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        print('Run this audit only in GitHub Actions; local execution is prohibited.', file=sys.stderr)
        return 2
    if '--self-test' in argv:
        return self_test()
    registry = json.loads(REGISTRY.read_text(encoding='utf-8'))
    inventory = json.loads(INVENTORY.read_text(encoding='utf-8'))['entries']
    result = audit(WORKFLOWS, registry['actions'], inventory)
    remote_notes = []
    if '--verify-remote' in argv:
        remote_errors, remote_notes = verify_remote(registry['actions'])
        result['errors'].extend(remote_errors)
    report(result, remote_notes)
    for error in result['errors']:
        print('::error title=Action pin::' + error.replace('\n', ' '))
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
