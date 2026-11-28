#!/usr/bin/env bash
# Static/argument regression test: no Boreas binary, privileges or network needed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
python3 - <<'PY'
import re
import subprocess
from pathlib import Path

smoke = Path('netns_daemon_smoke.sh').read_text()
cutover = Path('netns_pool_cutover.sh').read_text()
replica = Path('netns_dns_replica.sh').read_text()

def one(pattern, text):
    matches = re.findall(pattern, text, re.MULTILINE)
    assert len(matches) == 1, f'expected one match for {pattern!r}, got {len(matches)}'
    return matches[0]

def check_args(rows, mode, label):
    assert rows.count('--transport') == 1, (label, rows)
    assert rows[rows.index('--transport') + 1] == mode, (label, rows)
    assert rows[:2] in (['daemon', 'serve'], ['daemon', 'connect']), (label, rows)

# Execute the exact shell command arguments from each main-daemon launch using
# a recording run_node, not a text-only search for a nearby --transport token.
for mode in ('wss', 'direct'):
    for role in ('CORE', 'EDGE'):
        command = one(r'(run_node "\$' + role + r'_NS" "\$BIN" daemon (?:serve|connect) \\\n(?:.*\\\n)*?)  > "\$WORK/(?:core|edge)\.out"[^\n]*&', smoke)
        setup = '''TRANSPORT=$1 CORE_NS=c EDGE_NS=e BIN=b WORK=/tmp CORE_MAT=c EDGE_MAT=e
CORE_STATE=c EDGE_STATE=e STATE_OWNER_UID=0 TUN_MTU=1360
CORE_LIFETIME_SECONDS=1 EDGE_LIFETIME_SECONDS=1
CORE_POLICY_ARGS=() EDGE_POLICY_ARGS=() CORE_DNS_ARGS=() EDGE_DNS_ARGS=()
TUN_GSO_ARGS=() ACTIVE_LANE_ARGS=()
run_node() { shift 2; printf '%s\\n' "$@"; }
'''
        rows = subprocess.run(['bash', '-euc', setup + command, 'test', mode],
                              check=True, text=True, stdout=subprocess.PIPE).stdout.splitlines()
        check_args(rows, mode, 'smoke ' + role)

# Re-evaluate the exact arrays shared by offline checks and live resume. The
# target common array flows into both roles; legacy arrays are used for the
# admission setup and old-policy rejection.
legacy_core = one(r'  (legacy_core=\(daemon serve [\s\S]*?\))\n  legacy_edge=', cutover)
legacy_edge = one(r'  (legacy_edge=\(daemon connect [\s\S]*?\))\n  run_node', cutover)
target = one(r'    (args=\(--transport [\s\S]*?\))\n    if \[\[ "\$role"', cutover)
core = one(r'      (core_args=\(daemon serve [^\n]*\))', cutover)
edge = one(r'      (edge_args=\(daemon connect [^\n]*\))', cutover)
for mode in ('wss', 'direct'):
    setup = '''TRANSPORT=$1 WORK=/tmp CORE_MAT=c EDGE_MAT=e CORE_STATE=c EDGE_STATE=e STATE_OWNER_UID=0
legacy_core_policy=() legacy_edge_policy=() role=core state=/tmp
'''
    for name, array in [('legacy_core', legacy_core), ('legacy_edge', legacy_edge),
                        ('core_args', target + '\n' + core), ('edge_args', target + '\n' + edge)]:
        rows = subprocess.run(['bash', '-euc', setup + array + '\nprintf "%s\\n" "${' + name + '[@]}"',
                               'test', mode], check=True, text=True,
                              stdout=subprocess.PIPE).stdout.splitlines()
        check_args(rows, mode, 'cutover ' + name)

# DNS replica negative TLS tests require WSS even when CLI defaults change.
for role in ('serve', 'connect'):
    command = one(r'(run_node [^\n]* daemon ' + role + r' [^\n]*\\\n(?:.*\\\n)*?)    >?[^\n]*&', replica) if role == 'serve' else one(r'(run_node [^\n]* daemon connect [^\n]*\\\n(?:.*\\\n)*?)    --tun-name[^\n]*&', replica)
    assert '--transport wss' in command, role
assert '"$DNS_REPLICAS" != 0 && "$TRANSPORT" != wss' in smoke
assert 'rm -- "$CORE_MAT/outer.pem"' not in smoke
assert 'test -s "$CORE_MAT/outer.pem"' in smoke
assert 'test -s "$CORE_MAT/outer.key"' in smoke
assert 'test -s "$EDGE_MAT/outer-ca.pem"' in smoke
print('netns transport argument regression: PASS (wss/direct, both roles, cutover, DNS replicas)')
PY
