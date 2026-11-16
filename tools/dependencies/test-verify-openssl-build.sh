#!/usr/bin/env bash
# Actions-only regression fixture for tools/dependencies/verify-openssl-build.sh.
#
# It never builds OpenSSL and never touches the network. It fabricates a
# throw-away OpenSSL source tree, install prefix and fake openssl/perl/nm/readelf
# tools, then drives the REAL verifier against them. A weakened assertion, a
# misparsed tool output or an unreachable check therefore turns this job red
# instead of leaving a silently green verifier behind.
#
# It relaxes no production assertion: every failure case asserts that the
# verifier stopped on the intended check rather than on an earlier one, so a
# wrong-first error cannot mask the target assertion.
#
# This is regression evidence about the verifier only. The OpenSSL CVE gate stays
# blocking and the Actions-only restriction is unchanged; nothing here is a
# waiver, and real reduced-build/mTLS evidence is still required.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true ]]; then
    echo 'Run this fixture only in GitHub Actions; local execution is prohibited.' >&2
    exit 2
fi

self_path=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")
tools_dir=$(dirname -- "$self_path")
repo_root=$(CDPATH='' cd -- "$tools_dir/../.." && pwd -P)
verifier=$tools_dir/verify-openssl-build.sh
review_json=$tools_dir/openssl-review.json

fail() { printf 'FAIL - %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

[[ -f $verifier ]] || fail "$verifier is missing"
[[ -f $review_json ]] || fail "$review_json is missing"

# Self-guard: this fixture must stay free of build and network steps.
if grep -Eq '^[[:space:]]*(curl|wget|make|cmake|git|configure|\./Configure)[[:space:]]' "$self_path"; then
    fail 'the fixture must not invoke a build or network command'
fi

# Exercise the reviewed pin, and notice drift between the review record and the
# workflow pins that supply OPENSSL_VERSION to the verifier.
expected_version=$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([0-9]+(\.[0-9]+)+)".*$/\1/p' "$review_json" | head -n 1)
[[ -n $expected_version ]] || fail 'could not read the pinned OpenSSL version from openssl-review.json'
mapfile -t pinned_workflows < <(sed -nE 's/^.*"workflow"[[:space:]]*:[[:space:]]*"([^"]+)".*$/\1/p' "$review_json" | sort -u)
(( ${#pinned_workflows[@]} > 0 )) || fail 'openssl-review.json records no workflow configurations'
for workflow in "${pinned_workflows[@]}"; do
    [[ -f $repo_root/$workflow ]] || fail "reviewed workflow $workflow is missing"
    grep -Fq "OPENSSL_VERSION: ${expected_version}" "$repo_root/$workflow" ||
        fail "$workflow does not pin OPENSSL_VERSION: ${expected_version}"
done
ok "pin ${expected_version} matches ${#pinned_workflows[@]} reviewed workflow(s)"

work=$(mktemp -d "${TMPDIR:-/tmp}/openssl-verifier-fixture.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
work=$(CDPATH='' cd -- "$work" && pwd -P)
fake_bin=$work/fakebin
mkdir -p "$fake_bin"

verifier_hash_before=$(sha256sum -- "$verifier")
review_hash_before=$(sha256sum -- "$review_json")

# Required public disabled-feature macros the verifier asserts on every
# configuration.h. Kept in sync deliberately: if the verifier grows a macro the
# happy path below fails loudly instead of silently under-covering it.
required_macros=(OPENSSL_NO_QUIC OPENSSL_NO_CMS OPENSSL_NO_SIV OPENSSL_NO_TESTS OPENSSL_NO_EC_EXPLICIT_CURVES)

# Every distinct verifier diagnostic, so a failure case can prove that no other
# assertion fired before its target. Each entry must be a substring of exactly
# one production message.
signatures=(
    'is missing required'
    'Required disabled feature missing'
    'does not confirm'
    'CMS command remains registered'
    'QUIC method implementation remains defined'
    'remains registered despite no-siv'
    'ordinary AES-256-GCM is unavailable'
    'X25519MLKEM768 TLS group is unavailable'
    'native mldsa65 TLS signature algorithm is unavailable'
    'does not match pinned'
    'static libssl archive not found'
    'unexpectedly links shared libssl/libcrypto'
)

write_fake_tools() {
    cat > "$fake_bin/openssl" <<'FAKE_OPENSSL'
#!/usr/bin/env bash
# Fixture-only fake `openssl`: serves canned output from FIXTURE_DATA_DIR and
# fails loudly on an invocation the fixture does not describe.
set -euo pipefail
data=${FIXTURE_DATA_DIR:?FIXTURE_DATA_DIR must point at fixture scenario data}

emit() {
    [[ -f $1 ]] || { printf 'fake openssl: missing fixture data %s\n' "$1" >&2; exit 64; }
    cat -- "$1"
}

if [[ ${1:-} == version ]]; then
    printf 'OpenSSL %s 1 Jan 2026\n' "$(cat -- "$data/version")"
    printf 'built on: fixture-fake\n'
    printf 'platform: fixture\n'
    exit 0
fi

[[ ${1:-} == list ]] || { printf 'fake openssl: unsupported invocation: %s\n' "$*" >&2; exit 64; }
shift

mode=
option_target=
while (($# > 0)); do
    case $1 in
        -disabled) mode=disabled ;;
        -cipher-algorithms) mode=ciphers ;;
        -tls-groups) mode=groups ;;
        -tls-signature-algorithms) mode=sigalgs ;;
        -commands) mode=commands ;;
        -options) mode=options; shift; option_target=${1:-} ;;
        -1) ;;
        *) ;;
    esac
    shift
done

case $mode in
    disabled)
        [[ -f $data/disabled ]] || { printf 'fake openssl: missing fixture data disabled\n' >&2; exit 64; }
        printf 'Disabled algorithms:\n'
        while IFS= read -r feature; do
            [[ -n $feature ]] || continue
            printf '\t- %s\n' "$feature"
        done < "$data/disabled"
        ;;
    options)
        [[ -n $option_target ]] || { printf 'fake openssl: list -options needs a target\n' >&2; exit 64; }
        emit "$data/options_$option_target"
        ;;
    ciphers|groups|sigalgs|commands)
        emit "$data/$mode"
        ;;
    *)
        printf 'fake openssl: unsupported list invocation: %s\n' "$*" >&2
        exit 64
        ;;
esac
FAKE_OPENSSL

    cat > "$fake_bin/perl" <<'FAKE_PERL'
#!/usr/bin/env bash
# Fixture-only fake `perl`, covering exactly the two invocations the verifier
# uses: `perl configdata.pm --dump` and `perl -I. -Mconfigdata -e <script>`.
set -euo pipefail
data=${FIXTURE_DATA_DIR:?FIXTURE_DATA_DIR must point at fixture scenario data}

want_dump=0
want_configdata=0
for arg in "$@"; do
    case $arg in
        --dump) want_dump=1 ;;
        -Mconfigdata) want_configdata=1 ;;
    esac
done

if ((want_dump)); then
    [[ -f $data/dump ]] || { printf 'fake perl: missing fixture data dump\n' >&2; exit 64; }
    cat -- "$data/dump"
    exit 0
fi

if ((want_configdata)); then
    [[ -f $data/configdata_disabled ]] || { printf 'fake perl: missing fixture data configdata_disabled\n' >&2; exit 64; }
    # Mirrors the inline script's contract: die unless every required feature is
    # present in the disabled map, otherwise report each feature.
    feature=
    for feature in quic cms siv shared tests ec_explicit_curves; do
        if ! grep -Fxq -- "$feature" "$data/configdata_disabled"; then
            printf 'Required disabled feature missing: %s\n' "$feature" >&2
            exit 1
        fi
    done
    for feature in quic cms siv shared tests ec_explicit_curves; do
        printf '%s: no\n' "$feature"
    done
    exit 0
fi

printf 'fake perl: unsupported invocation: %s\n' "$*" >&2
exit 64
FAKE_PERL

    cat > "$fake_bin/nm" <<'FAKE_NM'
#!/usr/bin/env bash
# Fixture-only fake `nm`: prints the scenario's canned symbol table verbatim,
# including how a symbol is recorded (T/W define, U references only).
set -euo pipefail
data=${FIXTURE_DATA_DIR:?FIXTURE_DATA_DIR must point at fixture scenario data}

archive=
arg=
for arg in "$@"; do
    case $arg in
        -*) ;;
        *) archive=$arg ;;
    esac
done
[[ -n $archive ]] || { printf 'fake nm: an archive argument is required\n' >&2; exit 64; }
[[ -f $archive ]] || { printf 'fake nm: %s not found\n' "$archive" >&2; exit 1; }
[[ -f $data/nm_symbols ]] || { printf 'fake nm: missing fixture data nm_symbols\n' >&2; exit 64; }
cat -- "$data/nm_symbols"
FAKE_NM

    cat > "$fake_bin/readelf" <<'FAKE_READELF'
#!/usr/bin/env bash
# Fixture-only fake `readelf -d`: prints the scenario's canned dynamic section.
set -euo pipefail
data=${FIXTURE_DATA_DIR:?FIXTURE_DATA_DIR must point at fixture scenario data}

object=
arg=
for arg in "$@"; do
    case $arg in
        -*) ;;
        *) object=$arg ;;
    esac
done
[[ -n $object ]] || { printf 'fake readelf: an object argument is required\n' >&2; exit 64; }
[[ -f $object ]] || { printf 'fake readelf: %s not found\n' "$object" >&2; exit 1; }
[[ -f $data/readelf ]] || { printf 'fake readelf: missing fixture data readelf\n' >&2; exit 64; }
cat -- "$data/readelf"
FAKE_READELF

    chmod 0755 "$fake_bin/openssl" "$fake_bin/perl" "$fake_bin/nm" "$fake_bin/readelf"
}

write_fake_tools

# The fabricated tools must win PATH resolution, otherwise the fixture would
# silently consult host tooling (and a real OpenSSL prefix could never exist).
for tool in openssl perl nm readelf; do
    resolved=$(PATH="$fake_bin:$PATH" bash -c 'command -v "$1"' fake-check "$tool") ||
        fail "$tool is not resolvable"
    [[ $resolved == "$fake_bin/$tool" ]] || fail "$tool resolves to $resolved instead of the fixture fake"
done
ok 'fabricated openssl/perl/nm/readelf shadow the host tools'

# --- production guards that must stay in force ------------------------------

usage_dir=$work/usage-guard
mkdir -p "$usage_dir"
usage_status=0
PATH="$fake_bin:$PATH" FIXTURE_DATA_DIR="$usage_dir" OPENSSL_VERSION="$expected_version" \
    bash "$verifier" "$usage_dir/source" "$usage_dir/prefix" "$usage_dir/runtime.txt" \
    > "$usage_dir/stdout.txt" 2> "$usage_dir/stderr.txt" || usage_status=$?
[[ $usage_status -eq 2 ]] || fail "the verifier must reject a 3-argument call with exit 2 (got $usage_status)"
grep -Fq 'usage:' "$usage_dir/stderr.txt" || fail 'the verifier usage error was not reported'
[[ ! -e $usage_dir/runtime.txt ]] || fail 'the verifier wrote evidence before validating its arguments'
ok 'argument validation still fails closed before touching evidence'

actions_status=0
env -u GITHUB_ACTIONS PATH="$fake_bin:$PATH" FIXTURE_DATA_DIR="$usage_dir" OPENSSL_VERSION="$expected_version" \
    bash "$verifier" "$usage_dir/source" "$usage_dir/prefix" "$usage_dir/runtime.txt" "$usage_dir/build.txt" \
    > "$usage_dir/stdout-actions.txt" 2> "$usage_dir/stderr-actions.txt" || actions_status=$?
[[ $actions_status -eq 2 ]] || fail "the verifier must refuse to run without GITHUB_ACTIONS (got $actions_status)"
grep -Fq 'only in GitHub Actions' "$usage_dir/stderr-actions.txt" || fail 'the Actions-only refusal message is missing'

actions_false_status=0
GITHUB_ACTIONS=false PATH="$fake_bin:$PATH" FIXTURE_DATA_DIR="$usage_dir" OPENSSL_VERSION="$expected_version" \
    bash "$verifier" "$usage_dir/source" "$usage_dir/prefix" "$usage_dir/runtime.txt" "$usage_dir/build.txt" \
    > "$usage_dir/stdout-actions-false.txt" 2> "$usage_dir/stderr-actions-false.txt" || actions_false_status=$?
[[ $actions_false_status -eq 2 ]] || fail "the verifier must refuse GITHUB_ACTIONS=false (got $actions_false_status)"
ok 'Actions-only guard still refuses non-Actions execution'

# --- fabricated tree -------------------------------------------------------

root=
src=
prefix=
data=
run_stdout=
run_stderr=
run_build=
run_runtime=
status=0

print_headers() {
    local mode=$1 omit_generated=$2 omit_installed=$3
    local header macro omit
    for header in "$src/include/openssl/configuration.h" "$prefix/include/openssl/configuration.h"; do
        omit=$omit_generated
        if [[ $header == "$prefix/include/openssl/configuration.h" ]]; then
            omit=$omit_installed
        fi
        {
            printf '/* fixture configuration.h: %s */\n' "$mode"
            printf '#ifndef OPENSSL_CONFIGURATION_H\n'
            printf '#define OPENSSL_CONFIGURATION_H\n'
            for macro in "${required_macros[@]}"; do
                if [[ $macro == "$omit" ]]; then
                    continue
                fi
                printf '# define %s\n' "$macro"
            done
            if [[ $mode == decoy ]]; then
                # The required macro appears, but only in forms an anchored
                # #define check must reject.
                printf '/* # define OPENSSL_NO_SIV */\n'
                printf '#ifndef OPENSSL_NO_SIV\n'
                printf '# define OPENSSL_NO_SIV_LEGACY 1\n'
                printf '#endif\n'
            fi
            printf '#endif\n'
        } > "$header"
    done
}

seed_defaults() {
    root=$work/$1
    src=$root/source
    prefix=$root/prefix
    data=$root/data
    run_stdout=$root/stdout.txt
    run_stderr=$root/stderr.txt
    run_runtime=$root/reports/runtime.txt
    run_build=$root/reports/build-evidence.txt
    rm -rf "$root"
    mkdir -p "$data" "$src/include/openssl" "$prefix/include/openssl" "$prefix/bin" \
        "$prefix/lib" "$prefix/ssl" "$root/reports"
    printf 'openssl_conf = openssl_init\n' > "$prefix/ssl/openssl.cnf"
    # The verifier resolves its CLI as "$prefix/bin/openssl" and requires it to
    # be executable, so every scenario installs the fabricated CLI there.
    cp -- "$fake_bin/openssl" "$prefix/bin/openssl"
    chmod 0755 "$prefix/bin/openssl"
    printf '# fixture stub: the fixture fake perl replaces the real configdata.pm\n' > "$src/configdata.pm"
    printf '!<arch>\n' > "$prefix/lib/libssl.a"
    printf 'configdata.pm --dump fixture diagnostic output\n' > "$data/dump"
    printf '%s\n' "$expected_version" > "$data/version"
    printf 'quic\ncms\nsiv\nshared\ntests\nec_explicit_curves\n' > "$data/configdata_disabled"
    printf 'QUIC\nCMS\nSIV\nTESTS\nEC_EXPLICIT_CURVES\n' > "$data/disabled"
    printf 'asn1parse\nciphers\ns_client\nversion\n' > "$data/commands"
    printf 'AES-128-CBC\nAES-256-GCM\nid-aes256-GCM\n' > "$data/ciphers"
    printf 'X25519MLKEM768\nX25519\n' > "$data/groups"
    printf 'mldsa65\nrsa_pss_rsae_sha256\n' > "$data/sigalgs"
    printf '%s\n' 'Valid options are:' 'quic' 'connect' 'tls1_3' 'groups' > "$data/options_s_client"
    # A defined *_method_name plus an undefined *_method reference: neither is a
    # QUIC method implementation, so the happy path must keep passing.
    printf '0000000000000000 T SSL_new\n' > "$data/nm_symbols"
    printf '0000000000000000 T OSSL_QUIC_client_method_name\n' >> "$data/nm_symbols"
    printf '                 U OSSL_QUIC_client_method\n' >> "$data/nm_symbols"
    printf ' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n' > "$data/readelf"
    print_headers normal '' ''
}

apply_variant() {
    case $1 in
        happy) ;;
        missing_quic_macro) print_headers normal OPENSSL_NO_QUIC OPENSSL_NO_QUIC ;;
        missing_siv_macro) print_headers normal OPENSSL_NO_SIV OPENSSL_NO_SIV ;;
        missing_macro_prefix_only) print_headers normal '' OPENSSL_NO_TESTS ;;
        macro_not_anchored) print_headers decoy OPENSSL_NO_SIV OPENSSL_NO_SIV ;;
        configdata_missing_siv)
            printf 'quic\ncms\nshared\ntests\nec_explicit_curves\n' > "$data/configdata_disabled" ;;
        configdata_missing_shared)
            printf 'quic\ncms\nsiv\ntests\nec_explicit_curves\n' > "$data/configdata_disabled" ;;
        cms_command) printf 'asn1parse\ncms\ns_client\nversion\n' > "$data/commands" ;;
        disabled_listing_missing_siv) printf 'QUIC\nCMS\nTESTS\nEC_EXPLICIT_CURVES\n' > "$data/disabled" ;;
        quic_method_undefined_only)
            printf '                 U OSSL_QUIC_client_method\n' > "$data/nm_symbols"
            printf '0000000000000000 T OSSL_QUIC_client_method_name\n' >> "$data/nm_symbols" ;;
        quic_method_defined)
            printf '0000000000000000 T OSSL_QUIC_client_method\n' > "$data/nm_symbols" ;;
        quic_method_weak_defined)
            printf '0000000000000000 W OSSL_QUIC_server_method\n' > "$data/nm_symbols" ;;
        siv_algorithm) printf 'AES-128-SIV\nAES-256-GCM-SIV\nAES-256-GCM\n' > "$data/ciphers" ;;
        missing_aes_gcm) printf 'AES-128-CBC\nCHACHA20-POLY1305\n' > "$data/ciphers" ;;
        wrong_version) printf '4.0.4\n' > "$data/version" ;;
        shared_libssl)
            printf ' 0x0000000000000001 (NEEDED)             Shared library: [libssl.so.3]\n' > "$data/readelf"
            printf ' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n' >> "$data/readelf" ;;
        shared_libcrypto)
            printf ' 0x0000000000000001 (NEEDED)             Shared library: [libcrypto.so.3]\n' > "$data/readelf" ;;
        missing_tls_group) printf 'X25519\nP-256\n' > "$data/groups" ;;
        missing_mldsa65) printf 'rsa_pss_rsae_sha256\n' > "$data/sigalgs" ;;
        no_static_archive) rm -f "$prefix/lib/libssl.a" ;;
        missing_cli) rm -f "$prefix/bin/openssl" ;;
        missing_configdata) rm -f "$src/configdata.pm" ;;
        missing_openssl_conf) rm -f "$prefix/ssl/openssl.cnf" ;;
        *) fail "unknown scenario: $1" ;;
    esac
}

run_scenario() {
    status=0
    PATH="$fake_bin:$PATH" FIXTURE_DATA_DIR="$data" OPENSSL_VERSION="$expected_version" \
        bash "$verifier" "$src" "$prefix" "$run_runtime" "$run_build" \
        > "$run_stdout" 2> "$run_stderr" || status=$?
}

show_output() {
    sed 's/^/  | /' "$run_stderr" >&2 || true
    sed 's/^/  | /' "$run_stdout" >&2 || true
}

assert_pass() {
    local name=$1
    if [[ $status -ne 0 ]]; then
        show_output
        fail "scenario $name must pass, but the verifier exited $status"
    fi
    grep -Fq 'Validation: reduction/capability assertions PASSED' "$run_build" ||
        fail "scenario $name: the verifier did not record its passed validation"
    grep -Fq 'Validation: INCOMPLETE (not a CVE waiver)' "$run_build" ||
        fail "scenario $name: the verifier dropped the not-a-waiver line from its evidence"
    grep -Fq "OpenSSL ${expected_version} reduction and native pq768 capability assertions passed" "$run_stdout" ||
        fail "scenario $name: the verifier success summary is missing"
    grep -Fq "OpenSSL ${expected_version}" "$run_runtime" ||
        fail "scenario $name: the runtime report does not record the pinned runtime"
    # The covered nuance: the 4.1.0 CLI still advertises a bare quic s_client
    # option (the premise an old `^quic` CLI regex misread as implementation
    # presence), while the linked static library must not define a QUIC method
    # implementation.
    grep -Eq '^quic[[:space:]]*$' "$run_build" ||
        fail "scenario $name: the CLI was never fed a bare quic s_client option"
    grep -Fq 'fixture-fake' "$run_runtime" ||
        fail "scenario $name: the fabricated prefix/bin/openssl was not the tool under test"
    grep -Fq 'libssl.a defined symbols' "$run_build" ||
        fail "scenario $name: the static-archive symbol stage did not run"
    grep -Fq 'readelf -d openssl' "$run_build" ||
        fail "scenario $name: the static-linkage stage did not run"
    if grep -Eq '[[:space:]][TtWw][[:space:]]+OSSL_QUIC_(client|server)_method$' "$run_build"; then
        fail "scenario $name: a defined QUIC method symbol was recorded but the verifier passed"
    fi
    grep -Fq 'AES-256-GCM' "$run_build" ||
        fail "scenario $name: no ordinary AES-GCM algorithm was recorded"
    grep -Fq 'X25519MLKEM768' "$run_build" ||
        fail "scenario $name: no native pq768 TLS group was recorded"
    grep -Fq 'mldsa65' "$run_build" ||
        fail "scenario $name: no native ML-DSA TLS signature algorithm was recorded"
    if [[ $name == quic_method_undefined_only ]]; then
        grep -Eq '^[[:space:]]*U[[:space:]]+OSSL_QUIC_client_method$' "$run_build" ||
            fail "scenario $name: the undefined OSSL_QUIC_client_method reference was not fed to nm"
    fi
    ok "$name: verifier passed on fabricated evidence"
}

expected_message() {
    case $1 in
        missing_quic_macro) printf 'is missing required OPENSSL_NO_QUIC' ;;
        missing_siv_macro | macro_not_anchored) printf 'is missing required OPENSSL_NO_SIV' ;;
        missing_macro_prefix_only) printf 'is missing required OPENSSL_NO_TESTS' ;;
        configdata_missing_siv) printf 'Required disabled feature missing: siv' ;;
        configdata_missing_shared) printf 'Required disabled feature missing: shared' ;;
        cms_command) printf 'CMS command remains registered' ;;
        disabled_listing_missing_siv) printf 'does not confirm SIV' ;;
        quic_method_defined | quic_method_weak_defined) printf 'QUIC method implementation remains defined' ;;
        siv_algorithm) printf 'AES-SIV/AES-GCM-SIV remains registered despite no-siv' ;;
        missing_aes_gcm) printf 'ordinary AES-256-GCM is unavailable' ;;
        wrong_version) printf 'OpenSSL runtime does not match pinned' ;;
        shared_libssl | shared_libcrypto) printf 'unexpectedly links shared libssl/libcrypto' ;;
        missing_tls_group) printf 'native X25519MLKEM768 TLS group is unavailable' ;;
        missing_mldsa65) printf 'native mldsa65 TLS signature algorithm is unavailable' ;;
        no_static_archive) printf 'static libssl archive not found' ;;
        *) printf '' ;;
    esac
}

assert_fail() {
    local name=$1 expected=$2 signature
    if [[ $status -eq 0 ]]; then
        show_output
        fail "scenario $name must fail, but the verifier passed"
    fi
    if [[ $status -eq 2 ]]; then
        show_output
        fail "scenario $name exited 2 (usage/Actions guard); that is not the intended assertion"
    fi
    if [[ -n $expected ]]; then
        if ! grep -Fq -- "$expected" "$run_stderr"; then
            show_output
            fail "scenario $name did not report its intended assertion: $expected"
        fi
    else
        if [[ -s $run_stderr || -s $run_stdout ]]; then
            show_output
            fail "scenario $name must fail before any assertion, but it produced output"
        fi
    fi
    for signature in "${signatures[@]}"; do
        if [[ $signature == *"$expected"* || $expected == *"$signature"* ]]; then
            continue
        fi
        if grep -Fq -- "$signature" "$run_stderr"; then
            show_output
            fail "scenario $name fired an earlier assertion ($signature) instead of $expected"
        fi
    done
    ok "$name: verifier failed on ${expected:-a pre-assertion test}"
}

# --- scenarios -------------------------------------------------------------

passing_scenarios=(happy quic_method_undefined_only)

failure_scenarios=(
    missing_quic_macro
    missing_siv_macro
    missing_macro_prefix_only
    macro_not_anchored
    configdata_missing_siv
    configdata_missing_shared
    cms_command
    disabled_listing_missing_siv
    quic_method_defined
    quic_method_weak_defined
    siv_algorithm
    missing_aes_gcm
    wrong_version
    shared_libssl
    shared_libcrypto
    missing_tls_group
    missing_mldsa65
    no_static_archive
    missing_cli
    missing_configdata
    missing_openssl_conf
)

silent_scenarios=(missing_cli missing_configdata missing_openssl_conf)

for name in "${passing_scenarios[@]}"; do
    seed_defaults "$name"
    apply_variant "$name"
    run_scenario "$name"
    assert_pass "$name"
done

for name in "${failure_scenarios[@]}"; do
    seed_defaults "$name"
    apply_variant "$name"
    message=$(expected_message "$name")
    if [[ -z $message && " ${silent_scenarios[*]} " != *" $name "* ]]; then
        fail "scenario $name declares no expected diagnostic"
    fi
    run_scenario "$name"
    assert_fail "$name" "$message"
done

# The fixture drives the verifier read-only. Only the authorized production
# inputs are hash-pinned here: workflow log files and unrelated concurrent
# writers elsewhere in the repository are deliberately out of scope.
verifier_hash_after=$(sha256sum -- "$verifier")
review_hash_after=$(sha256sum -- "$review_json")
[[ $verifier_hash_before == "$verifier_hash_after" ]] || fail 'the fixture modified verify-openssl-build.sh'
[[ $review_hash_before == "$review_hash_after" ]] || fail 'the fixture modified openssl-review.json'
ok 'verify-openssl-build.sh and openssl-review.json are unchanged'

printf '\nFixture summary: %s scenarios (%s expected-pass, %s expected-fail) against %s.\n' \
    "$(( ${#passing_scenarios[@]} + ${#failure_scenarios[@]} ))" \
    "${#passing_scenarios[@]}" "${#failure_scenarios[@]}" "$(basename -- "$verifier")"
printf 'Verifier regression evidence only; the reduced-build CVE gate stays blocking.\n'
