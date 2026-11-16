#!/usr/bin/env bash
# Actions-only assertions for the pinned reduced build, NOT a CVE waiver.
# Real mTLS/ML-DSA tests and the independent dependency gate remain mandatory.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true ]]; then
    echo 'Run this verification only in GitHub Actions; local testing is prohibited.' >&2
    exit 2
fi

if [[ $# -ne 4 ]]; then
    echo "usage: $0 SOURCE_DIR PREFIX RUNTIME_REPORT BUILD_EVIDENCE" >&2
    exit 2
fi
source_dir=$1
prefix=$2
runtime_report=$3
build_evidence=$4
bin="${prefix}/bin/openssl"
: "${OPENSSL_VERSION:?OPENSSL_VERSION must name the expected release}"
test -x "$bin"
test -f "${source_dir}/configdata.pm"
mkdir -p "$(dirname "$runtime_report")" "$(dirname "$build_evidence")"
printf 'Pinned OpenSSL: %s\nRequired options: no-quic no-cms no-siv no-shared no-tests\nValidation: INCOMPLETE (not a CVE waiver)\n' "$OPENSSL_VERSION" > "$build_evidence"
# Append evidence before assertions so always-upload retains failure diagnostics.
record() { printf '\n=== %s ===\n%s\n' "$1" "$2" >> "$build_evidence"; }

# Do not inherit a different build's config/provider search path (e.g. GNU -> musl).
export OPENSSL_CONF="${prefix}/ssl/openssl.cnf"
unset OPENSSL_MODULES
test -s "$OPENSSL_CONF"
version_output="$("$bin" version -a)"
printf '%s\n' "$version_output" | tee "$runtime_report"
if ! grep -Eq "^OpenSSL ${OPENSSL_VERSION//./\\.} " <<<"$version_output"; then
    echo "OpenSSL runtime does not match pinned ${OPENSSL_VERSION}" >&2
    exit 1
fi

# --dump is diagnostic text, not a promise to print OPENSSL_NO_* macros.
configdata_output="$(cd "$source_dir" && perl configdata.pm --dump)"
record 'configdata.pm --dump (diagnostic only)' "$configdata_output"
# Inspect BOTH the generated build header and installed consumer header. Checking
# anchored #define lines avoids accepting an #ifndef, comment or command argument.
for header in "${source_dir}/include/openssl/configuration.h" "${prefix}/include/openssl/configuration.h"; do
    test -s "$header"
    record "$header" "$(<"$header")"
    for macro in OPENSSL_NO_QUIC OPENSSL_NO_CMS OPENSSL_NO_SIV OPENSSL_NO_TESTS OPENSSL_NO_EC_EXPLICIT_CURVES; do
        if ! grep -Eq "^[[:space:]]*#[[:space:]]*define[[:space:]]+${macro}([[:space:]]|$)" "$header"; then
            echo "${header} is missing required ${macro}" >&2
            exit 1
        fi
    done
done
# shared is deliberately excluded from public feature macros in 4.1.0 Configure.
# Read the structured disabled map rather than searching --dump formatting.
(cd "$source_dir" && perl -I. -Mconfigdata -e '
    for my $feature (qw(quic cms siv shared tests ec_explicit_curves)) {
        die "Required disabled feature missing: $feature\n" unless exists $configdata::disabled{$feature};
        print "$feature: $configdata::disabled{$feature}\n";
    }
') >> "$build_evidence"

disabled_output="$("$bin" list -disabled)"
record 'openssl list -disabled' "$disabled_output"
# 4.1.0 apps/list.c OPENSSL_PRINT_DISABLED prints section headings followed
# by "\t- %s\n"; Configure populates the arrays with upper-case names.
for feature in QUIC CMS SIV TESTS EC_EXPLICIT_CURVES; do
    if ! grep -Eq "^[[:space:]]+- ${feature}[[:space:]]*$" <<<"$disabled_output"; then
        echo "openssl list -disabled does not confirm ${feature}" >&2
        exit 1
    fi
done

commands_output="$("$bin" list -1 -commands)"
record 'openssl list -1 -commands' "$commands_output"
if grep -Fxq 'cms' <<<"$commands_output"; then
    echo 'CMS command remains registered despite no-cms' >&2
    exit 1
fi
client_options_output="$("$bin" list -options s_client)"
record 'openssl list -options s_client' "$client_options_output"
# OpenSSL 4.1.0 apps/s_client.c registers -quic unconditionally; only the
# OPT_QUIC implementation is guarded by OPENSSL_NO_QUIC. CLI option presence
# therefore cannot prove implementation presence. Inspect the linked static
# library definitions instead, alongside the header/configdata checks above.
ssl_archives=("${prefix}"/lib/libssl.a "${prefix}"/lib64/libssl.a)
ssl_archive=
for candidate in "${ssl_archives[@]}"; do
    if [[ -f "$candidate" ]]; then ssl_archive=$candidate; break; fi
done
[[ -n "$ssl_archive" ]] || { echo 'static libssl archive not found' >&2; exit 1; }
ssl_symbols="$(nm --defined-only "$ssl_archive")"
record 'libssl.a defined symbols (QUIC method implementations must be absent)' "$ssl_symbols"
if grep -Eq '[[:space:]][TtWw][[:space:]]+OSSL_QUIC_(client|server)_method$' <<<"$ssl_symbols"; then
    echo 'QUIC method implementation remains defined despite no-quic' >&2
    exit 1
fi
ciphers_output="$("$bin" list -cipher-algorithms)"
record 'openssl list -cipher-algorithms' "$ciphers_output"
if grep -Eiq 'AES-(128|192|256)-(GCM-)?SIV' <<<"$ciphers_output"; then
    echo 'AES-SIV/AES-GCM-SIV remains registered despite no-siv' >&2
    exit 1
fi
# A functioning provider must retain ordinary AES-GCM; an empty algorithm list
# must not turn the disabled-algorithm negative assertion into a false green.
if ! grep -Eiq 'AES-256-GCM' <<<"$ciphers_output"; then
    echo 'ordinary AES-256-GCM is unavailable' >&2
    exit 1
fi
groups_output="$("$bin" list -tls-groups)"
record 'openssl list -tls-groups' "$groups_output"
if ! grep -F 'X25519MLKEM768' <<<"$groups_output" >/dev/null; then
    echo 'native X25519MLKEM768 TLS group is unavailable' >&2
    exit 1
fi
sigalgs_output="$("$bin" list -tls-signature-algorithms)"
record 'openssl list -tls-signature-algorithms' "$sigalgs_output"
if ! grep -Fi 'mldsa65' <<<"$sigalgs_output" >/dev/null; then
    echo 'native mldsa65 TLS signature algorithm is unavailable' >&2
    exit 1
fi
linkage_output="$(readelf -d "$bin")"
record 'readelf -d openssl (libssl/libcrypto must be static)' "$linkage_output"
if grep -Eq 'Shared library: \[lib(ssl|crypto)\.so' <<<"$linkage_output"; then
    echo 'OpenSSL CLI unexpectedly links shared libssl/libcrypto' >&2
    exit 1
fi
printf '\nValidation: reduction/capability assertions PASSED; real mTLS and CVE review still required.\n' >> "$build_evidence"
printf '%s\n' "OpenSSL ${OPENSSL_VERSION} reduction and native pq768 capability assertions passed"
