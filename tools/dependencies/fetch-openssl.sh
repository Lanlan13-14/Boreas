#!/usr/bin/env bash
# Fetch the pinned OpenSSL source and check it before anything builds it.
#
# The pin is a commit on the openssl-4.1 branch, not a release tag. OpenSSL
# 4.1.1 has not been published, and 4.1.0 is the newest release on that line,
# but 4.1.0 is affected by the eight CVEs in the 2026-11-10 and 2026-11-17
# advisories. Those fixes exist only as commits until 2026-12-01, so the build
# uses the earliest commit that contains every fix and its regression test.
#
# The tree reports version 4.1.1-dev. That is a development snapshot, not the
# 4.1.1 release, and this script refuses to describe it as one.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 DESTINATION" >&2
    exit 2
fi
destination=$1

: "${OPENSSL_COMMIT:?OPENSSL_COMMIT must be the full pinned commit}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 must be the GitHub archive digest}"
: "${OPENSSL_VERSION_TRIPLE:?OPENSSL_VERSION_TRIPLE must be MAJOR.MINOR.PATCH}"
: "${OPENSSL_PRERELEASE:?OPENSSL_PRERELEASE must be the VERSION.dat pre-release tag}"

archive=openssl.tar.gz
url="https://github.com/openssl/openssl/archive/${OPENSSL_COMMIT}.tar.gz"

curl --fail --location --retry 3 --max-time 180 "$url" -o "$archive"
echo "${OPENSSL_SHA256}  ${archive}" | sha256sum --check --strict

top=$(tar -tzf "$archive" | head -n 1 | cut -d/ -f1)
if [[ "$top" != "openssl-${OPENSSL_COMMIT}" ]]; then
    echo "archive root is '${top}', expected openssl-${OPENSSL_COMMIT}" >&2
    exit 1
fi

mkdir -p "$destination"
tar -xzf "$archive" --strip-components=1 -C "$destination"

# shellcheck disable=SC1091
source "${destination}/VERSION.dat"
if [[ "${MAJOR}.${MINOR}.${PATCH}" != "$OPENSSL_VERSION_TRIPLE" ]]; then
    echo "VERSION.dat is ${MAJOR}.${MINOR}.${PATCH}, expected ${OPENSSL_VERSION_TRIPLE}" >&2
    exit 1
fi
if [[ "${PRE_RELEASE_TAG}" != "$OPENSSL_PRERELEASE" ]]; then
    echo "VERSION.dat pre-release tag is '${PRE_RELEASE_TAG}', expected '${OPENSSL_PRERELEASE}'" >&2
    exit 1
fi

echo "Pinned OpenSSL ${OPENSSL_VERSION_TRIPLE}-${OPENSSL_PRERELEASE} at commit ${OPENSSL_COMMIT}"
