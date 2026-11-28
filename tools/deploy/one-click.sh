#!/bin/sh
# Convenience entry point for a preverified local development bundle only.
# Security checks and mutations are delegated unchanged to install.sh.
set -eu

usage() {
  cat <<'EOF'
Usage: sh tools/deploy/one-click.sh --stage ABS_DIR --network-id HEX32
       --sha256 HEX64 --release ID --service none|systemd
       (--dry-run | --apply) [--accept-legacy-service]

The stage contains boreas, node.toml, material/, policy/, and pins/
(root.ed25519.der and root.mldsa65.der). Independently authenticate the
binary and deployment tools before running. --dry-run is read-only and does
not execute the candidate; --apply invokes install.sh and may execute it.
Service systemd is a root development template and requires explicit
--accept-legacy-service. This wrapper does not start or enable a service.
No downloading, certificate issuance, firewall or network setup is performed.
EOF
}
fail() { printf 'one-click: %s\n' "$*" >&2; exit 2; }
STAGE='' NET_ID='' DIGEST='' RELEASE='' SERVICE='' ACTION='' LEGACY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --stage|--network-id|--sha256|--release|--service)
      [ "$#" -ge 2 ] || fail "$1 requires a value"
      case "$1" in
        --stage) [ -z "$STAGE" ] || fail 'duplicate --stage'; STAGE=$2 ;;
        --network-id) [ -z "$NET_ID" ] || fail 'duplicate --network-id'; NET_ID=$2 ;;
        --sha256) [ -z "$DIGEST" ] || fail 'duplicate --sha256'; DIGEST=$2 ;;
        --release) [ -z "$RELEASE" ] || fail 'duplicate --release'; RELEASE=$2 ;;
        --service) [ -z "$SERVICE" ] || fail 'duplicate --service'; SERVICE=$2 ;;
      esac
      shift 2 ;;
    --dry-run|--apply)
      [ -z "$ACTION" ] || fail 'choose exactly one action'
      ACTION=$1; shift ;;
    --accept-legacy-service)
      [ "$LEGACY" -eq 0 ] || fail 'duplicate --accept-legacy-service'
      LEGACY=1; shift ;;
    *) fail "unknown option: $1" ;;
  esac
done
case "$STAGE" in /*) ;; *) fail '--stage must be an absolute path' ;; esac
while [ "${STAGE%/}" != "$STAGE" ]; do STAGE=${STAGE%/}; done
[ -n "$STAGE" ] || fail '--stage must not be /'
[ -n "$NET_ID" ] || fail '--network-id is required'
[ -n "$DIGEST" ] || fail '--sha256 is required'
[ -n "$RELEASE" ] || fail '--release is required'
case "$SERVICE" in
  none) [ "$LEGACY" -eq 0 ] || fail 'legacy acknowledgement only applies to systemd' ;;
  systemd) [ "$LEGACY" -eq 1 ] || fail 'systemd requires --accept-legacy-service' ;;
  *) fail 'choose --service none or systemd' ;;
esac
[ -n "$ACTION" ] || fail 'choose --dry-run or --apply'
SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
set -- --binary "$STAGE/boreas" --sha256 "$DIGEST" --release "$RELEASE" \
  --materials "$STAGE/material" --config "$STAGE/node.toml" \
  --policy-dir "$STAGE/policy" --network-id "$NET_ID" \
  --network-root-ed25519-der "$STAGE/pins/root.ed25519.der" \
  --network-root-mldsa65-der "$STAGE/pins/root.mldsa65.der" \
  --prefix /opt/boreas --service "$SERVICE"
[ "$LEGACY" -eq 0 ] || set -- "$@" --accept-legacy-service
[ "$ACTION" != --dry-run ] || set -- "$@" --dry-run
exec sh "$SELF_DIR/install.sh" "$@"
