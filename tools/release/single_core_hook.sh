#!/bin/sh
# The legacy hook protocol invokes bash; keep the wrapper free of mutations.
exec python3 "$(dirname "$0")/single_core_hook.py" "$@"
