#!/bin/sh
set -eu
if ! command -v node >/dev/null 2>&1; then
    printf '%s\n' 'Install Node.js 20 or newer with npm, then run this script again.' >&2
    exit 1
fi
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec node "$script_dir/start.mjs" "$@"
