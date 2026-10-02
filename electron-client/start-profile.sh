#!/usr/bin/env sh
set -eu
profile="${1:-WB1}"
exec "$(dirname "$0")/node_modules/.bin/electron" "$(dirname "$0")" "--profile=$profile"
