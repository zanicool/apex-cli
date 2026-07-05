#!/bin/bash
# Wrapper that ensures APEX_HOME is set correctly
export APEX_HOME="${APEX_HOME:-$(dirname "$(readlink -f "$0")")/..}"
exec "$APEX_HOME/build/apex-cli" "$@"
