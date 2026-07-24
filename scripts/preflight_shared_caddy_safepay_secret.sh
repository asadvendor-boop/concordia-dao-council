#!/bin/sh
set -eu

caddy_container="${1:-${CADDY_CONTAINER:-}}"
secret_path="${SAFEPAY_CADDY_SECRET_PATH:-/run/secrets/safepay_proxy_secret}"
app_secret_path="${SAFEPAY_APP_SECRET_PATH:-${SAFEPAY_PROXY_SECRET_FILE:-/opt/apps/concordia/secrets/safepay_proxy_secret}}"

if [ -z "$caddy_container" ]; then
    printf '%s\n' "usage: CADDY_CONTAINER=<name> $0 [container]" >&2
    exit 64
fi
if [ ! -r "$app_secret_path" ]; then
    printf '%s\n' "SafePay application secret file is unreadable" >&2
    exit 66
fi

# The shared Caddy process is intentionally outside Concordia Compose. Probe
# its runtime namespace directly without ever copying the value into argv,
# environment, a shell variable, or output. Equal byte counts before and after
# whitespace removal prove there is no header-breaking whitespace/newline
# drift; cmp proves the Caddy mount is byte-identical to the application source.
docker exec -i "$caddy_container" sh -eu -c '
    secret_path="$1"
    test -r "$secret_path"
    file_bytes="$(wc -c < "$secret_path" | tr -d " ")"
    test "$file_bytes" -ge 32
    compact_bytes="$(
        tr -d "[:space:]" < "$secret_path" | wc -c | tr -d " "
    )"
    test "$file_bytes" -eq "$compact_bytes"
    cmp -s "$secret_path" -
' sh "$secret_path" < "$app_secret_path"

printf '%s\n' "SafePay shared-Caddy secret preflight passed"
