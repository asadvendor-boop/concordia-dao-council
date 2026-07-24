#!/bin/sh
set -eu

fail() {
  printf '%s\n' "OCI_IMAGE_IDENTITY_INVALID" >&2
  exit 64
}

[ "$#" -eq 3 ] || fail

revision=$1
deployment=$2
source_url=$3

case "$revision" in
  *[!0-9a-f]*|'') fail ;;
esac
[ "${#revision}" -eq 40 ] || fail
[ "$deployment" = "$revision" ] || fail
[ "$source_url" = "https://github.com/asadvendor-boop/concordia-dao-council" ] || fail
