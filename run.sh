#!/bin/sh
set -e

(
  cd "$(dirname "$0")"
  go build -o /tmp/dns-resolver app/*.go
)

exec /tmp/dns-resolver "$@"