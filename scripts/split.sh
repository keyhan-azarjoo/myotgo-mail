#!/usr/bin/env bash
# Runs ON THE SERVER. When the domain's other mailboxes live at another provider (SHARED_DOMAIN_HOST
# in .env, e.g. mx.zoho.eu), mail this server sends to an address of the domain with no mailbox or
# alias here goes on to that provider instead of being refused. Rebuilt from the mailboxes and
# aliases (mailctl calls it after changing them, and cron every 10 minutes for the console's).
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
: "${DOMAIN:?}"
out=data/config/postfix-transport.pcre
mkdir -p data/config
names=$( { cut -d'|' -f1 data/config/postfix-accounts.cf 2>/dev/null; cut -d' ' -f1 data/config/postfix-virtual.cf 2>/dev/null; } \
  | grep -i "@${DOMAIN}$" | sed "s/@.*//" | sed 's/[.+]/\\&/g' | sort -u | paste -sd'|' - || true)
tmp=$(mktemp)
{
  echo "# Made by scripts/split.sh: edit SHARED_DOMAIN_HOST in .env, not this file."
  if [[ -n ${SHARED_DOMAIN_HOST:-} ]]; then
    d=${DOMAIN//./\\.}
    if [[ -n $names ]]; then
      echo "/^(?!(${names})@${d}\$)[^@]+@${d}\$/i smtp:[${SHARED_DOMAIN_HOST}]:25"
    else
      echo "/^[^@]+@${d}\$/i smtp:[${SHARED_DOMAIN_HOST}]:25"
    fi
  fi
} > "$tmp"
if ! cmp -s "$tmp" "$out"; then
  mv "$tmp" "$out"; chmod 644 "$out"
  docker exec mailserver postfix reload >/dev/null 2>&1 || true
else
  rm -f "$tmp"
fi
