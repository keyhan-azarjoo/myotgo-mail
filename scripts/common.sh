# Shared by every script that runs on YOUR computer. Loads mail.conf.
# shellcheck shell=bash

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONF=${MAIL_CONF:-$ROOT/mail.conf}

if [[ ! -f $CONF ]]; then
  echo "mail.conf not found. Create it first:  cp mail.conf.example mail.conf  (then edit it)" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

expand() { echo "${1/#\~/$HOME}"; }
SSH_KEY=$(expand "${SSH_KEY:-~/.ssh/id_ed25519}")
SECRETS_DIR=$(expand "${SECRETS_DIR:-~/.mail-secrets}")
DNS_CREDENTIALS=$(expand "${DNS_CREDENTIALS:-$SECRETS_DIR/dns.env}")
REMOTE_DIR=${REMOTE_DIR:-/opt/mailserver}
CERT_METHOD=${CERT_METHOD:-http}
DKIM_SELECTOR=${DKIM_SELECTOR:-mail}
export SSH_KEY SECRETS_DIR DNS_CREDENTIALS REMOTE_DIR CERT_METHOD DKIM_SELECTOR

for v in DOMAIN MAIL_HOST SERVER_IP SSH_TARGET ACME_EMAIL; do
  if [[ -z ${!v:-} || ${!v} == *example.com* || ${!v} == *203.0.113.* ]]; then
    echo "mail.conf: please set $v (it still has the example value)" >&2
    exit 1
  fi
done

SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15)
remote() { ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "$@"; }
dms() { remote docker exec mailserver setup "$@"; }
