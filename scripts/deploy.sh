#!/usr/bin/env bash
# Runs on YOUR computer (`./mail deploy`). Copies this folder to the server, writes the
# server's settings, gets the certificate the first time, installs the renewal and
# backup jobs, and (re)starts the mail server. Safe to run again after any change.
set -euo pipefail
source "$(dirname "$0")/common.sh"

echo "== copying files to $SSH_TARGET:$REMOTE_DIR"
remote "mkdir -p '$REMOTE_DIR'"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
  --exclude '/.git/' --exclude '/data/' --exclude '/secrets/' --exclude '/.env' \
  --exclude '/mail.conf' --exclude '__pycache__/' \
  "$ROOT/" "$SSH_TARGET:$REMOTE_DIR/"

# Settings the server-side scripts and compose.yaml read
printf 'MAIL_HOST=%s\nDOMAIN=%s\nSERVER_IP=%s\nACME_EMAIL=%s\nCERT_METHOD=%s\nDNS_PROVIDER=%s\nAPP_BUILD=%s\n' \
  "$MAIL_HOST" "$DOMAIN" "$SERVER_IP" "$ACME_EMAIL" "$CERT_METHOD" "${DNS_PROVIDER:-}" "${APP_BUILD:-0}" |
  remote "umask 077 && cat > '$REMOTE_DIR/.env'"

if [[ $CERT_METHOD == dns ]]; then
  [[ -f $DNS_CREDENTIALS ]] || { echo "CERT_METHOD=dns but $DNS_CREDENTIALS doesn't exist" >&2; exit 1; }
  remote "mkdir -p '$REMOTE_DIR/secrets' && chmod 700 '$REMOTE_DIR/secrets' && umask 077 && cat > '$REMOTE_DIR/secrets/dns.env'" < "$DNS_CREDENTIALS"
fi

echo "== configuring and starting"
remote "cd '$REMOTE_DIR' && bash scripts/apply.sh && ln -sf '$REMOTE_DIR/mailctl' /usr/local/bin/mailctl"
echo "deployed."
