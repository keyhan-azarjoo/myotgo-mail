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
printf 'MAIL_HOST=%s\nDOMAIN=%s\nSERVER_IP=%s\nACME_EMAIL=%s\nCERT_METHOD=%s\nDNS_PROVIDER=%s\n' \
  "$MAIL_HOST" "$DOMAIN" "$SERVER_IP" "$ACME_EMAIL" "$CERT_METHOD" "${DNS_PROVIDER:-}" |
  remote "umask 077 && cat > '$REMOTE_DIR/.env'"

if [[ $CERT_METHOD == dns ]]; then
  [[ -f $DNS_CREDENTIALS ]] || { echo "CERT_METHOD=dns but $DNS_CREDENTIALS doesn't exist" >&2; exit 1; }
  remote "mkdir -p '$REMOTE_DIR/secrets' && chmod 700 '$REMOTE_DIR/secrets' && umask 077 && cat > '$REMOTE_DIR/secrets/dns.env'" < "$DNS_CREDENTIALS"
fi

echo "== configuring and starting"
remote bash -s <<EOF
set -euo pipefail
cd '$REMOTE_DIR'
chmod +x scripts/*.sh
mkdir -p data/config
sed 's/SERVER_IP/$SERVER_IP/' config/fail2ban-jail.cf > data/config/fail2ban-jail.cf
cp config/postfix-main.cf data/config/postfix-main.cf
if command -v ufw >/dev/null; then
  for p in 25 465 587 993; do ufw allow \$p/tcp >/dev/null; done
fi
[ -f "data/certs/$MAIL_HOST.crt" ] || scripts/cert.sh
cat > /etc/cron.d/mailserver-cert <<CRON
# Renew the mail server certificate (cert.sh restarts mail only when it changed)
17 4 * * 1 root cd '$REMOTE_DIR' && scripts/cert.sh >> /var/log/mailserver-cert.log 2>&1
CRON
cat > /etc/cron.d/mailserver-backup <<CRON
# Nightly copy of the mail data, last 7 kept in /var/backups/mailserver
31 3 * * * root cd '$REMOTE_DIR' && scripts/backup.sh >> /var/log/mailserver-backup.log 2>&1
CRON
docker compose pull -q
docker compose up -d --remove-orphans
EOF
echo "deployed."
