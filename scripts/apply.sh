#!/usr/bin/env bash
# Runs ON THE SERVER, from the install folder. Applies the configuration in .env and (re)starts
# everything. Used by install.sh, `mailctl update` and `./mail deploy`. Safe to run again.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
: "${MAIL_HOST:?}" "${DOMAIN:?}" "${SERVER_IP:?}"

chmod +x scripts/*.sh mailctl 2>/dev/null || true
mkdir -p data/config data/app secrets
chmod 700 secrets

# the key that encrypts stored mailbox passwords: created once, kept (and backed up) with the data
if [[ ! -f secrets/app.env ]]; then
  (umask 077; echo "APP_SECRET_KEY=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > secrets/app.env)
fi

sed -e "s/SERVER_IP/$SERVER_IP/" -e "s#TRUSTED_IPS#${TRUSTED_IPS:-}#" config/fail2ban-jail.cf > data/config/fail2ban-jail.cf
cp config/postfix-main.cf data/config/postfix-main.cf

if command -v ufw >/dev/null; then
  for p in 25 443 465 587 993; do ufw allow "$p/tcp" >/dev/null; done
fi

[[ -f "data/certs/$MAIL_HOST.crt" ]] || scripts/cert.sh

here=$(pwd)
cat > /etc/cron.d/mailserver-cert <<CRON
# Renew the mail server certificate (cert.sh restarts the services only when it changed)
17 4 * * 1 root cd '$here' && scripts/cert.sh >> /var/log/mailserver-cert.log 2>&1
CRON
cat > /etc/cron.d/mailserver-backup <<CRON
# Nightly copy of the mail data, last 7 kept in /var/backups/mailserver
31 3 * * * root cd '$here' && scripts/backup.sh >> /var/log/mailserver-backup.log 2>&1
CRON

docker compose pull -q mailserver
# the console/API/MCP app: the published image, or built here if asked to (or if it can't be pulled)
if [[ ${APP_BUILD:-0} == 1 ]] || ! docker compose pull -q app 2>/dev/null; then
  docker compose build -q app
fi
docker compose up -d --remove-orphans
docker image prune -f >/dev/null

# don't report success unless both services really came up
for _ in $(seq 1 60); do
  app=$(docker inspect mailapp --format '{{.State.Health.Status}}' 2>/dev/null || echo missing)
  mail=$(docker inspect mailserver --format '{{.State.Health.Status}}' 2>/dev/null || echo missing)
  [[ $app == healthy && $mail == healthy ]] && { echo "mail server and console are up"; exit 0; }
  # a brand-new install has no mailbox yet, and the mail server waits for one before it starts
  if [[ $app == healthy && ! -s data/config/postfix-accounts.cf ]] &&
     [[ $(docker inspect mailserver --format '{{.State.Running}}' 2>/dev/null) == true ]]; then
    echo "console is up; the mail server starts once the first mailbox exists"; exit 0
  fi
  sleep 5
done
echo "ERROR: after 5 minutes: mailserver=$mail, mailapp=$app. Last lines of the console log:" >&2
docker logs mailapp --tail 30 >&2 2>&1 || true
exit 1
