#!/usr/bin/env bash
# Runs ON THE SERVER (weekly from cron, and by `./mail deploy`). Gets or renews the
# Let's Encrypt certificate for MAIL_HOST, copies it where the mail server reads it,
# and restarts the mail server only when the certificate changed.
#   CERT_METHOD=http  uses port 80 for a few seconds (nothing else may listen on 80)
#   CERT_METHOD=dns   uses the DNS provider API (secrets/dns.env holds its keys)
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

LEGO_DIR=data/lego
CERT_DIR=data/certs
mkdir -p "$LEGO_DIR" "$CERT_DIR"

args=(--accept-tos --email "$ACME_EMAIL" --path /data --domains "$MAIL_HOST" --no-random-sleep)
docker_args=(--rm -v "$PWD/$LEGO_DIR:/data")
case "${CERT_METHOD:-http}" in
  http)
    command -v ufw >/dev/null && ufw allow 80/tcp >/dev/null
    docker_args+=(-p 80:80)
    args+=(--http)
    ;;
  dns)
    [[ -n ${DNS_PROVIDER:-} && -f secrets/dns.env ]] || { echo "CERT_METHOD=dns needs DNS_PROVIDER and secrets/dns.env" >&2; exit 1; }
    docker_args+=(--env-file secrets/dns.env)
    # Check the provider's own name servers; public resolvers may cache "no record".
    args+=(--dns "$DNS_PROVIDER" --dns.propagation.disable-rns)
    ;;
  *) echo "unknown CERT_METHOD: $CERT_METHOD" >&2; exit 1 ;;
esac

status=0
docker run "${docker_args[@]}" goacme/lego:v5.5.2 run "${args[@]}" || status=$?
if [[ ${CERT_METHOD:-http} == http ]] && command -v ufw >/dev/null; then
  ufw delete allow 80/tcp >/dev/null || true
fi
[[ $status -eq 0 ]] || exit $status

crt=$(find "$LEGO_DIR" -name "$MAIL_HOST.crt" -not -name '*issuer*' | head -1)
key=$(find "$LEGO_DIR" -name "$MAIL_HOST.key" | head -1)
[[ -n "$crt" && -n "$key" ]] || { echo "certificate files not found under $LEGO_DIR" >&2; exit 1; }

if ! cmp -s "$crt" "$CERT_DIR/$MAIL_HOST.crt"; then
  install -m 644 "$crt" "$CERT_DIR/$MAIL_HOST.crt"
  install -m 600 "$key" "$CERT_DIR/$MAIL_HOST.key"
  echo "certificate updated"
  for c in mailserver mailapp; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then docker restart "$c" >/dev/null; fi
  done
else
  echo "certificate unchanged"
fi
