#!/usr/bin/env bash
# Runs ON THE SERVER (weekly from cron, and by `./mail deploy`). Gets or renews the
# Let's Encrypt certificate for MAIL_HOST, copies it where the mail server reads it,
# and restarts the mail server only when the certificate changed.
#   CERT_METHOD=http        uses port 80 for a few seconds (nothing else may listen on 80)
#   CERT_METHOD=dns         uses the DNS provider API (secrets/dns.env holds its keys)
#   CERT_METHOD=selfsigned  FOR TESTING ONLY: a private test CA (data/certs/ca.crt), no internet needed
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

LEGO_DIR=data/lego
CERT_DIR=data/certs
mkdir -p "$LEGO_DIR" "$CERT_DIR"

if [[ ${CERT_METHOD:-http} == selfsigned ]]; then
  if [[ ! -f $CERT_DIR/$MAIL_HOST.crt ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=Test CA for $MAIL_HOST" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" \
      -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$MAIL_HOST" -keyout "$CERT_DIR/$MAIL_HOST.key" \
      -out "$CERT_DIR/$MAIL_HOST.csr" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/$MAIL_HOST.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
      -CAcreateserial -days 825 -out "$CERT_DIR/$MAIL_HOST.crt" \
      -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash' "$MAIL_HOST") 2>/dev/null
    chmod 600 "$CERT_DIR/$MAIL_HOST.key" "$CERT_DIR/ca.key"
    echo "test certificate created (signed by data/certs/ca.crt)"
  fi
  exit 0
fi

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
if [[ $status -ne 0 && ${CERT_METHOD:-http} == http ]]; then
  echo "The certificate couldn't be issued. Check that $MAIL_HOST points to this server and that inbound" >&2
  echo "TCP port 80 is allowed, including any firewall in your hosting provider's control panel." >&2
fi
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
