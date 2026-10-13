#!/usr/bin/env bash
# One-line installer for a fresh Ubuntu/Debian server. Run as root ON THE SERVER:
#
#   curl -fsSL https://raw.githubusercontent.com/keyhan-azarjoo/myotgo-mail/main/install.sh | sudo bash
#
# It asks a few questions (or reads them from the environment), installs Docker, the firewall, the
# mail server and the web console/API/MCP app, gets the certificate, creates your first mailboxes
# and admin login, and prints the DNS records to add. Safe to run again: it keeps existing data.
#
# Non-interactive:  DOMAIN=example.com ADMIN_EMAIL=you@example.com ACME_EMAIL=you@gmail.com \
#                   curl -fsSL .../install.sh | sudo -E bash -s -- --yes
set -euo pipefail

REPO=${MAILSERVER_REPO:-https://github.com/keyhan-azarjoo/myotgo-mail.git}
DIR=${MAILSERVER_DIR:-/opt/mailserver}
SECRETS_DIR=/root/.mail-secrets
YES=0
for a in "$@"; do [[ $a == --yes || $a == -y ]] && YES=1; done

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

ask() {   # ask VAR "question" "default"
  local var=$1 q=$2 def=${3:-} ans
  if [[ -n ${!var:-} ]]; then return; fi
  if [[ $YES == 1 || ! -t 0 && ! -e /dev/tty ]]; then
    [[ -n $def ]] || die "$var is required (set it in the environment)"
    printf -v "$var" '%s' "$def"; return
  fi
  read -r -p "  $q${def:+ [$def]}: " ans </dev/tty
  printf -v "$var" '%s' "${ans:-$def}"
}

valid_domain() { [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; }
valid_email()  { [[ $1 =~ ^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]]; }

# ---------- checks ------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root: curl -fsSL ... | sudo bash"
. /etc/os-release 2>/dev/null || true
[[ ${ID:-} == ubuntu || ${ID:-} == debian || ${ID_LIKE:-} == *debian* ]] || die "this installer supports Ubuntu and Debian"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
(( mem_mb >= 700 )) || die "at least 1 GB of RAM is needed (found ${mem_mb} MB)"

bold "Self-hosted mail: installer"
info "Answers can be changed later in $DIR/.env (then run: mailctl update)."

# ---------- questions ---------------------------------------------------------------------------
existing=0
if [[ -f $DIR/.env ]]; then
  existing=1
  set -a; source "$DIR/.env"; set +a
  info "Existing install found in $DIR: keeping its settings and data."
fi
ask DOMAIN "Your domain (addresses will be name@domain)" ""
DOMAIN=$(tr 'A-Z' 'a-z' <<<"$DOMAIN"); valid_domain "$DOMAIN" || die "'$DOMAIN' isn't a valid domain"
ask MAIL_HOST "Name of this mail server" "mx.$DOMAIN"
MAIL_HOST=$(tr 'A-Z' 'a-z' <<<"$MAIL_HOST"); [[ $MAIL_HOST == *."$DOMAIN" ]] || die "MAIL_HOST must end in .$DOMAIN"
ask ADMIN_EMAIL "Your own mailbox (it's also your admin login)" "admin@$DOMAIN"
valid_email "$ADMIN_EMAIL" || die "'$ADMIN_EMAIL' isn't an email address"
ask ACME_EMAIL "An email OUTSIDE $DOMAIN for certificate and problem notices (e.g. a Gmail)" ""
valid_email "$ACME_EMAIL" || die "'$ACME_EMAIL' isn't an email address"
# if this server has a problem, a warning sent to an address on this same server would never arrive
[[ $ACME_EMAIL != *@"$DOMAIN" ]] || die "use an address outside $DOMAIN for ACME_EMAIL (for example your Gmail)"
detected_ip=$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
ask SERVER_IP "This server's public IPv4 address" "$detected_ip"
[[ $SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$SERVER_IP' isn't an IPv4 address"
ask CERT_METHOD "Certificate: http (port 80, simplest) or dns" "http"
[[ $CERT_METHOD =~ ^(http|dns|selfsigned)$ ]] || die "CERT_METHOD must be http or dns"
if [[ $CERT_METHOD == dns ]]; then
  ask DNS_PROVIDER "DNS provider (lego code, e.g. cloudflare, godaddy)" ""
  [[ -f $DIR/secrets/dns.env || -n ${DNS_ENV_FILE:-} ]] || die "for CERT_METHOD=dns, put your provider's API keys in a file and set DNS_ENV_FILE=/path/to/it"
fi

# ---------- system ------------------------------------------------------------------------------
bold "1/6  Preparing the server"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y ca-certificates curl git ufw fail2ban openssl python3 python3-venv dnsutils age rsync >/dev/null
if ! command -v docker >/dev/null; then
  info "installing Docker"
  curl -fsSL https://get.docker.com | sh >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1
systemctl enable --now fail2ban >/dev/null 2>&1
hostnamectl set-hostname "$MAIL_HOST" 2>/dev/null || true
sed -i "/[[:space:]]${MAIL_HOST//./\\.}\([[:space:]]\|$\)/d" /etc/hosts
printf '%s %s\n' "$SERVER_IP" "$MAIL_HOST" >> /etc/hosts
if (( mem_mb < 2048 )) && ! swapon --show | grep -q .; then
  info "adding 2 GB of swap (small server)"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
ufw allow 22/tcp >/dev/null
for p in 25 443 465 587 993; do ufw allow "$p/tcp" >/dev/null; done
ufw --force enable >/dev/null
info "firewall: SSH, mail (25, 465, 587, 993) and HTTPS (443) open"

# ---------- files -------------------------------------------------------------------------------
bold "2/6  Downloading"
if [[ -n ${MAILSERVER_SRC:-} ]]; then
  mkdir -p "$DIR" && cp -a "$MAILSERVER_SRC"/. "$DIR"/   # local copy (for testing the installer)
elif [[ -d $DIR/.git ]]; then
  git -C "$DIR" pull --ff-only -q
else
  [[ ! -e $DIR || -z $(find "$DIR" -mindepth 1 -maxdepth 1 ! -name data ! -name secrets ! -name .env -print -quit) ]] ||
    die "$DIR exists and isn't a git checkout"
  tmp=$(mktemp -d); git clone -q --depth 1 "$REPO" "$tmp"; cp -a "$tmp"/. "$DIR"/; rm -rf "$tmp"
fi
cd "$DIR"
mkdir -p secrets && chmod 700 secrets
[[ -n ${DNS_ENV_FILE:-} ]] && install -m 600 "$DNS_ENV_FILE" secrets/dns.env
ca_line=""
[[ $CERT_METHOD == selfsigned ]] && ca_line="MAIL_CA_FILE=/certs/ca.crt"
(umask 077; cat > .env <<EOF
MAIL_HOST=$MAIL_HOST
DOMAIN=$DOMAIN
SERVER_IP=$SERVER_IP
ACME_EMAIL=$ACME_EMAIL
ADMIN_EMAIL=$ADMIN_EMAIL
CERT_METHOD=$CERT_METHOD
DNS_PROVIDER=${DNS_PROVIDER:-}
APP_IMAGE=${APP_IMAGE:-ghcr.io/keyhan-azarjoo/myotgo-mail-app:latest}
APP_BUILD=${APP_BUILD:-0}
$ca_line
# Off-site, encrypted backups (recommended). Make a key pair on YOUR computer with: age-keygen -o backup-key.txt
# and paste only its public key (age1...) here. Keep backup-key.txt safe and off this server.
BACKUP_AGE_RECIPIENT=${BACKUP_AGE_RECIPIENT:-}
BACKUP_RSYNC_TARGET=${BACKUP_RSYNC_TARGET:-}
BACKUP_RCLONE_REMOTE=${BACKUP_RCLONE_REMOTE:-}
EOF
)
ln -sf "$DIR/mailctl" /usr/local/bin/mailctl
info "installed in $DIR; command: mailctl"

# ---------- DNS before the certificate -----------------------------------------------------------
bold "3/6  Checking that $MAIL_HOST points to this server"
if [[ $CERT_METHOD == http ]]; then
  info "The certificate check uses port 80 for a few seconds. This server's firewall is handled here, but if"
  info "your hosting provider has its own firewall in its control panel, it must allow inbound TCP 80 and 443"
  info "(and 25, 465, 587, 993 for mail)."
  for i in $(seq 1 60); do
    resolved=$(dig +short A "$MAIL_HOST" @1.1.1.1 | tail -1)
    [[ $resolved == "$SERVER_IP" ]] && { info "$MAIL_HOST -> $SERVER_IP: ok"; break; }
    if (( i == 1 )); then
      info "Create this DNS record at your domain provider now, then wait here:"
      info "    A    $MAIL_HOST    $SERVER_IP"
      info "(found: ${resolved:-nothing}; checking every 10 seconds for up to 10 minutes)"
    fi
    (( i == 60 )) && die "$MAIL_HOST still doesn't point to $SERVER_IP. Add the A record and run the installer again."
    sleep 10
  done
else
  info "skipped (certificate method: $CERT_METHOD)"
fi

# ---------- start ------------------------------------------------------------------------------
bold "4/6  Starting the mail server and the console"
scripts/apply.sh
info "waiting for the services"
for i in $(seq 1 90); do
  docker exec mailserver supervisorctl status postfix 2>/dev/null | grep -q RUNNING &&
    docker exec mailapp python -c "import urllib.request,ssl;urllib.request.urlopen('https://127.0.0.1:8443/healthz',context=ssl._create_unverified_context(),timeout=3)" 2>/dev/null && break
  sleep 2
done

# ---------- first mailboxes and admin -------------------------------------------------------------
bold "5/6  Creating your mailboxes and admin login"
newpass() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(24)))'; }
mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR"
app() { docker exec -i mailapp python -m mailapp.cli "$@"; }
admin_pw=""
if [[ $existing == 0 ]] || ! docker exec mailserver setup email list 2>/dev/null | grep -q '^\*'; then
  if [[ $ADMIN_EMAIL == *@"$DOMAIN" ]]; then
    admin_pw=$(newpass)
    printf '%s\n' "$admin_pw" | app mailbox-password "$ADMIN_EMAIL" >/dev/null
    (umask 077; printf '%s\n' "$admin_pw" > "$SECRETS_DIR/$ADMIN_EMAIL.txt")
    for n in postmaster abuse; do docker exec mailserver setup alias add "$n@$DOMAIN" "$ADMIN_EMAIL" 2>/dev/null || true; done
    info "mailbox $ADMIN_EMAIL (postmaster@ and abuse@ forward to it)"
  fi
  p=$(newpass); printf '%s\n' "$p" | app mailbox-password "no-reply@$DOMAIN" >/dev/null
  (umask 077; printf '%s\n' "$p" > "$SECRETS_DIR/no-reply@$DOMAIN.txt")
  info "mailbox no-reply@$DOMAIN (sends sign-in codes)"
  docker exec mailserver setup config dkim keytype rsa keysize 2048 selector mail domain "$DOMAIN" >/dev/null 2>&1 || true
  out=$(app create-admin "$ADMIN_EMAIL" 2>&1 || true)
  temp=$(sed -n 's/^temporary password: //p' <<<"$out")
  if [[ -n $temp && -n $admin_pw ]]; then
    # one password for the login and the mailbox
    printf '%s\n' "$temp" | app mailbox-password "$ADMIN_EMAIL" >/dev/null
    (umask 077; printf '%s\n' "$temp" > "$SECRETS_DIR/$ADMIN_EMAIL.txt")
    admin_pw=$temp
  elif [[ -n $temp ]]; then
    admin_pw=$temp
  fi
  info "console admin $ADMIN_EMAIL"
else
  info "mailboxes already exist: nothing created"
fi

# ---------- DNS records and checks --------------------------------------------------------------
bold "6/6  DNS records to add at your domain provider"
mailctl dns records | tee "$DIR/DNS-RECORDS.txt" | sed 's/^/  /'
info "(saved in $DIR/DNS-RECORDS.txt; check them any time with: mailctl dns check)"

out25="open"
timeout 8 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null || out25="BLOCKED"

bold "Done"
cat <<EOF
  Web console:   https://$MAIL_HOST
  Admin login:   $ADMIN_EMAIL
EOF
[[ -n $admin_pw ]] && printf '  Password:      %s   (temporary: you choose your own at first sign-in;\n                 it is also the password of the mailbox in Outlook)\n' "$admin_pw"
cat <<EOF
  Mail apps:     IMAP $MAIL_HOST:993 (SSL), SMTP $MAIL_HOST:465 (SSL), user = full address
  Manage:        mailctl help      (add mailboxes, aliases, status, update, tests)
  Passwords:     $SECRETS_DIR/

Next steps
  1. Add the DNS records above. Leave MX for last: it moves your mail here.
  2. Set reverse DNS (PTR) for $SERVER_IP to $MAIL_HOST in your hosting provider's panel.
  3. Check:  mailctl dns check     then test:  mailctl test $ADMIN_EMAIL
EOF
if [[ $out25 == BLOCKED ]]; then
  cat <<EOF

  Outgoing port 25 is BLOCKED by your hosting provider: receiving works, sending to other domains
  waits in the queue. Once the DNS records exist, ask them to unblock it ("please unblock outbound
  SMTP port 25 for $SERVER_IP; it runs a mail server for $DOMAIN with host name $MAIL_HOST,
  reverse DNS, SPF and DKIM are set up").
EOF
fi
