#!/usr/bin/env bash
# Runs ON THE SERVER, once, via `./mail server-setup`. Prepares a fresh Ubuntu/Debian VPS:
# Docker, firewall, swap (small servers), host name, SSH key-only login, fail2ban for SSH.
# Safe to run again. Expects MAIL_HOST and SERVER_IP in the environment.
set -euo pipefail
: "${MAIL_HOST:?}" "${SERVER_IP:?}"
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get -qq update
apt-get -qq install -y ca-certificates curl ufw fail2ban rsync >/dev/null
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1
systemctl enable --now fail2ban >/dev/null 2>&1

echo "== host name: $MAIL_HOST"
hostnamectl set-hostname "$MAIL_HOST"
sed -i '/[[:space:]]'"${MAIL_HOST//./\\.}"'\([[:space:]]\|$\)/d' /etc/hosts
printf '127.0.1.1 %s %s\n%s %s\n' "$MAIL_HOST" "${MAIL_HOST%%.*}" "$SERVER_IP" "$MAIL_HOST" >> /etc/hosts

echo "== swap (only if the server has less than 2 GB RAM and no swap)"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( mem_mb < 2048 )) && ! swapon --show | grep -q .; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo vm.swappiness=10 > /etc/sysctl.d/90-swappiness.conf && sysctl -q vm.swappiness=10
fi

echo "== firewall: SSH + mail ports"
ufw allow 22/tcp >/dev/null
for p in 25 465 587 993; do ufw allow "$p/tcp" >/dev/null; done
ufw --force enable >/dev/null

echo "== SSH: key login only"
if [[ -s /root/.ssh/authorized_keys ]]; then
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
    > /etc/ssh/sshd_config.d/00-mailserver-hardening.conf
  sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)
else
  echo "   skipped: /root/.ssh/authorized_keys is empty, password login stays on"
fi

echo "== outgoing port 25"
if timeout 8 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null; then
  echo "   open: this server can send mail directly"
else
  echo "   BLOCKED by your hosting provider. Receiving works, but sending to other domains won't"
  echo "   until they unblock it (see README: 'Outgoing port 25')."
fi
echo "server ready"
