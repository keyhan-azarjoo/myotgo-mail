#!/usr/bin/env bash
# Runs ON THE SERVER, nightly from cron (or `./mail backup`). Saves a compressed copy of
# everything the mail server stores (mailboxes, accounts, DKIM key, certificate) in
# /var/backups/mailserver and keeps the last 7. This protects against deleted mail or a
# broken update, not against losing the whole server: copy the files elsewhere for that.
set -euo pipefail
cd "$(dirname "$0")/.."

DEST=${BACKUP_DIR:-/var/backups/mailserver}
KEEP=${BACKUP_KEEP:-7}
mkdir -p "$DEST" && chmod 700 "$DEST"

f="$DEST/mail-$(date +%Y%m%d-%H%M%S).tar.gz"
# Sockets are recreated on start; logs aren't worth keeping.
tar --numeric-owner --warning=no-file-ignored --exclude='data/mail-logs' -czf "$f.part" data secrets .env
mv "$f.part" "$f"
chmod 600 "$f"

ls -1t "$DEST"/mail-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup: $f ($(du -h "$f" | cut -f1))"
