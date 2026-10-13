#!/usr/bin/env bash
# Runs ON THE SERVER, nightly from cron (or `mailctl backup`). Saves everything the mail server stores
# (mailboxes, accounts, DKIM key, certificate, console database and its key) in /var/backups/mailserver,
# keeps the last 7, and optionally copies each backup off the server.
#
# Settings in .env (all optional):
#   BACKUP_AGE_RECIPIENT   an age public key (age1...): backups are encrypted to it. The private key stays
#                          with you, NOT on the server, so a stolen server or backup copy can't be read.
#   BACKUP_RSYNC_TARGET    user@host:/path  - copy each backup there over SSH (root's SSH key)
#   BACKUP_RCLONE_REMOTE   remote:path      - copy each backup with rclone (S3, B2, Google Drive, ...)
#   BACKUP_KEEP            how many local backups to keep (default 7)
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; source .env; set +a; }

DEST=${BACKUP_DIR:-/var/backups/mailserver}
KEEP=${BACKUP_KEEP:-7}
mkdir -p "$DEST" && chmod 700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# a consistent copy of the console database (it is in use, so not a plain file copy)
if docker ps --format '{{.Names}}' | grep -qx mailapp; then
  docker exec mailapp python -c "import sqlite3;s=sqlite3.connect('/data/app.db');d=sqlite3.connect('/data/backup.db');s.backup(d);d.close()"
fi

# exit code 1 from GNU tar means "a file changed while being read" (the spam filter's live state):
# that copy is still fine, and the next backup has the newer version. Anything else is a real error.
status=0
tar --numeric-owner --warning=no-file-ignored --warning=no-file-changed -czf "$work/mail-$stamp.tar.gz" \
  --exclude='data/mail-logs' --exclude='data/app/app.db' --exclude='data/app/app.db-wal' --exclude='data/app/app.db-shm' \
  data secrets .env || status=$?
(( status == 0 || status == 1 )) || { echo "backup failed (tar exit $status)" >&2; exit "$status"; }
rm -f data/app/backup.db

if [[ -n ${BACKUP_AGE_RECIPIENT:-} ]]; then
  command -v age >/dev/null || { echo "BACKUP_AGE_RECIPIENT is set but 'age' isn't installed (apt install age)" >&2; exit 1; }
  age -r "$BACKUP_AGE_RECIPIENT" -o "$work/mail-$stamp.tar.gz.age" "$work/mail-$stamp.tar.gz"
  rm -f "$work/mail-$stamp.tar.gz"
fi
file=$(ls "$work"/mail-"$stamp".tar.gz*)
install -m 600 "$file" "$DEST/"
final="$DEST/$(basename "$file")"

# keep the newest $KEEP locally
find "$DEST" -maxdepth 1 -name 'mail-*.tar.gz*' -printf '%T@ %p\n' | sort -rn | tail -n +$((KEEP + 1)) |
  cut -d' ' -f2- | xargs -r rm -f

if [[ -n ${BACKUP_RSYNC_TARGET:-} ]]; then
  rsync -a -e "ssh -o BatchMode=yes" "$final" "$BACKUP_RSYNC_TARGET/" && echo "copied to $BACKUP_RSYNC_TARGET"
fi
if [[ -n ${BACKUP_RCLONE_REMOTE:-} ]]; then
  rclone copy "$final" "$BACKUP_RCLONE_REMOTE" && echo "copied to $BACKUP_RCLONE_REMOTE"
fi
echo "backup: $final ($(du -h "$final" | cut -f1))"
