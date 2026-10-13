#!/usr/bin/env bash
# Runs ON THE SERVER (`mailctl restore`). Puts a backup made by backup.sh back in place.
#
#   scripts/restore.sh <backup file> [--key <age identity file>] [--yes]
#   scripts/restore.sh --check <backup file> [--key <file>]    only verify the backup, change nothing
#
# A restore stops the services, moves the current data aside (data.before-restore-<time>), unpacks the
# backup and starts again. Encrypted backups (.age) need the private key, which you keep off the server.
set -euo pipefail
cd "$(dirname "$0")/.."

check=0 yes=0 key="" file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) check=1 ;;
    --yes|-y) yes=1 ;;
    --key) key=$2; shift ;;
    *) file=$1 ;;
  esac
  shift
done
[[ -f $file ]] || { echo "usage: restore.sh [--check] <backup file> [--key <age identity>] [--yes]" >&2; exit 1; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
tarball=$file
if [[ $file == *.age ]]; then
  [[ -f $key ]] || { echo "this backup is encrypted: give the private key with --key <file>" >&2; exit 1; }
  age -d -i "$key" -o "$work/backup.tar.gz" "$file"
  tarball=$work/backup.tar.gz
fi

# verify before touching anything
mkdir "$work/x"
tar --numeric-owner -xzf "$tarball" -C "$work/x"
for need in .env secrets/app.env data/config/postfix-accounts.cf; do
  [[ -f $work/x/$need ]] || { echo "the backup is missing $need" >&2; exit 1; }
done
mailboxes=$(grep -c '|' "$work/x/data/config/postfix-accounts.cf" || true)
db="$work/x/data/app/backup.db"
if [[ -f $db ]]; then
  python3 - "$db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "console database is damaged"
print(f"console database ok: {c.execute('SELECT COUNT(*) FROM users').fetchone()[0]} logins")
PY
fi
echo "backup ok: $mailboxes mailboxes, $(du -sh "$work/x/data/mail-data" 2>/dev/null | cut -f1) of mail"
[[ $check == 1 ]] && exit 0

if [[ $yes != 1 ]]; then
  read -r -p "Replace the current mail data with this backup? Type 'restore' to continue: " ans </dev/tty
  [[ $ans == restore ]] || { echo "cancelled"; exit 1; }
fi
docker compose down
aside="data.before-restore-$(date +%Y%m%d-%H%M%S)"
mv data "$aside"
cp -a "$work/x/data" data
[[ -f data/app/backup.db ]] && mv data/app/backup.db data/app/app.db
cp -a "$work/x/secrets/." secrets/
docker compose up -d
echo "restored. The previous data is in $(pwd)/$aside (delete it once you're happy)."
