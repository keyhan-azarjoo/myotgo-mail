#!/usr/bin/env bash
# Runs on YOUR computer. Mailboxes and aliases (used by `./mail add|passwd|del|alias|list`).
# New passwords are printed once and saved to SECRETS_DIR/<address>.txt (never in git).
set -euo pipefail
source "$(dirname "$0")/common.sh"

newpass() {
  local p
  p=$(python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(24)))')
  mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR"
  (umask 077 && printf '%s\n' "$p" >"$SECRETS_DIR/$1.txt")
  echo "$p"
}

app_running() { remote "docker ps --format '{{.Names}}' | grep -qx mailapp"; }

# Create a mailbox or set its password. With the console running, the password travels on stdin
# (never on a command line, where other processes could see it) and the console stays in step.
set_password() {
  if app_running; then
    printf '%s\n' "$2" | remote "docker exec -i mailapp python -m mailapp.cli mailbox-password '$1'"
  elif [[ $3 == add ]]; then
    dms email add "$1" "$2"
  else
    dms email update "$1" "$2"
  fi
}

need_addr() {
  local re="^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?@${DOMAIN//./\\.}$"
  [[ ${1:-} =~ $re ]] || { echo "give a full address ending in @$DOMAIN (letters, digits, . _ + -)" >&2; exit 1; }
}

case "${1:-}" in
  add)
    need_addr "${2:-}"
    first=$(dms email list 2>/dev/null | grep -c '^\* ' || true)
    p=$(newpass "$2")
    set_password "$2" "$p" add
    echo "created $2"
    echo "password: $p   (also saved in $SECRETS_DIR/$2.txt)"
    if [[ $first == 0 && -n ${DEFAULT_ALIASES:-} ]]; then
      IFS=, read -ra names <<<"$DEFAULT_ALIASES"
      for n in "${names[@]}"; do dms alias add "$n@$DOMAIN" "$2" && echo "alias $n@$DOMAIN -> $2"; done
    fi
    ;;
  passwd)
    need_addr "${2:-}"
    p=$(newpass "$2")
    set_password "$2" "$p" update
    echo "new password for $2: $p   (also saved in $SECRETS_DIR/$2.txt)"
    ;;
  del)
    need_addr "${2:-}"
    read -r -p "Delete $2 and ALL its mail? Type the address again to confirm: " again
    [[ $again == "$2" ]] || { echo "cancelled"; exit 1; }
    dms email del -y "$2" && rm -f "$SECRETS_DIR/$2.txt" && echo "deleted $2"
    ;;
  alias)
    need_addr "${2:-}"; [[ ${3:-} =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "bad target" >&2; exit 1; }
    dms alias add "$2" "$3" && echo "alias $2 -> $3"
    ;;
  unalias)
    need_addr "${2:-}"; need_addr "${3:-}"
    dms alias del "$2" "$3" && echo "removed alias $2 -> $3"
    ;;
  list)
    echo "Mailboxes:"; dms email list 2>/dev/null | grep -E '^\*' | sed 's/^\* /  /'
    echo "Aliases:";   dms alias list 2>/dev/null | grep -E '^\*' | sed 's/^\* //; s/ / -> /; s/^/  /'
    ;;
  *)
    echo "usage: account.sh add|passwd|del <address> | alias|unalias <from> <to> | list" >&2
    exit 1
    ;;
esac
