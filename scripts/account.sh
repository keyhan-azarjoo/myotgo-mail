#!/usr/bin/env bash
# Runs on YOUR computer. Mailboxes and aliases (used by `./mail add|passwd|del|alias|list`).
# New passwords are printed once and saved to SECRETS_DIR/<address>.txt (never in git).
set -euo pipefail
source "$(dirname "$0")/common.sh"

newpass() {
  local p
  p=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)
  mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR"
  (umask 077 && printf '%s\n' "$p" >"$SECRETS_DIR/$1.txt")
  echo "$p"
}

need_addr() {
  [[ ${1:-} == *@"$DOMAIN" ]] || { echo "give a full address ending in @$DOMAIN" >&2; exit 1; }
}

case "${1:-}" in
  add)
    need_addr "${2:-}"
    first=$(dms email list 2>/dev/null | grep -c '^\* ' || true)
    p=$(newpass "$2")
    dms email add "$2" "$p"
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
    dms email update "$2" "$p"
    echo "new password for $2: $p   (also saved in $SECRETS_DIR/$2.txt)"
    ;;
  del)
    need_addr "${2:-}"
    read -r -p "Delete $2 and ALL its mail? Type the address again to confirm: " again
    [[ $again == "$2" ]] || { echo "cancelled"; exit 1; }
    dms email del -y "$2" && rm -f "$SECRETS_DIR/$2.txt" && echo "deleted $2"
    ;;
  alias)
    need_addr "${2:-}"; need_addr "${3:-}"
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
