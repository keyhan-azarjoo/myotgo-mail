"""Mailboxes and aliases, kept in docker-mailserver's own files. The mail server notices
changes to these files by itself within a few seconds (its "changedetector")."""
import fcntl
import os
import re
import shutil
from contextlib import contextmanager
from pathlib import Path

from passlib.hash import sha512_crypt

from . import config

ACCOUNTS = config.MAILCONF_DIR / "postfix-accounts.cf"
VIRTUAL = config.MAILCONF_DIR / "postfix-virtual.cf"
QUOTAS = config.MAILCONF_DIR / "dovecot-quotas.cf"
LOCK = config.MAILCONF_DIR / ".mailapp.lock"

LOCAL_PART = r"[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?"
ADDRESS_RE = re.compile(rf"^{LOCAL_PART}@{re.escape(config.DOMAIN)}$")
ANY_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


class MailConfError(ValueError):
    pass


def normalize_local(address: str) -> str:
    address = (address or "").strip().lower()
    if not ADDRESS_RE.fullmatch(address) or ".." in address:
        raise MailConfError(f"Use an address ending in @{config.DOMAIN} (letters, digits, . _ + -).")
    return address


@contextmanager
def _locked():
    LOCK.touch(exist_ok=True)
    with open(LOCK) as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _read(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _write(path: Path, lines: list[str]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(line + "\n" for line in lines))
    os.chmod(tmp, 0o640)   # hashes: readable by root (the mail server) only
    os.replace(tmp, path)


def _hash(password: str) -> str:
    # SHA512-CRYPT like `setup email add`, but with 200,000 rounds instead of 5,000: the hash is
    # as slow to crack as it can be while a mail-app sign-in still takes well under a second.
    return "{SHA512-CRYPT}" + sha512_crypt.using(rounds=200_000).hash(password)


# ---------- mailboxes -----------------------------------------------------------------

def list_accounts() -> list[str]:
    return sorted(line.split("|", 1)[0].lower() for line in _read(ACCOUNTS))


def account_exists(address: str) -> bool:
    return address.lower() in list_accounts()


def add_account(address: str, password: str) -> None:
    address = normalize_local(address)
    with _locked():
        lines = _read(ACCOUNTS)
        if any(line.split("|", 1)[0].lower() == address for line in lines):
            raise MailConfError(f"{address} already exists.")
        if address in aliases():
            raise MailConfError(f"{address} is an alias. Remove the alias first.")
        _write(ACCOUNTS, lines + [f"{address}|{_hash(password)}"])


def set_password(address: str, password: str) -> None:
    address = normalize_local(address)
    with _locked():
        lines = _read(ACCOUNTS)
        out, found = [], False
        for line in lines:
            if line.split("|", 1)[0].lower() == address:
                out.append(f"{address}|{_hash(password)}")
                found = True
            else:
                out.append(line)
        if not found:
            raise MailConfError(f"{address} doesn't exist.")
        _write(ACCOUNTS, out)


def delete_account(address: str) -> None:
    """Remove the mailbox, every alias pointing only to it, and its stored mail."""
    address = normalize_local(address)
    with _locked():
        lines = _read(ACCOUNTS)
        kept = [line for line in lines if line.split("|", 1)[0].lower() != address]
        if len(kept) == len(lines):
            raise MailConfError(f"{address} doesn't exist.")
        _write(ACCOUNTS, kept)
        _write(QUOTAS, [line for line in _read(QUOTAS) if not line.lower().startswith(address + ":")])
        _write(VIRTUAL, _without_target(_read(VIRTUAL), address))
    local, domain = address.split("@")
    maildir = (config.MAILDATA_DIR / domain / local).resolve()
    if maildir.parent == (config.MAILDATA_DIR / domain).resolve() and maildir.is_dir():
        shutil.rmtree(maildir)


# ---------- aliases ------------------------------------------------------------------

def aliases() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in _read(VIRTUAL):
        parts = line.split()
        if len(parts) >= 2:
            out.setdefault(parts[0].lower(), []).extend(t.lower() for t in ",".join(parts[1:]).split(",") if t)
    return out


def add_alias(alias: str, target: str) -> None:
    alias = normalize_local(alias)
    target = (target or "").strip().lower()
    if not ANY_ADDRESS_RE.fullmatch(target):
        raise MailConfError("The destination isn't a valid email address.")
    if alias == target:
        raise MailConfError("An alias can't point to itself.")
    with _locked():
        if alias in list_accounts():
            raise MailConfError(f"{alias} is a mailbox, so it can't also be an alias.")
        current = aliases()
        if target in current.get(alias, []):
            raise MailConfError("That alias already exists.")
        _write(VIRTUAL, _read(VIRTUAL) + [f"{alias} {target}"])


def delete_alias(alias: str, target: str) -> None:
    alias, target = alias.strip().lower(), target.strip().lower()
    with _locked():
        lines = _read(VIRTUAL)
        out = []
        for line in lines:
            parts = line.split()
            if parts and parts[0].lower() == alias:
                targets = [t for t in ",".join(parts[1:]).lower().split(",") if t and t != target]
                if targets:
                    out.append(f"{alias} {','.join(targets)}")
            else:
                out.append(line)
        if out == lines:
            raise MailConfError("That alias doesn't exist.")
        _write(VIRTUAL, out)


def _without_target(lines: list[str], target: str) -> list[str]:
    out = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if parts[0].lower() == target:
            continue
        targets = [t for t in ",".join(parts[1:]).lower().split(",") if t and t != target]
        if targets:
            out.append(f"{parts[0]} {','.join(targets)}")
    return out


def aliases_of(address: str) -> list[str]:
    address = address.lower()
    return sorted(a for a, targets in aliases().items() if address in targets)
