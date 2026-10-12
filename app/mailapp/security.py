"""Passwords, tokens, encryption, two-step verification and rate limits."""
import base64
import hashlib
import hmac
import json
import os
import re
import random
import secrets
import threading
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, db

_ph = PasswordHasher()  # argon2id with the library's current recommended parameters
# each hash needs ~64 MB of memory: never run more than a few at once
_hash_slots = threading.BoundedSemaphore(3)
# A real hash of a random password, verified on unknown users so timing doesn't reveal them.
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))

MIN_PASSWORD = 12


# ---------- passwords ----------------------------------------------------------------

def hash_password(password: str) -> str:
    with _hash_slots:
        return _ph.hash(password)


def verify_password(stored: str | None, password: str) -> bool:
    if len(password or "") > 256:
        return False
    try:
        with _hash_slots:
            return _ph.verify(stored or _DUMMY_HASH, password) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problem(password: str, email: str = "") -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if len(password) > 256:
        return "That password is too long."
    if email and email.split("@")[0].lower() in password.lower():
        return "Don't use your user name in your password."
    if len(set(password)) < 6:
        return "That password is too simple."
    return None


def generate_password(length: int = 20) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------- tokens -------------------------------------------------------------------

def new_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------- encryption at rest -------------------------------------------------------

def encrypt(plain: str, context: str) -> str:
    """AES-256-GCM. `context` (e.g. "mailbox:a@b.com") is bound in as associated data, so a
    value copied into another row or field can't be decrypted there."""
    nonce = os.urandom(12)
    ct = AESGCM(config.SECRET_KEY).encrypt(nonce, plain.encode(), b"mailapp:" + context.encode())
    return "v2:" + base64.b64encode(nonce + ct).decode()


def decrypt(blob: str, context: str) -> str:
    if blob.startswith("v2:"):
        raw = base64.b64decode(blob[3:])
        return AESGCM(config.SECRET_KEY).decrypt(raw[:12], raw[12:], b"mailapp:" + context.encode()).decode()
    raw = base64.b64decode(blob)   # values stored before contexts were added
    return AESGCM(config.SECRET_KEY).decrypt(raw[:12], raw[12:], b"mailapp").decode()


# ---------- two-step verification (TOTP) ---------------------------------------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=config.APP_NAME)


def check_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the time step of a valid code (allowing one step of clock drift), or None.
    Codes from a step that was already used are refused, so a code works only once."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    now = time.time()
    for drift in (0, -1, 1):
        at = now + drift * 30
        if hmac.compare_digest(totp.at(at), code):
            step = int(at // 30)
            return step if step > last_step else None
    return None


def new_recovery_codes() -> tuple[list[str], str]:
    codes = ["-".join(secrets.token_hex(3) for _ in range(2)) for _ in range(10)]
    return codes, json.dumps([token_hash(c) for c in codes])


def use_recovery_code(stored_json: str, code: str) -> str | None:
    """If the code is valid, return the stored list without it; otherwise None."""
    hashes = json.loads(stored_json or "[]")
    h = token_hash((code or "").strip().lower())
    if h in hashes:
        hashes.remove(h)
        return json.dumps(hashes)
    return None


# ---------- rate limits ---------------------------------------------------------------

def ip_key(ip: str | None) -> str:
    """The unit rate limits count: one IPv4 address, or one IPv6 /64 (what a single customer gets)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return ip or "?"
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)

def recent_hits(key: str, window: int) -> int:
    return db.one("SELECT COUNT(*) AS n FROM rate WHERE key = ? AND ts > ?", (key, time.time() - window))["n"]


def record_hit(key: str) -> None:
    now = time.time()
    with db.tx() as conn:
        if random.random() < 0.01:
            conn.execute("DELETE FROM rate WHERE ts < ?", (now - 86400,))
        conn.execute("INSERT INTO rate(key, ts) VALUES(?, ?)", (key, now))


def rate_limited(key: str, limit: int, window: int) -> bool:
    """Record one hit for key; True if there were already `limit` hits in `window` seconds."""
    now = time.time()
    with db.tx() as conn:
        if random.random() < 0.01:
            conn.execute("DELETE FROM rate WHERE ts < ?", (now - 86400,))
        count = conn.execute("SELECT COUNT(*) FROM rate WHERE key = ? AND ts > ?", (key, now - window)).fetchone()[0]
        if count >= limit:
            return True
        conn.execute("INSERT INTO rate(key, ts) VALUES(?, ?)", (key, now))
    return False
