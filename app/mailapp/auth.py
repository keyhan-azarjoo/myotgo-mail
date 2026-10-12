"""Signing in (password, then two-step code), browser sessions and personal API tokens."""
import json
import re
import secrets
import time

from . import config, db, security, service

LOCK_AFTER = 5            # failed passwords in a row
LOCK_SECONDS = 15 * 60
PAT_PREFIX = "mm_pat_"


class AuthError(Exception):
    pass


# ---------- password and two-step -----------------------------------------------------------

def check_password(email: str, password: str, ip: str | None) -> dict:
    """Return the user row (as dict) if the password is right. Same error for every failure."""
    # only failed attempts count, so an office sharing one address isn't blocked by normal use
    if security.recent_hits(f"login-fail:{ip}", 900) >= 30:
        raise AuthError("Too many failed sign-ins from your network. Wait a few minutes and try again.")
    email = (email or "").strip().lower()
    row = db.one("SELECT * FROM users WHERE email = ?", (email,))
    now = time.time()
    if row and row["locked_until"] > now:
        security.verify_password(None, password or "")
        raise AuthError("This account is locked for a few minutes after too many failed attempts.")
    ok = security.verify_password(row["password_hash"] if row else None, password or "")
    if not ok or row["disabled"]:
        if row:
            fails = row["failed_logins"] + 1
            locked = now + LOCK_SECONDS if fails >= LOCK_AFTER else 0
            db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                       (0 if locked else fails, locked, row["id"]))
        security.record_hit(f"login-fail:{ip}")
        db.audit(email, "login.failed", email, None, ip)
        raise AuthError("Wrong email or password.")
    db.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (row["id"],))
    return dict(row)


def check_second_step(user_id: int, code: str, ip: str | None) -> bool:
    """The second step: a 6-digit code from the authenticator app or from the email we sent
    (each works once), or one of the recovery codes."""
    if security.rate_limited(f"2step:{user_id}", 20, 600):
        raise AuthError("Too many codes tried. Wait a few minutes.")
    row = db.one("SELECT totp_secret, totp_enabled, totp_last_step, recovery_codes, email, two_step_method "
                 "FROM users WHERE id = ?", (user_id,))
    if not row or not row["totp_enabled"]:
        return False
    if row["two_step_method"] == "email":
        if _check_email_code(user_id, code):
            return True
    else:
        step = security.check_totp(security.decrypt(row["totp_secret"]), code, row["totp_last_step"])
        if step is not None:
            db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user_id))
            return True
    remaining = security.use_recovery_code(row["recovery_codes"], code)
    if remaining is not None:
        db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (remaining, user_id))
        db.audit(row["email"], "login.recovery_code_used", row["email"], None, ip)
        return True
    db.audit(row["email"], "login.bad_code", row["email"], None, ip)
    return False


# ---------- email codes ----------------------------------------------------------------------

EMAIL_CODE_SECONDS = 600


def code_sender() -> str | None:
    """The mailbox sign-in codes are sent from: the admin's choice, else no-reply@DOMAIN."""
    chosen = db.setting("code_sender", "") or f"no-reply@{config.DOMAIN}"
    row = db.one("SELECT password FROM mailboxes WHERE address = ? AND password IS NOT NULL", (chosen,))
    return chosen if row else None


def send_email_code(user_id: int, ip: str | None = None) -> str:
    """Email a fresh 6-digit code to the user's own address. Returns the address."""
    from . import mailcore
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    if security.rate_limited(f"emailcode:{user_id}", 10, 600):
        raise AuthError("Too many codes sent. Wait a few minutes, then try again.")
    sender = code_sender()
    if not sender:
        raise AuthError(f"Email codes aren't set up: an admin must create and link no-reply@{config.DOMAIN} "
                        "or choose another sender in Settings.")
    code = f"{secrets.randbelow(1_000_000):06d}"
    with db.tx() as conn:
        conn.execute("UPDATE email_codes SET used = 1 WHERE user_id = ? AND used = 0", (user_id,))  # one live code
        conn.execute("INSERT INTO email_codes(user_id, code_hash, expires_at) VALUES(?,?,?)",
                     (user_id, security.token_hash(code), time.time() + EMAIL_CODE_SECONDS))
    msg, rcpts = mailcore.build(sender, to=[row["email"]], sender_name=config.APP_NAME,
                                subject=f"Your sign-in code: {code}",
                                text=(f"Your {config.APP_NAME} sign-in code is {code}.\n\n"
                                      f"It works once and expires in 10 minutes. If you didn't try to sign in, "
                                      f"change your password and tell your administrator."))
    pw = security.decrypt(db.one("SELECT password FROM mailboxes WHERE address = ?", (sender,))["password"])
    try:
        mailcore.send(sender, pw, msg, rcpts)
    except mailcore.MailError as e:
        raise AuthError(f"Couldn't send the code: {e}") from None
    db.audit(row["email"], "two_step.email_code_sent", row["email"], None, ip)
    return row["email"]


def _check_email_code(user_id: int, code: str) -> bool:
    code = re.sub(r"\s", "", code or "")
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM email_codes WHERE user_id = ? AND used = 0 AND expires_at > ? "
                           "ORDER BY id DESC LIMIT 1", (user_id, time.time())).fetchone()
        if not row or row["attempts"] >= 5:
            return False
        if security.same(row["code_hash"], security.token_hash(code)):
            conn.execute("UPDATE email_codes SET used = 1 WHERE id = ?", (row["id"],))
            return True
        conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
        return False


def start_email_two_step(user_id: int, ip: str | None) -> str:
    db.execute("UPDATE users SET two_step_method = 'email_pending' WHERE id = ? AND totp_enabled = 0", (user_id,))
    return send_email_code(user_id, ip)


def confirm_email_two_step(user_id: int, code: str) -> list[str] | None:
    if not _check_email_code(user_id, code):
        return None
    codes, stored = security.new_recovery_codes()
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    db.execute("UPDATE users SET totp_enabled = 1, two_step_method = 'email', totp_secret = NULL, recovery_codes = ? "
               "WHERE id = ?", (stored, user_id))
    db.audit(row["email"], "two_step.enabled", row["email"], {"method": "email"})
    return codes


def start_two_step(user_id: int) -> tuple[str, str]:
    """New secret (not active until confirmed). Returns (secret, otpauth URI)."""
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    secret = security.new_totp_secret()
    db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?", (security.encrypt(secret), user_id))
    return secret, security.totp_uri(secret, row["email"])


def confirm_two_step(user_id: int, code: str) -> list[str] | None:
    row = db.one("SELECT totp_secret, totp_last_step, email FROM users WHERE id = ?", (user_id,))
    if not row or not row["totp_secret"]:
        return None
    step = security.check_totp(security.decrypt(row["totp_secret"]), code, row["totp_last_step"])
    if step is None:
        return None
    codes, stored = security.new_recovery_codes()
    db.execute("UPDATE users SET totp_enabled = 1, two_step_method = 'totp', totp_last_step = ?, recovery_codes = ? "
               "WHERE id = ?", (step, stored, user_id))
    db.audit(row["email"], "two_step.enabled", row["email"], {"method": "authenticator app"})
    return codes


def disable_two_step(user_id: int) -> None:
    with db.tx() as conn:
        conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, two_step_method = NULL, "
                     "recovery_codes = '[]' WHERE id = ?", (user_id,))
        # tokens were issued under two-step: take them back
        conn.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
        conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    db.audit(row["email"], "two_step.disabled", row["email"])


def change_password(user_id: int, current: str, new: str) -> None:
    row = db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not security.verify_password(row["password_hash"], current or ""):
        raise AuthError("Your current password is wrong.")
    if problem := security.password_problem(new, row["email"]):
        raise AuthError(problem)
    if security.verify_password(row["password_hash"], new):
        raise AuthError("Choose a password different from the current one.")
    with db.tx() as conn:
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                     (security.hash_password(new), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    db.audit(row["email"], "password.changed", row["email"])


# ---------- browser sessions ----------------------------------------------------------------

def create_session(user_id: int, mfa_ok: bool, ip: str | None) -> tuple[str, str]:
    sid = security.new_token()
    csrf = security.new_token()
    now = time.time()
    db.execute("INSERT INTO sessions(id_hash, user_id, csrf, mfa_ok, created_at, last_seen, ip) VALUES(?,?,?,?,?,?,?)",
               (security.token_hash(sid), user_id, csrf, int(mfa_ok), now, now, ip))
    db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, user_id))
    return sid, csrf


def load_session(sid: str | None):
    if not sid:
        return None
    row = db.one("SELECT s.*, u.email, u.role, u.disabled, u.must_change_password, u.totp_enabled, u.name, "
                 "u.two_step_method "
                 "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?", (security.token_hash(sid),))
    now = time.time()
    if (not row or row["disabled"] or now - row["last_seen"] > config.SESSION_IDLE_MINUTES * 60
            or now - row["created_at"] > config.SESSION_MAX_HOURS * 3600):
        if row:
            db.execute("DELETE FROM sessions WHERE id_hash = ?", (row["id_hash"],))
        return None
    if now - row["last_seen"] > 60:
        db.execute("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (now, row["id_hash"]))
    return row


def end_session(sid: str | None) -> None:
    if sid:
        db.execute("DELETE FROM sessions WHERE id_hash = ?", (security.token_hash(sid),))


def mark_session_mfa(sid: str) -> None:
    db.execute("UPDATE sessions SET mfa_ok = 1 WHERE id_hash = ?", (security.token_hash(sid),))


# ---------- personal API tokens -----------------------------------------------------------

def two_step_ok_for_tokens(user_id: int, issued_with_mfa: bool) -> bool:
    """When the admin requires two-step, a token only works if it was issued after a two-step
    check and its owner still has two-step switched on."""
    if not service.require_two_step():
        return True
    row = db.one("SELECT totp_enabled FROM users WHERE id = ?", (user_id,))
    return bool(row and row["totp_enabled"] and issued_with_mfa)


def create_api_token(user_id: int, name: str, scopes: list[str], days: int | None,
                     mfa: bool = False) -> tuple[str, dict]:
    user = db.one("SELECT role, email FROM users WHERE id = ?", (user_id,))
    scopes = [s for s in service.SCOPES if s in set(scopes)]
    if user["role"] != "admin":
        scopes = [s for s in scopes if s != "admin"]
    if not scopes:
        raise AuthError("Pick at least one permission for the token.")
    name = (name or "").strip()[:60] or "token"
    token = security.new_token(PAT_PREFIX)
    expires = time.time() + days * 86400 if days else None
    tid = db.execute("INSERT INTO api_tokens(user_id, name, token_hash, prefix, scopes, created_at, expires_at, mfa) "
                     "VALUES(?,?,?,?,?,?,?,?)",
                     (user_id, name, security.token_hash(token), token[:12], json.dumps(scopes), time.time(), expires,
                      int(mfa)))
    db.audit(user["email"], "token.create", name, {"scopes": scopes, "days": days})
    return token, {"id": tid, "name": name, "scopes": scopes, "expires_at": expires}


def list_api_tokens(user_id: int) -> list[dict]:
    return [{**dict(r), "scopes": json.loads(r["scopes"])} for r in db.query(
        "SELECT id, name, prefix, scopes, created_at, expires_at, last_used_at, revoked FROM api_tokens "
        "WHERE user_id = ? ORDER BY revoked, id DESC", (user_id,))]


def revoke_api_token(user_id: int, token_id: int) -> bool:
    with db.tx() as conn:
        cur = conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?", (token_id, user_id))
        changed = cur.rowcount > 0
    if changed:
        row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
        db.audit(row["email"], "token.revoke", str(token_id))
    return changed


def list_oauth_grants(user_id: int) -> list[dict]:
    """Apps signed in with OAuth (e.g. Claude) that still have a valid refresh token."""
    rows = db.query("SELECT t.family, t.client_id, t.scopes, MIN(t.created_at) AS since, c.info "
                    "FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.client_id = t.client_id "
                    "WHERE t.user_id = ? AND t.kind = 'refresh' AND t.revoked = 0 AND t.expires_at > ? "
                    "GROUP BY t.family ORDER BY since DESC", (user_id, time.time()))
    out = []
    for r in rows:
        name = json.loads(r["info"]).get("client_name") if r["info"] else None
        out.append({"id": r["family"][:24], "client": name or r["client_id"], "scopes": json.loads(r["scopes"]),
                    "since": r["since"]})
    return out


def revoke_oauth_grant(user_id: int, grant_id: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{24}", grant_id or ""):
        return False
    with db.tx() as conn:
        cur = conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE user_id = ? AND substr(family, 1, 24) = ?",
                           (user_id, grant_id))
        changed = cur.rowcount > 0
    if changed:
        row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
        db.audit(row["email"], "oauth.revoked_by_user", grant_id)
    return changed


def load_api_token(token: str):
    row = db.one("SELECT t.*, u.disabled FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?",
                 (security.token_hash(token),))
    if not row or row["revoked"] or row["disabled"]:
        return None
    if row["expires_at"] and row["expires_at"] < time.time():
        return None
    if not two_step_ok_for_tokens(row["user_id"], bool(row["mfa"])):
        return None
    if not row["last_used_at"] or time.time() - row["last_used_at"] > 60:
        db.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (time.time(), row["id"]))
    return row
