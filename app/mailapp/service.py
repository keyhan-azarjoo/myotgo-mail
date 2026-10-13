"""Every operation, with its permission check. The web console, the REST API and the MCP
tools all call these functions, so the rules are written once.

Permissions
  role admin           manages users, mailboxes and aliases, and can use every mailbox
  role user            only the mailboxes an admin granted, with the granted rights:
                         read      list folders, search, read messages and attachments
                         send      send, reply, forward, save drafts
                         organize  flag, move, delete messages; create/rename/delete folders
  token / OAuth scopes narrow this further: mail.read, mail.send, mail.organize, admin
"""
import json
import time
from dataclasses import dataclass, field

from . import config, db, mailconf, mailcore, security
from .mailcore import MailError

SCOPES = ("mail.read", "mail.send", "mail.organize", "admin")
PERM_SCOPE = {"read": "mail.read", "send": "mail.send", "organize": "mail.organize"}


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Invalid(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    user_id: int
    email: str
    role: str
    scopes: frozenset = field(default_factory=lambda: frozenset(SCOPES))
    via: str = "web"
    ip: str | None = None
    direct_send: bool = True       # False: sending waits for the owner's approval in the console
    requested_by: str = ""         # the app or token acting, shown on the approval page

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and "admin" in self.scopes

    @property
    def actor(self) -> str:
        return f"{self.email} ({self.via})"


def principal_for(user_id: int, scopes=SCOPES, via="web", ip=None, direct_send=True, requested_by="") -> Principal:
    row = db.one("SELECT id, email, role, disabled FROM users WHERE id = ?", (user_id,))
    if not row or row["disabled"]:
        raise Forbidden("This account is disabled.")
    scopes = frozenset(s for s in scopes if s in SCOPES)
    if row["role"] != "admin":
        scopes -= {"admin"}
    return Principal(row["id"], row["email"], row["role"], scopes, via, ip, direct_send, requested_by)


def _audit(p: Principal, action: str, target=None, detail=None):
    db.audit(p.actor, action, target, detail, p.ip)


# ---------- mailbox access --------------------------------------------------------------

def mailbox_permissions(p: Principal) -> dict[str, dict[str, bool]]:
    accounts = mailconf.list_accounts()
    if p.role == "admin":
        perms = {a: {"read": True, "send": True, "organize": True} for a in accounts}
    else:
        perms = {}
        for g in db.query("SELECT * FROM grants WHERE user_id = ?", (p.user_id,)):
            if g["mailbox"].lower() in accounts:
                perms[g["mailbox"].lower()] = {"read": bool(g["can_read"]), "send": bool(g["can_send"]),
                                               "organize": bool(g["can_organize"])}
    for rights in perms.values():
        for perm, scope in PERM_SCOPE.items():
            rights[perm] = rights[perm] and scope in p.scopes
    return {a: r for a, r in perms.items() if any(r.values())}


def _require(p: Principal, mailbox: str, perm: str) -> str:
    mailbox = (mailbox or "").strip().lower()
    rights = mailbox_permissions(p).get(mailbox)
    if not rights:
        raise Forbidden(f"You don't have access to {mailbox or 'that mailbox'}.")
    if not rights[perm]:
        raise Forbidden(f"You don't have '{perm}' permission on {mailbox}.")
    return mailbox


def _password(mailbox: str) -> str:
    row = db.one("SELECT password FROM mailboxes WHERE address = ?", (mailbox,))
    if not row or not row["password"]:
        raise MailError(f"{mailbox} isn't linked to the console yet. An admin can link it on the Mailboxes page.")
    return security.decrypt(row["password"], f"mailbox:{mailbox}")


class _Box:
    """Open an IMAP connection to a mailbox the principal may use."""

    def __init__(self, p: Principal, mailbox: str, perm: str):
        self.mailbox = _require(p, mailbox, perm)
        self._cm = mailcore.imap(self.mailbox, _password(self.mailbox))

    def __enter__(self):
        return self._cm.__enter__()

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)


def list_mailboxes(p: Principal) -> list[dict]:
    linked = {r["address"].lower() for r in db.query("SELECT address FROM mailboxes WHERE password IS NOT NULL")}
    return [{"address": a, "permissions": [k for k, v in r.items() if v], "linked": a in linked,
             "aliases": mailconf.aliases_of(a)}
            for a, r in sorted(mailbox_permissions(p).items())]


# ---------- reading ---------------------------------------------------------------------

def list_folders(p, mailbox):
    with _Box(p, mailbox, "read") as c:
        return mailcore.list_folders(c)


def search(p, mailbox, folder="INBOX", **filters):
    with _Box(p, mailbox, "read") as c:
        return mailcore.search(c, folder, **filters)


def read(p, mailbox, folder, uid, mark_seen=False, include_html=False):
    perm = "organize" if mark_seen else "read"
    _require(p, mailbox, "read")
    with _Box(p, mailbox, perm) as c:
        return mailcore.read(c, folder, uid, mark_seen=mark_seen, include_html=include_html)


def attachment(p, mailbox, folder, uid, index):
    with _Box(p, mailbox, "read") as c:
        return mailcore.attachment(c, folder, uid, index)


# ---------- sending ---------------------------------------------------------------------

def _from(mailbox: str, from_address: str | None) -> str:
    if not from_address or from_address.lower() == mailbox:
        return mailbox
    if from_address.lower() in mailconf.aliases_of(mailbox):
        return from_address.lower()
    raise Forbidden(f"{mailbox} can only send as itself or its aliases ({', '.join(mailconf.aliases_of(mailbox)) or 'none'}).")


def send(p, mailbox, *, to, subject, text="", html=None, cc=(), bcc=(), attachments=(), from_address=None,
         from_name=None):
    mailbox = _require(p, mailbox, "send")
    sender = _from(mailbox, from_address)
    msg, rcpts = mailcore.build(sender, to=to, cc=cc, bcc=bcc, subject=subject, text=text, html_body=html,
                                attachments=attachments, sender_name=from_name)
    return _deliver(p, "send", mailbox, msg, rcpts)


def reply(p, mailbox, folder, uid, *, text, reply_all=False, html=None, attachments=()):
    mailbox = _require(p, mailbox, "send")
    _require(p, mailbox, "read")
    password = _password(mailbox)
    with mailcore.imap(mailbox, password) as c:
        orig = mailcore.original(c, folder, uid)
    import email.utils as eu
    me = {mailbox, *mailconf.aliases_of(mailbox)}
    to = [a for a in eu.getaddresses([str(orig.get("Reply-To") or orig.get("From") or "")]) if a[1]]
    cc = []
    if reply_all:
        others = eu.getaddresses([str(orig.get("To") or ""), str(orig.get("Cc") or "")])
        cc = [a for a in others if a[1] and a[1].lower() not in me and a[1].lower() not in {t[1].lower() for t in to}]
    subject = str(orig.get("Subject") or "")
    if not subject.lower().startswith("re:"):
        subject = "Re: " + subject
    refs = " ".join(x for x in (str(orig.get("References") or ""), str(orig.get("Message-ID") or "")) if x).strip()
    msg, rcpts = mailcore.build(mailbox, to=[eu.formataddr(a) for a in to], cc=[eu.formataddr(a) for a in cc],
                                subject=subject.replace("\n", " ").replace("\r", " ")[:900],
                                text=mailcore.quote(orig, text), html_body=html, attachments=attachments,
                                in_reply_to=str(orig.get("Message-ID") or "") or None, references=refs or None)
    return _deliver(p, "reply", mailbox, msg, rcpts, after={"answered": [folder, int(uid)]})


def forward(p, mailbox, folder, uid, *, to, text="", cc=()):
    mailbox = _require(p, mailbox, "send")
    _require(p, mailbox, "read")
    password = _password(mailbox)
    with mailcore.imap(mailbox, password) as c:
        orig = mailcore.original(c, folder, uid)
    subject = str(orig.get("Subject") or "").replace("\n", " ").replace("\r", " ")
    if not subject.lower().startswith("fwd:"):
        subject = "Fwd: " + subject
    msg, rcpts = mailcore.build(mailbox, to=to, cc=cc, subject=subject[:900], text=text or "Forwarded message attached.")
    mailcore.attach_original(msg, orig)
    return _deliver(p, "forward", mailbox, msg, rcpts)


# ---------- sending, now or after the owner's approval ------------------------------------

APPROVAL_DAYS = 7


def _send_now(p, kind, mailbox, msg, rcpts, after=None) -> dict:
    password = _password(mailbox)
    status = mailcore.send(mailbox, password, msg, rcpts)
    with mailcore.imap(mailbox, password) as c:
        mailcore.append(c, mailcore.special_folder(c, "\\Sent", "Sent"), msg)
        if after and after.get("answered"):
            folder, uid = after["answered"]
            try:
                mailcore.set_flags(c, folder, [uid], answered=True)
            except MailError:
                pass   # the original was moved meanwhile: the reply still went out
    _audit(p, f"mail.{kind}", mailbox, {"to": rcpts, "subject": str(msg["Subject"] or "")})
    return {"status": status, "message_id": msg["Message-ID"], "recipients": rcpts}


def _deliver(p, kind, mailbox, msg, rcpts, after=None) -> dict:
    """Send now, or, for connections that may not send on their own (AI assistants by default),
    keep the exact message until its owner approves it in the console."""
    if p.direct_send:
        return _send_now(p, kind, mailbox, msg, rcpts, after)
    import base64
    import email.policy
    raw = base64.b64encode(msg.as_bytes(policy=email.policy.SMTP)).decode()
    now = time.time()
    oid = db.execute("INSERT INTO outbox(user_id, mailbox, kind, subject, message, recipients, after, requested_by, "
                     "created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (p.user_id, mailbox, kind, str(msg["Subject"] or "")[:300], "", json.dumps(rcpts),
                      json.dumps(after or {}), p.requested_by or p.via, now, now + APPROVAL_DAYS * 86400))
    db.execute("UPDATE outbox SET message = ? WHERE id = ?", (security.encrypt(raw, f"outbox:{oid}"), oid))
    _audit(p, f"mail.{kind}.queued", mailbox, {"approval_id": oid, "to": rcpts, "subject": str(msg["Subject"] or "")})
    _notify_approval(p)
    return {"status": "waiting_for_approval", "approval_id": oid, "recipients": rcpts,
            "approve_at": f"{config.PUBLIC_URL}/approvals",
            "note": "Nothing was sent yet. The owner must approve this message in the web console "
                    "(Approvals). Tell them it is waiting there."}


def _notify_approval(p):
    """Tell the owner something is waiting (at most once every 10 minutes); the email only links
    to the console, where approving needs a signed-in session."""
    if security.rate_limited(f"approval-note:{p.user_id}", 1, 600):
        return
    from . import auth
    sender = auth.code_sender()
    if not sender or sender == p.email:
        return
    try:
        msg, rcpts = mailcore.build(sender, to=[p.email], sender_name=config.APP_NAME,
                                    subject="An email is waiting for your approval",
                                    text=(f"{p.requested_by or 'An app'} prepared an email on your behalf. "
                                          f"Nothing is sent until you approve it:\n\n{config.PUBLIC_URL}/approvals\n"))
        mailcore.send(sender, _password(sender), msg, rcpts)
    except Exception:  # noqa: BLE001 - a missing notification must never block the queue
        pass


def _outbox_row(p, oid: int):
    row = db.one("SELECT * FROM outbox WHERE id = ? AND user_id = ?", (int(oid), p.user_id))
    if not row:
        raise NotFound("No such message waiting for approval.")
    return row


def _outbox_message(row):
    import base64
    import email.policy
    raw = base64.b64decode(security.decrypt(row["message"], f"outbox:{row['id']}"))
    return email.message_from_bytes(raw, policy=email.policy.default)


def _expire_outbox():
    db.execute("UPDATE outbox SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at < ?",
               (time.time(), time.time()))


def list_approvals(p, include_done=False) -> list[dict]:
    _expire_outbox()
    if include_done:
        rows = db.query("SELECT * FROM outbox WHERE user_id = ? ORDER BY id DESC LIMIT 100", (p.user_id,))
    else:
        rows = db.query("SELECT * FROM outbox WHERE user_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 100",
                        (p.user_id,))
    return [{"id": r["id"], "mailbox": r["mailbox"], "kind": r["kind"], "subject": r["subject"],
             "recipients": json.loads(r["recipients"]), "requested_by": r["requested_by"], "status": r["status"],
             "created_at": r["created_at"], "decided_at": r["decided_at"]} for r in rows]


def approval_detail(p, oid: int) -> dict:
    _expire_outbox()
    row = _outbox_row(p, oid)
    msg = _outbox_message(row)
    header_rcpts = {a[1].lower() for a in __import__("email.utils").utils.getaddresses(
        [str(msg.get("To") or ""), str(msg.get("Cc") or "")])}
    body = msg.get_body(preferencelist=("plain", "html"))
    return {"id": row["id"], "status": row["status"], "kind": row["kind"], "mailbox": row["mailbox"],
            "requested_by": row["requested_by"], "created_at": row["created_at"],
            "from": str(msg.get("From") or ""), "to": str(msg.get("To") or ""), "cc": str(msg.get("Cc") or ""),
            "bcc": ", ".join(r for r in json.loads(row["recipients"]) if r.lower() not in header_rcpts),
            "subject": str(msg.get("Subject") or ""), "text": body.get_content() if body else "",
            "attachments": [{"filename": a.get_filename() or "attachment", "size": len(a.get_payload(decode=True) or b"")}
                            for a in msg.iter_attachments()],
            "result": json.loads(row["result"]) if row["result"] else None}


def decide_approval(p, oid: int, approve: bool) -> dict:
    """Only the signed-in owner, in the console, can decide. Tokens and AI assistants can't."""
    if p.via != "web":
        raise Forbidden("Messages can only be approved in the web console.")
    _expire_outbox()
    with db.tx() as conn:   # claim it, so a double click can't send twice
        row = conn.execute("SELECT * FROM outbox WHERE id = ? AND user_id = ?", (int(oid), p.user_id)).fetchone()
        if not row:
            raise NotFound("No such message waiting for approval.")
        if row["status"] != "pending":
            raise Invalid(f"This message is already {row['status']}.")
        conn.execute("UPDATE outbox SET status = ?, decided_at = ? WHERE id = ?",
                     ("sending" if approve else "rejected", time.time(), row["id"]))
    if not approve:
        _audit(p, "mail.approval.rejected", row["mailbox"], {"approval_id": row["id"]})
        return {"status": "rejected"}
    owner = principal_for(p.user_id, via=f"approved:{row['requested_by']}"[:80], ip=p.ip)
    try:
        _require(owner, row["mailbox"], "send")   # still allowed to send from this mailbox?
        result = _send_now(owner, row["kind"], row["mailbox"], _outbox_message(row), json.loads(row["recipients"]),
                           json.loads(row["after"] or "{}"))
        status = "sent"
    except (Forbidden, MailError, Invalid) as e:
        result, status = {"error": str(e)}, "failed"
    db.execute("UPDATE outbox SET status = ?, result = ? WHERE id = ?", (status, json.dumps(result, default=str), row["id"]))
    _audit(p, f"mail.approval.{status}", row["mailbox"], {"approval_id": row["id"]})
    if status == "failed":
        raise Invalid(f"It couldn't be sent: {result['error']}")
    return {"status": status, **result}


def pending_count(user_id: int) -> int:
    return db.one("SELECT COUNT(*) AS n FROM outbox WHERE user_id = ? AND status = 'pending' AND expires_at > ?",
                  (user_id, time.time()))["n"]


def save_draft(p, mailbox, *, to=(), subject="", text="", html=None, cc=(), bcc=(), attachments=()):
    mailbox = _require(p, mailbox, "send")
    msg, _ = mailcore.build(mailbox, to=to, cc=cc, bcc=bcc, subject=subject, text=text, html_body=html,
                            attachments=attachments)
    with _Box(p, mailbox, "send") as c:
        folder = mailcore.special_folder(c, "\\Drafts", "Drafts")
        mailcore.append(c, folder, msg, flags=(b"\\Draft", b"\\Seen"))
    _audit(p, "mail.draft", mailbox, {"subject": msg["Subject"]})
    return {"status": "saved", "folder": folder, "message_id": msg["Message-ID"]}


# ---------- organizing ------------------------------------------------------------------

def set_flags(p, mailbox, folder, uids, *, seen=None, flagged=None):
    with _Box(p, mailbox, "organize") as c:
        n = mailcore.set_flags(c, folder, uids, seen=seen, flagged=flagged)
    return {"updated": n}


def move(p, mailbox, folder, uids, target):
    with _Box(p, mailbox, "organize") as c:
        n = mailcore.move(c, folder, uids, target)
    _audit(p, "mail.move", mailbox, {"from": folder, "to": target, "count": n})
    return {"moved": n, "to": target}


def delete(p, mailbox, folder, uids, permanent=False):
    with _Box(p, mailbox, "organize") as c:
        result = mailcore.delete(c, folder, uids, permanent=permanent)
    _audit(p, "mail.delete", mailbox, {"folder": folder, "uids": uids, "result": result})
    return {"status": result}


def create_folder(p, mailbox, name):
    with _Box(p, mailbox, "organize") as c:
        mailcore.create_folder(c, name)
    _audit(p, "folder.create", mailbox, name)
    return {"created": name}


def rename_folder(p, mailbox, old, new):
    with _Box(p, mailbox, "organize") as c:
        mailcore.rename_folder(c, old, new)
    _audit(p, "folder.rename", mailbox, {"from": old, "to": new})
    return {"renamed": old, "to": new}


def delete_folder(p, mailbox, name):
    with _Box(p, mailbox, "organize") as c:
        mailcore.delete_folder(c, name)
    _audit(p, "folder.delete", mailbox, name)
    return {"deleted": name}


# ---------- admin: users ------------------------------------------------------------------

def _admin(p: Principal):
    if not p.is_admin:
        raise Forbidden("Admin access is required.")


def _user_dict(row) -> dict:
    grants = db.query("SELECT * FROM grants WHERE user_id = ? ORDER BY mailbox", (row["id"],))
    return {
        "id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"],
        "disabled": bool(row["disabled"]), "two_step": bool(row["totp_enabled"]),
        "two_step_method": row["two_step_method"] if row["totp_enabled"] else None,
        "created_at": row["created_at"], "last_login_at": row["last_login_at"],
        "grants": [{"mailbox": g["mailbox"], "read": bool(g["can_read"]), "send": bool(g["can_send"]),
                    "organize": bool(g["can_organize"])} for g in grants],
    }


def list_users(p):
    _admin(p)
    return [_user_dict(r) for r in db.query("SELECT * FROM users ORDER BY email")]


def get_user(p, user_id: int):
    _admin(p)
    row = db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not row:
        raise NotFound("No such user.")
    return _user_dict(row)


def find_user_id(email: str) -> int:
    row = db.one("SELECT id FROM users WHERE email = ?", ((email or "").strip(),))
    if not row:
        raise NotFound(f"No user {email}.")
    return row["id"]


def user_id_by_email(p, email: str) -> int:
    _admin(p)
    return find_user_id(email)


def create_user(p, email: str, name: str = "", role: str = "user", password: str | None = None) -> dict:
    """Create a login. Returns the user and a one-time password they must change at first login."""
    if p is not None:
        _admin(p)
    email = (email or "").strip().lower()
    if not mailconf.ANY_ADDRESS_RE.fullmatch(email):
        raise Invalid("The user name must be an email address.")
    if role not in ("admin", "user"):
        raise Invalid("Role must be admin or user.")
    if db.one("SELECT 1 FROM users WHERE email = ?", (email,)):
        raise Invalid(f"{email} already has an account.")
    temp = password or security.generate_password()
    if password and (problem := security.password_problem(password, email)):
        raise Invalid(problem)
    uid = db.execute("INSERT INTO users(email, name, password_hash, role, must_change_password, created_at) "
                     "VALUES(?,?,?,?,1,?)",
                     (email, (name or "").strip()[:100], security.hash_password(temp), role, time.time()))
    db.audit(p.actor if p else "cli", "user.create", email, {"role": role}, p.ip if p else None)
    return {"user": _user_dict(db.one("SELECT * FROM users WHERE id = ?", (uid,))), "temporary_password": temp}


def update_user(p, user_id: int, *, name=None, role=None, disabled=None) -> dict:
    _admin(p)
    row = db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not row:
        raise NotFound("No such user.")
    if user_id == p.user_id and (role == "user" or disabled):
        raise Invalid("You can't remove your own admin role or disable yourself.")
    if role is not None and role not in ("admin", "user"):
        raise Invalid("Role must be admin or user.")
    with db.tx() as conn:
        if name is not None:
            conn.execute("UPDATE users SET name = ? WHERE id = ?", (name.strip()[:100], user_id))
        if role is not None:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if disabled is not None:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
            if disabled:
                _revoke_everything(conn, user_id)
    if disabled and row["email"].lower() in mailconf.list_accounts():
        # one password for login and mailbox: a disabled person must lose mail-app access too
        new = security.generate_password(32)
        mailconf.set_password(row["email"].lower(), new)
        _store_mailbox_password(row["email"].lower(), new)
        _wait_for_login(row["email"].lower(), new)   # the mail server applies it within seconds
    _audit(p, "user.update", row["email"], {"name": name, "role": role, "disabled": disabled})
    return get_user(p, user_id)


def _revoke_everything(conn, user_id: int):
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))


def reset_user_password(p, user_id: int) -> dict:
    _admin(p)
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    if not row:
        raise NotFound("No such user.")
    temp = security.generate_password()
    # one password: the mailbox gets the temporary password too, so the old one stops working everywhere
    sync_mailbox_password(row["email"], temp)
    with db.tx() as conn:
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1, failed_logins = 0, "
                     "locked_until = 0 WHERE id = ?", (security.hash_password(temp), user_id))
        _revoke_everything(conn, user_id)
    _audit(p, "user.reset_password", row["email"])
    return {"email": row["email"], "temporary_password": temp}


def reset_user_two_step(p, user_id: int) -> dict:
    _admin(p)
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    if not row:
        raise NotFound("No such user.")
    with db.tx() as conn:
        conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, two_step_method = NULL, "
                     "two_step_email = NULL, recovery_codes = '[]' WHERE id = ?",
                     (user_id,))
        _revoke_everything(conn, user_id)
    _audit(p, "user.reset_two_step", row["email"])
    return {"email": row["email"], "two_step": False}


def delete_user(p, user_id: int) -> dict:
    _admin(p)
    if user_id == p.user_id:
        raise Invalid("You can't delete your own account.")
    row = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    if not row:
        raise NotFound("No such user.")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    forget_rate_limits(user_id)
    if row["email"].lower() in mailconf.list_accounts():
        # the person loses mail-app access too; the mailbox and its mail stay for the admin
        sync_mailbox_password(row["email"], security.generate_password(32))
    _audit(p, "user.delete", row["email"])
    return {"deleted": row["email"]}


def forget_rate_limits(user_id: int) -> None:
    """User ids can be reused after a delete: don't let a new user inherit old counters."""
    db.execute("DELETE FROM rate WHERE key IN (?, ?, ?, ?)",
               (f"2step:{user_id}", f"2step-fail:{user_id}", f"2step-fail-day:{user_id}", f"emailcode:{user_id}"))


def set_grant(p, user_id: int, mailbox: str, *, read=False, send=False, organize=False) -> dict:
    _admin(p)
    mailbox = (mailbox or "").strip().lower()
    if mailbox not in mailconf.list_accounts():
        raise NotFound(f"There is no mailbox {mailbox}.")
    user = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    if not user:
        raise NotFound("No such user.")
    if read or send or organize:
        db.execute("INSERT INTO grants(user_id, mailbox, can_read, can_send, can_organize) VALUES(?,?,?,?,?) "
                   "ON CONFLICT(user_id, mailbox) DO UPDATE SET can_read = excluded.can_read, "
                   "can_send = excluded.can_send, can_organize = excluded.can_organize",
                   (user_id, mailbox, int(bool(read)), int(bool(send)), int(bool(organize))))
    else:
        db.execute("DELETE FROM grants WHERE user_id = ? AND mailbox = ?", (user_id, mailbox))
    _audit(p, "grant.set", user["email"], {"mailbox": mailbox, "read": read, "send": send, "organize": organize})
    return get_user(p, user_id)


# ---------- admin: mailboxes and aliases ---------------------------------------------------

def admin_mailboxes(p) -> list[dict]:
    _admin(p)
    linked = {r["address"].lower(): r for r in db.query("SELECT * FROM mailboxes")}
    out = []
    for a in mailconf.list_accounts():
        users = [r["email"] for r in db.query(
            "SELECT u.email FROM grants g JOIN users u ON u.id = g.user_id WHERE g.mailbox = ?", (a,))]
        out.append({"address": a, "linked": bool(linked.get(a) and linked[a]["password"]),
                    "aliases": mailconf.aliases_of(a), "users_with_access": users})
    return out


def _wait_for_login(address: str, password: str, seconds: int = 20) -> bool:
    """The mail server applies account changes within a few seconds; wait until it has."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if mailcore.check_login(address, password):
            return True
        time.sleep(1)
    return False


def sync_mailbox_password(email: str, password: str) -> bool:
    """If this login is also a mailbox on the server, give the mailbox the same password
    (so the website, Outlook and other mail apps all use one password). True if synced."""
    address = (email or "").strip().lower()
    if address not in mailconf.list_accounts():
        return False
    mailconf.set_password(address, password)
    _store_mailbox_password(address, password)
    _wait_for_login(address, password)
    db.audit(address, "mailbox.password_synced", address)
    return True


def _store_mailbox_password(address: str, password: str):
    db.execute("INSERT INTO mailboxes(address, password, created_at) VALUES(?,?,?) "
               "ON CONFLICT(address) DO UPDATE SET password = excluded.password",
               (address, security.encrypt(password, f"mailbox:{address}"), time.time()))


def create_mailbox(p, address: str) -> dict:
    if p is not None:
        _admin(p)
    try:
        address = mailconf.normalize_local(address)
        password = security.generate_password(24)
        mailconf.add_account(address, password)
    except mailconf.MailConfError as e:
        raise Invalid(str(e)) from None
    _store_mailbox_password(address, password)
    ready = _wait_for_login(address, password)
    db.audit(p.actor if p else "cli", "mailbox.create", address, None, p.ip if p else None)
    return {"address": address, "password": password, "ready": ready,
            "note": "Shown once. Use it in Outlook or any mail app." + ("" if ready else
                    " The mail server is still applying the change; try in a minute.")}


def reset_mailbox_password(p, address: str) -> dict:
    _admin(p)
    try:
        address = mailconf.normalize_local(address)
        password = security.generate_password(24)
        mailconf.set_password(address, password)
    except mailconf.MailConfError as e:
        raise Invalid(str(e)) from None
    _store_mailbox_password(address, password)
    ready = _wait_for_login(address, password)
    # the console login with the same address gets the same password (to be changed at next sign-in),
    # and everything signed in with the old one is signed out
    user = db.one("SELECT id FROM users WHERE email = ?", (address,))
    if user:
        with db.tx() as conn:
            conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                         (security.hash_password(password), user["id"]))
            _revoke_everything(conn, user["id"])
    _audit(p, "mailbox.reset_password", address)
    return {"address": address, "password": password, "ready": ready,
            "note": "Shown once. Mail apps using the old password must be updated."}


def link_mailbox(p, address: str, password: str) -> dict:
    """Store the password of an existing mailbox so the console can use it (checked first)."""
    if p is not None:
        _admin(p)
    address = (address or "").strip().lower()
    if address not in mailconf.list_accounts():
        raise NotFound(f"There is no mailbox {address}.")
    if not mailcore.check_login(address, password):
        raise Invalid("That password doesn't work for this mailbox.")
    _store_mailbox_password(address, password)
    # keep the console login with the same address on the same password, and sign it out
    user = db.one("SELECT id FROM users WHERE email = ?", (address,))
    if user:
        with db.tx() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (security.hash_password(password), user["id"]))
            _revoke_everything(conn, user["id"])
    db.audit(p.actor if p else "cli", "mailbox.link", address, None, p.ip if p else None)
    return {"address": address, "linked": True}


def delete_mailbox(p, address: str, confirm: str) -> dict:
    _admin(p)
    address = (address or "").strip().lower()
    if (confirm or "").strip().lower() != address:
        raise Invalid("To delete a mailbox, repeat its address in the confirmation field.")
    try:
        mailconf.delete_account(address)
    except mailconf.MailConfError as e:
        raise Invalid(str(e)) from None
    with db.tx() as conn:
        conn.execute("DELETE FROM mailboxes WHERE address = ?", (address,))
        conn.execute("DELETE FROM grants WHERE mailbox = ?", (address,))
    _audit(p, "mailbox.delete", address)
    return {"deleted": address}


def list_aliases(p) -> list[dict]:
    _admin(p)
    return [{"alias": a, "targets": t} for a, t in sorted(mailconf.aliases().items())]


def create_alias(p, alias: str, target: str) -> dict:
    _admin(p)
    try:
        mailconf.add_alias(alias, target)
    except mailconf.MailConfError as e:
        raise Invalid(str(e)) from None
    _audit(p, "alias.create", alias, {"target": target})
    return {"alias": alias.lower(), "target": target.lower()}


def delete_alias(p, alias: str, target: str) -> dict:
    _admin(p)
    try:
        mailconf.delete_alias(alias, target)
    except mailconf.MailConfError as e:
        raise Invalid(str(e)) from None
    _audit(p, "alias.delete", alias, {"target": target})
    return {"deleted": alias.lower(), "target": target.lower()}


def audit_log(p, limit: int = 200, offset: int = 0) -> list[dict]:
    _admin(p)
    limit = max(1, min(int(limit), 500))
    rows = db.query("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?", (limit, max(0, int(offset))))
    return [dict(r) for r in rows]


def require_two_step() -> bool:
    return db.setting("require_two_step", "0") == "1"


def set_require_two_step(p, value: bool) -> dict:
    _admin(p)
    db.set_setting("require_two_step", "1" if value else "0")
    _audit(p, "settings.require_two_step", None, {"value": value})
    return {"require_two_step": value}
