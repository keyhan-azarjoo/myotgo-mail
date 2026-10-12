"""Talking to the mail server: IMAP for reading/organizing, SMTP for sending.
Every connection signs in as the mailbox itself, so the mail server's own rules
(who may send as whom, spam checks, DKIM signing) apply to the app exactly as to Outlook."""
import base64
import datetime as dt
import email
import email.header
import email.policy
import email.utils
import html
import re
import smtplib
import ssl
from contextlib import contextmanager
from email.message import EmailMessage

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError, LoginError

from . import config

ADDRESS_RE = re.compile(r"^[^@\s<>\"',;:\\()\[\]]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
SPECIAL = ("\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive")


class MailError(Exception):
    """Something the caller did wrong or that the mail server refused; safe to show."""


def _ssl() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


@contextmanager
def imap(address: str, password: str):
    try:
        client = IMAPClient(config.IMAP_HOST, port=config.IMAP_PORT, ssl=True, ssl_context=_ssl(), timeout=30)
    except OSError as e:
        raise MailError(f"Can't reach the mail server: {e}") from None
    try:
        try:
            client.login(address, password)
        except LoginError:
            raise MailError(f"The stored password for {address} no longer works. "
                            "An admin needs to reset or re-link this mailbox.") from None
        yield client
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001 - already closing
            pass


def check_login(address: str, password: str) -> bool:
    try:
        with imap(address, password):
            return True
    except MailError:
        return False


# ---------- helpers -------------------------------------------------------------------

def clean_text(value: str, field: str, max_len: int = 998) -> str:
    value = value or ""
    if "\r" in value or "\n" in value or "\x00" in value:
        raise MailError(f"{field} can't contain line breaks.")
    if len(value) > max_len:
        raise MailError(f"{field} is too long.")
    return value


def clean_addresses(values, field: str) -> list[str]:
    if isinstance(values, str):
        values = [values]
    out = []
    for v in values or []:
        v = clean_text(str(v).strip(), field, 320)
        name, addr = email.utils.parseaddr(v)
        if not addr or not ADDRESS_RE.fullmatch(addr):
            raise MailError(f"{field}: '{v}' isn't a valid email address.")
        out.append(email.utils.formataddr((name, addr)) if name else addr)
    return out


def _dec(value) -> str:
    if value is None:
        return ""
    return str(email.header.make_header(email.header.decode_header(str(value)))) if not isinstance(value, str) else value


def _addr_list(value) -> list[str]:
    if not value:
        return []
    return [email.utils.formataddr(a) if a[0] else a[1] for a in email.utils.getaddresses([str(value)])]


def _date(value) -> str | None:
    if not value:
        return None
    try:
        return email.utils.parsedate_to_datetime(str(value)).isoformat()
    except (TypeError, ValueError):
        return str(value)


def _html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style|head).*?</\1>", "", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</h\d>|</li>", "\n", markup)
    text = html.unescape(re.sub(r"<[^>]+>", "", markup))
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()


def folder_names(client: IMAPClient) -> list[str]:
    return [name for _flags, _delim, name in client.list_folders()]


def require_folder(client: IMAPClient, folder: str) -> str:
    folder = clean_text(folder or "INBOX", "Folder", 200)
    names = folder_names(client)
    for name in names:
        if name == folder or (folder.upper() == "INBOX" and name.upper() == "INBOX"):
            return name
    raise MailError(f"There is no folder called '{folder}'. Folders: {', '.join(names)}")


def special_folder(client: IMAPClient, use: str, fallback: str) -> str:
    for flags, _delim, name in client.list_folders():
        if use.encode() in flags or use in [f.decode() if isinstance(f, bytes) else f for f in flags]:
            return name
    if fallback not in folder_names(client):
        client.create_folder(fallback)
    return fallback


# ---------- folders -------------------------------------------------------------------

def list_folders(client: IMAPClient) -> list[dict]:
    out = []
    for flags, _delim, name in client.list_folders():
        flags = [f.decode() if isinstance(f, bytes) else str(f) for f in flags]
        if "\\Noselect" in flags:
            continue
        status = client.folder_status(name, [b"MESSAGES", b"UNSEEN"])
        out.append({
            "name": name,
            "role": next((f[1:].lower() for f in flags if f in SPECIAL), "inbox" if name.upper() == "INBOX" else None),
            "messages": status.get(b"MESSAGES", 0),
            "unread": status.get(b"UNSEEN", 0),
        })
    return out


PROTECTED = {"INBOX", "SENT", "DRAFTS", "TRASH", "JUNK"}


def create_folder(client: IMAPClient, name: str) -> None:
    name = clean_text(name, "Folder name", 200).strip()
    if not name or name in folder_names(client):
        raise MailError("That folder name is empty or already exists.")
    client.create_folder(name)


def rename_folder(client: IMAPClient, old: str, new: str) -> None:
    old = require_folder(client, old)
    new = clean_text(new, "Folder name", 200).strip()
    if old.upper() in PROTECTED:
        raise MailError(f"'{old}' is a system folder and can't be renamed.")
    if not new or new in folder_names(client):
        raise MailError("The new name is empty or already exists.")
    client.rename_folder(old, new)


def delete_folder(client: IMAPClient, name: str) -> None:
    name = require_folder(client, name)
    if name.upper() in PROTECTED:
        raise MailError(f"'{name}' is a system folder and can't be deleted.")
    client.delete_folder(name)


# ---------- reading -------------------------------------------------------------------

SUMMARY_HEADERS = b"BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE)]"
SUMMARY_KEY = b"BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE)]"


def search(client: IMAPClient, folder: str, *, text=None, from_=None, to=None, subject=None,
           since=None, before=None, unread=None, flagged=None, limit=20, offset=0) -> dict:
    folder = require_folder(client, folder)
    client.select_folder(folder, readonly=True)
    criteria: list = []
    for key, value in (("TEXT", text), ("FROM", from_), ("TO", to), ("SUBJECT", subject)):
        if value:
            criteria += [key, clean_text(str(value), key.title(), 200)]
    for key, value in (("SINCE", since), ("BEFORE", before)):
        if value:
            try:
                criteria += [key, dt.date.fromisoformat(str(value)[:10])]
            except ValueError:
                raise MailError(f"{key.lower()} must be a date like 2026-01-31.") from None
    if unread is True:
        criteria.append("UNSEEN")
    elif unread is False:
        criteria.append("SEEN")
    if flagged is True:
        criteria.append("FLAGGED")
    elif flagged is False:
        criteria.append("UNFLAGGED")
    uids = sorted(client.search(criteria or ["ALL"], charset="UTF-8" if criteria else None), reverse=True)
    limit = max(1, min(int(limit or 20), 100))
    offset = max(0, int(offset or 0))
    page = uids[offset: offset + limit]
    data = client.fetch(page, [SUMMARY_HEADERS, b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE"]) if page else {}
    messages = []
    for uid in page:
        item = data.get(uid)
        if not item:
            continue
        hdr = email.message_from_bytes(item.get(SUMMARY_KEY, b""), policy=email.policy.default)
        flags = [f.decode() if isinstance(f, bytes) else str(f) for f in item.get(b"FLAGS", ())]
        messages.append({
            "uid": uid,
            "date": _date(hdr.get("Date")) or (item[b"INTERNALDATE"].isoformat() if item.get(b"INTERNALDATE") else None),
            "from": _addr_list(hdr.get("From")),
            "to": _addr_list(hdr.get("To")),
            "subject": _dec(hdr.get("Subject")),
            "unread": "\\Seen" not in flags,
            "flagged": "\\Flagged" in flags,
            "answered": "\\Answered" in flags,
            "has_attachments": (hdr.get_content_type() or "").startswith("multipart/mixed"),
            "size": item.get(b"RFC822.SIZE"),
        })
    return {"folder": folder, "total": len(uids), "offset": offset, "messages": messages}


def _fetch_raw(client: IMAPClient, folder: str, uid: int, mark_seen: bool) -> tuple[bytes, list[str]]:
    folder = require_folder(client, folder)
    client.select_folder(folder, readonly=not mark_seen)
    key = b"BODY[]" if mark_seen else b"BODY.PEEK[]"
    data = client.fetch([int(uid)], [key, b"FLAGS", b"RFC822.SIZE"])
    item = data.get(int(uid))
    if not item:
        raise MailError(f"No message with uid {uid} in '{folder}'.")
    if (item.get(b"RFC822.SIZE") or 0) > 50 * 1024 * 1024:
        raise MailError("That message is larger than 50 MB.")
    flags = [f.decode() if isinstance(f, bytes) else str(f) for f in item.get(b"FLAGS", ())]
    return item[b"BODY[]"], flags


def _attachments(msg) -> list:
    """Attached files, in order. A forwarded email (message/rfc822) counts as one attachment."""
    out = []

    def visit(part, top=False):
        if part.get_content_type() == "message/rfc822" and not top:
            out.append(part)
        elif part.is_multipart():
            for sub in part.iter_parts():
                visit(sub)
        elif part.get_content_disposition() == "attachment" or (
                part.get_content_disposition() == "inline" and part.get_filename()):
            out.append(part)

    visit(msg, top=True)
    return out


def _part_bytes(part) -> bytes:
    if part.get_content_type() == "message/rfc822":
        inner = part.get_payload(0) if part.is_multipart() else part.get_payload()
        return inner.as_bytes(policy=email.policy.SMTP) if hasattr(inner, "as_bytes") else str(inner).encode()
    return part.get_payload(decode=True) or b""


def _part_name(part, index: int) -> str:
    return part.get_filename() or ("message.eml" if part.get_content_type() == "message/rfc822" else f"attachment-{index}")


def read(client: IMAPClient, folder: str, uid: int, *, mark_seen=False, include_html=False, max_chars=100_000) -> dict:
    raw, flags = _fetch_raw(client, folder, uid, mark_seen)
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    text = text_part.get_content() if text_part else (_html_to_text(html_part.get_content()) if html_part else "")
    result = {
        "uid": int(uid),
        "folder": folder,
        "message_id": msg.get("Message-ID"),
        "date": _date(msg.get("Date")),
        "from": _addr_list(msg.get("From")),
        "reply_to": _addr_list(msg.get("Reply-To")),
        "to": _addr_list(msg.get("To")),
        "cc": _addr_list(msg.get("Cc")),
        "subject": _dec(msg.get("Subject")),
        "flags": flags,
        "text": text[:max_chars],
        "truncated": len(text) > max_chars,
        "attachments": [
            {"index": i, "filename": _part_name(p, i), "content_type": p.get_content_type(),
             "size": len(_part_bytes(p))}
            for i, p in enumerate(_attachments(msg))
        ],
    }
    if include_html and html_part:
        result["html"] = html_part.get_content()[:max_chars]
    return result


def attachment(client: IMAPClient, folder: str, uid: int, index: int) -> tuple[str, str, bytes]:
    raw, _ = _fetch_raw(client, folder, uid, False)
    parts = _attachments(email.message_from_bytes(raw, policy=email.policy.default))
    if not 0 <= int(index) < len(parts):
        raise MailError(f"That message has {len(parts)} attachment(s); index {index} doesn't exist.")
    part = parts[int(index)]
    return _part_name(part, int(index)), part.get_content_type(), _part_bytes(part)


# ---------- organizing ----------------------------------------------------------------

def _uids(uids) -> list[int]:
    if isinstance(uids, (int, str)):
        uids = [uids]
    out = [int(u) for u in uids or []]
    if not out or len(out) > 1000:
        raise MailError("Give between 1 and 1000 message uids.")
    return out


def set_flags(client: IMAPClient, folder: str, uids, *, seen=None, flagged=None, answered=None) -> int:
    folder = require_folder(client, folder)
    uids = _uids(uids)
    client.select_folder(folder)
    for flag, value in ((b"\\Seen", seen), (b"\\Flagged", flagged), (b"\\Answered", answered)):
        if value is True:
            client.add_flags(uids, [flag], silent=True)
        elif value is False:
            client.remove_flags(uids, [flag], silent=True)
    return len(uids)


def move(client: IMAPClient, folder: str, uids, target: str) -> int:
    folder = require_folder(client, folder)
    target = require_folder(client, target)
    uids = _uids(uids)
    if folder == target:
        raise MailError("The messages are already in that folder.")
    client.select_folder(folder)
    client.move(uids, target)
    return len(uids)


def delete(client: IMAPClient, folder: str, uids, *, permanent=False) -> str:
    folder = require_folder(client, folder)
    uids = _uids(uids)
    trash = special_folder(client, "\\Trash", "Trash")
    client.select_folder(folder)
    if permanent or folder == trash:
        client.add_flags(uids, [b"\\Deleted"], silent=True)
        client.uid_expunge(uids)
        return "deleted permanently"
    client.move(uids, trash)
    return f"moved to {trash}"


# ---------- writing and sending -------------------------------------------------------

def build(sender: str, *, to=(), cc=(), bcc=(), subject="", text="", html_body=None, attachments=(),
          in_reply_to=None, references=None, sender_name=None) -> tuple[EmailMessage, list[str]]:
    to, cc, bcc = clean_addresses(to, "To"), clean_addresses(cc, "Cc"), clean_addresses(bcc, "Bcc")
    recipients = [email.utils.parseaddr(a)[1] for a in to + cc + bcc]
    if len(recipients) > config.MAX_RECIPIENTS:
        raise MailError(f"At most {config.MAX_RECIPIENTS} recipients per message.")
    msg = EmailMessage()
    msg["From"] = email.utils.formataddr((clean_text(sender_name, "Name", 200), sender)) if sender_name else sender
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = clean_text(subject or "", "Subject")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=config.DOMAIN)
    if in_reply_to:
        msg["In-Reply-To"] = clean_text(in_reply_to, "In-Reply-To")
    if references:
        msg["References"] = clean_text(references, "References", 4000)
    msg.set_content(text or "")
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    total = 0
    for att in attachments or ():
        name = clean_text(att.get("filename") or "attachment", "Attachment name", 200).replace("/", "_")
        try:
            content = base64.b64decode(att.get("content_base64") or att.get("data") or "", validate=True)
        except (ValueError, TypeError):
            raise MailError(f"Attachment '{name}' isn't valid base64.") from None
        total += len(content)
        if total > config.MAX_ATTACHMENT_BYTES:
            raise MailError("Attachments are larger than 20 MB in total.")
        ctype = att.get("content_type") or "application/octet-stream"
        if not re.fullmatch(r"[\w.+-]+/[\w.+-]+", ctype):
            raise MailError(f"'{ctype}' isn't a valid content type.")
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=name)
    return msg, recipients


def send(address: str, password: str, msg: EmailMessage, recipients: list[str]) -> str:
    if not recipients:
        raise MailError("Add at least one recipient.")
    try:
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=_ssl(), timeout=60) as smtp:
            smtp.login(address, password)
            refused = smtp.send_message(msg, from_addr=address, to_addrs=recipients)
    except smtplib.SMTPAuthenticationError:
        raise MailError(f"The stored password for {address} no longer works.") from None
    except smtplib.SMTPRecipientsRefused as e:
        raise MailError(f"The mail server refused every recipient: {', '.join(e.recipients)}") from None
    except smtplib.SMTPSenderRefused as e:
        raise MailError(f"The mail server refused the sender: {e.smtp_error.decode(errors='replace')}") from None
    except (smtplib.SMTPException, OSError) as e:
        raise MailError(f"Sending failed: {e}") from None
    if refused:
        return f"sent, but refused for: {', '.join(refused)}"
    return "sent"


def append(client: IMAPClient, folder: str, msg: EmailMessage, flags=(b"\\Seen",)) -> None:
    client.append(folder, msg.as_bytes(policy=email.policy.SMTP), flags=flags)


def original(client: IMAPClient, folder: str, uid: int) -> email.message.EmailMessage:
    raw, _ = _fetch_raw(client, folder, uid, False)
    return email.message_from_bytes(raw, policy=email.policy.default)


def quote(orig, text: str) -> str:
    body = orig.get_body(preferencelist=("plain", "html"))
    content = ""
    if body is not None:
        content = body.get_content()
        if body.get_content_type() == "text/html":
            content = _html_to_text(content)
    who = _dec(orig.get("From")) or "someone"
    when = orig.get("Date") or ""
    quoted = "\n".join("> " + line for line in content.splitlines()[:500])
    return f"{text}\n\nOn {when}, {who} wrote:\n{quoted}\n"


def attach_original(msg: EmailMessage, orig) -> None:
    msg.add_attachment(orig, filename="forwarded-message.eml")  # attached whole, as message/rfc822


IMAPError = IMAPClientError
