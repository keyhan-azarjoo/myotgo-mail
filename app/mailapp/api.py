"""REST API: /api/v1/... with `Authorization: Bearer <token>` (a personal API token from the
console, or an OAuth access token). Same permissions as the MCP tools."""
import base64

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from . import security, service
from .mailcore import MailError
from .oauth import Provider

router = APIRouter(prefix="/api/v1")
_provider = Provider()


async def principal(request: Request) -> service.Principal:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "Send 'Authorization: Bearer <token>'.", headers={"WWW-Authenticate": "Bearer"})
    token = await _provider.load_access_token(header[7:].strip())
    if token is None:
        raise HTTPException(401, "The token is invalid, expired or revoked.", headers={"WWW-Authenticate": "Bearer"})
    if security.rate_limited(f"api:{security.token_hash(token.token)[:16]}", 600, 60):
        raise HTTPException(429, "Too many requests. Slow down.")
    try:
        return service.principal_for(int(token.subject), token.scopes, via="api", ip=request.client.host)
    except service.Forbidden as e:
        raise HTTPException(403, str(e)) from None


async def call(fn, *args, **kwargs):
    try:
        return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))
    except service.Forbidden as e:
        raise HTTPException(403, str(e)) from None
    except service.NotFound as e:
        raise HTTPException(404, str(e)) from None
    except (service.Invalid, MailError) as e:
        raise HTTPException(400, str(e)) from None


P = Depends(principal)


class Attachment(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    content_base64: str


class SendBody(BaseModel):
    to: list[str]
    subject: str = ""
    text: str = ""
    html: str | None = None
    cc: list[str] = []
    bcc: list[str] = []
    attachments: list[Attachment] = []
    from_address: str | None = None
    from_name: str | None = None


class ReplyBody(BaseModel):
    text: str
    reply_all: bool = False
    attachments: list[Attachment] = []


class ForwardBody(BaseModel):
    to: list[str]
    text: str = ""
    cc: list[str] = []


class DraftBody(BaseModel):
    to: list[str] = []
    cc: list[str] = []
    subject: str = ""
    text: str = ""
    attachments: list[Attachment] = []


class FlagsBody(BaseModel):
    uids: list[int] = Field(min_length=1, max_length=1000)
    read: bool | None = None
    flagged: bool | None = None


class MoveBody(BaseModel):
    uids: list[int] = Field(min_length=1, max_length=1000)
    to_folder: str


class DeleteBody(BaseModel):
    uids: list[int] = Field(min_length=1, max_length=1000)
    permanent: bool = False


class FolderBody(BaseModel):
    name: str


class RenameBody(BaseModel):
    new_name: str


class UserBody(BaseModel):
    email: str
    name: str = ""
    role: str = "user"


class UserUpdate(BaseModel):
    name: str | None = None
    role: str | None = None
    disabled: bool | None = None


class GrantBody(BaseModel):
    mailbox: str
    read: bool = False
    send: bool = False
    organize: bool = False


class MailboxBody(BaseModel):
    address: str


class AliasBody(BaseModel):
    alias: str
    target: str


def _atts(items):
    return [a.model_dump() for a in items]


# ---------- me ----------
@router.get("/me")
async def me(p=P):
    return {"email": p.email, "role": p.role, "scopes": sorted(p.scopes)}


@router.get("/mailboxes")
async def mailboxes(p=P):
    return await call(service.list_mailboxes, p)


@router.get("/mailboxes/{mailbox}/folders")
async def folders(mailbox: str, p=P):
    return await call(service.list_folders, p, mailbox)


@router.post("/mailboxes/{mailbox}/folders", status_code=201)
async def folder_create(mailbox: str, body: FolderBody, p=P):
    return await call(service.create_folder, p, mailbox, body.name)


@router.patch("/mailboxes/{mailbox}/folders/{folder:path}")
async def folder_rename(mailbox: str, folder: str, body: RenameBody, p=P):
    return await call(service.rename_folder, p, mailbox, folder, body.new_name)


@router.delete("/mailboxes/{mailbox}/folders/{folder:path}")
async def folder_delete(mailbox: str, folder: str, p=P):
    return await call(service.delete_folder, p, mailbox, folder)


# ---------- messages ----------
@router.get("/mailboxes/{mailbox}/messages")
async def messages(mailbox: str, p=P, folder: str = "INBOX", q: str | None = None, from_: str | None = Query(None, alias="from"),
                   to: str | None = None, subject: str | None = None, since: str | None = None, before: str | None = None,
                   unread: bool | None = None, flagged: bool | None = None,
                   limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    return await call(service.search, p, mailbox, folder, text=q, from_=from_, to=to, subject=subject, since=since,
                      before=before, unread=unread, flagged=flagged, limit=limit, offset=offset)


@router.get("/mailboxes/{mailbox}/messages/{uid}")
async def message(mailbox: str, uid: int, p=P, folder: str = "INBOX", html: bool = False, mark_read: bool = False):
    return await call(service.read, p, mailbox, folder, uid, mark_seen=mark_read, include_html=html)


@router.get("/mailboxes/{mailbox}/messages/{uid}/attachments/{index}")
async def attachment(mailbox: str, uid: int, index: int, p=P, folder: str = "INBOX"):
    name, ctype, data = await call(service.attachment, p, mailbox, folder, uid, index)
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "._- ")[:150] or "attachment"
    # always a download, never rendered: the content type comes from whoever sent the email
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Original-Content-Type": ctype[:100]})


@router.post("/mailboxes/{mailbox}/send")
async def send(mailbox: str, body: SendBody, p=P):
    return await call(service.send, p, mailbox, to=body.to, subject=body.subject, text=body.text, html=body.html,
                      cc=body.cc, bcc=body.bcc, attachments=_atts(body.attachments), from_address=body.from_address,
                      from_name=body.from_name)


@router.post("/mailboxes/{mailbox}/messages/{uid}/reply")
async def reply(mailbox: str, uid: int, body: ReplyBody, p=P, folder: str = "INBOX"):
    return await call(service.reply, p, mailbox, folder, uid, text=body.text, reply_all=body.reply_all,
                      attachments=_atts(body.attachments))


@router.post("/mailboxes/{mailbox}/messages/{uid}/forward")
async def forward(mailbox: str, uid: int, body: ForwardBody, p=P, folder: str = "INBOX"):
    return await call(service.forward, p, mailbox, folder, uid, to=body.to, text=body.text, cc=body.cc)


@router.post("/mailboxes/{mailbox}/drafts", status_code=201)
async def draft(mailbox: str, body: DraftBody, p=P):
    return await call(service.save_draft, p, mailbox, to=body.to, cc=body.cc, subject=body.subject, text=body.text,
                      attachments=_atts(body.attachments))


@router.post("/mailboxes/{mailbox}/messages/flags")
async def flags(mailbox: str, body: FlagsBody, p=P, folder: str = "INBOX"):
    return await call(service.set_flags, p, mailbox, folder, body.uids, seen=body.read, flagged=body.flagged)


@router.post("/mailboxes/{mailbox}/messages/move")
async def move(mailbox: str, body: MoveBody, p=P, folder: str = "INBOX"):
    return await call(service.move, p, mailbox, folder, body.uids, body.to_folder)


@router.post("/mailboxes/{mailbox}/messages/delete")
async def delete(mailbox: str, body: DeleteBody, p=P, folder: str = "INBOX"):
    return await call(service.delete, p, mailbox, folder, body.uids, body.permanent)


# ---------- admin ----------
@router.get("/admin/users")
async def users(p=P):
    return await call(service.list_users, p)


@router.post("/admin/users", status_code=201)
async def user_create(body: UserBody, p=P):
    return await call(service.create_user, p, body.email, body.name, body.role)


@router.get("/admin/users/{user_id}")
async def user_get(user_id: int, p=P):
    return await call(service.get_user, p, user_id)


@router.patch("/admin/users/{user_id}")
async def user_update(user_id: int, body: UserUpdate, p=P):
    return await call(service.update_user, p, user_id, name=body.name, role=body.role, disabled=body.disabled)


@router.post("/admin/users/{user_id}/reset-password")
async def user_reset(user_id: int, p=P):
    return await call(service.reset_user_password, p, user_id)


@router.post("/admin/users/{user_id}/reset-two-step")
async def user_reset_2fa(user_id: int, p=P):
    return await call(service.reset_user_two_step, p, user_id)


@router.put("/admin/users/{user_id}/grants")
async def user_grant(user_id: int, body: GrantBody, p=P):
    return await call(service.set_grant, p, user_id, body.mailbox, read=body.read, send=body.send,
                      organize=body.organize)


@router.delete("/admin/users/{user_id}")
async def user_delete(user_id: int, p=P):
    return await call(service.delete_user, p, user_id)


@router.get("/admin/mailboxes")
async def admin_mailboxes(p=P):
    return await call(service.admin_mailboxes, p)


@router.post("/admin/mailboxes", status_code=201)
async def mailbox_create(body: MailboxBody, p=P):
    return await call(service.create_mailbox, p, body.address)


@router.post("/admin/mailboxes/{address}/reset-password")
async def mailbox_reset(address: str, p=P):
    return await call(service.reset_mailbox_password, p, address)


@router.delete("/admin/mailboxes/{address}")
async def mailbox_delete(address: str, p=P, confirm: str = ""):
    return await call(service.delete_mailbox, p, address, confirm)


@router.get("/admin/aliases")
async def aliases(p=P):
    return await call(service.list_aliases, p)


@router.post("/admin/aliases", status_code=201)
async def alias_create(body: AliasBody, p=P):
    return await call(service.create_alias, p, body.alias, body.target)


@router.delete("/admin/aliases")
async def alias_delete(alias: str, target: str, p=P):
    return await call(service.delete_alias, p, alias, target)


@router.get("/admin/audit")
async def audit(p=P, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    return await call(service.audit_log, p, limit, offset)


def error_handler(request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)


__all__ = ["router", "error_handler", "base64"]
