"""MCP tools. Each one runs as the signed-in user, with that user's permissions narrowed
by the token's scopes, so an AI assistant can never do more than the person who connected it."""
import base64
import functools
import logging
from typing import Annotated, Any

import anyio
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import service
from .mailcore import MailError

log = logging.getLogger("mailapp.mcp")

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

Mailbox = Annotated[str, Field(description="Mailbox address, e.g. support@example.com (see list_mailboxes)")]
Folder = Annotated[str, Field(description="Folder name, e.g. INBOX, Sent, Drafts, Trash, Junk (see list_folders)")]
Uid = Annotated[int, Field(description="Message uid from search_emails")]
Uids = Annotated[list[int], Field(description="Message uids from search_emails")]
Addresses = Annotated[list[str], Field(description="Email addresses, e.g. ['Anna <anna@x.com>', 'bob@y.com']")]
Attachments = Annotated[list[dict] | None, Field(
    description="Files to attach: [{'filename': 'a.pdf', 'content_type': 'application/pdf', 'content_base64': '...'}]")]


def _principal() -> service.Principal:
    token = get_access_token()
    if token is None or not token.subject:
        raise ToolError("Not signed in.")
    try:
        return service.principal_for(int(token.subject), token.scopes, via="mcp")
    except service.Forbidden as e:
        raise ToolError(str(e)) from None


async def _run(fn, *args, **kwargs):
    p = _principal()
    try:
        return await anyio.to_thread.run_sync(functools.partial(fn, p, *args, **kwargs))
    except (service.Forbidden, service.NotFound, service.Invalid, MailError) as e:
        raise ToolError(str(e)) from None
    except ToolError:
        raise
    except Exception:  # noqa: BLE001 - never leak internals to the client
        log.exception("tool failed")
        raise ToolError("Something went wrong on the server. Try again, or check the server log.") from None


def register(mcp) -> None:
    # ----- who am I / where can I go -----
    @mcp.tool(annotations=READ)
    async def whoami() -> dict[str, Any]:
        """Who you are signed in as, your role and the permissions of this connection."""
        p = _principal()
        return {"email": p.email, "role": p.role, "scopes": sorted(p.scopes)}

    @mcp.tool(annotations=READ)
    async def list_mailboxes() -> list[dict]:
        """Mailboxes you can use, with your permissions on each (read, send, organize)."""
        return await _run(service.list_mailboxes)

    @mcp.tool(annotations=READ)
    async def list_folders(mailbox: Mailbox) -> list[dict]:
        """Folders of a mailbox with message and unread counts."""
        return await _run(service.list_folders, mailbox)

    # ----- reading -----
    @mcp.tool(annotations=READ)
    async def search_emails(
        mailbox: Mailbox,
        folder: Folder = "INBOX",
        text: Annotated[str | None, Field(description="Words anywhere in the message")] = None,
        from_address: Annotated[str | None, Field(description="Sender contains")] = None,
        to_address: Annotated[str | None, Field(description="Recipient contains")] = None,
        subject: Annotated[str | None, Field(description="Subject contains")] = None,
        since: Annotated[str | None, Field(description="On or after this date, YYYY-MM-DD")] = None,
        before: Annotated[str | None, Field(description="Before this date, YYYY-MM-DD")] = None,
        unread: Annotated[bool | None, Field(description="true = only unread, false = only read")] = None,
        flagged: Annotated[bool | None, Field(description="true = only flagged")] = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        """Find messages in a folder, newest first. Returns uids for read_email and the other tools."""
        return await _run(service.search, mailbox, folder, text=text, from_=from_address, to=to_address,
                          subject=subject, since=since, before=before, unread=unread, flagged=flagged,
                          limit=limit, offset=offset)

    @mcp.tool(annotations=READ)
    async def read_email(mailbox: Mailbox, uid: Uid, folder: Folder = "INBOX",
                         include_html: bool = False,
                         mark_as_read: Annotated[bool, Field(description="Needs 'organize' permission")] = False) -> dict[str, Any]:
        """Read one message: headers, plain text body and the list of attachments."""
        return await _run(service.read, mailbox, folder, uid, mark_seen=mark_as_read, include_html=include_html)

    @mcp.tool(annotations=READ)
    async def download_attachment(mailbox: Mailbox, uid: Uid, index: Annotated[int, Field(
            description="Attachment index from read_email")], folder: Folder = "INBOX") -> dict[str, Any]:
        """Get one attachment as base64 (up to 20 MB)."""
        name, ctype, data = await _run(service.attachment, mailbox, folder, uid, index)
        if len(data) > 20 * 1024 * 1024:
            raise ToolError("That attachment is larger than 20 MB.")
        return {"filename": name, "content_type": ctype, "size": len(data),
                "content_base64": base64.b64encode(data).decode()}

    # ----- writing -----
    @mcp.tool(annotations=WRITE)
    async def send_email(mailbox: Mailbox, to: Addresses, subject: str, text: str,
                         cc: Addresses | None = None, bcc: Addresses | None = None,
                         html: Annotated[str | None, Field(description="Optional HTML version of the body")] = None,
                         attachments: Attachments = None,
                         from_address: Annotated[str | None, Field(
                             description="Send as one of the mailbox's aliases instead")] = None,
                         from_name: Annotated[str | None, Field(description="Display name, e.g. 'Support team'")] = None,
                         ) -> dict[str, Any]:
        """Send an email from a mailbox. A copy is saved in its Sent folder."""
        return await _run(service.send, mailbox, to=to, subject=subject, text=text, html=html, cc=cc or [],
                          bcc=bcc or [], attachments=attachments or [], from_address=from_address, from_name=from_name)

    @mcp.tool(annotations=WRITE)
    async def reply_email(mailbox: Mailbox, uid: Uid, text: str, folder: Folder = "INBOX",
                          reply_all: bool = False, attachments: Attachments = None) -> dict[str, Any]:
        """Reply to a message (quotes it, keeps the conversation threaded, marks it answered)."""
        return await _run(service.reply, mailbox, folder, uid, text=text, reply_all=reply_all,
                          attachments=attachments or [])

    @mcp.tool(annotations=WRITE)
    async def forward_email(mailbox: Mailbox, uid: Uid, to: Addresses, text: str = "",
                            folder: Folder = "INBOX", cc: Addresses | None = None) -> dict[str, Any]:
        """Forward a message, attached in full, with an optional note."""
        return await _run(service.forward, mailbox, folder, uid, to=to, text=text, cc=cc or [])

    @mcp.tool(annotations=WRITE)
    async def save_draft(mailbox: Mailbox, subject: str, text: str, to: Addresses | None = None,
                         cc: Addresses | None = None, attachments: Attachments = None) -> dict[str, Any]:
        """Save a message in Drafts without sending it, so a person can review and send it."""
        return await _run(service.save_draft, mailbox, to=to or [], subject=subject, text=text, cc=cc or [],
                          attachments=attachments or [])

    # ----- organizing -----
    @mcp.tool(annotations=WRITE)
    async def mark_emails(mailbox: Mailbox, uids: Uids, folder: Folder = "INBOX",
                          read: Annotated[bool | None, Field(description="true = read, false = unread")] = None,
                          flagged: Annotated[bool | None, Field(description="true = flag, false = unflag")] = None,
                          ) -> dict[str, Any]:
        """Mark messages read/unread and flagged/unflagged."""
        return await _run(service.set_flags, mailbox, folder, uids, seen=read, flagged=flagged)

    @mcp.tool(annotations=WRITE)
    async def move_emails(mailbox: Mailbox, uids: Uids, to_folder: Folder, folder: Folder = "INBOX") -> dict[str, Any]:
        """Move messages to another folder."""
        return await _run(service.move, mailbox, folder, uids, to_folder)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def delete_emails(mailbox: Mailbox, uids: Uids, folder: Folder = "INBOX",
                            permanent: Annotated[bool, Field(description="Skip Trash and delete for good")] = False,
                            ) -> dict[str, Any]:
        """Move messages to Trash (or delete them permanently)."""
        return await _run(service.delete, mailbox, folder, uids, permanent=permanent)

    @mcp.tool(annotations=WRITE)
    async def create_folder(mailbox: Mailbox, name: str) -> dict[str, Any]:
        """Create a folder."""
        return await _run(service.create_folder, mailbox, name)

    @mcp.tool(annotations=WRITE)
    async def rename_folder(mailbox: Mailbox, folder: Folder, new_name: str) -> dict[str, Any]:
        """Rename a folder (not INBOX, Sent, Drafts, Trash or Junk)."""
        return await _run(service.rename_folder, mailbox, folder, new_name)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def delete_folder(mailbox: Mailbox, folder: Folder) -> dict[str, Any]:
        """Delete a folder and the messages in it (not system folders)."""
        return await _run(service.delete_folder, mailbox, folder)

    # ----- administration (admin role and 'admin' scope) -----
    @mcp.tool(annotations=READ)
    async def admin_list_users() -> list[dict]:
        """All console users with their role, two-step status and mailbox permissions."""
        return await _run(service.list_users)

    @mcp.tool(annotations=WRITE)
    async def admin_create_user(email: str, name: str = "",
                                role: Annotated[str, Field(pattern="^(admin|user)$")] = "user") -> dict[str, Any]:
        """Create a console user. Returns a temporary password they must change at first sign-in."""
        return await _run(service.create_user, email, name, role)

    @mcp.tool(annotations=WRITE)
    async def admin_update_user(email: str, name: str | None = None,
                                role: Annotated[str | None, Field(pattern="^(admin|user)$")] = None,
                                disabled: bool | None = None) -> dict[str, Any]:
        """Change a user's name or role, or disable/enable the account (disabling signs them out everywhere)."""
        uid = await _run(service.user_id_by_email, email)
        return await _run(service.update_user, uid, name=name, role=role, disabled=disabled)

    @mcp.tool(annotations=WRITE)
    async def admin_set_permissions(email: str, mailbox: Mailbox, read: bool = False, send: bool = False,
                                    organize: bool = False) -> dict[str, Any]:
        """Give a user access to a mailbox (all false = remove access)."""
        uid = await _run(service.user_id_by_email, email)
        return await _run(service.set_grant, uid, mailbox, read=read, send=send, organize=organize)

    @mcp.tool(annotations=WRITE)
    async def admin_reset_user_password(email: str) -> dict[str, Any]:
        """Give a user a new temporary password (signs them out everywhere)."""
        uid = await _run(service.user_id_by_email, email)
        return await _run(service.reset_user_password, uid)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def admin_delete_user(email: str) -> dict[str, Any]:
        """Delete a console user (their mailboxes are not touched)."""
        uid = await _run(service.user_id_by_email, email)
        return await _run(service.delete_user, uid)

    @mcp.tool(annotations=READ)
    async def admin_list_mailboxes() -> list[dict]:
        """Every mailbox on the server, its aliases and who has access."""
        return await _run(service.admin_mailboxes)

    @mcp.tool(annotations=WRITE)
    async def admin_create_mailbox(address: Mailbox) -> dict[str, Any]:
        """Create a mailbox. Returns its password once (for Outlook or other mail apps)."""
        return await _run(service.create_mailbox, address)

    @mcp.tool(annotations=WRITE)
    async def admin_reset_mailbox_password(address: Mailbox) -> dict[str, Any]:
        """New password for a mailbox (mail apps must be updated). Returned once."""
        return await _run(service.reset_mailbox_password, address)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def admin_delete_mailbox(address: Mailbox, confirm_address: Annotated[str, Field(
            description="Type the address again to confirm")]) -> dict[str, Any]:
        """Delete a mailbox and ALL its mail. Cannot be undone."""
        return await _run(service.delete_mailbox, address, confirm_address)

    @mcp.tool(annotations=READ)
    async def admin_list_aliases() -> list[dict]:
        """All aliases (forwarding addresses)."""
        return await _run(service.list_aliases)

    @mcp.tool(annotations=WRITE)
    async def admin_create_alias(alias: str, target: str) -> dict[str, Any]:
        """Forward mail for alias@domain to target."""
        return await _run(service.create_alias, alias, target)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def admin_delete_alias(alias: str, target: str) -> dict[str, Any]:
        """Stop forwarding alias to target."""
        return await _run(service.delete_alias, alias, target)

    @mcp.tool(annotations=READ)
    async def admin_audit_log(limit: Annotated[int, Field(ge=1, le=500)] = 50) -> list[dict[str, Any]]:
        """Recent security and admin events (sign-ins, sends, changes)."""
        return await _run(service.audit_log, limit)
