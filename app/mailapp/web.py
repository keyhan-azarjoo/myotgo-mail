"""The web console: sign-in, two-step verification, users, mailboxes, aliases, API tokens,
audit log, and the consent page MCP clients send people to."""
import json
import time

import anyio
from pathlib import Path
from urllib.parse import quote, urlsplit

import segno
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import auth, config, db, devices, mailconf, oauth, security, service
from .mailcore import MailError

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
COOKIE = "__Host-mailapp"
PRE_COOKIE = "__Host-mailapp-pre"
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

OK_MESSAGES = {
    "saved": "Saved.", "password": "Password changed.", "revoked": "Token revoked.", "deleted": "Deleted.",
    "alias": "Alias saved.", "linked": "Mailbox linked.", "two_step_off": "Two-step verification is off.",
    "settings": "Settings saved.", "grants": "Permissions saved.",
    "code_sent": "We emailed you a code. It works once and expires in 10 minutes.",
    "approved": "Approved: the message was sent.", "rejected": "Rejected: nothing was sent.",
}


# ---------- helpers ---------------------------------------------------------------------------

def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# sign-in pages hash passwords (64 MB each): they get their own small pool of threads, so a flood
# of sign-ins waits there instead of taking the threads every other page and API call needs
LOGIN_PATHS = ("/login", "/login/code", "/password")
_login_threads = anyio.CapacityLimiter(4)


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parts = urlsplit(value)
    return value if not parts.scheme and not parts.netloc else "/"


def _render(request, name, sess=None, status=200, **ctx):
    ctx.setdefault("pending_approvals", service.pending_count(sess["user_id"]) if sess else 0)
    ctx.update(request=request, sess=sess, app_name=config.APP_NAME, domain=config.DOMAIN,
               ok=OK_MESSAGES.get(request.query_params.get("ok", "")), csrf=sess["csrf"] if sess else "")
    resp = templates.TemplateResponse(request, name, ctx, status_code=status)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _fmt(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else ""


def _redirect(url: str):
    return RedirectResponse(url, status_code=303)


class Gate(Exception):
    def __init__(self, response):
        self.response = response


def _session(request: Request, *, admin=False, allow_pending=False):
    """The signed-in session, or a Gate exception holding the redirect to follow."""
    sess = auth.load_session(request.cookies.get(COOKIE))
    here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    if not sess:
        raise Gate(_redirect(f"/login?next={quote(here)}"))
    if sess["totp_enabled"] and not sess["mfa_ok"]:
        raise Gate(_redirect(f"/login/code?next={quote(here)}"))
    if not allow_pending:
        if sess["must_change_password"]:
            raise Gate(_redirect("/password"))
        if service.require_two_step() and not sess["totp_enabled"]:
            raise Gate(_redirect("/security?required=1"))
    if admin and sess["role"] != "admin":
        raise Gate(_render(request, "error.html", sess, 403, message="This page is for admins."))
    return sess


def _csrf(sess, token: str):
    if not sess or not security.same(sess["csrf"], token or ""):
        raise Gate(HTMLResponse("Invalid or expired form. Go back, reload the page and try again.", status_code=403))


def _p(request, sess) -> service.Principal:
    return service.principal_for(sess["user_id"], via="web", ip=_ip(request))


def guarded(fn):
    """Run a page handler in a worker thread (password hashing, database and IMAP work must never
    block the server), turn Gate into its response, and show service errors on an error page."""
    import functools

    @functools.wraps(fn)
    async def wrapper(request: Request, *args, **kwargs):
        if request.method == "POST":
            request.state.form = await request.form()   # read here; handlers run in a thread
        try:
            limiter = _login_threads if request.url.path in LOGIN_PATHS else None
            return await anyio.to_thread.run_sync(functools.partial(fn, request, *args, **kwargs), limiter=limiter)
        except Gate as g:
            return g.response
        except service.Forbidden as e:
            return _render(request, "error.html", auth.load_session(request.cookies.get(COOKIE)), 403, message=str(e))
        except service.NotFound as e:
            return _render(request, "error.html", auth.load_session(request.cookies.get(COOKIE)), 404, message=str(e))
        except (service.Invalid, MailError, auth.AuthError) as e:
            return _render(request, "error.html", auth.load_session(request.cookies.get(COOKIE)), 400, message=str(e))
    return wrapper


def _set_cookie(resp, sid: str):
    resp.set_cookie(COOKIE, sid, httponly=True, secure=True, samesite="strict", path="/",
                    max_age=config.SESSION_MAX_HOURS * 3600)
    return resp


# ---------- sign in / out -----------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
@guarded
def login_page(request: Request, next: str = "/"):
    pre = security.new_token()
    resp = _render(request, "login.html", next=_safe_next(next), pre=pre)
    # login CSRF protection: the form must come back with the value of this cookie
    resp.set_cookie(PRE_COOKIE, pre, httponly=True, secure=True, samesite="strict", path="/", max_age=3600)
    return resp


@router.post("/login")
@guarded
def login(request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("/"),
          pre: str = Form("")):
    cookie = request.cookies.get(PRE_COOKIE, "")
    if not cookie or not security.same(cookie, pre):
        return _redirect(f"/login?next={quote(_safe_next(next))}")   # form not from our page, or expired
    try:
        user = auth.check_password(email, password, _ip(request))
    except auth.AuthError as e:
        resp = _render(request, "login.html", status=401, error=str(e), email=email, next=_safe_next(next), pre=cookie)
        return resp
    auth.end_session(request.cookies.get(COOKIE))  # never reuse a session id across sign-ins
    sid, _ = auth.create_session(user["id"], mfa_ok=not user["totp_enabled"], ip=_ip(request))
    db.audit(user["email"], "login.password_ok", user["email"], None, _ip(request))
    target = f"/login/code?next={quote(_safe_next(next))}" if user["totp_enabled"] else _safe_next(next)
    if user["totp_enabled"] and user.get("two_step_method") == "email":
        try:
            auth.send_email_code(user["id"], _ip(request))
        except auth.AuthError:
            target += "&problem=send"
    return _set_cookie(_redirect(target), sid)


@router.get("/login/code", response_class=HTMLResponse)
@guarded
def code_page(request: Request, next: str = "/"):
    sess = auth.load_session(request.cookies.get(COOKIE))
    if not sess:
        return _redirect("/login")
    problem = "We couldn't send your code. Use “Send a new code” or a recovery code." \
        if request.query_params.get("problem") == "send" else None
    return _render(request, "code.html", sess, next=_safe_next(next), error=problem,
                   code_to=auth.masked(sess["two_step_email"]))


@router.post("/login/code/resend")
@guarded
def code_resend(request: Request, next: str = Form("/"), csrf: str = Form("")):
    sess = auth.load_session(request.cookies.get(COOKIE))
    if not sess:
        return _redirect("/login")
    _csrf(sess, csrf)
    auth.send_email_code(sess["user_id"], _ip(request))
    return _redirect(f"/login/code?next={quote(_safe_next(next))}&ok=code_sent")


@router.post("/login/code")
@guarded
def code(request: Request, code: str = Form(""), next: str = Form("/"), csrf: str = Form("")):
    sess = auth.load_session(request.cookies.get(COOKIE))
    if not sess:
        return _redirect("/login")
    _csrf(sess, csrf)
    if not auth.check_second_step(sess["user_id"], code, _ip(request)):
        return _render(request, "code.html", sess, 401, error="That code isn't right. Try the newest one.",
                       next=_safe_next(next))
    # new session id once fully signed in
    old = request.cookies.get(COOKIE)
    sid, _ = auth.create_session(sess["user_id"], mfa_ok=True, ip=_ip(request))
    auth.end_session(old)
    db.audit(sess["email"], "login.ok", sess["email"], {"two_step": True}, _ip(request))
    return _set_cookie(_redirect(_safe_next(next)), sid)


@router.post("/logout")
@guarded
def logout(request: Request, csrf: str = Form("")):
    sess = auth.load_session(request.cookies.get(COOKIE))
    if sess:
        _csrf(sess, csrf)
        auth.end_session(request.cookies.get(COOKIE))
    resp = _redirect("/login")
    resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.get("/password", response_class=HTMLResponse)
@guarded
def password_page(request: Request):
    sess = _session(request, allow_pending=True)
    return _render(request, "password.html", sess, is_mailbox=_is_mailbox(sess["email"]))


def _is_mailbox(email: str) -> bool:
    from . import mailconf
    return (email or "").lower() in mailconf.list_accounts()


@router.post("/password")
@guarded
def password(request: Request, current: str = Form(""), new: str = Form(""), again: str = Form(""),
                   csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    if new != again:
        return _render(request, "password.html", sess, 400, error="The two new passwords don't match.",
                       is_mailbox=_is_mailbox(sess["email"]))
    try:
        auth.change_password(sess["user_id"], current, new)
    except auth.AuthError as e:
        return _render(request, "password.html", sess, 400, error=str(e), is_mailbox=_is_mailbox(sess["email"]))
    sid, _ = auth.create_session(sess["user_id"], mfa_ok=True, ip=_ip(request))
    return _set_cookie(_redirect("/?ok=password"), sid)


# ---------- home, security, tokens ---------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
@guarded
def home(request: Request):
    sess = _session(request)
    p = _p(request, sess)
    return _render(request, "home.html", sess, mailboxes=service.list_mailboxes(p),
                   require_two_step=service.require_two_step())


@router.get("/security", response_class=HTMLResponse)
@guarded
def security_page(request: Request, required: str = ""):
    sess = _session(request, allow_pending=True)
    return _render(request, "security.html", sess, required=bool(required), is_mailbox=_is_mailbox(sess["email"]))


@router.post("/security/two-step/start", response_class=HTMLResponse)
@guarded
def two_step_start(request: Request, csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    if sess["totp_enabled"]:
        return _redirect("/security")
    secret, uri = auth.start_two_step(sess["user_id"])
    qr = segno.make(uri, error="m").svg_data_uri(scale=5, dark="#0f172a")
    return _render(request, "security.html", sess, setup=True, qr=qr, secret=secret)


@router.post("/security/two-step/confirm", response_class=HTMLResponse)
@guarded
def two_step_confirm(request: Request, code: str = Form(""), csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    codes = auth.confirm_two_step(sess["user_id"], code)
    if not codes:
        return _render(request, "security.html", sess, 400, error="That code didn't match. Start again.")
    auth.mark_session_mfa(request.cookies.get(COOKIE))
    sess = auth.load_session(request.cookies.get(COOKIE))
    return _render(request, "security.html", sess, recovery_codes=codes)


@router.post("/security/two-step/email/start", response_class=HTMLResponse)
@guarded
def email_two_step_start(request: Request, address: str = Form(""), csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    if sess["totp_enabled"]:
        return _redirect("/security")
    try:
        sent_to = auth.start_email_two_step(sess["user_id"], address, _ip(request))
    except auth.AuthError as e:
        return _render(request, "security.html", sess, 400, error=str(e), is_mailbox=_is_mailbox(sess["email"]))
    return _render(request, "security.html", sess, email_setup=True, sent_to=sent_to)


@router.post("/security/two-step/email/confirm", response_class=HTMLResponse)
@guarded
def email_two_step_confirm(request: Request, code: str = Form(""), csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    codes = auth.confirm_email_two_step(sess["user_id"], code)
    if not codes:
        return _render(request, "security.html", sess, 400, error="That code didn't match or expired. Start again.")
    auth.mark_session_mfa(request.cookies.get(COOKIE))
    sess = auth.load_session(request.cookies.get(COOKIE))
    return _render(request, "security.html", sess, recovery_codes=codes)


@router.post("/two-step/send-code")
@guarded
def send_code(request: Request, next: str = Form("/"), csrf: str = Form("")):
    """'Email me a code' on the token and consent pages."""
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    auth.send_email_code(sess["user_id"], _ip(request))
    target = _safe_next(next)
    return _redirect(target + ("&" if "?" in target else "?") + "ok=code_sent")


@router.post("/security/two-step/disable")
@guarded
def two_step_disable(request: Request, code: str = Form(""), csrf: str = Form("")):
    sess = _session(request, allow_pending=True)
    _csrf(sess, csrf)
    if service.require_two_step():
        return _render(request, "security.html", sess, 400, error="Your admin requires two-step verification.")
    if not auth.check_second_step(sess["user_id"], code, _ip(request)):
        return _render(request, "security.html", sess, 400, error="That code isn't right.")
    auth.disable_two_step(sess["user_id"])
    return _redirect("/security?ok=two_step_off")


@router.get("/tokens", response_class=HTMLResponse)
@guarded
def tokens_page(request: Request):
    sess = _session(request)
    return _render(request, "tokens.html", sess, tokens=auth.list_api_tokens(sess["user_id"]), now=time.time(),
                   scopes=_scopes_for(sess), here="/tokens", grants=auth.list_oauth_grants(sess["user_id"]), fmt=_fmt)


def _scopes_for(sess):
    return [s for s in service.SCOPES if s != "admin" or sess["role"] == "admin"]


@router.post("/tokens", response_class=HTMLResponse)
@guarded
def token_create(request: Request, name: str = Form(""), days: int = Form(90), code: str = Form(""),
                 direct_send: str = Form(""), csrf: str = Form("")):
    sess = _session(request)
    _csrf(sess, csrf)
    form = request.state.form
    scopes = form.getlist("scopes")
    ctx = dict(tokens=auth.list_api_tokens(sess["user_id"]), now=time.time(), scopes=_scopes_for(sess), here="/tokens",
               grants=auth.list_oauth_grants(sess["user_id"]), fmt=_fmt)
    if sess["totp_enabled"] and not auth.check_second_step(sess["user_id"], code, _ip(request)):
        return _render(request, "tokens.html", sess, 400, error="Enter a current two-step code to create a token.", **ctx)
    try:
        token, info = auth.create_api_token(sess["user_id"], name, scopes, days if days in (7, 30, 90, 365) else 90,
                                            mfa=bool(sess["totp_enabled"]), direct_send=bool(direct_send))
    except auth.AuthError as e:
        return _render(request, "tokens.html", sess, 400, error=str(e), **ctx)
    ctx["tokens"] = auth.list_api_tokens(sess["user_id"])
    return _render(request, "tokens.html", sess, new_token=token, new_info=info, **ctx)


@router.post("/tokens/{token_id}/revoke")
@guarded
def token_revoke(request: Request, token_id: int, csrf: str = Form("")):
    sess = _session(request)
    _csrf(sess, csrf)
    auth.revoke_api_token(sess["user_id"], token_id)
    return _redirect("/tokens?ok=revoked")


@router.post("/tokens/apps/{grant_id}/revoke")
@guarded
def app_revoke(request: Request, grant_id: str, csrf: str = Form("")):
    sess = _session(request)
    _csrf(sess, csrf)
    auth.revoke_oauth_grant(sess["user_id"], grant_id)
    return _redirect("/tokens?ok=revoked")


@router.get("/approvals", response_class=HTMLResponse)
@guarded
def approvals_page(request: Request):
    sess = _session(request)
    p = _p(request, sess)
    pending = [service.approval_detail(p, a["id"]) for a in service.list_approvals(p)]
    done = [a for a in service.list_approvals(p, include_done=True) if a["status"] != "pending"][:20]
    return _render(request, "approvals.html", sess, pending=pending, done=done, fmt=_fmt)


@router.post("/approvals/{approval_id}")
@guarded
def approval_decide(request: Request, approval_id: int, decision: str = Form(""), csrf: str = Form("")):
    sess = _session(request)
    _csrf(sess, csrf)
    if decision not in ("approve", "reject"):
        raise service.Invalid("Choose approve or reject.")
    service.decide_approval(_p(request, sess), approval_id, decision == "approve")
    return _redirect("/approvals?ok=" + ("approved" if decision == "approve" else "rejected"))


@router.get("/connect", response_class=HTMLResponse)
@guarded
def connect(request: Request):
    sess = _session(request)
    return _render(request, "connect.html", sess, mcp_url=config.MCP_URL, api_url=f"{config.PUBLIC_URL}/api/v1",
                   mail_host=config.MAIL_HOST)


# ---------- add a mailbox to a phone or computer with a QR code ---------------------------------

@router.get("/setup/{address}", response_class=HTMLResponse)
@guarded
def device_setup(request: Request, address: str):
    sess = _session(request)
    address = address.strip().lower()
    if address not in service.mailbox_permissions(_p(request, sess)):
        raise service.Forbidden(f"You don't have access to {address}.")
    link = f"{config.PUBLIC_URL}/d/{devices.make_link(address)}"
    qr = segno.make(link, error="m").svg_data_uri(scale=5, dark="#0f172a")
    return _render(request, "setup.html", sess, s=devices.settings(address), qr=qr, link=link,
                   minutes=devices.LINK_SECONDS // 60)


def _device_address(token: str) -> str:
    address = devices.check_link(token)
    if not address or address not in mailconf.list_accounts():
        raise Gate(HTMLResponse("This setup link has expired or isn't valid. Open the console and show the "
                                "QR code again.", status_code=404))
    return address


@router.get("/d/{token}", response_class=HTMLResponse)
@guarded
def device_page(request: Request, token: str):
    address = _device_address(token)
    return _render(request, "device.html", s=devices.settings(address), token=token)


@router.get("/d/{token}/mail.mobileconfig")
@guarded
def device_profile(request: Request, token: str):
    address = _device_address(token)
    db.audit(address, "device.profile", address, None, _ip(request))
    return Response(devices.profile(address), media_type="application/x-apple-aspen-config", headers={
        "Content-Disposition": f'attachment; filename="{address}.mobileconfig"', "Cache-Control": "no-store"})


# ---------- admin: users ------------------------------------------------------------------------

@router.get("/admin/users", response_class=HTMLResponse)
@guarded
def users(request: Request):
    sess = _session(request, admin=True)
    return _render(request, "users.html", sess, users=service.list_users(_p(request, sess)), fmt=_fmt)


@router.post("/admin/users", response_class=HTMLResponse)
@guarded
def user_create(request: Request, email: str = Form(""), name: str = Form(""), role: str = Form("user"),
                      csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    p = _p(request, sess)
    try:
        result = service.create_user(p, email, name, role)
    except service.Invalid as e:
        return _render(request, "users.html", sess, 400, users=service.list_users(p), error=str(e), fmt=_fmt)
    return _render(request, "secret.html", sess, title="Account created",
                   lines=[("User name", result["user"]["email"]), ("Temporary password", result["temporary_password"])],
                   note="Give these to the person. They must choose their own password when they first sign in.",
                   back=f"/admin/users/{result['user']['id']}", back_label="Set mailbox permissions")


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
@guarded
def user_page(request: Request, user_id: int):
    sess = _session(request, admin=True)
    p = _p(request, sess)
    user = service.get_user(p, user_id)
    grants = {g["mailbox"]: g for g in user["grants"]}
    return _render(request, "user.html", sess, user=user, grants=grants,
                   mailboxes=[m["address"] for m in service.admin_mailboxes(p)])


@router.post("/admin/users/{user_id}")
@guarded
def user_update(request: Request, user_id: int, name: str = Form(""), role: str = Form("user"),
                      disabled: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.update_user(_p(request, sess), user_id, name=name, role=role, disabled=bool(disabled))
    return _redirect(f"/admin/users/{user_id}?ok=saved")


@router.post("/admin/users/{user_id}/grants")
@guarded
def user_grants(request: Request, user_id: int, csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    p = _p(request, sess)
    form = request.state.form
    for mailbox in [m["address"] for m in service.admin_mailboxes(p)]:
        service.set_grant(p, user_id, mailbox, read=form.get(f"read:{mailbox}") == "1",
                          send=form.get(f"send:{mailbox}") == "1", organize=form.get(f"organize:{mailbox}") == "1")
    return _redirect(f"/admin/users/{user_id}?ok=grants")


@router.post("/admin/users/{user_id}/reset-password", response_class=HTMLResponse)
@guarded
def user_reset(request: Request, user_id: int, csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    r = service.reset_user_password(_p(request, sess), user_id)
    return _render(request, "secret.html", sess, title="New temporary password",
                   lines=[("User name", r["email"]), ("Temporary password", r["temporary_password"])],
                   note="They have been signed out everywhere and must choose a new password at sign-in.",
                   back=f"/admin/users/{user_id}", back_label="Back to user")


@router.post("/admin/users/{user_id}/reset-two-step")
@guarded
def user_reset_two_step(request: Request, user_id: int, csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.reset_user_two_step(_p(request, sess), user_id)
    return _redirect(f"/admin/users/{user_id}?ok=saved")


@router.post("/admin/users/{user_id}/delete")
@guarded
def user_delete(request: Request, user_id: int, csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.delete_user(_p(request, sess), user_id)
    return _redirect("/admin/users?ok=deleted")


# ---------- admin: mailboxes and aliases ------------------------------------------------------------

@router.get("/admin/mailboxes", response_class=HTMLResponse)
@guarded
def mailboxes(request: Request):
    sess = _session(request, admin=True)
    p = _p(request, sess)
    return _render(request, "mailboxes.html", sess, mailboxes=service.admin_mailboxes(p),
                   aliases=service.list_aliases(p))


@router.post("/admin/mailboxes", response_class=HTMLResponse)
@guarded
def mailbox_create(request: Request, local: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    address = local if "@" in local else f"{local}@{config.DOMAIN}"
    r = service.create_mailbox(_p(request, sess), address)
    return _render(request, "secret.html", sess, title="Mailbox created",
                   lines=[("Address", r["address"]), ("Password", r["password"]),
                          ("Incoming (IMAP)", f"{config.MAIL_HOST} · port 993 · SSL/TLS"),
                          ("Outgoing (SMTP)", f"{config.MAIL_HOST} · port 465 · SSL/TLS")],
                   note=r["note"], back="/admin/mailboxes", back_label="Back to mailboxes")


@router.post("/admin/mailboxes/{address}/reset", response_class=HTMLResponse)
@guarded
def mailbox_reset(request: Request, address: str, csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    r = service.reset_mailbox_password(_p(request, sess), address)
    return _render(request, "secret.html", sess, title="New mailbox password",
                   lines=[("Address", r["address"]), ("Password", r["password"])], note=r["note"],
                   back="/admin/mailboxes", back_label="Back to mailboxes")


@router.post("/admin/mailboxes/{address}/link")
@guarded
def mailbox_link(request: Request, address: str, password: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.link_mailbox(_p(request, sess), address, password)
    return _redirect("/admin/mailboxes?ok=linked")


@router.post("/admin/mailboxes/{address}/delete")
@guarded
def mailbox_delete(request: Request, address: str, confirm: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.delete_mailbox(_p(request, sess), address, confirm)
    return _redirect("/admin/mailboxes?ok=deleted")


@router.post("/admin/aliases")
@guarded
def alias_create(request: Request, alias: str = Form(""), target: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    alias = alias if "@" in alias else f"{alias}@{config.DOMAIN}"
    service.create_alias(_p(request, sess), alias, target)
    return _redirect("/admin/mailboxes?ok=alias")


@router.post("/admin/aliases/delete")
@guarded
def alias_delete(request: Request, alias: str = Form(""), target: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    service.delete_alias(_p(request, sess), alias, target)
    return _redirect("/admin/mailboxes?ok=deleted")


# ---------- admin: audit and settings ---------------------------------------------------------------

@router.get("/admin/audit", response_class=HTMLResponse)
@guarded
def audit(request: Request, page: int = 0):
    sess = _session(request, admin=True)
    rows = service.audit_log(_p(request, sess), 100, max(0, page) * 100)
    return _render(request, "audit.html", sess, rows=rows, page=max(0, page),
                   fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)))


@router.get("/admin/settings", response_class=HTMLResponse)
@guarded
def settings_page(request: Request):
    sess = _session(request, admin=True)
    return _render(request, "settings.html", sess, require_two_step=service.require_two_step(),
                   senders=_linked_mailboxes(), code_sender=auth.code_sender() or "",
                   allow_local=db.setting("allow_local_code_mailboxes", "0") == "1")


def _linked_mailboxes():
    return [r["address"] for r in db.query("SELECT address FROM mailboxes WHERE password IS NOT NULL ORDER BY address")]


@router.post("/admin/settings")
@guarded
def settings_save(request: Request, require_two_step: str = Form(""), code_sender: str = Form(""),
                  allow_local: str = Form(""), csrf: str = Form("")):
    sess = _session(request, admin=True)
    _csrf(sess, csrf)
    if require_two_step and not sess["totp_enabled"]:
        return _render(request, "settings.html", sess, 400, require_two_step=False, senders=_linked_mailboxes(),
                       code_sender=auth.code_sender() or "", allow_local=False,
                       error="Turn on two-step verification for your own account first.")
    if code_sender and code_sender in _linked_mailboxes():
        db.set_setting("code_sender", code_sender)
    db.set_setting("allow_local_code_mailboxes", "1" if allow_local else "0")
    service.set_require_two_step(_p(request, sess), bool(require_two_step))
    return _redirect("/admin/settings?ok=settings")


# ---------- OAuth consent (MCP clients such as Claude) ------------------------------------------------

def _allow_redirect_to(resp, redirect_uri: str):
    """Browsers apply the form page's CSP form-action to the redirect after submitting,
    so the consent page must allow the client's callback address."""
    parts = urlsplit(redirect_uri)
    origin = f"{parts.scheme}://{parts.netloc}"
    resp.headers["Content-Security-Policy"] = CSP.replace("form-action 'self'", f"form-action 'self' {origin}")
    return resp


SCOPE_TEXT = {
    "mail.read": "Read your mailboxes: folders, messages and attachments",
    "mail.send": "Send, reply, forward and save drafts",
    "mail.organize": "Flag, move and delete messages; manage folders",
    "admin": "Administer users, mailboxes and aliases",
}


@router.get("/oauth/consent", response_class=HTMLResponse)
@guarded
def consent_page(request: Request):
    rid = request.query_params.get("request", "")
    sess = _session(request)
    row, client, params = oauth.pending_request(rid)
    if not row:
        return _render(request, "error.html", sess, 400, message="This sign-in request expired. Start again from your app.")
    if not sess["totp_enabled"] and service.require_two_step():
        return _redirect("/security?required=1")
    return _consent(request, sess, rid, client, params)


def _consent(request, sess, rid, client, params, status=200, error=None):
    offered = oauth.offered_scopes(client, params, sess["role"])
    resp = _render(request, "consent.html", sess, status, rid=rid, client=client,
                   redirect_host=urlsplit(str(params.redirect_uri)).hostname,
                   scopes=[(s, SCOPE_TEXT[s]) for s in offered if s != "admin"],
                   offer_admin="admin" in offered, need_code=bool(sess["totp_enabled"]),
                   code_to=auth.masked(sess["two_step_email"]), error=error,
                   here=f"/oauth/consent?request={rid}")
    return _allow_redirect_to(resp, str(params.redirect_uri))


@router.post("/oauth/consent")
@guarded
def consent(request: Request, request_id: str = Form(""), decision: str = Form(""), code: str = Form(""),
            allow_admin: str = Form(""), direct_send: str = Form(""), csrf: str = Form("")):
    sess = _session(request)
    _csrf(sess, csrf)
    if decision != "approve":
        url = oauth.deny(request_id)
        return _redirect(url) if url else _redirect("/")
    if service.require_two_step() and not sess["totp_enabled"]:
        return _redirect("/security?required=1")
    row, client, params = oauth.pending_request(request_id)
    if not row:
        return _render(request, "error.html", sess, 400, message="This sign-in request expired. Start again from your app.")
    if sess["totp_enabled"] and not auth.check_second_step(sess["user_id"], code, _ip(request)):
        return _consent(request, sess, request_id, client, params, 401, "That two-step code isn't right.")
    return _redirect(oauth.approve(request_id, sess["user_id"], mfa=bool(sess["totp_enabled"]),
                                   allow_admin=bool(allow_admin), direct_send=bool(direct_send)))


__all__ = ["router", "json"]
