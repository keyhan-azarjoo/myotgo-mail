"""End-to-end tests against a running server: web console, REST API, MCP and OAuth, plus the
security rules. They create their own mailboxes and users (prefixed e2e-) and remove them.

  ./mail app-test            (runs this with the right settings)

Two-step verification uses email codes here: every test login is also a mailbox on the
server, and the tests read the codes from it over IMAP.

Environment:
  BASE_URL                https://mx.example.com
  DOMAIN                  example.com
  ADMIN_EMAIL             an admin login made for the test; also a mailbox
  ADMIN_PASSWORD          its temporary console password
  ADMIN_MAILBOX_PASSWORD  the mailbox password
  CODES_MAILBOX           a separate mailbox that receives every test user's sign-in codes
  CODES_PASSWORD          its password
"""
import asyncio
import base64
import hashlib
import os
import re
import secrets
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import imaplib
import ssl

import httpx
import pytest

BASE = os.environ["BASE_URL"].rstrip("/")
DOMAIN = os.environ["DOMAIN"]
RUN = uuid.uuid4().hex[:6]
S: dict = {"seen_codes": set()}  # state shared by the ordered tests below
MAILBOX_PW: dict = {}             # address -> mailbox password, to read emailed codes

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


# ---------- helpers ------------------------------------------------------------------------------

def addr(name):
    return f"e2e-{RUN}-{name}@{DOMAIN}"


CODES = os.environ["CODES_MAILBOX"]


def emailed_code(address, timeout=60):
    """The newest sign-in code for login `address` (sent to the CODES mailbox) not used yet."""
    host = urlsplit(BASE).hostname
    deadline = time.time() + timeout
    while time.time() < deadline:
        with imaplib.IMAP4_SSL(host, 993, ssl_context=ssl.create_default_context()) as im:
            im.login(CODES, os.environ["CODES_PASSWORD"])
            im.select("INBOX")
            _, data = im.search(None, "SUBJECT", '"Your sign-in code"', "BODY", f'"for {address}"')
            for num in reversed(data[0].split()):
                _, hdr = im.fetch(num, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
                m = re.search(rb"Your sign-in code: (\d{6})", hdr[0][1])
                if m and (address, m.group(1).decode()) not in S["seen_codes"]:
                    S["seen_codes"].add((address, m.group(1).decode()))
                    return m.group(1).decode()
                break   # only the newest code is valid
        time.sleep(2)
    raise AssertionError(f"no sign-in code arrived for {address}")


class Browser:
    def __init__(self):
        self.c = httpx.Client(base_url=BASE, follow_redirects=False, timeout=60)

    def csrf(self, html):
        m = re.search(r'name="csrf" value="([^"]+)"', html)
        assert m, "no csrf field on page"
        return m.group(1)

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post_form(self, page, path, data):
        page_html = self.c.get(page).text
        return self.c.post(path, data={"csrf": self.csrf(page_html), **data})

    def post_login(self, email, password, next_="/"):
        """Submit the sign-in form the way a browser does (it carries the page's login token)."""
        page = self.c.get("/login")
        pre = re.search(r'name="pre" value="([^"]+)"', page.text).group(1)
        return self.c.post("/login", data={"email": email, "password": password, "next": next_, "pre": pre})

    def login(self, email, password, next_="/"):
        r = self.post_login(email, password, next_)
        if r.status_code != 303:
            return r
        if r.headers["location"].startswith("/login/code"):
            page = self.c.get(r.headers["location"])
            r = self.c.post("/login/code", data={"csrf": self.csrf(page.text), "code": emailed_code(email),
                                                  "next": next_})
        return r

    def fresh_code(self, email, page_path):
        """Press 'Email me a code' on a page and return the code that arrives."""
        page = self.c.get(page_path)
        r = self.c.post("/two-step/send-code", data={"csrf": self.csrf(page.text), "next": page_path})
        assert r.status_code == 303, r.text[:300]
        return emailed_code(email)

    def set_password(self, current, new):
        page = self.c.get("/password")
        return self.c.post("/password", data={"csrf": self.csrf(page.text), "current": current, "new": new, "again": new})

    def enable_two_step(self, email):
        """Two-step verification by email codes."""
        page = self.c.get("/security")
        r = self.c.post("/security/two-step/email/start", data={"csrf": self.csrf(page.text), "address": CODES})
        assert r.status_code == 200 and "We emailed a 6-digit code" in r.text, r.text[:500]
        r = self.c.post("/security/two-step/email/confirm", data={"csrf": self.csrf(r.text), "code": emailed_code(email)})
        codes = re.findall(r"<code>([0-9a-f]{6}-[0-9a-f]{6})</code>", r.text)
        assert len(codes) == 10, r.text[:500]
        return email, codes

    def create_token(self, name, scopes, email=None, days=30):
        data = {"name": name, "days": str(days), "scopes": scopes}
        if email:
            data["code"] = self.fresh_code(email, "/tokens")
        page = self.c.get("/tokens")
        r = self.c.post("/tokens", data={"csrf": self.csrf(page.text), **data})
        m = re.search(r"mm_pat_[\w-]+", r.text)
        assert m, re.findall(r'class="notice [a-z]+">([^<]+)', r.text) or r.text[:800]
        return m.group(0)


def api(token, method, path, **kw):
    return httpx.request(method, f"{BASE}/api/v1{path}", headers={"Authorization": f"Bearer {token}"},
                         timeout=120, **kw)


def ok(r, code=200):
    assert r.status_code == code, f"{r.request.method} {r.request.url} -> {r.status_code}: {r.text[:500]}"
    return r.json() if r.headers.get("content-type", "").startswith("application/json") else r


def wait_for(token, mailbox, subject, folder="INBOX", seconds=90):
    deadline = time.time() + seconds
    while time.time() < deadline:
        r = api(token, "GET", f"/mailboxes/{mailbox}/messages", params={"folder": folder, "subject": subject})
        if r.status_code == 200 and r.json()["messages"]:
            return r.json()["messages"][0]
        time.sleep(3)
    raise AssertionError(f"'{subject}' never arrived in {mailbox}/{folder}")


def mcp_call(token, calls):
    """Run MCP tool calls over the real streamable-HTTP transport. Returns [(is_error, data)]."""
    import httpx2
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def go():
        out = []
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=120) as hc:
            async with streamable_http_client(f"{BASE}/mcp", http_client=hc) as streams:
                read, write = streams[0], streams[1]
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    for name, args in calls:
                        if name == "__list__":
                            tools = await session.list_tools()
                            out.append((False, [t.name for t in tools.tools]))
                            continue
                        try:
                            res = await session.call_tool(name, args)
                        except Exception as e:  # surface JSON-RPC errors with their details
                            raise AssertionError(f"{name}: {getattr(e, 'code', '')} {getattr(e, 'message', e)} "
                                                 f"{getattr(e, 'data', '')}") from None
                        data = res.structured_content if res.structured_content is not None else None
                        text = " ".join(getattr(c, "text", "") for c in res.content)
                        if isinstance(data, dict) and set(data) == {"result"}:
                            data = data["result"]
                        if data is None and not res.is_error:
                            import json
                            try:
                                data = json.loads(text)
                            except ValueError:
                                pass
                        out.append((bool(res.is_error), data if data is not None else text))
        return out
    return asyncio.run(go())


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


# ---------- 1. transport, headers, admin sign-in --------------------------------------------------

def test_01_tls_and_security_headers():
    r = httpx.get(f"{BASE}/login")
    assert r.status_code == 200
    h = r.headers
    assert "max-age=31536000" in h["strict-transport-security"]
    assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert "server" not in h
    with pytest.raises((httpx.ConnectError, httpx.TimeoutException)):
        httpx.get(BASE.replace("https://", "http://") + ":8443/login", timeout=5)   # app port isn't exposed


ADMIN = os.environ["ADMIN_EMAIL"].lower()
MAILBOX_PW[ADMIN] = os.environ["ADMIN_MAILBOX_PASSWORD"]


def test_02_admin_first_login_forces_new_password():
    b = Browser()
    r = b.login(os.environ["ADMIN_EMAIL"], "wrong-password-123")
    assert r.status_code == 401 and "sign you in" in r.text
    # the sign-in form only works with the token from our own login page (login CSRF)
    assert b.c.post("/login", data={"email": ADMIN, "password": "x", "next": "/"}).status_code == 303
    r = b.login(os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"])
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "__Host-mailapp=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    assert b.get("/").headers["location"] == "/password"         # must change the temporary password
    assert b.set_password(os.environ["ADMIN_PASSWORD"], "short").status_code == 400
    S["admin_pw"] = "Adm1n-" + secrets.token_urlsafe(12)
    assert b.set_password(os.environ["ADMIN_PASSWORD"], S["admin_pw"]).status_code == 303
    # one password: the admin's login is also a mailbox, and now both use the new password
    MAILBOX_PW[ADMIN] = S["admin_pw"]
    with imaplib.IMAP4_SSL(urlsplit(BASE).hostname, 993) as im:
        im.login(ADMIN, S["admin_pw"])
    home = b.get("/")
    # 200, or the two-step setup page if the server already requires two-step for everyone
    assert home.status_code == 200 or home.headers["location"] == "/security?required=1"
    S["admin"] = b


def test_03_admin_two_step_and_token():
    b = S["admin"]
    # codes can't go to the mailbox you sign in as: it has the same password
    page = b.get("/security")
    for own in (ADMIN, ADMIN.replace("@", "+codes@")):
        r = b.c.post("/security/two-step/email/start", data={"csrf": b.csrf(page.text), "address": own})
        assert r.status_code == 400 and "own mailbox" in r.text, own
    _, S["admin_recovery"] = b.enable_two_step(ADMIN)
    # start from "two-step optional"; test_24 switches the requirement back on
    page = b.get("/admin/settings")
    assert b.c.post("/admin/settings", data={"csrf": b.csrf(page.text), "allow_local": "1"}).status_code == 303
    r = b.post_form("/tokens", "/tokens", {"name": "x", "days": "30", "scopes": ["mail.read"], "code": "000000"})
    assert r.status_code == 400                                    # token needs a valid two-step code
    S["admin_token"] = b.create_token("e2e admin", ["mail.read", "mail.send", "mail.organize", "admin"], ADMIN)
    me = ok(api(S["admin_token"], "GET", "/me"))
    assert me["role"] == "admin" and "admin" in me["scopes"]


def test_04_admin_creates_mailboxes_and_alias():
    t = S["admin_token"]
    for name in ("a", "b"):
        r = ok(api(t, "POST", "/admin/mailboxes", json={"address": addr(name)}), 201)
        assert r["ready"] and len(r["password"]) >= 20
        S[f"pw_{name}"] = r["password"]
    S["A"], S["B"] = addr("a"), addr("b")
    ok(api(t, "POST", "/admin/aliases", json={"alias": addr("alias"), "target": S["A"]}), 201)
    aliases = ok(api(t, "GET", "/admin/aliases"))
    assert {"alias": addr("alias"), "targets": [S["A"]]} in aliases
    boxes = {m["address"]: m for m in ok(api(t, "GET", "/admin/mailboxes"))}
    assert boxes[S["A"]]["linked"] and addr("alias") in boxes[S["A"]]["aliases"]
    # duplicates and foreign domains are refused
    assert api(t, "POST", "/admin/mailboxes", json={"address": S["A"]}).status_code == 400
    assert api(t, "POST", "/admin/mailboxes", json={"address": "x@evil.example"}).status_code == 400
    assert api(t, "POST", "/admin/mailboxes", json={"address": f"../../etc@{DOMAIN}"}).status_code == 400


def test_05_admin_creates_user_with_limited_access():
    t = S["admin_token"]
    S["U"] = addr("user")                     # the user's login is also a mailbox, for emailed codes
    MAILBOX_PW[S["U"]] = ok(api(t, "POST", "/admin/mailboxes", json={"address": S["U"]}), 201)["password"]
    r = ok(api(t, "POST", "/admin/users", json={"email": S["U"], "name": "Test <b>User</b>", "role": "user"}), 201)
    S["U_id"], S["U_temp"] = r["user"]["id"], r["temporary_password"]
    ok(api(t, "PUT", f"/admin/users/{S['U_id']}/grants", json={"mailbox": S["A"], "read": True}))
    u = ok(api(t, "PUT", f"/admin/users/{S['U_id']}/grants",
               json={"mailbox": S["B"], "read": True, "send": True, "organize": True}))
    assert {g["mailbox"] for g in u["grants"]} == {S["A"], S["B"]}
    assert api(t, "POST", "/admin/users", json={"email": S["U"]}).status_code == 400   # duplicate


def test_06_user_signs_in_and_gets_token():
    b = Browser()
    assert b.login(S["U"], S["U_temp"]).status_code == 303
    S["U_pw"] = "Us3r-" + secrets.token_urlsafe(12)
    assert b.set_password(S["U_temp"], S["U_pw"]).status_code == 303
    MAILBOX_PW[S["U"]] = S["U_pw"]                     # same password for the user's mailbox now
    with imaplib.IMAP4_SSL(urlsplit(BASE).hostname, 993) as im:
        im.login(S["U"], S["U_pw"])
    S["user"] = b
    S["user_token"] = b.create_token("e2e user", ["mail.read", "mail.send", "mail.organize", "admin"])
    me = ok(api(S["user_token"], "GET", "/me"))
    assert me["role"] == "user" and "admin" not in me["scopes"]      # admin scope dropped for users
    boxes = {m["address"]: m["permissions"] for m in ok(api(S["user_token"], "GET", "/mailboxes"))}
    assert boxes == {S["A"]: ["read"], S["B"]: ["read", "send", "organize"]}
    # pages for admins are refused
    assert b.get("/admin/users").status_code == 403


# ---------- 2. mail over the REST API ---------------------------------------------------------------

def test_07_send_with_attachment_and_html():
    S["subj1"] = f"e2e {RUN} hello"
    S["att"] = os.urandom(2048)
    r = ok(api(S["admin_token"], "POST", f"/mailboxes/{S['B']}/send", json={
        "to": [f"Mailbox A <{S['A']}>"], "subject": S["subj1"], "text": "plain body ✓", "html": "<p>html <b>body</b></p>",
        "attachments": [{"filename": "data.bin", "content_type": "application/octet-stream",
                         "content_base64": base64.b64encode(S["att"]).decode()}]}))
    assert r["status"] == "sent" and r["recipients"] == [S["A"]]
    sent = wait_for(S["admin_token"], S["B"], S["subj1"], folder="Sent")
    assert sent["subject"] == S["subj1"]


def test_08_user_reads_mail_and_attachment():
    t = S["user_token"]
    msg = wait_for(t, S["A"], S["subj1"])
    assert msg["unread"] and msg["has_attachments"]
    S["uid1"] = msg["uid"]
    full = ok(api(t, "GET", f"/mailboxes/{S['A']}/messages/{msg['uid']}", params={"html": True}))
    assert "plain body ✓" in full["text"] and "<b>body</b>" in full["html"]
    assert full["attachments"][0]["filename"] == "data.bin"
    data = api(t, "GET", f"/mailboxes/{S['A']}/messages/{msg['uid']}/attachments/0")
    assert data.status_code == 200 and data.content == S["att"]
    # reading without mark_read keeps it unread
    again = wait_for(t, S["A"], S["subj1"])
    assert again["unread"]
    folders = {f["name"]: f for f in ok(api(t, "GET", f"/mailboxes/{S['A']}/folders"))}
    assert {"INBOX", "Sent", "Drafts", "Trash", "Junk"} <= set(folders)
    assert ok(api(t, "GET", f"/mailboxes/{S['A']}/messages", params={"unread": True}))["total"] >= 1
    assert ok(api(t, "GET", f"/mailboxes/{S['A']}/messages", params={"q": "zzz-no-such-text-" + RUN}))["total"] == 0


def test_09_permission_boundaries():
    t = S["user_token"]
    A = S["A"]
    assert api(t, "POST", f"/mailboxes/{A}/send", json={"to": [S["B"]], "subject": "x", "text": "x"}).status_code == 403
    assert api(t, "POST", f"/mailboxes/{A}/messages/flags", json={"uids": [S["uid1"]], "read": True}).status_code == 403
    assert api(t, "POST", f"/mailboxes/{A}/messages/move", json={"uids": [S["uid1"]], "to_folder": "Junk"}).status_code == 403
    assert api(t, "POST", f"/mailboxes/{A}/messages/delete", json={"uids": [S["uid1"]]}).status_code == 403
    assert api(t, "POST", f"/mailboxes/{A}/folders", json={"name": "nope"}).status_code == 403
    assert api(t, "GET", f"/mailboxes/{A}/messages/{S['uid1']}", params={"mark_read": True}).status_code == 403
    assert api(t, "POST", f"/mailboxes/{A}/drafts", json={"subject": "x"}).status_code == 403
    assert api(t, "GET", f"/mailboxes/postmaster@{DOMAIN}/messages").status_code == 403
    assert api(t, "GET", f"/mailboxes/{addr('nobody')}/folders").status_code == 403
    for path in ("/admin/users", "/admin/mailboxes", "/admin/aliases", "/admin/audit"):
        assert api(t, "GET", path).status_code == 403
    assert api(t, "POST", "/admin/mailboxes", json={"address": addr("evil")}).status_code == 403


def test_10_reply_forward_draft_organize():
    at, ut = S["admin_token"], S["user_token"]
    S["subj2"] = f"e2e {RUN} to B"
    ok(api(at, "POST", f"/mailboxes/{S['A']}/send", json={"to": [S["B"]], "cc": [addr("alias")],
                                                          "subject": S["subj2"], "text": "question?"}))
    m = wait_for(ut, S["B"], S["subj2"])
    uid = m["uid"]
    r = ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/{uid}/reply", json={"text": "answer!", "reply_all": True}))
    assert S["A"] in r["recipients"]
    reply = wait_for(at, S["A"], "Re: " + S["subj2"])
    body = ok(api(at, "GET", f"/mailboxes/{S['A']}/messages/{reply['uid']}"))
    assert "answer!" in body["text"] and "> question?" in body["text"]
    flags = ok(api(ut, "GET", f"/mailboxes/{S['B']}/messages/{uid}"))["flags"]
    assert "\\Answered" in flags
    ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/{uid}/forward", json={"to": [S["A"]], "text": "fyi"}))
    fwd = wait_for(at, S["A"], "Fwd: " + S["subj2"])
    fbody = ok(api(at, "GET", f"/mailboxes/{S['A']}/messages/{fwd['uid']}"))
    assert "fyi" in fbody["text"] and fbody["attachments"][0]["content_type"] == "message/rfc822"
    ok(api(ut, "POST", f"/mailboxes/{S['B']}/drafts", json={"to": [S["A"]], "subject": f"draft {RUN}", "text": "later"}), 201)
    d = wait_for(ut, S["B"], f"draft {RUN}", folder="Drafts", seconds=10)
    assert d["subject"] == f"draft {RUN}"
    # flags
    ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/flags", json={"uids": [uid], "read": True, "flagged": True}))
    mm = ok(api(ut, "GET", f"/mailboxes/{S['B']}/messages", params={"flagged": True}))["messages"]
    assert any(x["uid"] == uid and not x["unread"] for x in mm)
    # folders and move
    ok(api(ut, "POST", f"/mailboxes/{S['B']}/folders", json={"name": f"Projects{RUN}"}), 201)
    ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/move", json={"uids": [uid], "to_folder": f"Projects{RUN}"}))
    moved = wait_for(ut, S["B"], S["subj2"], folder=f"Projects{RUN}", seconds=10)
    ok(api(ut, "PATCH", f"/mailboxes/{S['B']}/folders/Projects{RUN}", json={"new_name": f"Archive{RUN}"}))
    assert api(ut, "PATCH", f"/mailboxes/{S['B']}/folders/INBOX", json={"new_name": "x"}).status_code == 400
    # delete -> Trash, then permanently
    r = ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/delete?folder=Archive{RUN}", json={"uids": [moved["uid"]]}))
    assert "Trash" in r["status"]
    t = wait_for(ut, S["B"], S["subj2"], folder="Trash", seconds=10)
    r = ok(api(ut, "POST", f"/mailboxes/{S['B']}/messages/delete?folder=Trash", json={"uids": [t["uid"]]}))
    assert r["status"] == "deleted permanently"
    assert ok(api(ut, "GET", f"/mailboxes/{S['B']}/messages", params={"folder": "Trash", "subject": S["subj2"]}))["total"] == 0
    ok(api(ut, "DELETE", f"/mailboxes/{S['B']}/folders/Archive{RUN}"))
    assert api(ut, "DELETE", f"/mailboxes/{S['B']}/folders/Trash").status_code == 400


def test_11_alias_delivery_and_send_as():
    at = S["admin_token"]
    m = wait_for(at, S["A"], S["subj2"])                       # the Cc to the alias landed in A
    assert m
    r = ok(api(at, "POST", f"/mailboxes/{S['A']}/send", json={"to": [S["B"]], "subject": f"as alias {RUN}",
                                                              "text": "x", "from_address": addr("alias"),
                                                              "from_name": "Alias Name"}))
    assert r["status"] == "sent"
    got = wait_for(at, S["B"], f"as alias {RUN}")
    assert addr("alias") in got["from"][0]
    bad = api(at, "POST", f"/mailboxes/{S['A']}/send", json={"to": [S["B"]], "subject": "x", "text": "x",
                                                           "from_address": S["B"]})
    assert bad.status_code == 403


def test_12_input_validation():
    at, A = S["admin_token"], S["A"]
    send = lambda **kw: api(at, "POST", f"/mailboxes/{A}/send", json={"to": [S["B"]], "subject": "x", "text": "x", **kw})
    assert send(subject="evil\r\nBcc: victim@example.com").status_code == 400
    assert send(to=["not-an-address"]).status_code == 400
    assert send(to=["a@b.com\r\nX: y"]).status_code == 400
    assert send(to=[f"r{i}@example.com" for i in range(51)]).status_code == 400
    assert send(attachments=[{"filename": "x", "content_base64": "%%%not base64"}]).status_code == 400
    assert send(attachments=[{"filename": "x", "content_type": "text/plain\r\nX: y", "content_base64": "eA=="}]).status_code == 400
    assert send(to=[]).status_code == 400
    assert api(at, "GET", f"/mailboxes/{A}/messages", params={"folder": "../../etc"}).status_code == 400
    assert api(at, "GET", f"/mailboxes/{A}/messages", params={"since": "yesterday"}).status_code == 400
    assert api(at, "GET", f"/mailboxes/{A}/messages/99999999").status_code == 400
    assert api(at, "GET", f"/mailboxes/{A}/messages/{S['uid1']}/attachments/7").status_code == 400
    assert api(at, "GET", "/mailboxes/..%2F..%2Fetc%2Fpasswd/folders").status_code in (403, 404)
    assert api(at, "POST", "/admin/aliases", json={"alias": addr("x"), "target": "bad target"}).status_code == 400
    assert api(at, "POST", "/admin/users", json={"email": "not an email"}).status_code == 400


def test_13_narrow_scopes_and_bad_tokens():
    read_only = S["user"].create_token("read only", ["mail.read"])
    assert api(read_only, "GET", f"/mailboxes/{S['B']}/folders").status_code == 200
    assert api(read_only, "POST", f"/mailboxes/{S['B']}/send", json={"to": [S["A"]], "subject": "x", "text": "x"}).status_code == 403
    assert api(read_only, "POST", f"/mailboxes/{S['B']}/folders", json={"name": "x"}).status_code == 403
    page = S["user"].get("/tokens").text
    tid = re.findall(r'action="/tokens/(\d+)/revoke"', page)[0]
    S["user"].c.post(f"/tokens/{tid}/revoke", data={"csrf": S["user"].csrf(page)})
    assert api(read_only, "GET", "/me").status_code == 401           # revoked
    assert api("mm_pat_" + secrets.token_urlsafe(32), "GET", "/me").status_code == 401
    assert api("garbage", "GET", "/me").status_code == 401
    assert httpx.get(f"{BASE}/api/v1/me").status_code == 401
    assert httpx.get(f"{BASE}/api/v1/me", headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code == 401


# ---------- 3. MCP ----------------------------------------------------------------------------------

TOOLS = {"whoami", "list_mailboxes", "list_folders", "search_emails", "read_email", "download_attachment",
         "send_email", "reply_email", "forward_email", "save_draft", "mark_emails", "move_emails", "delete_emails",
         "create_folder", "rename_folder", "delete_folder", "admin_list_users", "admin_create_user",
         "admin_update_user", "admin_set_permissions", "admin_reset_user_password", "admin_delete_user",
         "admin_list_mailboxes", "admin_create_mailbox", "admin_reset_mailbox_password", "admin_delete_mailbox",
         "admin_list_aliases", "admin_create_alias", "admin_delete_alias", "admin_audit_log"}


def test_14_mcp_requires_auth():
    r = httpx.post(f"{BASE}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                   headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]
    meta = httpx.get(f"{BASE}/.well-known/oauth-protected-resource/mcp").json()
    assert meta["resource"].rstrip("/") == f"{BASE}/mcp" and meta["authorization_servers"]
    with pytest.raises(Exception):
        mcp_call("mm_pat_" + secrets.token_urlsafe(32), [("whoami", {})])


def test_15_mcp_user_tools():
    t, A, B = S["user_token"], S["A"], S["B"]
    subj = f"e2e {RUN} via mcp"
    res = mcp_call(t, [
        ("__list__", {}),
        ("whoami", {}),
        ("list_mailboxes", {}),
        ("list_folders", {"mailbox": B}),
        ("send_email", {"mailbox": B, "to": [A], "subject": subj, "text": "from mcp",
                        "attachments": [{"filename": "n.txt", "content_type": "text/plain",
                                         "content_base64": base64.b64encode(b"note").decode()}]}),
        ("send_email", {"mailbox": A, "to": [B], "subject": "x", "text": "x"}),       # no send on A
        ("admin_list_users", {}),                                                       # not admin
        ("create_folder", {"mailbox": A, "name": "x"}),                                 # no organize on A
    ])
    tools, who, boxes, folders, sent, deny_send, deny_admin, deny_org = res
    assert TOOLS <= set(tools[1]), set(TOOLS) - set(tools[1])
    assert who[1]["email"] == S["U"] and who[1]["role"] == "user"
    assert {b["address"] for b in boxes[1]} == {A, B}
    assert any(f["name"] == "INBOX" for f in folders[1])
    assert not sent[0] and sent[1]["status"] == "sent", sent
    assert deny_send[0] and "permission" in str(deny_send[1])
    assert deny_admin[0] and "Admin" in str(deny_admin[1])
    assert deny_org[0]
    msg = wait_for(t, A, subj)
    S["mcp_uid"] = msg["uid"]
    res = mcp_call(t, [
        ("search_emails", {"mailbox": A, "subject": subj}),
        ("read_email", {"mailbox": A, "uid": msg["uid"]}),
        ("download_attachment", {"mailbox": A, "uid": msg["uid"], "index": 0}),
        ("read_email", {"mailbox": A, "uid": msg["uid"], "mark_as_read": True}),        # needs organize on A
    ])
    found, read, att, deny_mark = res
    assert found[1]["total"] == 1 and found[1]["messages"][0]["uid"] == msg["uid"]
    assert "from mcp" in read[1]["text"] and read[1]["attachments"][0]["filename"] == "n.txt"
    assert base64.b64decode(att[1]["content_base64"]) == b"note"
    assert deny_mark[0]


def test_16_mcp_organize_reply_forward_draft():
    t, A, B = S["user_token"], S["A"], S["B"]
    subj = f"e2e {RUN} mcp-in-B"
    ok(api(S["admin_token"], "POST", f"/mailboxes/{A}/send", json={"to": [B], "subject": subj, "text": "ping"}))
    uid = wait_for(t, B, subj)["uid"]
    folder = f"Mcp{RUN}"
    res = mcp_call(t, [
        ("reply_email", {"mailbox": B, "uid": uid, "text": "pong"}),
        ("forward_email", {"mailbox": B, "uid": uid, "to": [A], "text": "see below"}),
        ("save_draft", {"mailbox": B, "subject": f"mcp draft {RUN}", "text": "draft", "to": [A]}),
        ("mark_emails", {"mailbox": B, "uids": [uid], "read": True, "flagged": True}),
        ("create_folder", {"mailbox": B, "name": folder}),
        ("move_emails", {"mailbox": B, "uids": [uid], "to_folder": folder}),
        ("rename_folder", {"mailbox": B, "folder": folder, "new_name": folder + "x"}),
        ("search_emails", {"mailbox": B, "folder": folder + "x", "subject": subj}),
    ])
    for i, (err, data) in enumerate(res):
        assert not err, (i, data)
    moved_uid = res[-1][1]["messages"][0]["uid"]
    res = mcp_call(t, [
        ("delete_emails", {"mailbox": B, "folder": folder + "x", "uids": [moved_uid], "permanent": True}),
        ("delete_folder", {"mailbox": B, "folder": folder + "x"}),
        ("delete_folder", {"mailbox": B, "folder": "INBOX"}),
        ("read_email", {"mailbox": B, "uid": 99999999}),
    ])
    assert not res[0][0] and res[0][1]["status"] == "deleted permanently"
    assert not res[1][0]
    assert res[2][0] and "system folder" in str(res[2][1])
    assert res[3][0]
    assert wait_for(S["admin_token"], A, "Re: " + subj)
    assert wait_for(S["admin_token"], A, "Fwd: " + subj)


def test_17_mcp_admin_tools():
    t = S["admin_token"]
    newbox, newuser = addr("c"), f"e2e-{RUN}-second@example.org"
    res = mcp_call(t, [
        ("admin_list_users", {}),
        ("admin_create_user", {"email": newuser, "name": "Second", "role": "user"}),
        ("admin_create_mailbox", {"address": newbox}),
        ("admin_set_permissions", {"email": newuser, "mailbox": newbox, "read": True, "send": True}),
        ("admin_update_user", {"email": newuser, "name": "Second Renamed"}),
        ("admin_reset_user_password", {"email": newuser}),
        ("admin_reset_mailbox_password", {"address": newbox}),
        ("admin_create_alias", {"alias": addr("c-alias"), "target": newbox}),
        ("admin_list_aliases", {}),
        ("admin_list_mailboxes", {}),
        ("admin_delete_alias", {"alias": addr("c-alias"), "target": newbox}),
        ("admin_delete_mailbox", {"address": newbox, "confirm_address": "wrong"}),
        ("admin_delete_mailbox", {"address": newbox, "confirm_address": newbox}),
        ("admin_update_user", {"email": newuser, "disabled": True}),
        ("admin_delete_user", {"email": newuser}),
        ("admin_audit_log", {"limit": 30}),
    ])
    names = [n for n, _ in [
        ("list_users", 0), ("create_user", 0), ("create_mailbox", 0), ("set_perm", 0), ("update", 0), ("reset_pw", 0),
        ("reset_box", 0), ("alias", 0), ("list_alias", 0), ("list_box", 0), ("del_alias", 0), ("del_box_wrong", 0),
        ("del_box", 0), ("disable", 0), ("del_user", 0), ("audit", 0)]]
    for name, (err, data) in zip(names, res):
        if name == "del_box_wrong":
            assert err and "confirm" in str(data), data
        else:
            assert not err, (name, data)
    # passwords never reach the AI
    assert "not shown" in res[1][1]["temporary_password"] and "not shown" in res[2][1]["password"]
    assert res[2][1]["ready"] and "not shown" in res[6][1]["password"]
    assert any(a["alias"] == addr("c-alias") for a in res[8][1])
    assert newbox in [m["address"] for m in res[9][1]]
    assert res[12][1]["deleted"] == newbox
    assert any(r["action"] == "mailbox.delete" for r in res[15][1])
    assert newbox not in [m["address"] for m in ok(api(t, "GET", "/admin/mailboxes"))]


# ---------- 4. OAuth for MCP clients ------------------------------------------------------------------

def test_18_oauth_full_flow_with_pkce_and_two_step():
    meta = httpx.get(f"{BASE}/.well-known/oauth-authorization-server").json()
    assert "S256" in meta["code_challenge_methods_supported"]
    for evil in ("http://evil.example/cb", "http://localhost.evil.example/cb", "http://user@localhost/cb",
                 "https://claude.ai@evil.example/cb", "javascript:alert(1)"):
        bad = httpx.post(meta["registration_endpoint"], json={"redirect_uris": [evil], "client_name": "evil"})
        assert bad.status_code == 400, evil
    reg = httpx.post(meta["registration_endpoint"], json={
        "redirect_uris": ["http://localhost:53682/callback"], "client_name": f"e2e client {RUN}",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": "mail.read mail.send mail.organize admin"}).json()
    cid = reg["client_id"]
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(8)
    r = httpx.get(meta["authorization_endpoint"], params={
        "response_type": "code", "client_id": cid, "redirect_uri": "http://localhost:53682/callback",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "scope": "mail.read mail.send admin", "resource": f"{BASE}/mcp"})
    assert r.status_code in (302, 303), r.text
    consent_url = r.headers["location"]
    assert consent_url.startswith(f"{BASE}/oauth/consent?request=")
    path = consent_url[len(BASE):]
    # not signed in -> sent to the login page, back to consent afterwards
    anon = Browser()
    assert anon.get(path).headers["location"].startswith("/login?next=")
    b = S["admin"]
    page = b.get(path)
    assert page.status_code == 200 and f"e2e client {RUN}" in page.text and "<code>localhost</code>" in page.text
    assert "form-action 'self' http://localhost:53682" in page.headers["content-security-policy"]
    rid = re.search(r'name="request_id" value="([^"]+)"', page.text).group(1)
    wrong = b.c.post("/oauth/consent", data={"csrf": b.csrf(page.text), "request_id": rid, "decision": "approve",
                                             "code": "000000"})
    assert wrong.status_code == 401
    assert 'name="allow_admin"' in page.text and "checked" not in page.text.split('name="allow_admin"')[1][:30]
    r = b.c.post("/oauth/consent", data={"csrf": b.csrf(page.text), "request_id": rid, "decision": "approve",
                                         "code": b.fresh_code(ADMIN, path), "allow_admin": "1"})
    assert r.status_code == 303
    cb = urlsplit(r.headers["location"])
    q = parse_qs(cb.query)
    assert cb.netloc == "localhost:53682" and q["state"] == [state]
    code = q["code"][0]
    token_url = meta["token_endpoint"]
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://localhost:53682/callback",
            "client_id": cid, "resource": f"{BASE}/mcp"}
    assert httpx.post(token_url, data={**form, "code_verifier": "x" * 50}).status_code == 400   # wrong PKCE
    tok = httpx.post(token_url, data={**form, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    tok = tok.json()
    assert set(tok["scope"].split()) == {"mail.read", "mail.send", "admin"}
    who = mcp_call(tok["access_token"], [("whoami", {}), ("list_mailboxes", {})])
    assert who[0][1]["email"] == ADMIN and "mail.organize" not in who[0][1]["scopes"]
    assert any(b["address"] == S["A"] for b in who[1][1])
    assert ok(api(tok["access_token"], "GET", "/me"))["role"] == "admin"
    # the code was already used: using it again fails AND cancels the tokens it produced (it leaked)
    assert httpx.post(token_url, data={**form, "code_verifier": verifier}).status_code == 400
    assert api(tok["access_token"], "GET", "/me").status_code == 401
    # a second, clean authorization for the refresh tests
    verifier, challenge = pkce()
    r = httpx.get(meta["authorization_endpoint"], params={
        "response_type": "code", "client_id": cid, "redirect_uri": "http://localhost:53682/callback",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s0", "resource": f"{BASE}/mcp"})
    path = r.headers["location"][len(BASE):]
    page = b.get(path)
    rid = re.search(r'name="request_id" value="([^"]+)"', page.text).group(1)
    r = b.c.post("/oauth/consent", data={"csrf": b.csrf(page.text), "request_id": rid, "decision": "approve",
                                         "code": b.fresh_code(ADMIN, path)})
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    tok = httpx.post(token_url, data={**form, "code": code, "code_verifier": verifier}).json()
    assert api(tok["access_token"], "GET", "/me").status_code == 200
    # refresh rotates; an old refresh token coming back ends the whole family
    ref = httpx.post(token_url, data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                      "client_id": cid}).json()
    assert ref["access_token"] != tok["access_token"]
    assert api(ref["access_token"], "GET", "/me").status_code == 200
    replay = httpx.post(token_url, data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                         "client_id": cid})
    assert replay.status_code == 400
    assert api(ref["access_token"], "GET", "/me").status_code == 401
    S["oauth"] = (meta, cid)


def test_19_oauth_deny_and_revoke():
    meta, cid = S["oauth"]
    verifier, challenge = pkce()
    r = httpx.get(meta["authorization_endpoint"], params={
        "response_type": "code", "client_id": cid, "redirect_uri": "http://localhost:53682/callback",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1"})
    b = S["admin"]
    page = b.get(r.headers["location"][len(BASE):])
    rid = re.search(r'name="request_id" value="([^"]+)"', page.text).group(1)
    r = b.c.post("/oauth/consent", data={"csrf": b.csrf(page.text), "request_id": rid, "decision": "deny"})
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["s1"]
    # revoke from the console's "Connected apps" list; admin wasn't ticked, so it isn't granted
    tok = _authorize(b, meta, cid, verifier, challenge, scope="mail.read admin")
    assert ok(api(tok["access_token"], "GET", "/me"))["scopes"] == ["mail.read"]
    assert api(tok["access_token"], "GET", "/admin/users").status_code == 403
    page = b.get("/tokens")
    assert f"e2e client {RUN}" in page.text
    gid = re.findall(r'action="/tokens/apps/([0-9a-f]{24})/revoke"', page.text)[0]
    b.c.post(f"/tokens/apps/{gid}/revoke", data={"csrf": b.csrf(page.text)})
    assert api(tok["access_token"], "GET", "/me").status_code == 401
    # the standard /revoke endpoint, for an app registered with a client secret
    reg = httpx.post(meta["registration_endpoint"], json={
        "redirect_uris": ["http://localhost:53682/callback"], "client_name": f"e2e secret client {RUN}",
        "token_endpoint_auth_method": "client_secret_post"}).json()
    verifier, challenge = pkce()
    tok = _authorize(b, meta, reg["client_id"], verifier, challenge, secret=reg["client_secret"])
    assert api(tok["access_token"], "GET", "/me").status_code == 200
    rv = httpx.post(meta["revocation_endpoint"], data={"token": tok["refresh_token"], "client_id": reg["client_id"],
                                                       "client_secret": reg["client_secret"]})
    assert rv.status_code == 200, rv.text
    assert api(tok["access_token"], "GET", "/me").status_code == 401


def _authorize(b, meta, cid, verifier, challenge, secret=None, scope=None):
    r = httpx.get(meta["authorization_endpoint"], params={
        "response_type": "code", "client_id": cid, "redirect_uri": "http://localhost:53682/callback",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s2", **({"scope": scope} if scope else {})})
    path = r.headers["location"][len(BASE):]
    page = b.get(path)
    rid = re.search(r'name="request_id" value="([^"]+)"', page.text).group(1)
    r = b.c.post("/oauth/consent", data={"csrf": b.csrf(page.text), "request_id": rid, "decision": "approve",
                                         "code": b.fresh_code(ADMIN, path)})
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    data = {"grant_type": "authorization_code", "code": code, "client_id": cid,
            "redirect_uri": "http://localhost:53682/callback", "code_verifier": verifier}
    if secret:
        data["client_secret"] = secret
    r = httpx.post(meta["token_endpoint"], data=data)
    assert r.status_code == 200, r.text
    return r.json()


# ---------- 5. web security ---------------------------------------------------------------------------

def test_20_csrf_xss_open_redirect():
    b = S["admin"]
    assert b.c.post("/admin/users", data={"email": addr("csrf"), "role": "admin"}).status_code == 403
    assert b.c.post("/admin/users", data={"csrf": "x" * 40, "email": addr("csrf"), "role": "admin"}).status_code == 403
    assert not any(u["email"] == addr("csrf") for u in ok(api(S["admin_token"], "GET", "/admin/users")))
    page = b.get("/admin/users").text
    assert "Test <b>User</b>" not in page and "Test &lt;b&gt;User&lt;/b&gt;" in page
    fresh = Browser()
    r = fresh.post_login(S["U"], S["U_pw"], "//evil.example/x")
    assert r.headers["location"] == "/"
    r = fresh.post_login(S["U"], S["U_pw"], "https://evil.example")
    assert r.headers["location"] == "/"
    # API is not usable with a browser cookie, and the console doesn't accept bearer tokens
    assert fresh.c.get("/api/v1/me").status_code == 401
    assert httpx.get(f"{BASE}/admin/users", headers={"Authorization": f"Bearer {S['admin_token']}"},
                     follow_redirects=False).status_code == 303


def test_21_lockout_after_failed_passwords():
    t = S["admin_token"]
    victim = f"e2e-{RUN}-lock@example.org"
    temp = ok(api(t, "POST", "/admin/users", json={"email": victim}), 201)["temporary_password"]
    b = Browser()
    for _ in range(5):
        assert b.login(victim, "Wrong-password-xyz").status_code == 401
    r = b.login(victim, temp)       # the right password is refused while locked, with the same message
    assert r.status_code == 401 and "sign you in" in r.text
    uid = next(u["id"] for u in ok(api(t, "GET", "/admin/users")) if u["email"] == victim)
    ok(api(t, "DELETE", f"/admin/users/{uid}"))


def test_22_logout_and_disable_end_access():
    b = Browser()
    assert b.login(S["U"], S["U_pw"]).status_code == 303
    cookie = b.c.cookies.get("__Host-mailapp")
    page = b.get("/").text
    b.c.post("/logout", data={"csrf": b.csrf(page)})
    replay = httpx.get(f"{BASE}/", cookies={"__Host-mailapp": cookie}, follow_redirects=False)
    assert replay.headers["location"].startswith("/login")
    t = S["admin_token"]
    ok(api(t, "PATCH", f"/admin/users/{S['U_id']}", json={"disabled": True}))
    assert api(S["user_token"], "GET", "/me").status_code == 401
    assert Browser().login(S["U"], S["U_pw"]).status_code == 401
    ok(api(t, "PATCH", f"/admin/users/{S['U_id']}", json={"disabled": False}))
    assert api(S["user_token"], "GET", "/me").status_code == 401         # tokens stay revoked
    me_id = next(u["id"] for u in ok(api(t, "GET", "/admin/users")) if u["email"] == os.environ["ADMIN_EMAIL"].lower())
    assert api(t, "PATCH", f"/admin/users/{me_id}", json={"disabled": True}).status_code == 400   # not yourself
    assert api(t, "DELETE", f"/admin/users/{me_id}").status_code == 400


def test_23_two_step_codes_work_once_and_recovery_codes():
    def to_code_page():
        b = Browser()
        r = b.post_login(os.environ["ADMIN_EMAIL"], S["admin_pw"])
        page = b.get(r.headers["location"])
        return b, b.csrf(page.text)

    def submit(b, csrf, code):
        return b.c.post("/login/code", data={"csrf": csrf, "code": code, "next": "/"})

    b1, c1 = to_code_page()
    code1 = emailed_code(ADMIN)
    assert submit(b1, c1, "000000").status_code == 401                   # wrong code
    assert submit(b1, c1, code1).status_code == 303 and b1.get("/").status_code == 200
    b2, c2 = to_code_page()
    code2 = emailed_code(ADMIN)
    assert submit(b2, c2, code1).status_code == 401                      # a used code never works again
    assert b2.get("/admin/users").headers["location"].startswith("/login/code")   # password alone opens nothing
    b3, c3 = to_code_page()                                              # sends a newer code...
    emailed_code(ADMIN)
    assert submit(b2, c2, code2).status_code == 401                      # ...so the older one is cancelled
    assert submit(b2, c2, S["admin_recovery"][0]).status_code == 303     # a recovery code works...
    b3, c3 = to_code_page()
    assert submit(b3, c3, S["admin_recovery"][0]).status_code == 401     # ...once


def test_24_require_two_step_for_everyone():
    b = S["admin"]
    page = b.get("/admin/settings")
    r = b.c.post("/admin/settings", data={"csrf": b.csrf(page.text), "require_two_step": "1", "allow_local": "1"})
    assert r.status_code == 303
    # the user's token was made without two-step: it stops working
    S["user"] = Browser()
    assert S["user"].login(S["U"], S["U_pw"]).status_code == 303
    assert S["user"].get("/").headers["location"] == "/security?required=1"
    S["user"].enable_two_step(S["U"])
    assert S["user"].get("/").status_code == 200
    new_token = S["user"].create_token("after two-step", ["mail.read"], S["U"])
    assert api(new_token, "GET", "/me").status_code == 200
    assert mcp_call(new_token, [("whoami", {})])[0][1]["email"] == S["U"]
    assert api(S["admin_token"], "GET", "/me").status_code == 200        # admin's token was made with two-step


def test_25_hardening():
    t = S["admin_token"]
    # oversized requests are refused before the app reads them
    big = httpx.post(f"{BASE}/api/v1/admin/aliases", headers={"Authorization": f"Bearer {t}"},
                     content=b"x" * (200 * 1024), timeout=60)
    assert big.status_code == 413
    # attachments always download as files, whatever the sender claimed
    a = api(t, "GET", f"/mailboxes/{S['A']}/messages/{S['uid1']}/attachments/0")
    assert a.headers["content-type"] == "application/octet-stream" and "attachment;" in a.headers["content-disposition"]
    # a new password signs out everything, including tokens
    b = Browser()
    victim = addr("pwchange")
    MAILBOX_PW[victim] = ok(api(t, "POST", "/admin/mailboxes", json={"address": victim}), 201)["password"]
    r = ok(api(t, "POST", "/admin/users", json={"email": victim}), 201)
    vid = r["user"]["id"]
    assert b.login(victim, r["temporary_password"]).status_code == 303
    pw1 = "Vict1m-" + secrets.token_urlsafe(10)
    b.set_password(r["temporary_password"], pw1)
    b = Browser()
    assert b.login(victim, pw1).status_code == 303
    b.enable_two_step(victim)
    tok = b.create_token("t", ["mail.read"], victim)
    assert api(tok, "GET", "/me").status_code == 200
    pw2 = "Vict1m-" + secrets.token_urlsafe(10)
    assert b.set_password(pw1, pw2).status_code == 303
    assert api(tok, "GET", "/me").status_code == 401
    # one password: the mailbox follows; disabling the person also locks the mailbox
    with imaplib.IMAP4_SSL(urlsplit(BASE).hostname, 993) as im:
        im.login(victim, pw2)
    ok(api(t, "PATCH", f"/admin/users/{vid}", json={"disabled": True}))
    with pytest.raises(imaplib.IMAP4.error):
        with imaplib.IMAP4_SSL(urlsplit(BASE).hostname, 993) as im:
            im.login(victim, pw2)
    ok(api(t, "DELETE", f"/admin/users/{vid}"))
    ok(api(t, "DELETE", f"/admin/mailboxes/{victim}", params={"confirm": victim}))


# ---------- 6. cleanup -------------------------------------------------------------------------------

def test_99_cleanup():
    t = S["admin_token"]
    for name in ("a", "b", "user"):
        ok(api(t, "DELETE", f"/admin/mailboxes/{addr(name)}", params={"confirm": addr(name)}))
    remaining = [m["address"] for m in ok(api(t, "GET", "/admin/mailboxes"))]
    assert not any(a.startswith(f"e2e-{RUN}") for a in remaining)
    assert not any(a["alias"].startswith(f"e2e-{RUN}") for a in ok(api(t, "GET", "/admin/aliases")))
    ok(api(t, "DELETE", f"/admin/users/{S['U_id']}"))
    users = [u["email"] for u in ok(api(t, "GET", "/admin/users"))]
    assert S["U"] not in users
