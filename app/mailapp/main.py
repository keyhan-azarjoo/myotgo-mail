"""One HTTPS server: the MCP endpoint (/mcp) with its OAuth endpoints, the REST API
(/api/v1) and the web console (everything else)."""
import logging
import re
import ssl
from pathlib import Path

import anyio
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Mount

from . import api, config, db, mcp_tools, security, service, web
from .oauth import Provider

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

INSTRUCTIONS = f"""Email for {config.DOMAIN}. Start with list_mailboxes to see which mailboxes you may use
and with which permissions (read, send, organize). Use search_emails to find messages (it returns uids),
then read_email, reply_email, forward_email, move_emails and so on with those uids.

Sending rule: never send, reply or forward on your own initiative. First show the person the complete
draft (from, to, cc, subject and the full text) and ask them to confirm. Only call send_email,
reply_email or forward_email after they clearly say yes, and send exactly what they approved. If they
ask for changes, show the new draft and ask again. If they say no or cancel, don't send (save_draft
only if they ask to keep it). admin_* tools are only for admins."""


def build_app():
    db.init()
    provider = Provider()
    mcp = MCPServer(
        name=config.APP_NAME,
        instructions=INSTRUCTIONS,
        website_url=config.PUBLIC_URL,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=config.PUBLIC_URL,
            resource_server_url=config.MCP_URL,
            service_documentation_url=f"{config.PUBLIC_URL}/connect",
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=list(service.SCOPES),
                default_scopes=["mail.read", "mail.send", "mail.organize"]),   # admin only when asked for and ticked
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=[],
            validate_token_resource=True,
        ),
    )
    mcp_tools.register(mcp)

    console = FastAPI(title=f"{config.APP_NAME} API", docs_url=None, redoc_url=None,
                      openapi_url="/api/v1/openapi.json")
    console.add_exception_handler(HTTPException, api.error_handler)
    console.include_router(api.router)
    console.include_router(web.router)
    console.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    @console.get("/healthz", include_in_schema=False)
    def healthz():
        return {"ok": True}

    host = config.MAIL_HOST
    app = mcp.streamable_http_app(
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[host, f"{host}:443", f"{host}:*"],
            allowed_origins=[config.PUBLIC_URL],
        ),
        host="0.0.0.0",
        stateless_http=True,
        json_response=True,
    )
    app.router.routes.append(Mount("/", app=console))
    return SecurityHeaders(Guard(app))


class Guard:
    """Limits every request before the app sees it: body size (small by default; large only where
    mail with attachments is sent, only with a valid token, and only two at a time) and per-IP
    rates on the public sign-in and OAuth endpoints."""

    SMALL, LARGE = 64 * 1024, 30 * 1024 * 1024
    LARGE_PATHS = re.compile(r"^/mcp$|^/api/v1/mailboxes/[^/]+/(send|drafts|messages/\d+/(reply|forward))$")
    RATES = {"/register": (20, 3600), "/authorize": (60, 600), "/token": (120, 600), "/revoke": (60, 600),
             "/login": (60, 600)}

    def __init__(self, app):
        self.app = app
        self.provider = Provider()
        self.large_slots = anyio.Semaphore(2)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path, method = scope["path"], scope["method"]
        headers = dict(scope.get("headers") or [])
        ip = security.ip_key((scope.get("client") or ("?",))[0])
        if path in self.RATES and (method == "POST" or path == "/authorize"):
            n, window = self.RATES[path]
            if await anyio.to_thread.run_sync(security.rate_limited, f"http:{path}:{ip}", n, window):
                return await self._reject(send, 429, "Too many requests. Try again later.")
        large = method == "POST" and bool(self.LARGE_PATHS.match(path))
        limit = self.SMALL
        if large:
            auth = headers.get(b"authorization", b"").decode(errors="replace")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if token and await self.provider.load_access_token(token):
                limit = self.LARGE       # big bodies only for signed-in callers
        length = headers.get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > limit):
            return await self._reject(send, 413, "Request too large.")
        # only requests that really carry a big body (or don't say how big) wait for one of the 2 slots
        if limit == self.LARGE and (length is None or int(length) > self.SMALL):
            async with self.large_slots:
                return await self._run(scope, receive, send, limit)
        return await self._run(scope, receive, send, limit)

    async def _run(self, scope, receive, send, limit):
        received, started = 0, False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestTooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestTooLarge:
            if not started:
                await self._reject(send, 413, "Request too large.")

    @staticmethod
    async def _reject(send, status, text):
        body = text.encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class RequestTooLarge(Exception):
    pass


class SecurityHeaders:
    """Adds strict security headers to every response."""

    HEADERS = {
        b"strict-transport-security": b"max-age=31536000; includeSubDomains",
        b"x-content-type-options": b"nosniff",
        b"x-frame-options": b"DENY",
        b"referrer-policy": b"no-referrer",
        b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=()",
        b"cross-origin-opener-policy": b"same-origin",
        b"content-security-policy": web.CSP.encode(),
    }

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message.get("headers", [])}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                headers += [(k, v) for k, v in self.HEADERS.items() if k not in present]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def main():
    uvicorn.run(build_app(), host="0.0.0.0", port=config.LISTEN_PORT, ssl_certfile=config.TLS_CERT,
                ssl_keyfile=config.TLS_KEY, ssl_version=ssl.PROTOCOL_TLS_SERVER,
                ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20",   # TLS 1.2 forward-secret AEAD only; 1.3 as negotiated
                proxy_headers=False, server_header=False, date_header=True,
                log_level="info", timeout_keep_alive=15, limit_concurrency=200, h11_max_incomplete_event_size=16384)


if __name__ == "__main__":
    main()
