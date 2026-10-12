"""One HTTPS server: the MCP endpoint (/mcp) with its OAuth endpoints, the REST API
(/api/v1) and the web console (everything else)."""
import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Mount

from . import api, config, db, mcp_tools, service, web
from .oauth import Provider

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

INSTRUCTIONS = f"""Email for {config.DOMAIN}. Start with list_mailboxes to see which mailboxes you may use
and with which permissions (read, send, organize). Use search_emails to find messages (it returns uids),
then read_email, reply_email, forward_email, move_emails and so on with those uids. Prefer save_draft
when a person should review a message before it goes out. admin_* tools are only for admins."""


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
                enabled=True, valid_scopes=list(service.SCOPES), default_scopes=list(service.SCOPES)),
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
    return SecurityHeaders(app)


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
                ssl_keyfile=config.TLS_KEY, proxy_headers=False, server_header=False, date_header=True,
                log_level="info", timeout_keep_alive=15, limit_concurrency=200)


if __name__ == "__main__":
    main()
