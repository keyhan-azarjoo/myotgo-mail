"""OAuth 2.1 for MCP clients (Claude and others). The MCP SDK serves the protocol endpoints
(/register, /authorize, /token, /revoke and the .well-known metadata) and checks PKCE; this
class stores everything in the database and sends people to our own sign-in and consent
pages, where the password and the two-step code are checked."""
import json
import secrets
import time
from urllib.parse import urlsplit

from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      RefreshToken, RegistrationError, TokenError)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from . import auth, config, db, security, service

MAX_CLIENTS = 1000
REQUEST_SECONDS = 600
CODE_SECONDS = 300


class Provider:
    # ---- clients (dynamic registration) ----
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = db.one("SELECT info FROM oauth_clients WHERE client_id = ?", (client_id,))
        if not row:
            return None
        client = OAuthClientInformationFull.model_validate_json(row["info"])
        if any(redirect_problem(str(u)) for u in client.redirect_uris or []):
            return None   # registered before the stricter rules: not usable any more
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # forget registrations that were never used, so the table can't be filled up for good
        db.execute("DELETE FROM oauth_clients WHERE created_at < ? AND client_id NOT IN "
                   "(SELECT DISTINCT client_id FROM oauth_tokens) AND client_id NOT IN "
                   "(SELECT DISTINCT client_id FROM oauth_requests)", (time.time() - 3600,))
        if db.one("SELECT COUNT(*) AS n FROM oauth_clients")["n"] >= MAX_CLIENTS:
            raise RegistrationError(error="invalid_client_metadata", error_description="Too many registered clients.")
        if len(client_info.client_name or "") > 64:
            raise RegistrationError(error="invalid_client_metadata", error_description="client_name is too long.")
        uris = [str(u) for u in client_info.redirect_uris or []]
        if not uris or len(uris) > 5:
            raise RegistrationError(error="invalid_redirect_uri", error_description="Give 1 to 5 redirect URIs.")
        for u in uris:
            if problem := redirect_problem(u):
                raise RegistrationError(error="invalid_redirect_uri", error_description=problem)
        db.execute("INSERT INTO oauth_clients(client_id, info, created_at) VALUES(?,?,?)",
                   (client_info.client_id, client_info.model_dump_json(), time.time()))
        db.audit(None, "oauth.client_registered", client_info.client_name or client_info.client_id,
                 {"redirect_uris": [str(u) for u in client_info.redirect_uris or []]})

    # ---- authorization: hand over to our sign-in page ----
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") != config.MCP_URL:
            raise AuthorizeError(error="invalid_request", error_description="Unknown resource.")
        rid = secrets.token_urlsafe(24)
        db.execute("DELETE FROM oauth_requests WHERE expires_at < ?", (time.time(),))
        db.execute("INSERT INTO oauth_requests(id, client_id, params, expires_at) VALUES(?,?,?,?)",
                   (rid, client.client_id, params.model_dump_json(), time.time() + REQUEST_SECONDS))
        return f"{config.PUBLIC_URL}/oauth/consent?request={rid}"

    # ---- codes ----
    async def load_authorization_code(self, client, authorization_code: str) -> AuthorizationCode | None:
        row = db.one("SELECT * FROM oauth_codes WHERE code_hash = ? AND client_id = ?",
                     (security.token_hash(authorization_code), client.client_id))
        if not row:
            return None
        if row["used"]:
            # A code used twice means it leaked: cancel everything issued from it.
            db.execute("UPDATE oauth_tokens SET revoked = 1 WHERE family = ?", (row["code_hash"],))
            return None
        return AuthorizationCode(code=authorization_code, scopes=json.loads(row["scopes"]), expires_at=row["expires_at"],
                                 client_id=row["client_id"], code_challenge=row["code_challenge"],
                                 redirect_uri=row["redirect_uri"], redirect_uri_provided_explicitly=bool(row["redirect_explicit"]),
                                 resource=config.MCP_URL, subject=str(row["user_id"]))

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        h = security.token_hash(authorization_code.code)
        with db.tx() as conn:
            row = conn.execute("SELECT * FROM oauth_codes WHERE code_hash = ?", (h,)).fetchone()
            if not row or row["used"] or row["expires_at"] < time.time():
                raise TokenError(error="invalid_grant", error_description="The code is invalid or expired.")
            conn.execute("UPDATE oauth_codes SET used = 1 WHERE code_hash = ?", (h,))
        return self._issue(client.client_id, row["user_id"], json.loads(row["scopes"]), family=h, mfa=bool(row["mfa"]),
                           direct_send=bool(row["direct_send"]))

    # ---- refresh ----
    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        raw = db.one("SELECT family, revoked FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'",
                     (security.token_hash(refresh_token),))
        if raw and raw["revoked"]:
            # An already-rotated refresh token came back: someone copied it. End the whole sign-in.
            db.execute("UPDATE oauth_tokens SET revoked = 1 WHERE family = ?", (raw["family"],))
            db.audit(None, "oauth.refresh_reuse_detected", client.client_id)
            return None
        row = self._token_row(refresh_token, "refresh")
        if not row or row["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=row["client_id"], scopes=json.loads(row["scopes"]),
                            expires_at=int(row["expires_at"]), resource=config.MCP_URL, subject=str(row["user_id"]))

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        h = security.token_hash(refresh_token.token)
        with db.tx() as conn:
            row = conn.execute("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'", (h,)).fetchone()
            if not row or row["revoked"]:
                if row:  # an old refresh token came back: someone copied it; end the whole family
                    conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE family = ?", (row["family"],))
                raise TokenError(error="invalid_grant", error_description="The refresh token is no longer valid.")
            conn.execute("UPDATE oauth_tokens SET revoked = 1 WHERE token_hash = ?", (h,))  # rotation
        granted = json.loads(row["scopes"])
        scopes = [s for s in (scopes or granted) if s in granted]
        return self._issue(client.client_id, row["user_id"], scopes, family=row["family"], mfa=bool(row["mfa"]),
                           direct_send=bool(row["direct_send"]))

    # ---- access tokens: OAuth ones and personal API tokens ----
    async def load_access_token(self, token: str) -> AccessToken | None:
        if token.startswith(auth.PAT_PREFIX):
            row = auth.load_api_token(token)
            if not row:
                return None
            return AccessToken(token=token, client_id=f"pat:{row['id']}", scopes=json.loads(row["scopes"]),
                               expires_at=int(row["expires_at"]) if row["expires_at"] else None,
                               resource=config.MCP_URL, subject=str(row["user_id"]),
                               claims={"direct_send": bool(row["direct_send"]), "app": f"token “{row['name']}”"})
        row = self._token_row(token, "access")
        if not row or not auth.two_step_ok_for_tokens(row["user_id"], bool(row["mfa"])):
            return None
        client = db.one("SELECT info FROM oauth_clients WHERE client_id = ?", (row["client_id"],))
        name = json.loads(client["info"]).get("client_name") if client else None
        return AccessToken(token=token, client_id=row["client_id"], scopes=json.loads(row["scopes"]),
                           expires_at=int(row["expires_at"]), resource=config.MCP_URL, subject=str(row["user_id"]),
                           claims={"direct_send": bool(row["direct_send"]), "app": name or "an app"})

    async def revoke_token(self, token) -> None:
        raw = getattr(token, "token", token)
        row = db.one("SELECT family FROM oauth_tokens WHERE token_hash = ?", (security.token_hash(raw),))
        if row:
            db.execute("UPDATE oauth_tokens SET revoked = 1 WHERE family = ?", (row["family"],))

    async def exchange_identity_assertion(self, *args, **kwargs):
        raise TokenError(error="unsupported_grant_type", error_description="Not supported.")

    # ---- helpers ----
    def _token_row(self, token: str, kind: str):
        row = db.one("SELECT t.*, u.disabled FROM oauth_tokens t JOIN users u ON u.id = t.user_id "
                     "WHERE t.token_hash = ? AND t.kind = ?", (security.token_hash(token), kind))
        if not row or row["revoked"] or row["disabled"] or row["expires_at"] < time.time():
            return None
        return row

    def _issue(self, client_id: str, user_id: int, scopes: list[str], family: str, mfa: bool,
               direct_send: bool = False) -> OAuthToken:
        access, refresh = security.new_token(), security.new_token()
        now = time.time()
        with db.tx() as conn:
            for tok, kind, ttl in ((access, "access", config.ACCESS_TOKEN_SECONDS),
                                   (refresh, "refresh", config.REFRESH_TOKEN_DAYS * 86400)):
                conn.execute("INSERT INTO oauth_tokens(token_hash, kind, family, client_id, user_id, scopes, "
                             "expires_at, created_at, mfa, direct_send) VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (security.token_hash(tok), kind, family, client_id, user_id, json.dumps(scopes),
                              now + ttl, now, int(mfa), int(direct_send)))
        return OAuthToken(access_token=access, expires_in=config.ACCESS_TOKEN_SECONDS, scope=" ".join(scopes),
                          refresh_token=refresh)


def redirect_problem(uri: str) -> str | None:
    """https anywhere, or plain http only to this computer (how desktop apps receive the code)."""
    p = urlsplit(uri)
    if p.username or p.password or p.fragment:
        return "Redirect URIs can't contain a user name, password or #fragment."
    if p.scheme == "https" and p.hostname:
        return None
    if p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1", "::1"):
        return None
    return "Redirect URIs must be https, or http to localhost."


def offered_scopes(client, params, role: str) -> list[str]:
    """What the consent page offers: what the app asked for (or registered for), never more than
    the person's role allows. Admin access is only ever granted when ticked on the page."""
    requested = params.scopes or (client.scope.split() if client.scope else ["mail.read", "mail.send", "mail.organize"])
    return [s for s in service.SCOPES if s in requested and (s != "admin" or role == "admin")]


def pending_request(rid: str):
    row = db.one("SELECT * FROM oauth_requests WHERE id = ? AND expires_at > ?", (rid or "", time.time()))
    if not row:
        return None, None, None
    client = db.one("SELECT info FROM oauth_clients WHERE client_id = ?", (row["client_id"],))
    if not client:
        return None, None, None
    return row, OAuthClientInformationFull.model_validate_json(client["info"]), AuthorizationParams.model_validate_json(row["params"])


def approve(rid: str, user_id: int, mfa: bool = False, allow_admin: bool = False, direct_send: bool = False) -> str:
    """Create the authorization code for a pending request and return the client redirect URL."""
    from mcp.server.auth.provider import construct_redirect_uri
    row, client, params = pending_request(rid)
    if not row:
        raise auth.AuthError("This sign-in request expired. Start again from your app.")
    user = db.one("SELECT role FROM users WHERE id = ?", (user_id,))
    scopes = [s for s in offered_scopes(client, params, user["role"]) if s != "admin" or allow_admin]
    code = security.new_token()
    with db.tx() as conn:
        conn.execute("DELETE FROM oauth_requests WHERE id = ?", (rid,))
        conn.execute("INSERT INTO oauth_codes(code_hash, client_id, user_id, scopes, code_challenge, redirect_uri, "
                     "redirect_explicit, expires_at, mfa, direct_send) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (security.token_hash(code), client.client_id, user_id, json.dumps(scopes), params.code_challenge,
                      str(params.redirect_uri), int(params.redirect_uri_provided_explicitly), time.time() + CODE_SECONDS,
                      int(mfa), int(direct_send)))
    db.audit(None, "oauth.approved", client.client_name or client.client_id,
             {"user_id": user_id, "scopes": scopes, "direct_send": direct_send})
    return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)


def deny(rid: str) -> str | None:
    from mcp.server.auth.provider import construct_redirect_uri
    row, client, params = pending_request(rid)
    if not row:
        return None
    db.execute("DELETE FROM oauth_requests WHERE id = ?", (rid,))
    return construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state)
