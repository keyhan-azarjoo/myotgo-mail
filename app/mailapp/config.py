"""Settings, all from environment variables (compose.yaml and secrets/app.env)."""
import base64
import os
from pathlib import Path


def _req(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing environment variable {name}")
    return value


MAIL_HOST = _req("MAIL_HOST")
DOMAIN = _req("DOMAIN").lower()
PUBLIC_URL = os.environ.get("PUBLIC_URL", f"https://{MAIL_HOST}").rstrip("/")
MCP_URL = f"{PUBLIC_URL}/mcp"
APP_NAME = os.environ.get("APP_NAME", f"{DOMAIN} mail")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "app.db"
MAILCONF_DIR = Path(os.environ.get("MAILCONF_DIR", "/mailconfig"))
MAILDATA_DIR = Path(os.environ.get("MAILDATA_DIR", "/maildata"))

# The mail server, reached inside the compose network under its public name, so TLS
# certificate checks work exactly as they do for any mail app.
IMAP_HOST = os.environ.get("IMAP_HOST", MAIL_HOST)
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
SMTP_HOST = os.environ.get("SMTP_HOST", MAIL_HOST)
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))

# Only for test installs (CERT_METHOD=selfsigned): the private CA that signed the test certificate.
MAIL_CA_FILE = os.environ.get("MAIL_CA_FILE", "").strip()

TLS_CERT = os.environ.get("TLS_CERT", f"/certs/{MAIL_HOST}.crt")
TLS_KEY = os.environ.get("TLS_KEY", f"/certs/{MAIL_HOST}.key")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8443"))

# 32-byte key that encrypts stored mailbox passwords and 2FA secrets (AES-256-GCM).
SECRET_KEY = base64.urlsafe_b64decode(_req("APP_SECRET_KEY") + "==")
if len(SECRET_KEY) != 32:
    raise SystemExit("APP_SECRET_KEY must be 32 bytes, base64url encoded")

SESSION_IDLE_MINUTES = 30
SESSION_MAX_HOURS = 12
ACCESS_TOKEN_SECONDS = 3600
REFRESH_TOKEN_DAYS = 30
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_RECIPIENTS = 50
