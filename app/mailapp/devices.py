"""Set up a phone or computer from a QR code.

The console shows a QR code per mailbox. It opens a short-lived link (signed, no sign-in needed)
with the settings and an Apple configuration profile: iPhone, iPad and Mac then add the account
in the Mail app by themselves and only ask for the password. The profile never contains the
password, and it is signed with the server's TLS certificate so Apple devices show it as verified.
"""
import base64
import hashlib
import hmac
import plistlib
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from . import config

LINK_SECONDS = 3600
_KEY = hmac.new(config.SECRET_KEY, b"mailapp:device-link", hashlib.sha256).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_link(address: str, now: float | None = None) -> str:
    """A token for address, valid for LINK_SECONDS."""
    expires = int((now or time.time()) + LINK_SECONDS)
    body = f"{_b64(address.lower().encode())}.{expires}"
    sig = _b64(hmac.new(_KEY, body.encode(), hashlib.sha256).digest()[:18])
    return f"{body}.{sig}"


def check_link(token: str, now: float | None = None) -> str | None:
    """The address a token was made for, or None when it is forged, malformed or expired."""
    try:
        enc, expires, sig = token.split(".")
        good = _b64(hmac.new(_KEY, f"{enc}.{expires}".encode(), hashlib.sha256).digest()[:18])
        if not hmac.compare_digest(sig, good) or int(expires) < (now or time.time()):
            return None
        return _unb64(enc).decode()
    except (ValueError, UnicodeDecodeError):
        return None


def settings(address: str) -> dict:
    return {"address": address, "host": config.MAIL_HOST, "imap_port": 993, "smtp_port": 465}


def _identifier(address: str) -> str:
    reverse = ".".join(reversed(config.DOMAIN.split(".")))
    return f"{reverse}.mail.{hashlib.sha256(address.encode()).hexdigest()[:12]}"


def profile(address: str) -> bytes:
    """An Apple configuration profile (.mobileconfig) that adds address to the Mail app.

    The UUIDs depend only on the address, so installing it again replaces the old one."""
    ident = _identifier(address)
    account = {
        "PayloadType": "com.apple.mail.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{ident}.account",
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, f"mailapp:{address}:account")).upper(),
        "PayloadDisplayName": address,
        "EmailAccountDescription": address,
        "EmailAccountType": "EmailTypeIMAP",
        "EmailAddress": address,
        "IncomingMailServerHostName": config.MAIL_HOST,
        "IncomingMailServerPortNumber": 993,
        "IncomingMailServerUseSSL": True,
        "IncomingMailServerUsername": address,
        "IncomingMailServerAuthentication": "EmailAuthPassword",
        "OutgoingMailServerHostName": config.MAIL_HOST,
        "OutgoingMailServerPortNumber": 465,
        "OutgoingMailServerUseSSL": True,
        "OutgoingMailServerUsername": address,
        "OutgoingMailServerAuthentication": "EmailAuthPassword",
        "OutgoingPasswordSameAsIncomingPassword": True,
    }
    top = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": ident,
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, f"mailapp:{address}")).upper(),
        "PayloadDisplayName": f"Mail: {address}",
        "PayloadDescription": f"Adds {address} to the Mail app. You'll be asked for its password.",
        "PayloadOrganization": config.APP_NAME,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [account],
    }
    return _sign(plistlib.dumps(top, fmt=plistlib.FMT_XML))


def _sign(data: bytes) -> bytes:
    """Sign with the server's certificate (and its chain). Unsigned when that isn't possible,
    e.g. a test install: devices then say 'Unverified' but still install it."""
    try:
        with open(config.TLS_CERT, "rb") as f:
            chain = x509.load_pem_x509_certificates(f.read())
        with open(config.TLS_KEY, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError):
        return data
    builder = pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(chain[0], key, hashes.SHA256())
    for extra in chain[1:]:
        builder = builder.add_certificate(extra)
    return builder.sign(serialization.Encoding.DER, [])
