#!/usr/bin/env python3
"""End-to-end checks against the live mail server. Run it with `./mail test <mailbox>`.

  ./mail test you@example.com                       all checks
  ./mail test you@example.com --external a@gmail.com   also send a real message to the outside

Settings come from mail.conf (exported by ./mail). The mailbox password comes from
MAIL_PASSWORD, or SECRETS_DIR/<address>.txt.
"""
import argparse
import email.utils
import imaplib
import os
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage
from pathlib import Path

HOST = os.environ["MAIL_HOST"]
DOMAIN = os.environ["DOMAIN"]
USER = os.environ["MAIL_USER"]
SERVER = os.environ["SSH_TARGET"]
SSH_KEY = os.environ["SSH_KEY"]
SECRETS = Path(os.environ["SECRETS_DIR"])
REMOTE_DIR = os.environ["REMOTE_DIR"]
ALIAS = f"postmaster@{DOMAIN}"  # created by the first `./mail add`
# Envelope sender for the "incoming mail" test: an empty one, like a delivery report,
# so no outside domain's SPF/DMARC policy gets in the way.
OUTSIDE_FROM = ""

results = []


def check(name):
    def wrap(fn):
        def run(*a):
            try:
                detail = fn(*a) or ""
                results.append((True, name, detail))
            except Exception as e:  # noqa: BLE001 - report every failure and carry on
                results.append((False, name, f"{type(e).__name__}: {e}"))
        return run
    return wrap


def password():
    if os.environ.get("MAIL_PASSWORD"):
        return os.environ["MAIL_PASSWORD"]
    return (SECRETS / f"{USER}.txt").read_text().strip()


def message(sender, to, token):
    m = EmailMessage()
    m["From"], m["To"] = sender, to
    m["Subject"] = f"mail check {token}"
    m["Date"] = email.utils.formatdate(localtime=True)
    m["Message-ID"] = email.utils.make_msgid(domain=DOMAIN)
    m.set_content(f"Automatic test message {token}.\n")
    return m


def on_server(cmd):
    return subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", SERVER, cmd],
                          capture_output=True, text=True, timeout=60).stdout


def smtp25():
    """Port 25 straight from this Mac, or through the server when the ISP blocks it."""
    try:
        return smtplib.SMTP(HOST, 25, timeout=15)
    except OSError:
        return None


@check("TLS certificate valid on 993 (IMAP)")
def tls_imap():
    with socket.create_connection((HOST, 993), timeout=15) as s:
        with ssl.create_default_context().wrap_socket(s, server_hostname=HOST) as t:
            return f"expires {t.getpeercert()['notAfter']}"


@check("TLS certificate valid on 465 (SMTPS)")
def tls_465():
    with smtplib.SMTP_SSL(HOST, 465, timeout=15, context=ssl.create_default_context()) as s:
        s.ehlo()


@check("STARTTLS on 587 (submission)")
def tls_587():
    with smtplib.SMTP(HOST, 587, timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.ehlo()


@check("wrong password is refused")
def bad_login():
    with smtplib.SMTP_SSL(HOST, 465, timeout=15) as s:
        try:
            s.login(USER, "wrong-" + uuid.uuid4().hex)
        except smtplib.SMTPAuthenticationError:
            return "refused"
    raise AssertionError("login with a wrong password succeeded")


@check("incoming mail on port 25 is accepted")
def inbound(token):
    m = message(f"Mail check <mailer-daemon@{HOST}>", USER, token)
    s = smtp25()
    if s is None:  # ISP blocks port 25: send from the server to its own public address
        out = on_server(
            "python3 - <<'E'\nimport smtplib\n"
            f"s=smtplib.SMTP('{HOST}',25,timeout=15);s.starttls();"
            f"s.sendmail({OUTSIDE_FROM!r},['{USER}'],{m.as_string()!r});print('OK')\nE")
        assert "OK" in out, out
        return "sent from the server (this network blocks port 25)"
    with s:
        s.starttls(context=ssl.create_default_context())
        s.send_message(m, OUTSIDE_FROM, [USER])
    return "sent directly on port 25"


@check("not an open relay: unauthenticated mail to outside is refused")
def open_relay():
    s = smtp25()
    if s is None:
        out = on_server(
            "python3 - <<'E'\nimport smtplib\n"
            f"s=smtplib.SMTP('{HOST}',25,timeout=15);s.starttls();s.ehlo();s.mail('x@example.org')\n"
            "print(s.rcpt('someone@gmail.com'))\nE")
        assert "554" in out or "Relay access denied" in out, out
        return out.strip()
    with s:
        s.starttls()
        s.ehlo()
        s.mail("x@example.org")
        code, msg = s.rcpt("someone@gmail.com")
        assert code >= 500, (code, msg)
        return f"{code} {msg.decode()[:60]}"


@check("signed-in user can't send as another address")
def spoofing():
    with smtplib.SMTP_SSL(HOST, 465, timeout=15) as s:
        s.login(USER, password())
        try:
            s.send_message(message(f"ceo@{DOMAIN}", USER, "spoof"), f"ceo@{DOMAIN}", [USER])
        except (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError) as e:
            return f"refused ({e.args[0]})"
    raise AssertionError("server accepted a forged sender")


@check("sending through 587 (signed in) works")
def submit(token):
    with smtplib.SMTP(HOST, 587, timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(USER, password())
        s.send_message(message(USER, USER, token))


@check("alias postmaster@ delivers to the mailbox")
def alias(token):
    with smtplib.SMTP_SSL(HOST, 465, timeout=15) as s:
        s.login(USER, password())
        s.send_message(message(USER, ALIAS, token))


def imap_find(tokens, timeout=60):
    found = {}
    deadline = time.time() + timeout
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=ssl.create_default_context()) as im:
        im.login(USER, password())
        while time.time() < deadline and len(found) < len(tokens):
            for box in ("INBOX", "Junk"):
                if im.select(box)[0] != "OK":
                    continue
                for t in tokens:
                    if t in found:
                        continue
                    typ, data = im.search(None, "SUBJECT", f'"{t}"')
                    if data and data[0]:
                        num = data[0].split()[-1]
                        _, msg = im.fetch(num, "(BODY.PEEK[HEADER])")
                        found[t] = (box, msg[0][1].decode(errors="replace"))
            time.sleep(3)
    return found


@check("external relay attempt")
def external(to, token):
    with smtplib.SMTP(HOST, 587, timeout=15) as s:
        s.starttls()
        s.login(USER, password())
        s.send_message(message(USER, to, token))
    time.sleep(20)
    log = on_server(f"grep -h '{to}' {REMOTE_DIR}/data/mail-logs/mail.log | tail -3")
    if "status=sent" in log:
        return "delivered: " + log.strip().splitlines()[-1][-120:]
    raise AssertionError("not delivered yet: " + (log.strip().splitlines() or ["no log line"])[-1][-200:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--external", help="also send a real message to this outside address")
    args = ap.parse_args()

    run = uuid.uuid4().hex[:8]
    t_in, t_sub, t_alias = f"in-{run}", f"sub-{run}", f"alias-{run}"
    tls_imap(); tls_465(); tls_587(); bad_login()
    inbound(t_in); open_relay(); spoofing(); submit(t_sub); alias(t_alias)

    found = {}

    @check("IMAP: all three test messages arrived")
    def arrived():
        found.update(imap_find([t_in, t_sub, t_alias]))
        missing = [t for t in (t_in, t_sub, t_alias) if t not in found]
        assert not missing, f"missing {missing}"
        return ", ".join(f"{t.split('-')[0]}→{found[t][0]}" for t in found)
    arrived()

    @check("outgoing mail is DKIM-signed")
    def dkim():
        hdr = found.get(t_sub, ("", ""))[1]
        assert "DKIM-Signature" in hdr and f"d={DOMAIN}" in hdr, f"no DKIM-Signature for {DOMAIN}"
    dkim()

    if args.external:
        external(args.external, f"ext-{run}")

    width = max(len(n) for _, n, _ in results)
    for ok, name, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}")
    failed = sum(not ok for ok, _, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
