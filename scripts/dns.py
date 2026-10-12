#!/usr/bin/env python3
"""Runs on YOUR computer, via `./mail dns <command>`. The DNS records a mail server needs.

  records    print every record to create, with the exact values (works with any DNS provider)
  check      look the records up on public DNS and say what is missing or wrong
  show       (GoDaddy) print the current mail-related records
  prepare    (GoDaddy) create the A record for MAIL_HOST, DKIM and DMARC. Mail keeps going where it goes now.
  spf        (GoDaddy) add the server's IP to SPF, keeping everything already allowed
  switch     (GoDaddy) point MX at MAIL_HOST: from now on mail for DOMAIN arrives at this server
  rollback   (GoDaddy) put back the MX and SPF records saved before the last switch

GoDaddy commands save every record to SECRETS_DIR/dns-backup-<time>.json before changing anything.
Settings come from mail.conf (exported by ./mail).
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DOMAIN = os.environ["DOMAIN"]
MAIL_HOST = os.environ["MAIL_HOST"]
IP = os.environ["SERVER_IP"]
SELECTOR = os.environ.get("DKIM_SELECTOR", "mail")
PROVIDER = os.environ.get("DNS_PROVIDER", "")
SECRETS = Path(os.environ["SECRETS_DIR"])
CREDS = Path(os.environ["DNS_CREDENTIALS"])
SSH = ["ssh", "-i", os.environ["SSH_KEY"], "-o", "BatchMode=yes", os.environ["SSH_TARGET"]]
REMOTE_DIR = os.environ["REMOTE_DIR"]

if not MAIL_HOST.endswith("." + DOMAIN):
    sys.exit(f"MAIL_HOST ({MAIL_HOST}) must be a name inside {DOMAIN}, e.g. mx.{DOMAIN}")
HOST = MAIL_HOST[: -len(DOMAIN) - 1]  # "mx"


# ---------- values -------------------------------------------------------------------

def dkim_value():
    out = subprocess.run(
        SSH + [f"cat {REMOTE_DIR}/data/config/rspamd/dkim/rsa-2048-{SELECTOR}-{DOMAIN}.public.dns.txt"],
        capture_output=True, text=True)
    value = out.stdout.strip()
    if out.returncode or not value.startswith("v=DKIM1;"):
        sys.exit("No DKIM key on the server yet. Run `./mail deploy` and `./mail add <first mailbox>` first.")
    return value


def wanted():
    return [
        ("A", MAIL_HOST, IP, "the mail server's name"),
        ("MX", DOMAIN, f"10 {MAIL_HOST}", "where mail for the domain is delivered (create this LAST: it moves your mail)"),
        ("TXT", DOMAIN, f"v=spf1 ip4:{IP} ~all",
         f"SPF: allows the server to send. If an SPF record exists, add ip4:{IP} to it instead"),
        ("TXT", f"{SELECTOR}._domainkey.{DOMAIN}", dkim_value(), "DKIM: lets receivers verify our signature"),
        ("TXT", f"_dmarc.{DOMAIN}", f"v=DMARC1; p=none; rua=mailto:postmaster@{DOMAIN}", "DMARC (only if you have none)"),
        ("PTR", IP, MAIL_HOST, "reverse DNS: set in your HOSTING provider's panel, not at the DNS provider"),
    ]


def records():
    for rtype, name, value, why in wanted():
        print(f"{rtype:<4} {name}\n     {value}\n     ({why})\n")


# ---------- check (public DNS, any provider) ------------------------------------------

def lookup(rtype, name):
    if not shutil.which("dig"):
        sys.exit("`check` needs the `dig` command (macOS has it; on Linux install dnsutils / bind-utils)")
    args = ["-x", name] if rtype == "PTR" else [name, rtype]
    out = subprocess.run(["dig", "+short", "@1.1.1.1", *args], capture_output=True, text=True).stdout
    return [line.strip().strip('"').replace('" "', "") for line in out.splitlines() if line.strip()]


def check():
    ok = True
    mx_here = False
    for rtype, name, value, _ in wanted():
        got = lookup(rtype, name)
        if rtype == "TXT" and value.startswith("v=spf1"):
            spf = [g for g in got if g.startswith("v=spf1")]
            good = len(spf) == 1 and (f"ip4:{IP}" in spf[0] or f"a:{MAIL_HOST}" in spf[0])
        elif rtype == "TXT" and value.startswith("v=DMARC1"):
            good = any(g.startswith("v=DMARC1") for g in got)
        elif rtype == "MX":
            good = mx_here = any(g.rstrip(".").endswith(MAIL_HOST) for g in got)
        else:
            good = any(g.rstrip(".") == value for g in got)
        if rtype != "MX":
            ok &= good
        mark = "OK " if good else ("-- " if rtype == "MX" else "BAD")
        print(f"{mark} {rtype:<4} {name}: {'; '.join(got)[:100] or '(nothing)'}")
    if not mx_here:
        print("\nMX still points elsewhere: expected until you run `./mail dns switch` (or change it by hand).")
    sys.exit(0 if ok else 1)


# ---------- GoDaddy automation ---------------------------------------------------------

def godaddy_keys():
    if PROVIDER != "godaddy":
        sys.exit(f"Automatic DNS changes only support DNS_PROVIDER=godaddy (yours: '{PROVIDER or 'none'}').\n"
                 "Run `./mail dns records` and create the records in your provider's panel.")
    vals = dict(line.split("=", 1) for line in CREDS.read_text().split() if "=" in line)
    return vals["GODADDY_API_KEY"], vals["GODADDY_API_SECRET"]


def api(method, path, body=None):
    key, secret = godaddy_keys()
    req = urllib.request.Request(
        f"https://api.godaddy.com/v1/domains/{DOMAIN}/records{path}",
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"sso-key {key}:{secret}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
    return json.loads(raw) if raw else None


def backup():
    SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    f = SECRETS / f"dns-backup-{time.strftime('%Y%m%d-%H%M%S')}.json"
    f.write_text(json.dumps(api("GET", ""), indent=2))
    f.chmod(0o600)
    print(f"backup: {f}")


def put(rtype, name, recs):
    api("PUT", f"/{rtype}/{name}", [{"ttl": 600, **r} for r in recs])
    print(f"set {rtype} {name}: {[r['data'][:60] for r in recs]}")


def show():
    for r in api("GET", ""):
        if r["type"] in ("MX", "TXT") or r["name"] in (HOST, "*"):
            print(r["type"], r["name"], r["data"][:90])


def prepare():
    backup()
    put("A", HOST, [{"data": IP}])
    put("TXT", f"{SELECTOR}._domainkey", [{"data": dkim_value()}])
    if not api("GET", "/TXT/_dmarc"):
        put("TXT", "_dmarc", [{"data": f"v=DMARC1; p=none; rua=mailto:postmaster@{DOMAIN}"}])


def add_ip_to_spf():
    txt = api("GET", "/TXT/@")
    spf = [r for r in txt if r["data"].startswith("v=spf1")]
    if len(spf) > 1:
        sys.exit(f"found {len(spf)} SPF records at {DOMAIN}; there must be only one. Fix that by hand first.")
    if spf and f"ip4:{IP}" in spf[0]["data"]:
        print(f"SPF already allows {IP}")
        return
    if spf:
        spf[0]["data"] = spf[0]["data"].replace("v=spf1", f"v=spf1 ip4:{IP}", 1)
    else:
        txt.append({"data": f"v=spf1 ip4:{IP} ~all"})
    # PUT replaces every TXT record at @, so send the others back unchanged
    put("TXT", "@", [{"data": r["data"], "ttl": r.get("ttl", 600)} for r in txt])


def spf():
    backup()
    add_ip_to_spf()


def switch():
    backup()
    add_ip_to_spf()
    put("MX", "@", [{"data": MAIL_HOST, "priority": 10}])
    print(f"Mail for {DOMAIN} now goes to {MAIL_HOST}. Caches take 10-60 minutes to follow.")


def rollback():
    files = sorted(SECRETS.glob("dns-backup-*.json"))
    # the backup taken by the last switch is the newest one that still has the old MX
    for f in reversed(files):
        recs = json.loads(f.read_text())
        mx = [r for r in recs if r["type"] == "MX" and r["name"] == "@"]
        if mx and all(r["data"] != MAIL_HOST for r in mx):
            break
    else:
        sys.exit("no backup with the old MX records found")
    backup()
    put("MX", "@", [{"data": r["data"], "priority": r["priority"], "ttl": r.get("ttl", 600)} for r in mx])
    txt = [r for r in recs if r["type"] == "TXT" and r["name"] == "@"]
    put("TXT", "@", [{"data": r["data"], "ttl": r.get("ttl", 600)} for r in txt])
    print(f"restored from {f}")


if __name__ == "__main__":
    cmds = {"records": records, "check": check, "show": show, "prepare": prepare,
            "spf": spf, "switch": switch, "rollback": rollback}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()
