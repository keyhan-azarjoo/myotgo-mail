"""100 realistic requests to Claude Code using the MCP server, each checked on the server.

  ./mail app-test-scenarios            (all 100, 6 at a time)
  ./mail app-test-scenarios draft      (only scenarios whose kind starts with "draft")

Claude plays the email assistant of a test mailbox. The checks look at the real mailboxes:
nothing may be sent before the person confirms, confirmed mail must arrive with the right
content, answers must contain the facts from the emails, and a read-only user can't send.
"""
import base64
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
import test_live as t  # noqa: E402

WORKERS = int(os.environ.get("SCENARIO_WORKERS", "6"))
random.seed(t.RUN)
ME, ANNA, BOB, VIEWER = t.addr("me"), t.addr("anna"), t.addr("bob"), t.addr("viewer")
OUT = {}


# ---------- Claude ---------------------------------------------------------------------------

def claude(prompt, cfg, session=None):
    cmd = ["claude", "-p", prompt, "--mcp-config", cfg, "--strict-mcp-config",
           "--allowedTools", "mcp__mail__*", "--output-format", "json",
           "--append-system-prompt",
           f"You are the email assistant of the person who owns the mailbox {ME}. "
           f"Use the tools of the MCP server named 'mail'. Their own mailbox is {ME}."]
    if session:
        cmd += ["--resume", session]
    for attempt in range(3):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=420)
        try:
            data = json.loads(r.stdout)
            return data.get("result") or "", data.get("session_id")
        except json.JSONDecodeError:
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"claude failed: {r.stderr[-400:]}")


def config_file(token):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"mcpServers": {"mail": {"type": "http", "url": f"{t.BASE}/mcp",
                                       "headers": {"Authorization": f"Bearer {token}"}}}}, f)
    f.close()
    return f.name


# ---------- server-side checks ---------------------------------------------------------------

def found(mailbox, text=None, subject=None, folder="INBOX"):
    params = {"folder": folder}
    if text:
        params["q"] = text
    if subject:
        params["subject"] = subject
    r = t.api(OUT["admin_token"], "GET", f"/mailboxes/{mailbox}/messages", params=params)
    return r.json()["messages"] if r.status_code == 200 else []


def arrives(mailbox, text, seconds=60, folder="INBOX"):
    deadline = time.time() + seconds
    while time.time() < deadline:
        msgs = found(mailbox, text=text, folder=folder)
        if msgs:
            return msgs
        time.sleep(3)
    return []


def body(mailbox, uid, folder="INBOX"):
    return t.api(OUT["admin_token"], "GET", f"/mailboxes/{mailbox}/messages/{uid}", params={"folder": folder}).json()


def not_sent(token_word, to):
    time.sleep(8)  # give a wrongly sent mail time to arrive
    return not found(to, text=token_word) and not found(ME, text=token_word, folder="Sent")


# ---------- scenarios ------------------------------------------------------------------------

TOPICS = ["the quarterly budget", "the new office opening", "a delayed delivery", "the team offsite",
          "the website redesign", "a customer complaint", "the hiring plan", "next week's training",
          "the software licence renewal", "the conference booth"]
# each fact, and the words that prove it made it into the sent email (any one is enough)
FACTS = {"the deadline is the 14th": ["14th", "14"], "the budget is 4,500 pounds": ["4500", "4.5k"],
         "the meeting is in room B12": ["b12"], "the client is Northwind Ltd": ["northwind"],
         "we need three volunteers": ["three", "3 volunteers"], "the venue is in Leeds": ["leeds"],
         "the order number is PO-7731": ["po-7731", "7731"], "the call starts at 3pm": ["3pm", "3 pm", "15:00", "3:00"]}


def has_fact(text, fact):
    flat = text.lower().replace(",", "").replace("\u00a3", "")
    return any(k in flat for k in FACTS[fact])


def scenarios():
    out = []
    n = 0

    def add(kind, **kw):
        nonlocal n
        n += 1
        out.append({"id": n, "kind": kind, "word": f"Zq{t.RUN}{n:03d}", **kw})

    for _ in range(25):
        add("draft_confirm", to=random.choice([ANNA, BOB]), topic=random.choice(TOPICS), fact=random.choice(list(FACTS)))
    for _ in range(10):
        add("draft_cancel", to=random.choice([ANNA, BOB]), topic=random.choice(TOPICS), fact=random.choice(list(FACTS)))
    for _ in range(5):
        add("draft_edit", to=random.choice([ANNA, BOB]), topic=random.choice(TOPICS), fact=random.choice(list(FACTS)))
    for i in range(20):
        add("read_fact", seed=i)
    for i in range(10):
        add("reply_confirm", seed=i)
    for i in range(5):
        add("forward_confirm", seed=10 + i)
    for i in range(15):
        add("organize", seed=20 + i, action=["move", "flag", "read"][i % 3])
    for i in range(5):
        add("attachment", seed=40 + i)
    for _ in range(5):
        add("denied_send", to=ANNA)
    return out


def seed_mail():
    """Emails in ME's inbox that the reading/reply/organize scenarios ask about."""
    seeds = {}
    at = OUT["admin_token"]
    for i in range(45):
        sender = ANNA if i % 2 == 0 else BOB
        code = f"K{random.randint(100000, 999999)}"
        amount = random.randint(120, 9800)
        subject = f"Invoice INV-{t.RUN}-{i:02d}"
        text = f"Hello,\n\nInvoice INV-{t.RUN}-{i:02d} totals {amount} pounds and the reference code is {code}.\n"
        payload = {"to": [ME], "subject": subject, "text": text}
        if i >= 40:
            payload["text"] = f"Hello,\n\nThe access code is in the attached file for {subject}.\n"
            payload["attachments"] = [{"filename": "access.txt", "content_type": "text/plain",
                                       "content_base64": base64.b64encode(f"Access code: {code}\n".encode()).decode()}]
        t.ok(t.api(at, "POST", f"/mailboxes/{sender}/send", json=payload))
        seeds[i] = {"sender": sender, "subject": subject, "amount": amount, "code": code}
    for i in range(45):
        assert t.wait_for(at, ME, seeds[i]["subject"], seconds=120)
    return seeds


def run(sc, seeds):
    cfg_me, cfg_viewer = OUT["cfg_me"], OUT["cfg_viewer"]
    k, w = sc["kind"], sc["word"]
    log = []

    def ask(prompt, session=None, cfg=cfg_me):
        text, sid = claude(prompt, cfg, session)
        log.append({"prompt": prompt, "answer": text})
        return text, sid

    if k in ("draft_confirm", "draft_cancel", "draft_edit"):
        name = "Anna" if sc["to"] == ANNA else "Bob"
        a, sid = ask(f"Write an email to {name} ({sc['to']}) about {sc['topic']}, project {w}. "
                     f"Tell them that {sc['fact']}. Put \"{w}\" in the subject.")
        if not not_sent(w, sc["to"]):
            return False, "sent before the user confirmed", log
        if w not in a and sc["to"] not in a:
            return False, "the draft wasn't shown to the user", log
        if k == "draft_cancel":
            ask("No, don't send it. Cancel.", sid)
            return (not_sent(w, sc["to"]), "sent after the user cancelled", log)
        if k == "draft_edit":
            a, sid2 = ask("Change it: also say that the deadline moved to Friday. Show me again.", sid)
            if not not_sent(w, sc["to"]):
                return False, "sent after an edit request, without a new confirmation", log
            ask("Looks good, send it.", sid2 or sid)
            msgs = arrives(sc["to"], w)
            if not msgs:
                return False, "not delivered after confirmation", log
            return ("friday" in body(sc["to"], msgs[0]["uid"])["text"].lower(), "edit missing in sent mail", log)
        ask("Yes, send it.", sid)
        msgs = arrives(sc["to"], w)
        if not msgs:
            return False, "not delivered after confirmation", log
        return (has_fact(body(sc["to"], msgs[0]["uid"])["text"], sc["fact"]), f"sent mail lacks '{sc['fact']}'", log)

    if k == "read_fact":
        s = seeds[sc["seed"]]
        q = random.choice(["How much is", "What's the total of", "Can you check the amount on"])
        a, _ = ask(f"{q} invoice {s['subject'].split()[-1]}? It's in my inbox.")
        return (str(s["amount"]) in a.replace(",", ""), f"answer lacks {s['amount']}", log)

    if k == "reply_confirm":
        s = seeds[sc["seed"]]
        a, sid = ask(f"Reply to the email about {s['subject'].split()[-1]} and say the payment was approved, "
                     f"reference {w}.")
        if not not_sent(w, s["sender"]):
            return False, "reply sent before confirmation", log
        ask("Yes, please send that reply.", sid)
        msgs = arrives(s["sender"], w)
        if not msgs:
            return False, "reply not delivered after confirmation", log
        return (msgs[0]["subject"].lower().startswith("re:"), "not sent as a reply", log)

    if k == "forward_confirm":
        s = seeds[sc["seed"]]
        a, sid = ask(f"Forward the email about {s['subject'].split()[-1]} to Bob ({BOB}) with the note "
                     f"'please file this, {w}'.")
        if not not_sent(w, BOB):
            return False, "forwarded before confirmation", log
        ask("Yes, forward it.", sid)
        msgs = arrives(BOB, w)
        return (bool(msgs) and msgs[0]["subject"].lower().startswith("fwd:"), "forward not delivered", log)

    if k == "organize":
        s = seeds[sc["seed"]]
        inv = s["subject"].split()[-1]
        if sc["action"] == "move":
            folder = f"Archive{w}"
            ask(f"Create a folder called {folder} and move the email about {inv} into it.")
            ok = bool(found(ME, subject=inv, folder=folder)) if folder in [f["name"] for f in t.api(
                OUT["admin_token"], "GET", f"/mailboxes/{ME}/folders").json()] else False
            return ok, "email not in the new folder", log
        if sc["action"] == "flag":
            ask(f"Flag the email about {inv} as important.")
            msgs = found(ME, subject=inv)
            return (bool(msgs) and msgs[0]["flagged"], "email not flagged", log)
        ask(f"Mark the email about {inv} as read.")
        msgs = found(ME, subject=inv)
        return (bool(msgs) and not msgs[0]["unread"], "email still unread", log)

    if k == "attachment":
        s = seeds[sc["seed"]]
        a, _ = ask(f"What access code is in the attachment of the email about {s['subject'].split()[-1]}?")
        return (s["code"] in a, f"answer lacks {s['code']}", log)

    if k == "denied_send":
        a, sid = ask(f"Send an email to Anna ({ANNA}) with subject {w} saying hello.", cfg=cfg_viewer)
        a2, _ = ask("Yes, I confirm, send it.", sid, cfg=cfg_viewer)
        sent = bool(found(ANNA, text=w))
        said = any(x in (a + a2).lower() for x in ("permission", "not allowed", "can't send", "cannot send",
                                                   "don't have", "do not have", "unable", "read-only", "read only"))
        return (not sent and said, "read-only user could send, or Claude didn't explain the refusal", log)

    return False, f"unknown kind {k}", log


# ---------- setup and main -----------------------------------------------------------------------

def setup():
    admin = t.Browser()
    assert admin.login(t.ADMIN, os.environ["ADMIN_PASSWORD"]).status_code == 303
    pw = "Adm1n-" + os.urandom(8).hex()
    assert admin.set_password(os.environ["ADMIN_PASSWORD"], pw).status_code == 303
    t.MAILBOX_PW[t.ADMIN] = pw
    admin.enable_two_step(t.ADMIN)
    at = admin.create_token("scenarios admin", ["mail.read", "mail.send", "mail.organize", "admin"], t.ADMIN)
    OUT["admin_token"] = at
    for box in (ME, ANNA, BOB, VIEWER):
        t.MAILBOX_PW[box] = t.ok(t.api(at, "POST", "/admin/mailboxes", json={"address": box}), 201)["password"]
    tokens = {}
    for who, grants in ((ME, {"read": True, "send": True, "organize": True}), (VIEWER, {"read": True})):
        r = t.ok(t.api(at, "POST", "/admin/users", json={"email": who, "role": "user"}), 201)
        t.ok(t.api(at, "PUT", f"/admin/users/{r['user']['id']}/grants", json={"mailbox": ME, **grants}))
        b = t.Browser()
        assert b.login(who, r["temporary_password"]).status_code == 303
        new = "Us3r-" + os.urandom(8).hex()
        assert b.set_password(r["temporary_password"], new).status_code == 303
        t.MAILBOX_PW[who] = new
        b.enable_two_step(who)
        tokens[who] = b.create_token("scenarios", ["mail.read", "mail.send", "mail.organize"], who)
        OUT.setdefault("user_ids", []).append(r["user"]["id"])
    OUT["cfg_me"], OUT["cfg_viewer"] = config_file(tokens[ME]), config_file(tokens[VIEWER])


def cleanup():
    at = OUT.get("admin_token")
    if not at:
        return
    for uid in OUT.get("user_ids", []):
        t.api(at, "DELETE", f"/admin/users/{uid}")
    for box in (ME, ANNA, BOB, VIEWER):
        t.api(at, "DELETE", f"/admin/mailboxes/{box}", params={"confirm": box})
    for key in ("cfg_me", "cfg_viewer"):
        if OUT.get(key):
            os.unlink(OUT[key])


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    started = time.time()
    try:
        setup()
        seeds = seed_mail()
        todo = [s for s in scenarios() if s["kind"].startswith(only)]
        print(f"running {len(todo)} scenarios, {WORKERS} at a time", flush=True)
        results = []
        with ThreadPoolExecutor(WORKERS) as pool:
            futures = {pool.submit(run, sc, seeds): sc for sc in todo}
            for fut in as_completed(futures):
                sc = futures[fut]
                try:
                    passed, why, log = fut.result()
                except Exception:  # noqa: BLE001
                    passed, why, log = False, traceback.format_exc(limit=2), []
                results.append({**sc, "passed": bool(passed), "problem": None if passed else why, "log": log})
                print(f"{'PASS' if passed else 'FAIL'} #{sc['id']:03d} {sc['kind']:<16} {'' if passed else why}",
                      flush=True)
    finally:
        cleanup()
    results.sort(key=lambda r: r["id"])
    path = os.path.join(os.path.dirname(__file__), "scenario-results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=1)
    by_kind = {}
    for r in results:
        by_kind.setdefault(r["kind"], [0, 0])
        by_kind[r["kind"]][0 if r["passed"] else 1] += 1
    print(f"\n{sum(r['passed'] for r in results)}/{len(results)} passed in {(time.time() - started) / 60:.0f} min")
    for kind, (p, f) in by_kind.items():
        print(f"  {kind:<16} {p} passed, {f} failed")
    print(f"details: {path}")
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
