"""Let Claude Code use the MCP server for real, then check on the server that it did the work.

  ./mail app-test-claude

Same environment as test_live.py (a throwaway admin whose login is also a mailbox). Needs the
`claude` command (Claude Code) on this computer.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
import test_live as t  # noqa: E402  (reuses the browser and API helpers)


def main():
    admin = t.Browser()
    assert admin.login(t.ADMIN, os.environ["ADMIN_PASSWORD"]).status_code == 303
    pw = "Adm1n-" + os.urandom(8).hex()
    assert admin.set_password(os.environ["ADMIN_PASSWORD"], pw).status_code == 303
    admin.enable_two_step(t.ADMIN)
    token = admin.create_token("claude check", ["mail.read", "mail.send", "mail.organize", "admin"], t.ADMIN)
    a, b = t.addr("claude-a"), t.addr("claude-b")
    for box in (a, b):
        t.ok(t.api(token, "POST", "/admin/mailboxes", json={"address": box}), 201)
    run = t.RUN
    prompt = f"""Use the tools of the MCP server named "mail" to do these steps in order. Don't ask questions.
1. Call whoami and list_mailboxes.
2. Send an email from {a} to {b} with subject "claude-check {run}" and body "hello from claude".
3. Find that email in {b}'s INBOX with search_emails (if it isn't there yet, wait a few seconds and search again,
   up to 10 tries) and read it with read_email.
4. Reply to it from {b} with the text "reply from claude".
5. In {b}: create the folder "Claude{run}", move the email there, and flag it with mark_emails.
6. Save a draft in {a} with subject "claude draft {run}" and body "draft from claude".
7. Call admin_list_mailboxes and count the mailboxes.
At the end, print one line of JSON: {{"read_body": <body text you read>, "mailbox_count": <number>}}"""
    config = {"mcpServers": {"mail": {"type": "http", "url": f"{t.BASE}/mcp",
                                      "headers": {"Authorization": f"Bearer {token}"}}}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        cfg = f.name
    try:
        started = time.time()
        out = subprocess.run(["claude", "-p", prompt, "--mcp-config", cfg, "--strict-mcp-config",
                              "--allowedTools", "mcp__mail__*", "--output-format", "text"],
                             capture_output=True, text=True, timeout=900)
    finally:
        os.unlink(cfg)
    print(f"--- Claude ({time.time() - started:.0f}s) ---\n{out.stdout.strip()}\n{out.stderr.strip()[-500:]}")

    # check on the server that the work was really done
    checks = []
    sent = t.ok(t.api(token, "GET", f"/mailboxes/{a}/messages", params={"folder": "Sent", "subject": f"claude-check {run}"}))
    checks.append(("email sent from A (in A/Sent)", sent["total"] >= 1))
    moved = t.ok(t.api(token, "GET", f"/mailboxes/{b}/messages", params={"folder": f"Claude{run}"}))
    checks.append(("email moved to B/Claude folder", moved["total"] == 1))
    checks.append(("moved email flagged", bool(moved["messages"]) and moved["messages"][0]["flagged"]))
    checks.append(("moved email marked answered", bool(moved["messages"]) and moved["messages"][0]["answered"]))
    reply = t.ok(t.api(token, "GET", f"/mailboxes/{a}/messages", params={"subject": f"Re: claude-check {run}"}))
    checks.append(("reply arrived in A", reply["total"] >= 1))
    draft = t.ok(t.api(token, "GET", f"/mailboxes/{a}/messages", params={"folder": "Drafts", "subject": f"claude draft {run}"}))
    checks.append(("draft saved in A/Drafts", draft["total"] == 1))
    checks.append(("Claude reported the body it read", "hello from claude" in out.stdout))
    audit = t.ok(t.api(token, "GET", "/admin/audit", params={"limit": 50}))
    checks.append(("actions logged as MCP", any("(mcp)" in (r["actor"] or "") for r in audit)))

    for box in (a, b):
        t.ok(t.api(token, "DELETE", f"/admin/mailboxes/{box}", params={"confirm": box}))
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    sys.exit(0 if all(p for _, p in checks) else 1)


if __name__ == "__main__":
    main()
