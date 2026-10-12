"""Server-side commands, run by `./mail` through `docker exec`:

  python -m mailapp.cli create-admin <email>        first admin; prints a temporary password
  python -m mailapp.cli mailbox-password <address>  password on stdin; creates the mailbox or sets a new password
  python -m mailapp.cli link-mailbox <address>      password on stdin; lets the console use the mailbox
  python -m mailapp.cli reset-two-step <email>      if someone lost their authenticator
  python -m mailapp.cli delete-user <email>
  python -m mailapp.cli unblock-ip <ip>            after too many failed sign-ins from one network
  python -m mailapp.cli cleanup-tests e2e-            remove leftovers of interrupted test runs
  python -m mailapp.cli require-two-step on|off
"""
import sys

from . import db, service


def main(argv):
    db.init()
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, arg = argv[0], argv[1]
    if cmd == "create-admin":
        r = service.create_user(None, arg, role="admin")
        print(f"admin {r['user']['email']} created\ntemporary password: {r['temporary_password']}")
    elif cmd == "mailbox-password":
        # create the mailbox, or give it a new password; the password comes on stdin, never as an argument
        from . import mailconf, security
        password = sys.stdin.readline().strip()
        if problem := security.password_problem(password):
            sys.exit(problem)
        address = mailconf.normalize_local(arg)
        if address in mailconf.list_accounts():
            mailconf.set_password(address, password)
        else:
            mailconf.add_account(address, password)
        service._store_mailbox_password(address, password)
        user = db.one("SELECT id FROM users WHERE email = ?", (address,))
        if user:   # one password: the console login follows, and is signed out
            with db.tx() as conn:
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                             (security.hash_password(password), user["id"]))
                service._revoke_everything(conn, user["id"])
        ready = service._wait_for_login(address, password)
        db.audit("cli", "mailbox.password_set", address)
        print(f"{address} ready" if ready else f"{address} saved; the mail server applies it within a minute")
    elif cmd == "link-mailbox":
        password = sys.stdin.readline().strip()
        service.link_mailbox(None, arg, password)
        print(f"linked {arg}")
    elif cmd == "reset-two-step":
        uid = service.find_user_id(arg)
        with db.tx() as conn:
            conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, two_step_method = NULL, "
                         "two_step_email = NULL, recovery_codes = '[]' WHERE id = ?", (uid,))
            service._revoke_everything(conn, uid)
        db.audit("cli", "user.reset_two_step", arg)
        print(f"two-step verification removed for {arg}")
    elif cmd == "delete-user":
        uid = service.find_user_id(arg)
        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        service.forget_rate_limits(uid)
        db.audit("cli", "user.delete", arg)
        print(f"deleted login {arg}")
    elif cmd == "unblock-ip":
        ip = arg.replace("\\", "").replace("%", "").replace("_", "")
        db.execute("DELETE FROM rate WHERE key = ? OR key LIKE ? OR key LIKE ?",
                   (f"login-fail:{ip}", f"login-fail:%:{ip}", f"http:%:{ip}"))
        db.audit("cli", "login.unblock_ip", arg)
        print(f"sign-in limit cleared for {arg}")
    elif cmd == "cleanup-tests":
        # remove what interrupted test runs left behind: everything named <arg>* (e.g. e2e-)
        from . import mailconf
        prefix = arg.lower()
        if len(prefix) < 4:
            sys.exit("give a prefix of at least 4 characters, e.g. e2e-")
        for alias, targets in mailconf.aliases().items():
            for target in targets:
                if alias.startswith(prefix) or target.startswith(prefix):
                    mailconf.delete_alias(alias, target)
        boxes = [a for a in mailconf.list_accounts() if a.startswith(prefix)]
        for a in boxes:
            mailconf.delete_account(a)
            db.execute("DELETE FROM mailboxes WHERE address = ?", (a,))
            db.execute("DELETE FROM grants WHERE mailbox = ?", (a,))
        users = [r["id"] for r in db.query("SELECT id, email FROM users") if r["email"].lower().startswith(prefix)]
        for uid in users:
            db.execute("DELETE FROM users WHERE id = ?", (uid,))
            service.forget_rate_limits(uid)
        db.audit("cli", "tests.cleanup", prefix, {"mailboxes": len(boxes), "users": len(users)})
        print(f"removed {len(boxes)} mailboxes and {len(users)} logins starting with {prefix}")
    elif cmd == "allow-local-code-mailboxes":
        db.set_setting("allow_local_code_mailboxes", "1" if arg == "on" else "0")
        db.audit("cli", "settings.allow_local_code_mailboxes", None, {"value": arg == "on"})
        print(f"dedicated code mailboxes on this server: {arg}")
    elif cmd == "require-two-step":
        db.set_setting("require_two_step", "1" if arg == "on" else "0")
        db.audit("cli", "settings.require_two_step", None, {"value": arg == "on"})
        print(f"require two-step: {arg}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (service.Invalid, service.NotFound, service.Forbidden) as e:
        sys.exit(str(e))
