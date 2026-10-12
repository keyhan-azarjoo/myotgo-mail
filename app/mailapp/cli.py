"""Server-side commands, run by `./mail` through `docker exec`:

  python -m mailapp.cli create-admin <email>        first admin; prints a temporary password
  python -m mailapp.cli link-mailbox <address>      password on stdin; lets the console use the mailbox
  python -m mailapp.cli reset-two-step <email>      if someone lost their authenticator
  python -m mailapp.cli delete-user <email>
  python -m mailapp.cli unblock-ip <ip>            after too many failed sign-ins from one network
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
    elif cmd == "link-mailbox":
        password = sys.stdin.readline().strip()
        service.link_mailbox(None, arg, password)
        print(f"linked {arg}")
    elif cmd == "reset-two-step":
        uid = service.find_user_id(arg)
        db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, two_step_method = NULL, "
                   "recovery_codes = '[]' WHERE id = ?", (uid,))
        db.audit("cli", "user.reset_two_step", arg)
        print(f"two-step verification removed for {arg}")
    elif cmd == "delete-user":
        uid = service.find_user_id(arg)
        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        service.forget_rate_limits(uid)
        db.audit("cli", "user.delete", arg)
        print(f"deleted login {arg}")
    elif cmd == "unblock-ip":
        db.execute("DELETE FROM rate WHERE key = ?", (f"login-fail:{arg}",))
        db.audit("cli", "login.unblock_ip", arg)
        print(f"sign-in limit cleared for {arg}")
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
