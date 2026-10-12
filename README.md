# Self-hosted business email in one command

Run your own email server for your domain (`you@yourcompany.com`) on a small rented server,
with **as many mailboxes as you like and no per-user fees**. You keep using Outlook, Apple Mail,
Thunderbird or your phone's mail app, exactly as with Google Workspace, Microsoft 365 or Zoho.

```bash
./mail init           # create your settings file
./mail server-setup   # prepare a fresh server
./mail deploy         # install the mail server
./mail add you@yourcompany.com
./mail test you@yourcompany.com
```

It is a thin, scripted layer on top of proven open-source mail software
([docker-mailserver](https://github.com/docker-mailserver/docker-mailserver): Postfix, Dovecot, Rspamd),
plus everything around it that usually takes a day of reading: certificates, DNS records, spam
protection, backups, tests and the steps to move an existing domain over safely.

- [What you get](#what-you-get)
- [How it works](#how-it-works)
- [What you need](#what-you-need)
- [Set it up, step by step](#set-it-up-step-by-step)
- [Move an existing domain (Zoho, Google, Microsoft…)](#move-an-existing-domain-from-zoho-google-microsoft)
- [Add the mailbox to Outlook and other apps](#add-the-mailbox-to-outlook-and-other-apps)
- [Everyday commands](#everyday-commands)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Limits](#limits)

---

## What you get

| | |
|---|---|
| Mailboxes and aliases | Unlimited. `sales@` can forward to `anna@`, and so on |
| Works with | Any mail app that speaks IMAP/SMTP: Outlook, Apple Mail, Thunderbird, iPhone, Android |
| Delivery to Gmail/Outlook | SPF, DKIM, DMARC and reverse DNS set up, so mail lands in the inbox |
| Spam filter | Rspamd; spam goes to the Junk folder |
| Protection | TLS everywhere, no open relay, no sending as someone else, bans after 6 wrong passwords |
| Certificates | Free Let's Encrypt certificate, renewed automatically every week |
| Backups | Nightly, last 7 kept on the server |
| Tests | One command checks 12 things end to end, including a real message to Gmail |
| Server size | Runs on 1 CPU / 1 GB RAM (it uses about 250 MB) |
| Interface | None on purpose: commands for the admin, normal mail apps for everyone else |

## How it works

### The parts

Everything runs in **one Docker container** on your server:

| Part | Job |
|---|---|
| **Postfix** | The post office. Receives mail from the internet on port 25, accepts mail from your apps on ports 465/587, and delivers outgoing mail to other servers |
| **Dovecot** | The mailbox store. Keeps every mailbox on disk and serves it to your apps over IMAP (port 993) |
| **Rspamd** | Scores incoming mail for spam and **signs** outgoing mail with your DKIM key |
| **fail2ban** | Watches for password guessing and blocks the attacker's IP |
| **lego** (separate, short-lived) | Gets the Let's Encrypt certificate and renews it |

Your computer only holds the scripts and your settings. The `./mail` command talks to the server over SSH.

### When someone emails you

```
sender's server ──► looks up MX record of yourcompany.com ──► mx.yourcompany.com:25
                                                                    │
                       Postfix: is it for one of our addresses? ◄───┘
                       Rspamd: spam score (SPF/DKIM/DMARC of the sender, content, blocklists)
                       Dovecot: stores it in the mailbox (spam → Junk)
                                                                    │
your Outlook ◄── IMAP over TLS, port 993 ◄─────────────────────────┘
```

### When you send an email

```
your Outlook ──► mx.yourcompany.com:465 (TLS) ──► Postfix checks your password and that
                                                 you only send as your own address
                                                 Rspamd adds a DKIM signature
                                                         │
recipient's server ◄── port 25, direct ◄─────────────────┘
   checks: SPF   "is this IP allowed to send for yourcompany.com?"  (DNS TXT record)
           DKIM  "is the signature valid?"                          (public key in DNS)
           DMARC "do SPF/DKIM match the From address?"              (DNS TXT record)
           PTR   "does this IP's reverse name match the server?"    (set at your hosting provider)
```

If all four pass, Gmail and Outlook treat you like any well-run mail provider. That is why most of
the setup below is DNS records: the server itself is the easy part.

### What lives where

| Where | What |
|---|---|
| Your computer, this folder | Scripts, `mail.conf` (your settings, never committed) |
| Your computer, `SECRETS_DIR` | Mailbox passwords, DNS backups |
| Server, `REMOTE_DIR/data/` | Mailboxes, accounts (hashed passwords), DKIM key, certificate |
| Server, `/var/backups/mailserver/` | Nightly backups (last 7) |

## What you need

1. **A domain** you control, e.g. `yourcompany.com`, with access to its DNS records.
2. **A small Linux server (VPS)** with a fixed public IPv4, Ubuntu 22.04+ or Debian 12+, 1 GB RAM or more,
   root SSH access with a key. Any provider works (IONOS, Hetzner, OVH, Contabo, DigitalOcean, Vultr…).
3. **Outgoing port 25 open.** Most providers block it on new servers against spam, and unblock it on request
   once you have the DNS records in place (see [Outgoing port 25](#outgoing-port-25)).
   AWS, Google Cloud and Azure make this very hard: prefer a classic VPS provider.
4. **Reverse DNS (PTR)**: your hosting provider's panel must let you set the server IP's reverse name.
5. On your computer: `bash`, `ssh`, `rsync`, `python3` and `dig` (all present on macOS and most Linux).

Using a separate server just for mail is recommended: it keeps port 80 free for the certificate and
keeps a problem on your web/app server away from your email.

## Set it up, step by step

### 1. Download and configure

```bash
git clone https://github.com/keyhan-azarjoo/myotgo-mail.git mailserver
cd mailserver
./mail init
```

Open `mail.conf` and fill in your values. The file explains every line. The important ones:

```ini
DOMAIN=yourcompany.com
MAIL_HOST=mx.yourcompany.com
SERVER_IP=203.0.113.10          # your server's public IPv4
SSH_TARGET=root@203.0.113.10
SSH_KEY=~/.ssh/id_ed25519
ACME_EMAIL=you@somewhere-else.com
CERT_METHOD=http                # or dns if port 80 on the server is in use
```

`mail.conf` is in `.gitignore`: your details stay on your computer.

### 2. Point the mail name at the server

At your DNS provider, create an **A record**: `mx.yourcompany.com` → your server's IP.
(With GoDaddy and `DNS_PROVIDER=godaddy`, `./mail dns prepare` does this later for you.)

### 3. Prepare the server

```bash
./mail server-setup
```

It installs Docker, opens the firewall for SSH and the mail ports, adds swap on small servers, sets the
host name, turns SSH password login off (only if a key is installed) and tells you whether outgoing port 25
is blocked.

### 4. Install the mail server

```bash
./mail deploy
```

It copies the files, fetches the certificate, installs the weekly renewal and nightly backup, and starts
the server. Run it again any time you change something: it is safe to repeat.

### 5. Create your first mailbox

```bash
./mail add you@yourcompany.com
```

The password is printed once and saved in `SECRETS_DIR`. The first mailbox also receives `postmaster@`
and `abuse@` (change this with `DEFAULT_ALIASES`).

### 6. Create the DNS records

```bash
./mail dns records
```

prints every record with its exact value: **A**, **SPF**, **DKIM**, **DMARC**, **PTR** and **MX**.

- Create A, SPF, DKIM and DMARC now at your DNS provider. If the domain already has an SPF record,
  **add** `ip4:<your IP>` to it; never create a second one.
- Set **PTR** (reverse DNS) in your hosting provider's panel to `mx.yourcompany.com`.
- **Leave MX for last**: it decides where mail for the domain goes.

With GoDaddy, `./mail dns prepare` and `./mail dns spf` do all of this except PTR for you.

Then check:

```bash
./mail dns check
```

### 7. Test it

```bash
./mail test you@yourcompany.com
./mail test you@yourcompany.com --external your.private@gmail.com
```

The first checks certificates, wrong-password refusal, incoming mail, open relay, spoofing, sending,
aliases, IMAP and DKIM. The second also sends a real message to an outside address. Open it in Gmail
and use **Show original**: SPF, DKIM and DMARC should all say **PASS**.

### 8. Go live

Point the domain's **MX** record at `mx.yourcompany.com` (priority 10), or with GoDaddy:

```bash
./mail dns switch
```

Mail starts arriving at your server within 10–60 minutes as DNS caches update.

### Outgoing port 25

`./mail server-setup` tells you whether it's blocked. If it is, finish steps 1–7 first. Providers
usually ask for exactly those three things: a host name (FQDN), reverse DNS and SPF. Then open a ticket:

> Please unblock outbound SMTP port 25 for my server `<IP>`. It runs a mail server for `<domain>`
> with host name `<mx.domain>`. Reverse DNS points to `<mx.domain>`, SPF allows the IP, mail is
> DKIM-signed, sending requires authentication and the server is not an open relay.

Until then, receiving and reading work; outgoing mail to other domains waits in the queue
(`./mail queue`) and goes out by itself once the port opens.

## Move an existing domain from Zoho, Google, Microsoft…

1. **List every address** that exists at the old provider. Create each one here first
   (`./mail add` or `./mail alias`): any address you forget will bounce after the switch.
2. Do steps 1–7. Keep the old provider in your SPF record while you move.
3. `./mail dns switch` (or change MX by hand).
4. **Keep the old service for a week.** Some senders cache the old MX for a while.
5. Copy old mail: add both accounts to Outlook or Thunderbird and drag the folders across.
6. Then cancel the old service and remove its entries from SPF.

`./mail dns rollback` (GoDaddy) puts the previous MX and SPF back if anything goes wrong.

## Add the mailbox to Outlook and other apps

`./mail outlook you@yourcompany.com` prints the values for any address:

| Setting | Value |
|---|---|
| Account type | **IMAP** |
| Email address / user name | the full address, e.g. `you@yourcompany.com` |
| Password | from `SECRETS_DIR/<address>.txt` |
| Incoming (IMAP) server | `mx.yourcompany.com`, port **993**, **SSL/TLS** |
| Outgoing (SMTP) server | `mx.yourcompany.com`, port **465**, **SSL/TLS** (or port 587, **STARTTLS**) |
| Outgoing needs sign-in | Yes, same user name and password |

### New Outlook (Windows) and Outlook on the web
1. **Settings** (gear icon) → **Accounts** → **Email accounts** → **Add account**.
2. Type the address → **Continue**. If asked for the provider, choose **IMAP**. If Outlook starts searching,
   choose **Advanced setup** / **Choose provider** → **IMAP**.
3. **Show more** / **Advanced settings**: fill in the IMAP and SMTP values above → **Continue**.

### Classic Outlook (Windows)
1. **File** → **Add Account** → type the address → **Advanced options** → tick
   **Let me set up my account manually** → **Connect** → **IMAP**.
2. Incoming: server, port 993, **SSL/TLS**. Outgoing: server, port 465, **SSL/TLS**.
   Leave "Secure Password Authentication (SPA)" **unticked** → **Next** → password → **Connect**.

### Outlook for Mac
1. **Outlook** menu → **Settings…** → **Accounts** → **+** → **New Account…** → type the address → **Continue**.
2. Choose **IMAP/POP** (sometimes under "Not your provider?").
3. Type **IMAP**, user name = full address, password, IMAP server port 993 with **Use SSL**, SMTP server
   port 465 with **Use SSL** → **Add Account**.

### Outlook on iPhone / Android
Profile picture → **Add account** → **Add email account** → address → **IMAP**
(or **Set up account manually**) → turn on **Advanced settings** → fill in the values → ✓.

### Apple Mail, iPhone Mail, Thunderbird, Gmail app
Add an account of type **Other / IMAP** and use the same table. Thunderbird usually finds the
settings by itself when you type the server name `mx.yourcompany.com`.

> To send from a second address in the same Outlook, add it as its own account and pick it in the
> **From** field when you write the email.

## Everyday commands

```text
./mail add anna@yourcompany.com          new mailbox (prints the password once)
./mail passwd anna@yourcompany.com       new password
./mail alias sales@yourcompany.com anna@yourcompany.com
./mail unalias sales@yourcompany.com anna@yourcompany.com
./mail del anna@yourcompany.com          delete mailbox and its mail (asks to confirm)
./mail list                              mailboxes and aliases
./mail outlook anna@yourcompany.com      settings for a mail app

./mail status                            services, queue, disk, certificate expiry
./mail logs                              live mail log
./mail queue | ./mail queue flush        waiting mail / retry now
./mail backup                            backup now
./mail unban 198.51.100.7                unblock an IP after wrong passwords
./mail ssh                               shell on the server
./mail deploy                            apply changes / update
```

**Updating** docker-mailserver: change the version in `compose.yaml`, then `./mail deploy`.

**Restoring a backup** (on the server): stop with `docker compose down`, move `data/` aside, extract the
backup with `tar --numeric-owner -xzf /var/backups/mailserver/mail-<date>.tar.gz`, then
`docker compose up -d`.

## Troubleshooting

| Problem | What to do |
|---|---|
| Outlook can't connect | `./mail test <address>` from your computer. If ports time out, your hosting provider's firewall (often a separate "firewall policy" in their panel) must allow TCP 25, 465, 587, 993 |
| "Authentication failed", then nothing works | 6 wrong passwords in an hour ban your IP for a day: `./mail unban <your IP>` (find it at https://api.ipify.org) |
| Sent mail never arrives | `./mail queue`. "Connection timed out" on port 25 = provider still blocks port 25 |
| Mail lands in the recipient's spam | `./mail dns check`; then send to Gmail and look at **Show original**. A missing PTR is the most common cause. New servers also need a few days of normal traffic to build reputation |
| Certificate problem | `./mail status` shows its expiry; `/var/log/mailserver-cert.log` on the server shows renewals |
| Something else | `./mail logs` while you try again |

## Security

- No passwords, keys or personal settings are in this repository: they live in `mail.conf`,
  `SECRETS_DIR` and on the server, all ignored by git.
- Mailbox passwords are stored hashed on the server. New ones are 24 random characters.
- Every connection is encrypted (TLS 1.2+). Sending requires a login, and you can only send as your own
  address or your aliases. Unauthenticated relaying is refused (the tests check both).
- fail2ban bans IPs that guess passwords. `server-setup` turns off SSH password login when a key is present.
- Keep the server updated (Ubuntu's unattended upgrades) and update the mail image now and then.
- Backups stay on the same server: copy `/var/backups/mailserver` somewhere else if losing the server
  would hurt.

## Limits

- **No webmail or admin web page**: you use mail apps, and the admin uses `./mail`. A webmail such as
  Roundcube can be added later as another container if you need one.
- **No antivirus scanning** (ClamAV needs about 1.5 GB more RAM). Rspamd still blocks a lot of malicious mail.
- **One server**: if it is down, other servers keep your incoming mail and retry for several days, so it
  arrives once you're back.
- **DNS automation** is built in for GoDaddy only; with any other provider you copy the values from
  `./mail dns records` into its panel (certificates work with 100+ providers through lego).

## Files

| Path | What |
|---|---|
| `mail` | the one command |
| `mail.conf.example` | settings template (copy to `mail.conf`) |
| `compose.yaml`, `mailserver.env` | the mail server container and its options |
| `config/` | fail2ban and Postfix settings copied to the server on deploy |
| `scripts/server-setup.sh` | prepares a fresh server |
| `scripts/deploy.sh` | installs/updates on the server |
| `scripts/cert.sh`, `scripts/backup.sh` | run on the server by cron |
| `scripts/account.sh`, `scripts/dns.py` | mailboxes and DNS |
| `tests/check.py` | end-to-end test |

## Credits

Built by **Keyhan Azarjoo** on top of
[docker-mailserver](https://github.com/docker-mailserver/docker-mailserver),
[Postfix](https://www.postfix.org/), [Dovecot](https://www.dovecot.org/), [Rspamd](https://rspamd.com/),
[fail2ban](https://github.com/fail2ban/fail2ban), [lego](https://github.com/go-acme/lego) and
[Let's Encrypt](https://letsencrypt.org/).

## License

[MIT](LICENSE)
