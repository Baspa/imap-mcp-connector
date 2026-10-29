# IMAP MCP Connector

Use your own mailbox from **Claude** or **ChatGPT**. This is a small self-hosted server: people sign in with their email address and (app) password, choose what the AI may do, and paste one connector URL into their AI app.

- Works with any IMAP mailbox that accepts a password or app password: Gmail, iCloud, Yahoo, Fastmail, Zoho, most hosting providers and self-run servers.
- One deployment serves many users, for example a company or a family.
- Per-user permission levels: **Read only**, **Read and draft** (default), **Full access** (send and delete-to-Trash).
- Remote MCP server with OAuth 2.1 (dynamic client registration, PKCE), so it works as a custom connector in Claude and ChatGPT.

> **Not supported yet:** Outlook.com and Microsoft 365, which no longer allow password sign-in over IMAP.

## Quickstart (Docker Compose, ~5 minutes)

1. Point a DNS name (e.g. `mail.example.com`) at your server, with ports 80 and 443 open.
2. Clone this repository and create your config:
   ```bash
   cp .env.example .env
   # fill in DOMAIN, PUBLIC_URL, ENCRYPTION_KEY (openssl rand -base64 32),
   # SESSION_SECRET (openssl rand -hex 32), ALLOWED_EMAIL_DOMAINS or ALLOWED_IMAP_HOSTS
   ```
3. Start it:
   ```bash
   docker compose up -d
   ```
4. Open `https://mail.example.com`, sign in with your email and app password, and follow the connect instructions shown on the settings page.

Caddy obtains HTTPS certificates automatically.

Other ways to run it: [try it from your own computer with a tunnel](docs/deploy/tunnel.md) (`npm run tunnel`), [a VPS with Docker Compose](docs/deploy/vps.md), or [Laravel Forge](docs/deploy/forge.md).

## Connect to Claude

Settings → Connectors → **Add custom connector** → paste `https://<your-domain>/mcp` → **Connect**. Sign in and approve access when prompted.

## Connect to ChatGPT

Settings → Connectors (turn on developer mode if your plan requires it) → **Create** → paste `https://<your-domain>/mcp` → authentication **OAuth**. Sign in and approve access when prompted.

## App passwords

Most big providers refuse your normal password over IMAP once two-factor sign-in is on. Create an app password and use it to sign in:

- Gmail: https://myaccount.google.com/apppasswords
- iCloud: https://support.apple.com/en-us/102654
- Yahoo: https://help.yahoo.com/kb/SLN15241.html
- Fastmail and Zoho: search their help for "app password".

Lost it? Create a new one and sign in again. The stored password is replaced.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `PUBLIC_URL` | yes | External origin, `https://` only (no path). |
| `ENCRYPTION_KEY` | yes | 32 random bytes, base64. Encrypts stored mail passwords. **Back it up**: if it is lost, users must sign in again. |
| `SESSION_SECRET` | yes | ≥ 32 characters, signs session cookies. |
| `ALLOWED_EMAIL_DOMAINS` | at least one of these | Comma-separated email domains allowed to sign in. |
| `ALLOWED_IMAP_HOSTS` | at least one of these | Comma-separated IMAP hosts allowed; `*` allows any public server that auto-discovery finds. Hand-entered servers must be listed by name. |
| `ALLOWED_RECIPIENT_DOMAINS` | no (empty) | Comma-separated domains the AI may send to. Empty allows any. A send to any other domain is refused, including via cc and bcc. |
| `ALLOWED_REDIRECT_HOSTS` | no (empty) | Comma-separated hosts (and their subdomains) that may receive an authorization code, e.g. `chatgpt.com,claude.ai`. Empty allows any. Registration is open by design, so this is what stops a client that names itself after a real app from redirecting to its own host. |
| `ALLOW_PRIVATE_HOSTS` | no (`false`) | Allow mail servers on private networks and unencrypted connections. |
| `DEFAULT_SEND_LIMIT_PER_HOUR` | no (`20`) | Emails each user's AI may send per hour. |
| `DATA_DIR` | no (`/data`) | Where the SQLite database lives. |
| `PORT` | no (`3000`) | Listen port. |

When both allowlists are set, a sign-in must pass **both**: the email domain must be in `ALLOWED_EMAIL_DOMAINS` **and** the IMAP host must be in `ALLOWED_IMAP_HOSTS` (unless it is `*`). A list that is not set does not restrict, so `ALLOWED_EMAIL_DOMAINS` alone allows any public mail server for those domains. The check runs at sign-in, when SMTP settings change, and again before each new mail connection.

Server settings are auto-discovered on first sign-in (built-in presets, the Thunderbird ISPDB, then DNS SRV records), and the first successful sign-in pins the server for that address. Settings typed into the sign-in form are accepted only when discovery definitively finds nothing **and** the IMAP host is listed by name in `ALLOWED_IMAP_HOSTS` (`*` does not count). Otherwise, whoever signed in first with an address could point it at a server they control and capture the real owner's password at the owner's first sign-in. If the automatic lookup fails temporarily (for example the ISPDB or DNS is unreachable), sign-in is refused with a request to try again. Most company domains publish no discoverable settings, including Google Workspace and Microsoft-hosted ones, so for those domains list their IMAP server, e.g. `ALLOWED_IMAP_HOSTS=imap.gmail.com` or `ALLOWED_IMAP_HOSTS=mail.example.com`.

**SMTP servers:** your mail password is also the default SMTP password, so a hand-entered or changed SMTP server is accepted only when it is the account's own IMAP host or is listed by name in `ALLOWED_IMAP_HOSTS` (`*` does not count). Re-saving the current SMTP server is always allowed.

**Upgrading from an earlier version:** accounts created before this rule are re-confirmed at their next sign-in. They keep working if their IMAP host matches a built-in preset, is listed in `ALLOWED_IMAP_HOSTS`, or matches what discovery finds now. Otherwise sign-in and AI access are refused until you list the host. Before listing a host, check that it is your users' real server:
```bash
docker compose exec app node -e "const db=require('better-sqlite3')('/data/imap-connector.db'); console.table(db.prepare(\"SELECT email, imap_host, smtp_host FROM users WHERE settings_source = 'legacy'\").all())"
```
Delete any account whose server is not its owner's real mail server (`DELETE FROM users WHERE email = ?`); the owner can then sign in normally.

To change one user's send limit (run in the deployment directory):
```bash
docker compose exec app node -e "const db=require('better-sqlite3')('/data/imap-connector.db'); db.prepare('UPDATE users SET send_limit_per_hour = ? WHERE email = ?').run(50, 'someone@example.com')"
```

## Tools the AI gets

| Level | Tools |
|---|---|
| Read only | `list_folders`, `search_messages`, `get_message`, `get_thread`, `get_attachment` |
| Read and draft | + `set_flags`, `move_messages`, `create_draft` |
| Full access | + `send_email`, `delete_messages` (moves to Trash, never permanent) |

## Security model

- **What is stored:** each user's email address, server settings, and mail password encrypted with AES-256-GCM using `ENCRYPTION_KEY`. OAuth codes and tokens are stored only as SHA-256 hashes.
- **What is never logged:** passwords, tokens, or message content.
- **Who can sign in:** only addresses or servers on your allowlist. Mail hosts resolving to private addresses are rejected unless `ALLOW_PRIVATE_HOSTS=true`. Connections go to the exact address that passed this check (TLS still verifies the hostname), so a second DNS answer cannot redirect them to an internal address.
- **Prompt injection:** an email can contain text written to manipulate an AI. Email content is marked as untrusted for the model (between tags carrying a random per-response id, so an email cannot fake the end of its block), tools carry read-only/destructive hints so AI apps ask before sending, sending is rate-limited, and sending is off by default. These measures reduce the risk but cannot eliminate it. Only enable **Full access** if you accept that risk.
- Users can revoke any connected AI app, or delete their account, from the settings page.

## Deployment notes and known limitations

- **Plain-http `PUBLIC_URL`:** it works only for `localhost` / `127.0.0.1`, even with `NODE_ENV=development`. The MCP SDK rejects any other non-https issuer URL.
- **Run behind exactly one reverse proxy:** the app sets Express `trust proxy` to 1, as in the provided compose file with Caddy. If you expose the app directly without a proxy, clients can spoof `X-Forwarded-For` and weaken the per-IP sign-in rate limit.
- **Folder roles on servers without SPECIAL-USE:** roles such as `sent` or `trash` are resolved from the server's SPECIAL-USE flags, then from common English top-level folder names, then from localized top-level names (for example "Gesendet" or "Papierkorb"). If a role still does not resolve, tools that take a folder accept the exact folder path returned by `list_folders`; `create_draft`, saving to Sent after `send_email`, and `delete_messages` need the Drafts, Sent and Trash roles to resolve.

## Development

```bash
npm install
npm test                 # unit tests
npm run test:integration # needs Docker (GreenMail test server)
npm run dev              # needs the env vars above; NODE_ENV=development allows http://localhost
```

Gmail's native thread search (`X-GM-EXT-1`) is not covered by the automated tests. Check it manually against a Gmail account before releases.

## License

MIT. Mail provider presets are adapted from [nikolausm/imap-mcp-server](https://github.com/nikolausm/imap-mcp-server) (MIT); see `THIRD_PARTY_NOTICES.md`.
