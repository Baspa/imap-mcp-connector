# VPS runbook: wipe the server and start the connector

Everything needed to go from a cleared Ubuntu 22.04 VPS to a running connector. Background and alternatives are in [vps.md](vps.md), [tunnel.md](tunnel.md) and [forge.md](forge.md).

## Decisions already made

- Host: the existing VPS, Ubuntu 22.04 LTS. **No OS upgrade needed** (supported until about April 2027, supported by Docker).
- Method: Docker Compose (app + Caddy). Caddy gets the HTTPS certificate automatically. Forge is not used.
- The server currently runs other things. Before wiping, copy off anything you still need.
- Run **one instance only**. SQLite is a local file.

## Before you wipe

- [ ] Back up anything on the VPS you still need (sites, databases, `.env` files, certificates).
- [ ] Decide the domain, e.g. `mail.yourdomain.com`, and which mail domains may sign in.
- [ ] Optionally try the app first from your own computer: `ALLOWED_EMAIL_DOMAINS=gmail.com npm run tunnel` (needs `brew install cloudflared`; see [tunnel.md](tunnel.md)).

## Values to prepare (store the secrets in a password manager, not in git)

| Value | How |
|---|---|
| `DOMAIN` | e.g. `mail.yourdomain.com` |
| `PUBLIC_URL` | `https://` + the same domain, no path |
| `ENCRYPTION_KEY` | `openssl rand -base64 32`. **Back it up.** If lost, every user must sign in again. |
| `SESSION_SECRET` | `openssl rand -hex 32` |
| `ALLOWED_EMAIL_DOMAINS` and/or `ALLOWED_IMAP_HOSTS` | At least one is required. If both are set, both must match. Google Workspace and most company domains need their IMAP server listed by name, e.g. `imap.gmail.com`. `*` allows any publicly discoverable server, but not hand-typed ones. |

## Steps after the wipe

1. **DNS:** point an A record for the domain at the VPS IP. Wait until `dig +short mail.yourdomain.com` returns it.
2. **Firewall:** allow 22, 80 and 443, both in the provider's panel and in `ufw` (`sudo ufw allow 22,80,443/tcp && sudo ufw enable`). Allow outbound IMAP (993) and SMTP (465/587), which is the default. Nothing else may use ports 80 or 443.
3. **Docker:**
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER   # log out and back in
   ```
4. **Code and config:**
   ```bash
   git clone https://github.com/Baspa/imap-mcp-connector.git && cd imap-mcp-connector
   cp .env.example .env
   nano .env    # fill in the values above
   ```
5. **Start:**
   ```bash
   docker compose up -d
   docker compose logs -f app    # wait for "listening"
   ```
6. **Check:** `https://mail.yourdomain.com/healthz` returns `{"ok":true}`.
7. **Sign in** at `https://mail.yourdomain.com` with an email address and an **app password** (Gmail, iCloud, Yahoo, Fastmail and Zoho all need one when 2FA is on).
8. **Connect Claude:** Settings → Connectors → Add custom connector → `https://mail.yourdomain.com/mcp` → Connect → approve.

## Operating it

- Update: `git pull && docker compose up -d --build`
- Logs: `docker compose logs -f app`
- Back up the `app_data` Docker volume (the SQLite database) and `ENCRYPTION_KEY`.
- Admin snippets (change a send limit, review legacy accounts) are in the README and use `docker compose exec app node -e ...`.

## If something fails

| Symptom | Likely cause |
|---|---|
| Caddy has no certificate | DNS not pointing at the VPS yet, or port 80/443 blocked or used by another service |
| App exits at startup with "Configuration error" | A required value is missing or malformed: `ENCRYPTION_KEY` must decode to 32 bytes, `SESSION_SECRET` ≥ 32 characters, `PUBLIC_URL` https with no path, at least one allowlist set |
| Sign-in says wrong password | Normal password used instead of an app password, or Outlook/Microsoft 365 (not supported; password sign-in over IMAP is disabled) |
| Sign-in refused for a company domain | Its IMAP host is not discoverable; list it in `ALLOWED_IMAP_HOSTS` |
| Rate limits behave oddly | Something sits in front of Caddy (CDN or another proxy). The app trusts exactly one proxy hop |

## Project status at the time of writing

- Feature-complete v0.1.0; 228 unit tests and the typecheck pass. The GreenMail integration tests (`npm run test:integration`, needs Docker) were not run.
- `npm audit` reports 6 production-dependency vulnerabilities (2 high, including zod, whose fix is a major upgrade). Acceptable for a trial; fix before a public release.
- Known, deliberately deferred review findings are listed in `docs/superpowers/follow-ups/2026-10-05-imap-mcp-connector-deferred.md`.
- Not yet verified on real infrastructure: the Forge guide, the Cloudflare tunnel script against a real tunnel, and the Docker Compose path on this VPS. Treat the first deploy as the test.
- Open housekeeping: the latest commit on `main` (`d9ffa03`, message "fix") has not been renamed to a semantic message; that needs a force-push of `main` and was waiting for approval.
