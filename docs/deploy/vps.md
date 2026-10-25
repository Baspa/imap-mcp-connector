# Hosting on a VPS with Docker Compose

This is the simplest production setup: Docker runs the app and Caddy, and Caddy fetches the HTTPS certificate.

## Requirements

- A supported Ubuntu LTS (22.04 or 24.04), Debian 12 or similar, with ports 80 and 443 open.
- A DNS name (for example `mail.example.com`) pointing at the server.
- Outbound IMAP (993) and SMTP (465/587) allowed.

## Steps

```bash
# 1. Install Docker (official convenience script)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER   # log out and back in afterwards

# 2. Get the code and configure it
git clone https://github.com/Baspa/imap-mcp-connector.git && cd imap-mcp-connector
cp .env.example .env
#   set DOMAIN, PUBLIC_URL, ENCRYPTION_KEY (openssl rand -base64 32),
#   SESSION_SECRET (openssl rand -hex 32) and ALLOWED_EMAIL_DOMAINS or ALLOWED_IMAP_HOSTS

# 3. Start
docker compose up -d
docker compose logs -f app     # look for "listening"
```

Then open `https://<your-domain>/healthz`, sign in at `https://<your-domain>`, and add `https://<your-domain>/mcp` as a custom connector.

Update later with `git pull && docker compose up -d --build`. Back up the `app_data` volume and `ENCRYPTION_KEY`.

## Old Ubuntu on the server

Docker needs a release that still gets security updates. If the server runs an end-of-life Ubuntu (for example 18.04 or 20.04), either:

- **Provision a fresh server** with Ubuntu 24.04 and follow the steps above. This is the safest and usually quickest option, because nothing needs migrating (the app is stateless apart from one SQLite file).
- **Upgrade in place**, one LTS at a time (20.04 → 22.04 → 24.04). Take a provider snapshot first, keep a second SSH session open, then run `sudo apt update && sudo apt full-upgrade`, `sudo do-release-upgrade`, reboot, and repeat. Releases that are fully end-of-life may need the `-d` flag or the old-releases mirror.
