# Hosting on Laravel Forge

Forge does not run Docker Compose for you, so skip the `Dockerfile`, `docker-compose.yml` and `Caddyfile`. Run the Node app as a Forge daemon behind Forge's Nginx. Nginx replaces Caddy, and Forge's Let's Encrypt integration replaces Caddy's certificates.

Verified against the code: the app listens on `PORT`, serves `/healthz`, sets Express `trust proxy` to 1, and answers `/mcp` with plain JSON (stateless, no streaming), so no special Nginx streaming settings are needed.
Not verified on a live Forge server: the exact menu names below, which can differ between Forge versions.

## 1. Server and site

- A server with at least 1 GB RAM and SSH access. Outbound IMAP (993) and SMTP (465/587) must be allowed (Forge allows outbound traffic by default).
- Create a site for your domain (for example `mail.example.com`). Pick a site type that does not need PHP ("Static HTML" or "Other"); Nginx will proxy to the app.
- Connect the GitHub repository to the site.

## 2. Node 24

The app requires Node 24 or newer (`engines` in `package.json`). Install it on the server as the `forge` user, for example with nvm, then note the absolute path from `which node`; the daemon needs it.

`better-sqlite3` is a native module. It installs from a prebuilt binary or compiles with the build tools that Forge servers normally include.

## 3. Data directory

```bash
mkdir -p /home/forge/imap-mcp-data
```

This holds the SQLite database. Keep it outside the site directory so deploys never touch it. Back it up together with `ENCRYPTION_KEY`; if the key is lost, every user must sign in again.

## 4. Environment file

**The app does not read `.env` by itself.** Create `.env` in the site directory and start the app with Node's `--env-file` flag (step 6). Setting variables in Forge's Environment tab alone has no effect unless the daemon is started with that file.

```
PUBLIC_URL=https://mail.example.com
ENCRYPTION_KEY=<openssl rand -base64 32>
SESSION_SECRET=<openssl rand -hex 32>
ALLOWED_EMAIL_DOMAINS=yourdomain.com
DATA_DIR=/home/forge/imap-mcp-data
PORT=3000
```

- `DOMAIN` is only used by Caddy; leave it out.
- Do not set `NODE_ENV` in this file. The app already defaults to production, and an exported `NODE_ENV=production` would make `npm ci` in the deploy script skip the dev dependencies that the build needs.
- Set at least one of `ALLOWED_EMAIL_DOMAINS` and `ALLOWED_IMAP_HOSTS` (see the README configuration table).

## 5. Deploy script

```bash
cd $FORGE_SITE_PATH
git pull origin $FORGE_SITE_BRANCH
npm ci
npm run build
npm prune --omit=dev
sudo -S supervisorctl restart daemon-<id>:*
```

Replace `daemon-<id>` with the name Forge shows after you create the daemon (step 6). `npm ci` installs the dev dependencies the TypeScript build needs; `npm prune --omit=dev` then removes them again, as the Dockerfile does.

## 6. Daemon (Server → Daemons)

- Command: `/full/path/to/node --env-file=.env dist/index.js`
- Directory: the site path, so `.env` and `dist/` resolve.
- User: `forge`

## 7. Nginx proxy

Edit the site's Nginx configuration and replace the default `location /` block with:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`X-Forwarded-Proto` matters: session cookies are `Secure`, so the app must see the original https scheme.

The app trusts exactly one proxy hop. Do not put a CDN or another proxy (for example Cloudflare) in front of Forge's Nginx, or the client IP used by the sign-in rate limit will be wrong.

## 8. SSL and checks

1. In the site's SSL tab, request a Let's Encrypt certificate.
2. Open `https://mail.example.com/healthz`; it should return `{"ok":true}`.
3. Open `https://mail.example.com`, sign in, and follow the connect instructions on the settings page (connector URL: `https://mail.example.com/mcp`).

## Operations

- Run a single instance. SQLite is a local file; do not scale across servers.
- The admin snippets in the README use `docker compose exec app node -e ...`. On Forge, run the same `node -e` from the site directory and change the database path to `/home/forge/imap-mcp-data/imap-connector.db`.
- Back up `DATA_DIR` and `ENCRYPTION_KEY`.
