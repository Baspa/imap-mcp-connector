# Trying it out from your own computer (Cloudflare quick tunnel)

For a quick test in Claude or ChatGPT without buying a server. The app runs on your machine and a free Cloudflare tunnel gives it a public `https://` address. It stops when your computer sleeps or you press Ctrl+C.

```bash
brew install cloudflared          # macOS; other systems: see Cloudflare's install docs
npm install
ALLOWED_EMAIL_DOMAINS=gmail.com npm run tunnel
```

`npm run tunnel` (`scripts/dev-tunnel.sh`):

1. starts a quick tunnel and reads the `https://….trycloudflare.com` address from it,
2. generates `ENCRYPTION_KEY` and `SESSION_SECRET` once and keeps them in `.env.tunnel` (gitignored),
3. starts the app with `PUBLIC_URL` set to that address and its database in `data/tunnel/`,
4. prints the address and the connector URL (`<address>/mcp`).

Use `ALLOWED_IMAP_HOSTS='*'` instead to allow any publicly discoverable mail server.

Limits:

- The address changes on every run. After a restart, remove and re-add the connector in Claude.
- Quick tunnels are for testing only; use the [VPS guide](vps.md) for real use.
