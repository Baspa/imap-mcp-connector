#!/usr/bin/env bash
# Run the connector locally behind a free Cloudflare quick tunnel, for trying it out in Claude or ChatGPT.
# Usage: ALLOWED_EMAIL_DOMAINS=example.com npm run tunnel
#        ALLOWED_IMAP_HOSTS='*' npm run tunnel
# Needs cloudflared (macOS: brew install cloudflared). Not for production: the URL changes on every run.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cloudflared >/dev/null || { echo "cloudflared not found. Install it first (macOS: brew install cloudflared)." >&2; exit 1; }
[ -n "${ALLOWED_EMAIL_DOMAINS:-}${ALLOWED_IMAP_HOSTS:-}" ] || {
  echo "Set ALLOWED_EMAIL_DOMAINS or ALLOWED_IMAP_HOSTS, e.g. ALLOWED_EMAIL_DOMAINS=gmail.com npm run tunnel" >&2
  exit 1
}

PORT="${PORT:-3000}"
DATA_DIR="${DATA_DIR:-$PWD/data/tunnel}"
SECRETS=.env.tunnel # gitignored; keeps the keys stable so users stay signed in between runs
mkdir -p "$DATA_DIR"
if [ ! -f "$SECRETS" ]; then
  umask 077
  printf 'ENCRYPTION_KEY=%s\nSESSION_SECRET=%s\n' "$(openssl rand -base64 32)" "$(openssl rand -hex 32)" > "$SECRETS"
fi

LOG="$(mktemp)"
cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" > "$LOG" 2>&1 &
TUNNEL_PID=$!
trap 'kill "$TUNNEL_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

URL=""
for _ in $(seq 1 60); do
  URL="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" | head -n1 || true)"
  [ -n "$URL" ] && break
  kill -0 "$TUNNEL_PID" 2>/dev/null || { cat "$LOG" >&2; echo "cloudflared exited" >&2; exit 1; }
  sleep 1
done
[ -n "$URL" ] || { cat "$LOG" >&2; echo "Timed out waiting for the tunnel URL" >&2; exit 1; }

echo
echo "  Open:           $URL"
echo "  Claude connector URL: $URL/mcp"
echo "  (the URL changes every run; remove and re-add the connector in Claude after a restart)"
echo

set -a
# shellcheck disable=SC1090
. "./$SECRETS"
set +a
PUBLIC_URL="$URL" DATA_DIR="$DATA_DIR" PORT="$PORT" npx tsx src/index.ts
