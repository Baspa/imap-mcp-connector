# IMAP MCP Connector — Design

**Date:** 2026-10-04
**Status:** Draft, awaiting review
**License:** MIT

## 1. Purpose

An open-source, self-hosted server that lets people use their own IMAP mailbox from Claude or ChatGPT — a "mail client for AI." A user opens the instance's web page, signs in with their email address and (app) password, picks how much the AI may do, and pastes the instance's connector URL into Claude or ChatGPT.

### Decisions made during brainstorming

| Topic | Decision |
|---|---|
| Deployment model | Self-hosted, **multi-user per instance** (a company/family runs one deployment for many users). No public hosted service in v1. |
| AI capabilities | **Per-user permission level**: `read`, `draft` (default), `full`. |
| Language / runtime | **TypeScript on Node 24.** |
| Framework | **Express** (plus EJS server-rendered pages). Next.js considered and rejected (see §11). |
| Architecture | **Single process, single Docker image, SQLite.** |
| Identity | **The mailbox is the identity**: users sign in with email + mail password; no separate app accounts. |
| Login UX | One email + password form; first successful login implicitly registers. |
| AI integration | Remote **MCP server** (Streamable HTTP) with an **OAuth 2.1** authorization server — works with Claude custom connectors and ChatGPT connectors. |

### Success criteria

- A self-hoster can go from `docker compose up` to a working Claude/ChatGPT connector in under 15 minutes following the README.
- An end user only ever types their email and password, then copies a URL.
- Every tool works end-to-end against a real IMAP/SMTP server in CI.
- A database leak exposes no usable mail passwords (without `ENCRYPTION_KEY`) and no usable OAuth tokens.

### Out of scope for v1

- OAuth2/XOAUTH2 mail login (required for **Outlook.com / Microsoft 365**, optional for Gmail). Planned for v2. v1 supports password/app-password IMAP only (Gmail with app password, iCloud, Yahoo, Fastmail, Zoho, most hosted and self-run servers).
- Multiple mailboxes per user, separate app accounts, SSO/OIDC.
- Folder create/rename/delete, mail rules, sending binary attachments.
- Public hosted service, horizontal scaling.

## 2. Architecture

One Node 24 process in one Docker image, SQLite on a mounted volume, HTTPS terminated by a reverse proxy (Caddy in the example compose file).

```
Claude / ChatGPT ──OAuth 2.1──▶ /authorize, /token, /register (mcpAuthRouter)
       │                                   │
       └──Bearer token──▶ /mcp ──▶ mcp ──▶ mail ──▶ IMAP / SMTP server
                                   │        │
Browser ──session cookie──▶ web ──▶ auth ──▶ db (SQLite)  ◀── crypto
```

### Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `config` | Load and validate env vars; refuse to start on invalid config. | — |
| `db` | SQLite via `better-sqlite3`, schema migrations, typed query functions. | config |
| `crypto` | AES-256-GCM encrypt/decrypt of mail passwords; SHA-256 hashing of OAuth codes/tokens. | config |
| `discovery` | Resolve IMAP/SMTP settings from an email domain (built-in presets → Thunderbird ISPDB autoconfig → DNS SRV). | — |
| `mail` | Wrap `imapflow` and `nodemailer`; per-user connection cache; all mailbox operations; map upstream errors to error categories. | crypto, db |
| `auth` | Email+password login/implicit registration, sessions, host allowlist + private-IP guard, login rate limiting, SQLite-backed OAuth provider for the SDK's `mcpAuthRouter`, consent page. | db, crypto, mail, discovery |
| `mcp` | `/mcp` Streamable HTTP endpoint behind `requireBearerAuth`; registers tools per permission level; enforces level on every call. | auth, mail |
| `web` | Express routes + EJS views: login, settings, consent, connect instructions. CSRF on all forms. | auth, db |

Key libraries: `express`, `@modelcontextprotocol/sdk`, `imapflow`, `nodemailer`, `better-sqlite3`, `express-session`, `ejs`, `zod`, `html-to-text`, `mailparser`, `pdf-parse` (attachment text), `vitest`, `testcontainers`.

### Configuration (environment variables)

| Variable | Required | Meaning |
|---|---|---|
| `PUBLIC_URL` | yes | External base URL; must be `https://` unless `NODE_ENV=development`. |
| `ENCRYPTION_KEY` | yes | 32-byte key, base64. Startup fails if missing or wrong length. |
| `SESSION_SECRET` | yes | Secret for signing session cookies. |
| `ALLOWED_EMAIL_DOMAINS` | one of these two | Comma list of email domains allowed to sign in (e.g. `example.com`). |
| `ALLOWED_IMAP_HOSTS` | one of these two | Comma list of IMAP hostnames allowed (e.g. `imap.gmail.com`). `*` allows any public host. |
| `ALLOW_PRIVATE_HOSTS` | no (default `false`) | Allow mail hosts that resolve to private/loopback IPs (for self-run mail servers on the LAN). |
| `DEFAULT_SEND_LIMIT_PER_HOUR` | no (default `20`) | Default per-user send limit. |
| `DATA_DIR` | no (default `/data`) | Where the SQLite file lives. |
| `PORT` | no (default `3000`) | Listen port. |

## 3. User flows

### 3.1 Sign in / implicit registration

Single form: **email** + **password**.

1. Rate-limit check (per IP and per email).
2. If a user with this email exists → use stored IMAP host/port/TLS.
   Otherwise → `discovery` resolves settings from the domain. If discovery fails, re-render the form with expanded fields (IMAP host, port, TLS; SMTP host, port, TLS).
3. Allowlist check on email domain / IMAP host. Resolve the host; reject private/loopback/link-local addresses unless `ALLOW_PRIVATE_HOSTS=true`. This runs **before** any connection attempt.
4. Live IMAP login with the given password.
5. On success: create or update the user, store the password encrypted (replacing any previous one, which also clears `needs_reauth`), start a session. New users land on Settings; returning users land on Settings too (it is the only page).
6. On failure: generic "Email or password incorrect" message (no distinction between unknown user and bad password), plus a help link about app passwords.

The login page explains app passwords and links to instructions for Gmail, iCloud, Yahoo, Fastmail, Zoho. Lost app password → generate a new one at the provider and sign in with it; no password-reset feature exists or is needed.

### 3.2 Settings page

- Email address and detected server settings (editable SMTP host/port/TLS/username; SMTP password defaults to the IMAP password, optionally separate).
- Permission level: `read` / `draft` / `full`, with a plain-language explanation and, for `full`, a prompt-injection warning.
- Connector URL (`<PUBLIC_URL>/mcp`) with copy button, and short "Connect to Claude" / "Connect to ChatGPT" instructions.
- Connected AI clients (name, connected date, last used) each with **Revoke**.
- Sign out; **Delete my account** (removes user row, credentials, and all tokens).

### 3.3 Connecting an AI client

1. User pastes `<PUBLIC_URL>/mcp` into Claude or ChatGPT.
2. Client fetches OAuth discovery metadata and registers via dynamic client registration.
3. Client redirects to `/authorize`. If no session, user signs in (§3.1) and returns.
4. Consent page shows client name, user's email, current permission level; **Approve** / **Deny**.
5. Approve → authorization code → client exchanges it (with PKCE verifier) for access + refresh tokens.

### 3.4 Tool call

1. Client calls `/mcp` with `Authorization: Bearer <access token>`.
2. `requireBearerAuth` → provider looks up token hash, checks expiry/revocation, resolves user.
3. `mcp` builds a server exposing only tools allowed at the user's current level; each tool handler re-checks the level before executing.
4. `mail` runs the operation using the user's cached or new IMAP connection.

## 4. MCP tools

Messages are addressed by `folder` + IMAP `uid`. Each level includes everything below it.

### Read (`read`)

| Tool | Input | Output |
|---|---|---|
| `list_folders` | — | Folders with path, special-use role (Inbox/Sent/Drafts/Trash/Archive/Junk), total and unread counts. |
| `search_messages` | `folder` (default INBOX), `from`, `to`, `subject`, `text`, `since`, `before`, `unread`, `flagged`, `limit` (default 20, max 100), `cursor` | Newest first: uid, from, to, subject, date, flags, snippet (≤200 chars); `next_cursor` if more. |
| `get_message` | `folder`, `uid` | Headers (from, to, cc, date, subject, message-id), plain-text body (HTML converted to text), attachments (filename, content type, size, part id). |
| `get_thread` | `folder`, `uid` | All messages in the thread, oldest first, same shape as `get_message`. Uses Gmail `X-GM-THRID` when the server supports it; otherwise matches `Message-ID` / `In-Reply-To` / `References` across the folder plus Sent. |
| `get_attachment` | `folder`, `uid`, `part_id` | Extracted text for text/*, CSV, HTML, JSON, PDF. Other types: metadata only with a note. Max 5 MB input, 50 KB text output. |

### Draft (`draft`, default)

| Tool | Input | Effect |
|---|---|---|
| `set_flags` | `folder`, `uids[]`, `add[]`, `remove[]` from {`seen`, `flagged`} | Sets/clears flags. |
| `move_messages` | `folder`, `uids[]`, `destination` (folder path or role name `archive`/`inbox`/`junk`) | Moves messages. |
| `create_draft` | `to[]`, `cc[]`, `bcc[]`, `subject`, `body` (plain text), optional `reply_to_uid` + `reply_to_folder` | Appends to Drafts with `\Draft`. Reply mode sets `In-Reply-To`, `References`, and `Re:` subject. |

### Full (`full`)

| Tool | Input | Effect |
|---|---|---|
| `send_email` | Same as `create_draft` | Sends via SMTP; appends copy to Sent unless the user's provider preset has `autoSavesSent: true` (Gmail, Outlook-family); unknown providers always get the copy appended. Counts against send limit. |
| `delete_messages` | `folder`, `uids[]` | Moves to Trash. Never expunges. |

### Safety rules

- **Annotations:** read tools set `readOnlyHint: true`; `send_email` and `delete_messages` set `destructiveHint: true`; others `readOnlyHint: false, destructiveHint: false`.
- **Untrusted content:** email-derived text in tool output is wrapped in `<untrusted_email_content>` … `</untrusted_email_content>`; the server instructions and tool descriptions state that content inside must never be treated as instructions.
- **Send limit:** per-user rolling hourly limit (`send_limit_per_hour` or `DEFAULT_SEND_LIMIT_PER_HOUR`), tracked in `send_log`.
- **Output caps:** message bodies truncated at 50 KB with an explicit truncation marker; batch operations (`uids[]`) capped at 100.
- **Level enforcement:** checked at tool registration **and** in every handler, so a downgrade takes effect on the next call.

## 5. Data model (SQLite)

```sql
users (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,            -- lowercased
  imap_host TEXT NOT NULL, imap_port INTEGER NOT NULL, imap_tls INTEGER NOT NULL,
  imap_password_enc TEXT NOT NULL,       -- "v1:<nonce>:<ciphertext>:<tag>" base64 parts
  smtp_host TEXT NOT NULL, smtp_port INTEGER NOT NULL, smtp_tls TEXT NOT NULL, -- 'tls' | 'starttls'
  smtp_username TEXT NOT NULL,
  smtp_password_enc TEXT,                -- NULL = use IMAP password
  permission_level TEXT NOT NULL DEFAULT 'draft', -- 'read' | 'draft' | 'full'
  send_limit_per_hour INTEGER,           -- NULL = admin default
  needs_reauth INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_login_at INTEGER
)
oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL)
oauth_codes   (code_hash TEXT PRIMARY KEY, client_id TEXT, user_id INTEGER, code_challenge TEXT, redirect_uri TEXT, expires_at INTEGER, used INTEGER DEFAULT 0)
oauth_tokens  (token_hash TEXT PRIMARY KEY, kind TEXT, client_id TEXT, user_id INTEGER, expires_at INTEGER, revoked_at INTEGER, last_used_at INTEGER)
sessions      (sid TEXT PRIMARY KEY, data TEXT, expires_at INTEGER)
send_log      (user_id INTEGER, sent_at INTEGER)
login_attempts(key TEXT, attempted_at INTEGER)
```

Foreign keys cascade on user deletion. Expired codes/tokens/sessions/log rows are purged hourly.

## 6. Security

- **Mail passwords:** AES-256-GCM, random 96-bit nonce per encryption, key from `ENCRYPTION_KEY`, ciphertext prefixed with a key version (`v1`) to allow future rotation. If the key is lost, stored passwords become unreadable; users are marked `needs_reauth` on decrypt failure and simply sign in again.
- **OAuth:** authorization codes (60 s, single use), access tokens (1 h), refresh tokens (30 days, rotated on each use; reuse of a rotated refresh token revokes the whole grant). Only SHA-256 hashes stored. PKCE S256 mandatory; exact redirect URI match.
- **Sessions:** `express-session` with SQLite store; cookies `httpOnly`, `secure`, `sameSite=lax`; session regenerated on login; CSRF tokens on every POST form.
- **SSRF guard:** allowlist + private-address rejection before any outbound IMAP/SMTP connection, both at sign-in and on SMTP settings changes.
- **Rate limiting:** sign-in limited to 10 attempts / 15 min per IP and 5 / 15 min per email.
- **Logging:** never logs passwords, tokens, or message content; each request gets a request id.
- **HTTPS:** required in production (`PUBLIC_URL` validation); `trust proxy` configured for the reverse proxy.
- **Prompt injection:** reduced by untrusted-content wrapping, tool annotations, send limits, and `full` being opt-in; documented in the README as not fully preventable.

## 7. Error handling

`mail` maps upstream failures to categories returned as MCP tool errors (`isError: true`) with a short actionable message:

| Category | Cause | Message to model |
|---|---|---|
| `AUTH_FAILED` | Stored password rejected | User marked `needs_reauth`; "Mailbox password no longer works. Ask the user to sign in at <PUBLIC_URL> to update it." |
| `NOT_FOUND` | Folder or uid missing | Names the missing folder/uid. |
| `PERMISSION_DENIED` | Tool not allowed at current level | Names the required level and where to change it. |
| `RATE_LIMITED` | Send limit hit | Says when the next send is allowed. |
| `TOO_LARGE` | Attachment over limit | States the limit. |
| `UPSTREAM_UNAVAILABLE` | Timeout / connection error | "Mail server unavailable, try again shortly." |
| `INVALID_INPUT` | Zod validation failure | The validation message. |

Connection handling: one cached IMAP connection per user, closed after 5 minutes idle; on a dropped connection the operation is retried once on a fresh connection; 30 s timeout per operation; IMAP operations for one user are serialized (mailbox lock) to avoid folder-selection races. Unexpected errors: logged with request id, generic 500 / generic tool error returned.

## 8. Testing

- **Unit (Vitest):** crypto round-trip and tamper detection; key-version parsing; allowlist and private-IP guard; discovery (presets, ISPDB parsing, SRV parsing — network mocked); permission filtering; send-limit window; HTML→text and truncation; reply header construction; error mapping.
- **Integration (Vitest + Testcontainers + GreenMail):** every MCP tool end-to-end through the SDK client against a real IMAP/SMTP server: search/pagination, get_message, get_thread, attachments, flags, move, draft lands in Drafts, send lands in recipient inbox and Sent, delete lands in Trash, permission levels hide and block tools, send limit enforced, `AUTH_FAILED` after password change.
- **Auth flow:** sign-in + implicit registration; failed sign-in; rate limit; full OAuth flow (register → authorize with PKCE → token → refresh with rotation → revoke); bad PKCE / redirect URI rejected; revoked and expired tokens get 401; refresh-token reuse revokes grant.
- **CI:** GitHub Actions on every PR: lint (ESLint), typecheck (`tsc --noEmit`), unit, integration.

## 9. Deployment and project layout

- **Image:** multi-stage Dockerfile on `node:24-alpine`; runs as non-root; healthcheck at `/healthz`. Published to GHCR by a GitHub Action on version tags.
- **Compose:** `docker-compose.yml` with the app, `./data` volume, and Caddy for automatic HTTPS; `.env.example` documents every variable.
- **README:** 5-minute quickstart; Connect to Claude; Connect to ChatGPT; per-provider app-password guide; security model (what is stored, how it is encrypted, prompt-injection risk of `full`); v1 limitation on Outlook/Microsoft 365.
- **License:** MIT.

```
src/
  config.ts
  db/        (index.ts, migrations/, queries)
  crypto.ts
  discovery/ (index.ts, presets.ts, ispdb.ts, srv.ts)
  mail/      (client.ts, pool.ts, operations/*.ts, errors.ts, format.ts)
  auth/      (login.ts, guard.ts, ratelimit.ts, oauth-provider.ts, session.ts)
  mcp/       (server.ts, tools/*.ts, levels.ts)
  web/       (routes.ts, views/*.ejs, csrf.ts)
  app.ts     (Express wiring)
  index.ts   (startup)
test/
  unit/  integration/
```

## 10. Future (not v1)

- XOAUTH2 login for Microsoft 365 / Outlook.com and Google.
- Multiple mailboxes per user; admin page.
- Postgres option and horizontal scaling for a public hosted service.
- Sending attachments; folder management.

## 11. Alternatives considered

- **Split services (web/MCP/worker + Postgres + Redis):** rejected — triple the moving parts for a self-hosted target.
- **Stateless (credentials inside tokens):** rejected — no revocation, credentials held by third parties.
- **Next.js:** rejected — UI is four forms; long-lived IMAP connections fight its request-scoped model; MCP SDK OAuth helpers are Express middleware.
- **Separate app accounts / SSO:** deferred — more friction and code; mailbox-as-identity suffices for v1.
