# IMAP MCP Connector — deferred review findings

Minor findings from per-task and final code reviews that were consciously deferred (none block release). Candidates for GitHub issues.

- **Task 1** — config tests lack cases for unparsable PUBLIC_URL, query/hash, invalid PORT, empty DATA_DIR
- **Task 1** — ENCRYPTION_KEY base64 not strictly validated (Buffer.from ignores bad chars)
- **Task 1** — ALLOW_PRIVATE_HOSTS only accepts exact 'true'
- **Task 1** — @types/nodemailer ^8 vs nodemailer ^7, @types/better-sqlite3 ^9 vs better-sqlite3 ^12 (typecheck is green; align majors when convenient)
- **Task 1** — npm audit reports 6 dev-dep vulns (1 high) — check before release
- **Task 2** — key length not validated in crypto fns (relies on config validation)
- **Task 2** — no AAD binding ciphertext to user row (format has no slot)
- **Task 2** — randomToken(bytes) has no minimum
- **Task 2** — no dedicated wrong-nonce-length test
- **Task 3** — listActiveGrants connectedAt drifts forward as old tokens are purged (UI "connected" date wrong for long-lived grants)
- **Task 3** — oauth_clients rows never purged (dynamic registration grows unbounded)
- **Task 3** — purge test doesn't cover pending/codes/sessions/send_log; cascade tests only for tokens
- **Task 3** — openDb silently accepts user_version > known migrations
- **Task 4** — SRV targets not tied to email domain; ISPDB body unbounded/redirects followed; trailing-dot domains miss presets; untested SRV branches
- **Task 4** — port test covers only empty port (not NaN/>65535); %EMAILDOMAIN% replace() replaces first occurrence only (fails safe)
- **Task 5** — IPv4-compatible IPv6 (::7f00:1) classified unicast — reject ::/96
- **Task 5** — SMTP host not checked against allowlist (only private-address check) — spec allowlists email domain / IMAP host only
- **Task 5** — no timeout on dns.lookup; lookup error cause swallowed; "could not resolve" vs "private" messages form a small internal-DNS oracle; thin guard tests
- **Task 6** — snippet can split surrogate pairs; truncateUtf8 strips a genuine U+FFFD at the cut; formatAddress doesn't quote names (don't reuse for outgoing headers); toMailError never yields PERMISSION_DENIED/RATE_LIMITED/TOO_LARGE/INVALID_INPUT (callers throw them)
- **Task 7** — queued ops use stale user.needsReauth snapshot (extra failed logins after AUTH_FAILED); no test for 'error' event / guarded discard; logout() in close/closeAll unbounded; closeAll misses in-flight connect; idle test timing-based
- **Task 13** — needs_settings response distinguishes unregistered emails on discovery-failure domains; discovery runs before guard; concurrent first-login race → unique-constraint 500
- **Task 13** — reserved attempt rows leak if verifyImap throws (fails closed); rate-limit check now runs after discover/guard
- **Task 8** — createFolders swallows all errors; cursor has no UIDVALIDITY check; lock-release-after-error untested; beforeEach leak on setup failure
- **Task 8** — listFolders role display can disagree with resolveRole for nested name-guessed folders; exact-path-beats-role only code-reviewed (GreenMail lacks special-use)
- **Task 9** — inline parts without filename (calendar, inline images, 2nd text part) dropped; 5MB check uses encoded size; textKind treats text/rtf, text/calendar as plain text; test gaps (rfc822, single-part, 50KB attachment cap)
- **Task 10** — null-date ordering/tie-break untested; messageId dedupe not normalized; Gmail results report All Mail folder
- **Task 10** — no test asserts readMessage only on survivors; survivor vanishing mid-read yields fewer than max; Gmail branch untested (README note owed by Task 18)
- **Task 11** — IMAP4rev2 servers may not list MOVE in capabilities → safe copy path or refusal (fails safe); count race if another client expunges mid-op
- **Task 12** — partial SMTP recipient rejection reported as success; no unit test for SMTP security mapping; validation after slot reservation; non-auth SMTP rejections (550/EENVELOPE) rethrown raw to tool layer
- **Task 14** — consume+issue not in one transaction; code reuse doesn't revoke tokens issued from it (no grant id on code row); missing security tests (cross-client revoke/refresh, refresh expiry, deleted user, double approve); confidential client secrets stored plaintext in metadata; resource not bound to tokens
- **Task 15** — anonymous GET /login creates 7-day session rows; trust proxy hard-coded 1 (X-Forwarded-For spoofing without proxy); session regeneration and open-redirect variants under-tested
- **Task 15** — 4xx logged at error level; in-flight request may re-save a session row for a deleted id (harmless with AUTOINCREMENT)
- **Task 16** — discovery test doesn't pin issuer/authorization_servers; non-localhost http dev PUBLIC_URL crashes at SDK checkIssuerUrl (document in README)
- **Task 17** — deleted-user 401 lacks WWW-Authenticate; /mcp body-parse errors render HTML; delete_messages openWorldHint true; loose schema string lengths, set_flags accepts empty add/remove; untested: non-POST /mcp, INTERNAL mapping, get_thread/get_attachment/set_flags/move via MCP
- **Task 18** — release workflow v* matches non-semver tags & actions tag-pinned; Docker image not test-built on PRs; .dockerignore could exclude .superpowers/.github/.env.*
- **Task 18** — no re-entrancy guard on shutdown (double SIGTERM → exit 1); server.close has no timeout; README command doesn't print changes
- **Final** — DNS outage at connect shows PERMISSION_DENIED; mailGuard optional in AppDeps; manual settings silently ignored when discovery succeeds (no override for wrong ISPDB data); AND allowlist changes behaviour for mixed configs (documented)
- **Residual** — partially published SRV (_imaps without submission) or ISPDB with only unusable SMTP → not_found → manual IMAP host accepted; consider pinning discovered IMAP host and only allowing typed SMTP; rate limits key on req.ip (IPv6 range spreading)

## Also deferred from the final review

- Request id not included in MCP tool error logs/results
- get_thread has no total output size cap (up to 50 × 50 KB)
- PDF extraction runs on the main thread (a crafted PDF can block the event loop)
- No grace window for refresh-token retries (a lost refresh response revokes the grant)
- Outlook/Microsoft 365 users get a generic 'wrong password' error instead of 'not supported yet'
- No copy button next to the connector URL
- list_folders output is not wrapped as untrusted (folder names are server-controlled)
