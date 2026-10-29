import ipaddr from 'ipaddr.js';
import type { Config } from '../config.js';
import { decryptSecret, encryptSecret } from '../crypto.js';
import { deleteLoginAttempt, loginFailuresSince, recordLoginFailure } from '../db/counters.js';
import type { Db } from '../db/index.js';
import {
  createUser, findUserByEmail, findUserById, normalizeEmail, recordLogin, serverSettingsOf, setSettingsSource, type User,
} from '../db/users.js';
import { revokeAllUserGrants } from '../db/oauth.js';
import { DiscoveryUnavailableError } from '../discovery/index.js';
import { audit } from '../log.js';
import { GuardError, isAllowedSmtpHost, isListedImapHost, isTrustedServer, type PinnedAddresses } from '../guard.js';
import type { ImapTarget, VerifyResult } from '../mail/imap.js';
import type { MailServerSettings, SettingsSource } from '../types.js';

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES_PER_IP = 10;
const MAX_FAILURES_PER_EMAIL = 5;
const MAX_DISCOVERIES_PER_IP = 20;

export interface LoginDeps {
  db: Db;
  config: Config;
  discover(email: string): Promise<MailServerSettings | null>;
  verifyImap(target: ImapTarget, password: string): Promise<VerifyResult>;
  guard(email: string, settings: MailServerSettings): Promise<PinnedAddresses | void>;
  now?: () => number;
}

export interface LoginInput {
  email: string;
  password: string;
  ip: string;
  manual?: MailServerSettings;
}

export type LoginResult =
  | { status: 'ok'; user: User; isNew: boolean }
  | { status: 'needs_settings'; message: string }
  | { status: 'error'; message: string };

const TOO_MANY = 'Too many sign-in attempts. Try again in 15 minutes.';
const UNAPPROVED_SERVER =
  "This instance only uses mail servers it can detect automatically or that the administrator listed in ALLOWED_IMAP_HOSTS, and yours is neither. Ask the administrator to add your IMAP server.";
const UNAPPROVED_SMTP =
  "The outgoing (SMTP) server must be the same as your IMAP server or listed by the administrator in ALLOWED_IMAP_HOSTS, because your mail password is sent to it.";
const BAD_CREDENTIALS =
  'Email or password incorrect. Many providers (Gmail, iCloud, Yahoo) require an app password instead of your normal password.';

/**
 * Rate-limit bucket for a client address. A single customer is routinely handed a whole IPv6 /64, so
 * keying on the full address would give one attacker as many attempts as they have addresses.
 */
export function rateLimitScope(ip: string): string {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(ip);
  } catch {
    // One shared bucket: an unparsable value is spoofed or unknown, and must not mint a fresh allowance.
    return 'unparsed';
  }
  if (parsed.kind() !== 'ipv6') return parsed.toNormalizedString();
  const v6 = parsed as ipaddr.IPv6;
  if (v6.isIPv4MappedAddress()) return v6.toIPv4Address().toNormalizedString();
  return `${v6.toByteArray().slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')}/64`;
}

/** The password currently stored for a user, or null when it cannot be read with this key. */
function storedPassword(deps: LoginDeps, user: User): string | null {
  try {
    return decryptSecret(deps.config.encryptionKey, user.imapPasswordEnc);
  } catch {
    return null;
  }
}

export async function login(deps: LoginDeps, input: LoginInput): Promise<LoginResult> {
  const email = normalizeEmail(input.email);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !input.password) {
    return { status: 'error', message: 'Enter your email address and password.' };
  }
  const now = deps.now?.() ?? Date.now();
  const since = now - WINDOW_MS;
  const ipKey = `ip:${rateLimitScope(input.ip)}`;
  const emailKey = `email:${email}`;

  // Checked before discovery so throttled clients cannot make the server hammer ISPDB/DNS.
  if (
    loginFailuresSince(deps.db, ipKey, since) >= MAX_FAILURES_PER_IP ||
    loginFailuresSince(deps.db, emailKey, since) >= MAX_FAILURES_PER_EMAIL
  ) {
    return { status: 'error', message: TOO_MANY };
  }

  const existing = findUserByEmail(deps.db, email);
  let settings: MailServerSettings;
  let source: SettingsSource;
  if (existing) {
    settings = serverSettingsOf(existing);
    source = existing.settingsSource;
    // Never send a password to a stored server that could have been chosen by someone else (see isTrustedServer).
    if (!isTrustedServer(deps.config, email, existing.imapHost, source)) {
      if (source !== 'legacy') return { status: 'error', message: UNAPPROVED_SERVER };
      const discovered = await rateLimitedDiscover(deps, input.ip, email, now, since);
      if (!discovered.ok) return discovered.result;
      if (discovered.settings?.imapHost.toLowerCase() !== existing.imapHost.toLowerCase()) {
        return { status: 'error', message: UNAPPROVED_SERVER };
      }
      source = 'discovered';
    }
  } else {
    const discovered = await rateLimitedDiscover(deps, input.ip, email, now, since);
    if (!discovered.ok) return discovered.result;
    // Discovered settings always win over user-supplied ones. User-supplied ones are only accepted when the lookup
    // definitively found nothing (not when it failed) and the administrator listed the server by name: otherwise
    // anyone could register someone else's address pinned to their own server and capture the real owner's
    // password at the owner's first sign-in.
    if (discovered.settings) {
      settings = discovered.settings;
      source = 'discovered';
    } else if (input.manual && isListedImapHost(deps.config, input.manual.imapHost)) {
      if (!isAllowedSmtpHost(deps.config, input.manual.imapHost, input.manual.smtpHost)) {
        return { status: 'error', message: UNAPPROVED_SMTP };
      }
      settings = input.manual;
      source = 'manual';
    } else if (input.manual || !deps.config.allowedImapHosts.some((h) => h !== '*')) {
      return { status: 'error', message: UNAPPROVED_SERVER };
    } else {
      return { status: 'needs_settings', message: "We couldn't detect your mail server settings. Enter them below." };
    }
  }

  let pinned: PinnedAddresses | void;
  try {
    pinned = await deps.guard(email, settings);
  } catch (err) {
    if (err instanceof GuardError) return { status: 'error', message: err.message };
    throw err;
  }

  const ipAttemptId = recordLoginFailure(deps.db, ipKey, now);
  const emailAttemptId = recordLoginFailure(deps.db, emailKey, now);

  if (
    loginFailuresSince(deps.db, ipKey, since) > MAX_FAILURES_PER_IP ||
    loginFailuresSince(deps.db, emailKey, since) > MAX_FAILURES_PER_EMAIL
  ) {
    deleteLoginAttempt(deps.db, ipAttemptId);
    deleteLoginAttempt(deps.db, emailAttemptId);
    return { status: 'error', message: TOO_MANY };
  }

  const result = await deps.verifyImap(
    { email, imapHost: settings.imapHost, imapPort: settings.imapPort, imapSecurity: settings.imapSecurity, connectAddress: pinned?.imap },
    input.password,
  );
  if (result === 'unavailable') {
    deleteLoginAttempt(deps.db, ipAttemptId);
    deleteLoginAttempt(deps.db, emailAttemptId);
    return { status: 'error', message: "Couldn't reach your mail server. Check the settings or try again shortly." };
  }
  if (result === 'bad_credentials') {
    return { status: 'error', message: BAD_CREDENTIALS };
  }

  deleteLoginAttempt(deps.db, ipAttemptId);
  deleteLoginAttempt(deps.db, emailAttemptId);

  const passwordEnc = encryptSecret(deps.config.encryptionKey, input.password);
  if (existing) {
    // A changed mail password is how someone locks a mailbox down, so connected AI apps must lose access too.
    // An unreadable stored password is a key rotation, not a change, and must not revoke everyone's apps.
    const stored = storedPassword(deps, existing);
    if (stored !== null && stored !== input.password) {
      revokeAllUserGrants(deps.db, existing.id, now);
      audit('grants_revoked', { userId: existing.id, email, reason: 'password_changed' });
    }
    recordLogin(deps.db, existing.id, passwordEnc, now);
    audit('sign_in', { userId: existing.id, email, isNew: false });
    if (source !== existing.settingsSource) setSettingsSource(deps.db, existing.id, source);
    return { status: 'ok', user: findUserById(deps.db, existing.id)!, isNew: false };
  }
  const user = createUser(
    deps.db,
    { ...settings, email, smtpUsername: email, imapPasswordEnc: passwordEnc, settingsSource: source === 'manual' ? 'manual' : 'discovered' },
    now,
  );
  audit('sign_in', { userId: user.id, email, isNew: true });
  return { status: 'ok', user, isNew: true };
}

type DiscoverOutcome = { ok: true; settings: MailServerSettings | null } | { ok: false; result: LoginResult };

/** Runs discovery under the per-IP discovery limit, turning a failed lookup into a "try again" result. */
async function rateLimitedDiscover(deps: LoginDeps, ip: string, email: string, now: number, since: number): Promise<DiscoverOutcome> {
  const discoverKey = `discover:${rateLimitScope(ip)}`;
  if (loginFailuresSince(deps.db, discoverKey, since) >= MAX_DISCOVERIES_PER_IP) {
    return { ok: false, result: { status: 'error', message: TOO_MANY } };
  }
  recordLoginFailure(deps.db, discoverKey, now);
  try {
    return { ok: true, settings: await deps.discover(email) };
  } catch (err) {
    if (err instanceof DiscoveryUnavailableError) {
      return {
        ok: false,
        result: { status: 'error', message: "We couldn't look up your mail server settings right now. Please try again in a few minutes." },
      };
    }
    throw err;
  }
}
