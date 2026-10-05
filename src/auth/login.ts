import type { Config } from '../config.js';
import { encryptSecret } from '../crypto.js';
import { deleteLoginAttempt, loginFailuresSince, recordLoginFailure } from '../db/counters.js';
import type { Db } from '../db/index.js';
import {
  createUser, findUserByEmail, findUserById, normalizeEmail, recordLogin, serverSettingsOf, type User,
} from '../db/users.js';
import { DiscoveryUnavailableError } from '../discovery/index.js';
import { GuardError } from '../guard.js';
import type { ImapTarget, VerifyResult } from '../mail/imap.js';
import type { MailServerSettings } from '../types.js';

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES_PER_IP = 10;
const MAX_FAILURES_PER_EMAIL = 5;
const MAX_DISCOVERIES_PER_IP = 20;

export interface LoginDeps {
  db: Db;
  config: Config;
  discover(email: string): Promise<MailServerSettings | null>;
  verifyImap(target: ImapTarget, password: string): Promise<VerifyResult>;
  guard(email: string, settings: MailServerSettings): Promise<void>;
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
const BAD_CREDENTIALS =
  'Email or password incorrect. Many providers (Gmail, iCloud, Yahoo) require an app password instead of your normal password.';

export async function login(deps: LoginDeps, input: LoginInput): Promise<LoginResult> {
  const email = normalizeEmail(input.email);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !input.password) {
    return { status: 'error', message: 'Enter your email address and password.' };
  }
  const now = deps.now?.() ?? Date.now();
  const since = now - WINDOW_MS;
  const ipKey = `ip:${input.ip}`;
  const emailKey = `email:${email}`;

  // Checked before discovery so throttled clients cannot make the server hammer ISPDB/DNS.
  if (
    loginFailuresSince(deps.db, ipKey, since) >= MAX_FAILURES_PER_IP ||
    loginFailuresSince(deps.db, emailKey, since) >= MAX_FAILURES_PER_EMAIL
  ) {
    return { status: 'error', message: TOO_MANY };
  }

  const existing = findUserByEmail(deps.db, email);
  let settings: MailServerSettings | null;
  if (existing) {
    settings = serverSettingsOf(existing);
  } else {
    const discoverKey = `discover:${input.ip}`;
    if (loginFailuresSince(deps.db, discoverKey, since) >= MAX_DISCOVERIES_PER_IP) {
      return { status: 'error', message: TOO_MANY };
    }
    recordLoginFailure(deps.db, discoverKey, now);
    let discovered: MailServerSettings | null;
    try {
      discovered = await deps.discover(email);
    } catch (err) {
      if (err instanceof DiscoveryUnavailableError) {
        return { status: 'error', message: "We couldn't look up your mail server settings right now. Please try again in a few minutes." };
      }
      throw err;
    }
    // Discovered settings always win over user-supplied ones, and user-supplied ones are only accepted when the
    // lookup definitively found nothing (not when it failed): otherwise anyone could register someone else's
    // address pinned to their own server and capture the real owner's password at the owner's first sign-in.
    settings = discovered ?? input.manual ?? null;
  }
  if (!settings) {
    return { status: 'needs_settings', message: "We couldn't detect your mail server settings. Enter them below." };
  }

  try {
    await deps.guard(email, settings);
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
    { email, imapHost: settings.imapHost, imapPort: settings.imapPort, imapSecurity: settings.imapSecurity },
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
    recordLogin(deps.db, existing.id, passwordEnc, now);
    return { status: 'ok', user: findUserById(deps.db, existing.id)!, isNew: false };
  }
  const user = createUser(deps.db, { ...settings, email, smtpUsername: email, imapPasswordEnc: passwordEnc }, now);
  return { status: 'ok', user, isNew: true };
}
