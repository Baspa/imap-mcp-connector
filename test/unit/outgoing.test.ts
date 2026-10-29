import { simpleParser } from 'mailparser';
import { describe, expect, it } from 'vitest';
import { encryptSecret } from '../../src/crypto.js';
import { sendsSince } from '../../src/db/counters.js';
import { findUserById, updateSmtpSettings, type User } from '../../src/db/users.js';
import { GuardError, type PinnedAddresses } from '../../src/guard.js';
import { sendEmail, type OutgoingDeps } from '../../src/mail/outgoing.js';
import { MailPool } from '../../src/mail/pool.js';
import type { SmtpFactory, SmtpTarget } from '../../src/mail/smtp.js';
import { TEST_KEY } from '../helpers/config.js';
import { createTestUser, testDb } from '../helpers/db.js';

function setup(
  opts: { smtpError?: Error; limit?: number; smtpDelayMs?: number; autoSavesSent?: boolean; guard?: (user: User) => Promise<PinnedAddresses | void>; allowedRecipientDomains?: string[] } = {},
) {
  const db = testDb();
  const user = createTestUser(db, { email: 'alice@x.org', password: 'imap-pw', autoSavesSent: opts.autoSavesSent ?? true });
  const sent: { envelope: { from: string; to: string[] }; raw: Buffer; password: string }[] = [];
  const targets: SmtpTarget[] = [];
  const smtpFactory: SmtpFactory = (target, password) => ({
    async sendMail(m) {
      targets.push(target);
      if (opts.smtpDelayMs) await new Promise((r) => setTimeout(r, opts.smtpDelayMs));
      if (opts.smtpError) throw opts.smtpError;
      sent.push({ ...m, password });
      return {};
    },
    close() {},
  });
  const pool = new MailPool({
    db,
    key: TEST_KEY,
    signInUrl: 'https://m.example.com/login',
    factory: () => {
      throw new Error('IMAP must not be used in this test');
    },
  });
  let now = 1_000_000;
  const deps: OutgoingDeps = {
    db, key: TEST_KEY, pool, smtpFactory, defaultSendLimitPerHour: opts.limit ?? 20,
    signInUrl: 'https://m.example.com/login', now: () => now, guard: opts.guard,
    allowedRecipientDomains: opts.allowedRecipientDomains ?? [],
  };
  return { db, user, deps, sent, targets, advance: (ms: number) => (now += ms) };
}

describe('sendEmail', () => {
  it('sends raw MIME without Bcc header to all recipients and records the send', async () => {
    const { db, user, deps, sent } = setup();
    const result = await sendEmail(deps, user, { to: ['bob@y.org'], cc: ['c@y.org'], bcc: ['s@z.org'], subject: 'Hi', body: 'Hello' });
    expect(result.savedToSent).toBe(false);
    expect(result.messageId).toMatch(/^<.+@x\.org>$/);
    expect(sent[0].envelope).toEqual({ from: 'alice@x.org', to: ['bob@y.org', 'c@y.org', 's@z.org'] });
    expect(sent[0].password).toBe('imap-pw');
    const parsed = await simpleParser(sent[0].raw);
    expect(parsed.bcc).toBeUndefined();
    expect(parsed.messageId).toBe(result.messageId);
    expect(sendsSince(db, user.id, 0).count).toBe(1);
  });

  it('uses a separate SMTP password when configured', async () => {
    const { db, user, deps, sent } = setup();
    updateSmtpSettings(db, user.id, { smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls', smtpUsername: 'alice', smtpPasswordEnc: encryptSecret(TEST_KEY, 'smtp-pw') });
    await sendEmail(deps, findUserById(db, user.id)!, { to: ['bob@y.org'], subject: 'Hi', body: 'x' });
    expect(sent[0].password).toBe('smtp-pw');
  });

  it('enforces the hourly send limit', async () => {
    const { user, deps, advance } = setup({ limit: 2 });
    await sendEmail(deps, user, { to: ['b@y.org'], subject: '1', body: 'x' });
    advance(1000);
    await sendEmail(deps, user, { to: ['b@y.org'], subject: '2', body: 'x' });
    const err = await sendEmail(deps, user, { to: ['b@y.org'], subject: '3', body: 'x' }).catch((e) => e);
    expect(err.code).toBe('RATE_LIMITED');
    expect(err.message).toContain(new Date(1_000_000 + 3_600_000).toISOString());
    advance(3_600_000);
    await expect(sendEmail(deps, user, { to: ['b@y.org'], subject: '4', body: 'x' })).resolves.toBeDefined();
  });

  it('cannot exceed the hourly limit with concurrent sends', async () => {
    const { db, user, deps, sent } = setup({ limit: 2, smtpDelayMs: 20 });
    const results = await Promise.allSettled(
      [1, 2, 3].map((n) => sendEmail(deps, user, { to: ['b@y.org'], subject: `c${n}`, body: 'x' })),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
    const rejected = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    expect(rejected).toHaveLength(1);
    expect(rejected[0].reason.code).toBe('RATE_LIMITED');
    expect(sent).toHaveLength(2);
    expect(sendsSince(db, user.id, 0).count).toBe(2);
  });

  it('still succeeds when the Sent copy cannot be saved', async () => {
    const { db, user, deps, sent } = setup({ autoSavesSent: false });
    const result = await sendEmail(deps, user, { to: ['b@y.org'], subject: 'x', body: 'x' });
    expect(result.savedToSent).toBe(false);
    expect(sent).toHaveLength(1);
    expect(sendsSince(db, user.id, 0).count).toBe(1);
  });

  it('reports SMTP auth failures without forcing IMAP re-auth', async () => {
    const { db, user, deps } = setup({ smtpError: Object.assign(new Error('535'), { code: 'EAUTH' }) });
    const err = await sendEmail(deps, user, { to: ['b@y.org'], subject: 'x', body: 'x' }).catch((e) => e);
    expect(err.code).toBe('AUTH_FAILED');
    expect(err.message).toMatch(/SMTP/);
    expect(findUserById(db, user.id)?.needsReauth).toBe(false);
    expect(sendsSince(db, user.id, 0).count).toBe(0);
  });

  it('connects to the SMTP address the guard vetted, not a fresh DNS answer', async () => {
    const { user, deps, targets } = setup({ guard: async () => ({ smtp: '93.184.216.35' }) });
    await sendEmail(deps, user, { to: ['b@y.org'], subject: 'x', body: 'x' });
    expect(targets[0]).toMatchObject({ smtpHost: user.smtpHost, connectAddress: '93.184.216.35' });
  });

  it('re-checks the guard before connecting to SMTP and releases the send slot', async () => {
    const guard = async () => {
      throw new GuardError('This mail server is not allowed on this instance. Ask the administrator.');
    };
    const { db, user, deps, sent } = setup({ guard });
    const err = await sendEmail(deps, user, { to: ['b@y.org'], subject: 'x', body: 'x' }).catch((e) => e);
    expect(err.code).toBe('PERMISSION_DENIED');
    expect(err.message).toMatch(/not allowed/);
    expect(sent).toHaveLength(0);
    expect(sendsSince(db, user.id, 0).count).toBe(0);
  });

  it('requires recipients and a subject when not replying', async () => {
    const { db, user, deps } = setup();
    await expect(sendEmail(deps, user, { to: [], subject: 'x', body: 'x' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(sendEmail(deps, user, { to: ['b@y.org'], body: 'x' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(sendsSince(db, user.id, 0).count).toBe(0);
  });
});

describe('sendEmail with a recipient allowlist', () => {
  it('sends to a listed domain', async () => {
    const { user, deps, sent } = setup({ allowedRecipientDomains: ['y.org'] });
    await sendEmail(deps, user, { to: ['bob@y.org'], subject: 'Hi', body: 'Hello' });
    expect(sent[0].envelope.to).toEqual(['bob@y.org']);
  });

  it('refuses a recipient outside the listed domains and does not use a send slot', async () => {
    const { db, user, deps, sent } = setup({ allowedRecipientDomains: ['y.org'] });
    await expect(sendEmail(deps, user, { to: ['attacker@evil.example'], subject: 'Hi', body: 'Hello' }))
      .rejects.toThrow(/evil\.example/);
    expect(sent).toHaveLength(0);
    expect(sendsSince(db, user.id, 0).count).toBe(0);
  });

  it('checks cc and bcc too, so one listed recipient cannot carry the rest', async () => {
    const { user, deps, sent } = setup({ allowedRecipientDomains: ['y.org'] });
    await expect(sendEmail(deps, user, { to: ['bob@y.org'], bcc: ['attacker@evil.example'], subject: 'Hi', body: 'Hello' }))
      .rejects.toThrow(/evil\.example/);
    expect(sent).toHaveLength(0);
  });

  it('sends anywhere when no domains are listed', async () => {
    const { user, deps, sent } = setup();
    await sendEmail(deps, user, { to: ['anyone@elsewhere.example'], subject: 'Hi', body: 'Hello' });
    expect(sent[0].envelope.to).toEqual(['anyone@elsewhere.example']);
  });
});
