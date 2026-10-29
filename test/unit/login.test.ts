import { describe, expect, it, vi } from 'vitest';
import { decryptSecret } from '../../src/crypto.js';
import { findUserByEmail, findUserById, setNeedsReauth } from '../../src/db/users.js';
import { login, type LoginDeps } from '../../src/auth/login.js';
import { DiscoveryUnavailableError } from '../../src/discovery/index.js';
import { GuardError } from '../../src/guard.js';
import type { MailServerSettings } from '../../src/types.js';
import type { VerifyResult } from '../../src/mail/imap.js';
import { TEST_KEY, testConfig } from '../helpers/config.js';
import { createTestUser, testDb } from '../helpers/db.js';

const settings: MailServerSettings = {
  imapHost: 'imap.x.org', imapPort: 993, imapSecurity: 'tls',
  smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
};

function deps(overrides: Partial<LoginDeps> = {}): LoginDeps {
  return {
    db: testDb(),
    config: testConfig(),
    discover: vi.fn(async () => settings),
    verifyImap: vi.fn(async (_t, pw: string) => (pw === 'right' ? 'ok' : 'bad_credentials') as VerifyResult),
    guard: vi.fn(async () => undefined),
    now: () => 1_000_000,
    ...overrides,
  };
}

const input = { email: 'alice@x.org', password: 'right', ip: '1.2.3.4' };

describe('login', () => {
  it('registers a new user using discovered settings', async () => {
    const d = deps();
    const r = await login(d, input);
    expect(r.status).toBe('ok');
    if (r.status !== 'ok') return;
    expect(r.isNew).toBe(true);
    expect(r.user).toMatchObject({ email: 'alice@x.org', imapHost: 'imap.x.org', smtpUsername: 'alice@x.org', permissionLevel: 'draft', settingsSource: 'discovered' });
    expect(decryptSecret(TEST_KEY, r.user.imapPasswordEnc)).toBe('right');
    expect(d.verifyImap).toHaveBeenCalledWith(expect.objectContaining({ email: 'alice@x.org', imapHost: 'imap.x.org' }), 'right');
  });

  it('normalizes email', async () => {
    const d = deps();
    await login(d, input);
    const r = await login(d, { ...input, email: '  Alice@X.ORG ' });
    expect(r.status === 'ok' && r.isNew).toBe(false);
    expect(d.discover).toHaveBeenCalledTimes(1);
  });

  it('signs in an existing user with stored settings and refreshes the password', async () => {
    const d = deps({ verifyImap: vi.fn(async () => 'ok' as VerifyResult) });
    const first = await login(d, input);
    if (first.status !== 'ok') throw new Error('expected ok');
    setNeedsReauth(d.db, first.user.id, true);
    const second = await login(d, { ...input, password: 'new-app-password' });
    expect(second.status).toBe('ok');
    const user = findUserById(d.db, first.user.id)!;
    expect(user.needsReauth).toBe(false);
    expect(decryptSecret(TEST_KEY, user.imapPasswordEnc)).toBe('new-app-password');
    expect(d.discover).toHaveBeenCalledTimes(1);
  });

  it('rejects a wrong password with a generic message', async () => {
    const d = deps();
    const r = await login(d, { ...input, password: 'wrong' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Email or password incorrect/) });
    expect(findUserByEmail(d.db, 'alice@x.org')).toBeUndefined();
  });

  it('rate limits after 5 failures for an email', async () => {
    const d = deps();
    for (let i = 0; i < 5; i++) await login(d, { ...input, password: 'wrong', ip: `10.0.0.${i}` });
    const r = await login(d, { ...input, ip: '9.9.9.9' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Too many/) });
    expect(d.verifyImap).toHaveBeenCalledTimes(5);
  });

  it('rate limits after 10 failures from one IP', async () => {
    const d = deps();
    for (let i = 0; i < 10; i++) await login(d, { ...input, email: `u${i}@x.org`, password: 'wrong' });
    const r = await login(d, { ...input, email: 'fresh@x.org' });
    expect(r.status).toBe('error');
  });

  it('counts IPv6 addresses in the same /64 as one client', async () => {
    const d = deps();
    for (let i = 0; i < 10; i++) {
      await login(d, { ...input, email: `u${i}@x.org`, password: 'wrong', ip: `2001:db8:1:2::${i + 1}` });
    }
    const r = await login(d, { ...input, email: 'fresh@x.org', ip: '2001:db8:1:2::ffff' });
    expect(r.status).toBe('error');
  });

  it('keeps separate counts for different IPv6 /64 ranges', async () => {
    const d = deps();
    for (let i = 0; i < 10; i++) {
      await login(d, { ...input, email: `u${i}@x.org`, password: 'wrong', ip: `2001:db8:1:2::${i + 1}` });
    }
    const r = await login(d, { ...input, email: 'fresh@x.org', ip: '2001:db8:9:9::1' });
    expect(r.status).toBe('ok');
  });

  it('asks for manual settings when discovery finds nothing, then uses a listed server', async () => {
    const d = deps({ discover: vi.fn(async () => null), config: testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org' }) });
    expect((await login(d, input)).status).toBe('needs_settings');
    const r = await login(d, { ...input, manual: { ...settings, imapHost: 'mail.custom.org', smtpHost: 'mail.custom.org' } });
    expect(r.status === 'ok' && r.user).toMatchObject({ imapHost: 'mail.custom.org', settingsSource: 'manual' });
  });

  it('refuses hand-entered settings that send the password to an unlisted SMTP server', async () => {
    const d = deps({ discover: vi.fn(async () => null), config: testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org' }) });
    const r = await login(d, { ...input, manual: { ...settings, imapHost: 'mail.custom.org', smtpHost: 'smtp.attacker.net' } });
    expect(r).toMatchObject({ status: 'error', message: expect.stringContaining('SMTP') });
    expect(findUserByEmail(d.db, input.email)).toBeUndefined();
    const listed = deps({ discover: vi.fn(async () => null), config: testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org,smtp.custom.org' }) });
    const ok = await login(listed, { ...input, manual: { ...settings, imapHost: 'mail.custom.org', smtpHost: 'SMTP.custom.org' } });
    expect(ok.status).toBe('ok');
  });

  it('refuses hand-entered settings for a server the administrator has not listed', async () => {
    // Otherwise whoever signs in first with an address decides which server receives its owner's password.
    const d = deps({ discover: vi.fn(async () => null), config: testConfig({ ALLOWED_IMAP_HOSTS: '*' }) });
    const manual = { ...settings, imapHost: 'imap.attacker.net', smtpHost: 'smtp.attacker.net' };
    const r = await login(d, { ...input, email: 'ceo@custom.org', manual });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/ALLOWED_IMAP_HOSTS/) });
    expect(d.verifyImap).not.toHaveBeenCalled();
    expect(findUserByEmail(d.db, 'ceo@custom.org')).toBeUndefined();
  });

  it('does not offer the settings form when no hand-entered server could be accepted', async () => {
    const d = deps({ discover: vi.fn(async () => null), config: testConfig({ ALLOWED_IMAP_HOSTS: '*' }) });
    expect(await login(d, input)).toEqual({ status: 'error', message: expect.stringMatching(/ALLOWED_IMAP_HOSTS/) });
  });

  it('refuses to sign in to a hand-entered account whose server is not listed', async () => {
    const d = deps();
    createTestUser(d.db, { email: input.email, imapHost: 'imap.attacker.net', settingsSource: 'manual' });
    const r = await login(d, input);
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/ALLOWED_IMAP_HOSTS/) });
    expect(d.verifyImap).not.toHaveBeenCalled();
  });

  it('confirms a legacy account whose server matches discovery', async () => {
    const d = deps();
    const legacy = createTestUser(d.db, { email: input.email, imapHost: 'imap.x.org', settingsSource: 'legacy' });
    const r = await login(d, input);
    expect(r.status).toBe('ok');
    expect(d.verifyImap).toHaveBeenCalledWith(expect.objectContaining({ imapHost: 'imap.x.org' }), 'right');
    expect(findUserById(d.db, legacy.id)!.settingsSource).toBe('discovered');
  });

  it('refuses a legacy account whose server does not match discovery', async () => {
    for (const discovered of [settings, null]) {
      const d = deps({ discover: vi.fn(async () => discovered) });
      const legacy = createTestUser(d.db, { email: input.email, imapHost: 'imap.attacker.net', settingsSource: 'legacy' });
      const r = await login(d, input);
      expect(r).toEqual({ status: 'error', message: expect.stringMatching(/ALLOWED_IMAP_HOSTS/) });
      expect(d.verifyImap).not.toHaveBeenCalled();
      expect(findUserById(d.db, legacy.id)!.settingsSource).toBe('legacy');
    }
  });

  it('asks to retry when a legacy account cannot be confirmed because discovery failed', async () => {
    const d = deps({ discover: vi.fn(async () => { throw new DiscoveryUnavailableError(); }) });
    createTestUser(d.db, { email: input.email, imapHost: 'imap.x.org', settingsSource: 'legacy' });
    expect(await login(d, input)).toEqual({ status: 'error', message: expect.stringMatching(/try again/) });
    expect(d.verifyImap).not.toHaveBeenCalled();
  });

  it('refuses manual settings when the lookup failed and asks to retry', async () => {
    const d = deps({ discover: vi.fn(async () => { throw new DiscoveryUnavailableError(); }) });
    const manual = { ...settings, imapHost: 'imap.attacker.net', smtpHost: 'smtp.attacker.net' };
    const r = await login(d, { ...input, manual });
    expect(r).toEqual({
      status: 'error',
      message: "We couldn't look up your mail server settings right now. Please try again in a few minutes.",
    });
    expect(d.verifyImap).not.toHaveBeenCalled();
    expect(d.guard).not.toHaveBeenCalled();
    expect(findUserByEmail(d.db, 'alice@x.org')).toBeUndefined();
  });

  it('does not run discovery for a rate-limited email', async () => {
    const d = deps();
    for (let i = 0; i < 5; i++) await login(d, { ...input, password: 'wrong', ip: `10.0.0.${i}` });
    expect(d.discover).toHaveBeenCalledTimes(5);
    const r = await login(d, { ...input, ip: '9.9.9.9' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Too many/) });
    expect(d.discover).toHaveBeenCalledTimes(5);
  });

  it('counts discovery lookups per IPv6 /64, not per address', async () => {
    const d = deps({ verifyImap: vi.fn(async () => 'ok' as VerifyResult) });
    for (let i = 0; i < 20; i++) {
      await login(d, { ...input, email: `u${i}@x.org`, ip: `2001:db8:5:5::${i + 1}` });
    }
    expect(d.discover).toHaveBeenCalledTimes(20);
    await login(d, { ...input, email: 'fresh@x.org', ip: '2001:db8:5:5::ffff' });
    expect(d.discover).toHaveBeenCalledTimes(20);
  });

  it('does not run discovery for a rate-limited IP', async () => {
    const d = deps();
    for (let i = 0; i < 10; i++) await login(d, { ...input, email: `u${i}@x.org`, password: 'wrong' });
    expect(d.discover).toHaveBeenCalledTimes(10);
    const r = await login(d, { ...input, email: 'fresh@x.org' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Too many/) });
    expect(d.discover).toHaveBeenCalledTimes(10);
  });

  it('limits new-user discoveries to 20 per IP per 15 minutes', async () => {
    let now = 1_000_000;
    const d = deps({ now: () => now });
    for (let i = 0; i < 20; i++) {
      expect((await login(d, { ...input, email: `new${i}@x.org` })).status).toBe('ok');
    }
    const r = await login(d, { ...input, email: 'new20@x.org' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Too many/) });
    expect(d.discover).toHaveBeenCalledTimes(20);
    expect(findUserByEmail(d.db, 'new20@x.org')).toBeUndefined();

    // Other IPs, existing users and a later window are unaffected.
    expect((await login(d, { ...input, email: 'new20@x.org', ip: '5.6.7.8' })).status).toBe('ok');
    expect((await login(d, { ...input, email: 'new0@x.org' })).status).toBe('ok');
    now += 15 * 60 * 1000 + 1;
    expect((await login(d, { ...input, email: 'new21@x.org' })).status).toBe('ok');
    expect(d.discover).toHaveBeenCalledTimes(22);
  });

  it('manual settings are ignored when discovery succeeds', async () => {
    const discovered = { ...settings, imapHost: 'imap.example.com', smtpHost: 'smtp.example.com' };
    const d = deps({ discover: vi.fn(async () => discovered) });
    const manual = { ...settings, imapHost: 'imap.attacker.net', smtpHost: 'smtp.attacker.net' };
    const r = await login(d, { ...input, manual });
    expect(r.status).toBe('ok');
    if (r.status !== 'ok') return;
    expect(d.discover).toHaveBeenCalledWith('alice@x.org');
    expect(d.verifyImap).toHaveBeenCalledWith(expect.objectContaining({ imapHost: 'imap.example.com' }), 'right');
    expect(d.guard).toHaveBeenCalledWith('alice@x.org', discovered);
    expect(r.user).toMatchObject({ imapHost: 'imap.example.com', smtpHost: 'smtp.example.com' });
  });

  it('verifies the password against the address the guard vetted', async () => {
    const d = deps({ guard: vi.fn(async () => ({ imap: '93.184.216.34' })) });
    await login(d, input);
    expect(d.verifyImap).toHaveBeenCalledWith(expect.objectContaining({ imapHost: 'imap.x.org', connectAddress: '93.184.216.34' }), 'right');
  });

  it('returns guard errors to the user', async () => {
    const d = deps({ guard: vi.fn(async () => { throw new GuardError('This mail server is not allowed on this instance.'); }) });
    expect(await login(d, input)).toEqual({ status: 'error', message: 'This mail server is not allowed on this instance.' });
    expect(d.verifyImap).not.toHaveBeenCalled();
  });

  it('reports unreachable servers without counting a failure', async () => {
    const d = deps({ verifyImap: vi.fn(async () => 'unavailable' as VerifyResult) });
    const r = await login(d, input);
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/reach/) });
  });

  it('validates input', async () => {
    expect((await login(deps(), { ...input, email: 'nope' })).status).toBe('error');
    expect((await login(deps(), { ...input, password: '' })).status).toBe('error');
  });

  it('existing user ignores manual settings', async () => {
    const d = deps({ verifyImap: vi.fn(async () => 'ok' as VerifyResult) });
    const first = await login(d, input);
    if (first.status !== 'ok') throw new Error('expected ok');

    const evilSettings = { ...settings, imapHost: 'evil.org', smtpHost: 'evil.org' };
    const second = await login(d, { ...input, manual: evilSettings, password: 'right' });

    expect(second.status).toBe('ok');
    if (second.status !== 'ok') return;
    expect(second.user.imapHost).toBe('imap.x.org');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lastCall = (d.verifyImap as any).mock.calls[(d.verifyImap as any).mock.calls.length - 1];
    expect(lastCall[0].imapHost).toBe('imap.x.org');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lastGuardCall = (d.guard as any).mock.calls[(d.guard as any).mock.calls.length - 1];
    expect(lastGuardCall[1].imapHost).toBe('imap.x.org');
  });

  it('rate limits are not bypassed by concurrent requests', async () => {
    const d = deps({
      verifyImap: vi.fn(async () => {
        await new Promise(r => setTimeout(r, 20));
        return 'bad_credentials' as VerifyResult;
      }),
    });

    const calls = [];
    for (let i = 0; i < 6; i++) {
      calls.push(login(d, { ...input, password: 'wrong' }));
    }
    const results = await Promise.all(calls);

    const errorCount = results.filter(r => r.status === 'error' && /Too many/.test(r.message)).length;
    expect(errorCount).toBeGreaterThanOrEqual(1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((d.verifyImap as any).mock.calls.length).toBeLessThanOrEqual(5);
  });

  it('unavailable errors do not count as login failures', async () => {
    let callCount = 0;
    const d = deps({
      verifyImap: vi.fn(async () => {
        callCount++;
        if (callCount <= 6) return 'unavailable' as VerifyResult;
        return 'ok' as VerifyResult;
      }),
    });

    for (let i = 0; i < 6; i++) {
      const r = await login(d, { ...input, ip: `10.0.0.${i}` });
      expect(r.status).toBe('error');
    }

    const goodResult = await login(d, { ...input, password: 'right', ip: '9.9.9.9' });
    expect(goodResult.status).toBe('ok');
  });

  it('rate limits IP after 10 bad attempts and rejects 11th without verifying', async () => {
    const d = deps();
    for (let i = 0; i < 10; i++) {
      await login(d, { ...input, email: `u${i}@x.org`, password: 'wrong' });
    }

    const r = await login(d, { ...input, email: 'u11@x.org' });
    expect(r).toEqual({ status: 'error', message: expect.stringMatching(/Too many/) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((d.verifyImap as any).mock.calls.length).toBe(10);
  });
});
