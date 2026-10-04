import { describe, expect, it, vi } from 'vitest';
import { decryptSecret } from '../../src/crypto.js';
import { findUserByEmail, findUserById, setNeedsReauth } from '../../src/db/users.js';
import { login, type LoginDeps } from '../../src/auth/login.js';
import { GuardError } from '../../src/guard.js';
import type { MailServerSettings } from '../../src/types.js';
import type { VerifyResult } from '../../src/mail/imap.js';
import { TEST_KEY, testConfig } from '../helpers/config.js';
import { testDb } from '../helpers/db.js';

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
    expect(r.user).toMatchObject({ email: 'alice@x.org', imapHost: 'imap.x.org', smtpUsername: 'alice@x.org', permissionLevel: 'draft' });
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

  it('asks for manual settings when discovery fails, then uses them', async () => {
    const d = deps({ discover: vi.fn(async () => null) });
    expect((await login(d, input)).status).toBe('needs_settings');
    const r = await login(d, { ...input, manual: { ...settings, imapHost: 'mail.custom.org' } });
    expect(r.status === 'ok' && r.user.imapHost).toBe('mail.custom.org');
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
