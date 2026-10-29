import { afterEach, describe, expect, it, vi } from 'vitest';
import { login, type LoginDeps } from '../../src/auth/login.js';
import { audit } from '../../src/log.js';
import type { VerifyResult } from '../../src/mail/imap.js';
import type { MailServerSettings } from '../../src/types.js';
import { testConfig } from '../helpers/config.js';
import { testDb } from '../helpers/db.js';

function captureLines(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((line: string) => void lines.push(line));
  return { lines, restore: () => spy.mockRestore() };
}

afterEach(() => vi.restoreAllMocks());

describe('audit', () => {
  it('writes one JSON line naming the event and the user', () => {
    const { lines, restore } = captureLines();
    audit('sign_in', { userId: 7, email: 'alice@x.org' });
    restore();

    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ level: 'info', msg: 'audit', event: 'sign_in', userId: 7, email: 'alice@x.org' });
  });

  it('carries a timestamp, so events can be put in order after an incident', () => {
    const { lines, restore } = captureLines();
    audit('send_email', { userId: 1 });
    restore();

    expect(Date.parse(JSON.parse(lines[0]).time as string)).not.toBeNaN();
  });
});

describe('audited events', () => {
  const settings: MailServerSettings = {
    imapHost: 'imap.x.org', imapPort: 993, imapSecurity: 'tls',
    smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
  };

  function loginDeps(): LoginDeps {
    return {
      db: testDb(),
      config: testConfig(),
      discover: vi.fn(async () => settings),
      verifyImap: vi.fn(async () => 'ok' as VerifyResult),
      guard: vi.fn(async () => undefined),
      now: () => 1_000_000,
    };
  }

  function auditEvents(lines: string[]): Record<string, unknown>[] {
    return lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((e) => e.msg === 'audit');
  }

  it('records a successful sign-in', async () => {
    const deps = loginDeps();
    const { lines, restore } = captureLines();
    await login(deps, { email: 'alice@x.org', password: 'pw', ip: '1.2.3.4' });
    restore();

    expect(auditEvents(lines)).toEqual([expect.objectContaining({ event: 'sign_in', email: 'alice@x.org' })]);
  });

  it('records that connected apps were revoked when the password changed', async () => {
    const deps = loginDeps();
    await login(deps, { email: 'alice@x.org', password: 'pw', ip: '1.2.3.4' });
    const { lines, restore } = captureLines();
    await login(deps, { email: 'alice@x.org', password: 'a-different-password', ip: '1.2.3.4' });
    restore();

    expect(auditEvents(lines)).toContainEqual(expect.objectContaining({ event: 'grants_revoked', reason: 'password_changed' }));
  });

  it('does not record the password anywhere in the line', async () => {
    const deps = loginDeps();
    const { lines, restore } = captureLines();
    await login(deps, { email: 'alice@x.org', password: 'super-secret-pw', ip: '1.2.3.4' });
    restore();

    expect(lines.join('\n')).not.toContain('super-secret-pw');
  });
});

describe('audited refusals', () => {
  const settings: MailServerSettings = {
    imapHost: 'imap.x.org', imapPort: 993, imapSecurity: 'tls',
    smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
  };

  it('records a sign-in that was refused, so a blocked attempt is visible', async () => {
    const deps: LoginDeps = {
      db: testDb(),
      config: testConfig(),
      discover: vi.fn(async (): Promise<MailServerSettings | null> => settings),
      verifyImap: vi.fn(async () => 'bad_credentials' as VerifyResult),
      guard: vi.fn(async () => undefined),
      now: () => 1_000_000,
    };
    const { lines, restore } = captureLines();
    await login(deps, { email: 'alice@x.org', password: 'wrong', ip: '1.2.3.4' });
    restore();

    const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((e) => e.msg === 'audit');
    expect(events).toContainEqual(expect.objectContaining({ event: 'sign_in_failed', reason: 'bad_credentials' }));
  });
});
