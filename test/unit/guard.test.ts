import { describe, expect, it } from 'vitest';
import {
  GuardError, guardMailSettings, guardStoredUser, isAllowed, isListedImapHost, isPublicAddress, isTrustedServer,
} from '../../src/guard.js';
import { createTestUser, testDb } from '../helpers/db.js';
import type { MailServerSettings } from '../../src/types.js';
import { testConfig } from '../helpers/config.js';

const settings: MailServerSettings = {
  imapHost: 'imap.example.com', imapPort: 993, imapSecurity: 'tls',
  smtpHost: 'smtp.example.com', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
};
const publicLookup = async () => [{ address: '93.184.216.34' }];

describe('isAllowed', () => {
  it('only domains set: any host for an allowed domain, other domains rejected', () => {
    const byDomain = testConfig({ ALLOWED_IMAP_HOSTS: undefined, ALLOWED_EMAIL_DOMAINS: 'example.com' });
    expect(isAllowed(byDomain, 'a@example.com', 'imap.other.net')).toBe(true);
    expect(isAllowed(byDomain, 'a@sub.example.com', 'imap.other.net')).toBe(false);
    expect(isAllowed(byDomain, 'a@x.org', 'imap.x.org')).toBe(false);
  });

  it('only hosts set: listed hosts for any domain, case-insensitively', () => {
    const byHost = testConfig({ ALLOWED_IMAP_HOSTS: 'imap.gmail.com' });
    expect(isAllowed(byHost, 'a@x.org', 'IMAP.gmail.com')).toBe(true);
    expect(isAllowed(byHost, 'a@x.org', 'imap.x.org')).toBe(false);
  });

  it('only hosts=*: any host for any domain', () => {
    expect(isAllowed(testConfig(), 'a@x.org', 'anything')).toBe(true);
  });

  it('both set: the domain AND the host must match', () => {
    const both = testConfig({ ALLOWED_EMAIL_DOMAINS: 'example.com', ALLOWED_IMAP_HOSTS: 'imap.example.com' });
    expect(isAllowed(both, 'a@example.com', 'imap.example.com')).toBe(true);
    expect(isAllowed(both, 'a@example.com', 'imap.attacker.net')).toBe(false);
    expect(isAllowed(both, 'a@x.org', 'imap.example.com')).toBe(false);
  });

  it('both set with hosts=*: the domain must match, any host', () => {
    const c = testConfig({ ALLOWED_EMAIL_DOMAINS: 'example.com', ALLOWED_IMAP_HOSTS: '*' });
    expect(isAllowed(c, 'a@example.com', 'imap.anything.net')).toBe(true);
    expect(isAllowed(c, 'a@x.org', 'imap.anything.net')).toBe(false);
  });
});

describe('isPublicAddress', () => {
  it.each([
    ['93.184.216.34', true],
    ['2606:2800:220:1:248:1893:25c8:1946', true],
    ['127.0.0.1', false],
    ['10.0.0.5', false],
    ['192.168.1.1', false],
    ['172.16.0.1', false],
    ['169.254.169.254', false],
    ['100.64.0.1', false],
    ['0.0.0.0', false],
    ['::1', false],
    ['fd00::1', false],
    ['fe80::1', false],
    ['::ffff:127.0.0.1', false],
    ['::ffff:93.184.216.34', true],
  ])('%s → %s', (addr, expected) => {
    expect(isPublicAddress(addr)).toBe(expected);
  });
});

describe('guardMailSettings', () => {
  it('returns the vetted addresses so connections cannot be re-pointed by a later DNS answer', async () => {
    const lookup = async (h: string) => [{ address: h === 'imap.example.com' ? '93.184.216.34' : '93.184.216.35' }];
    await expect(guardMailSettings(testConfig(), 'a@example.com', settings, lookup)).resolves.toEqual({
      imap: '93.184.216.34', smtp: '93.184.216.35',
    });
  });

  it('pins an IPv4 address when the host has both, since containers often lack IPv6', async () => {
    const lookup = async () => [{ address: '2606:2800:220:1:248:1893:25c8:1946' }, { address: '93.184.216.34' }];
    await expect(guardMailSettings(testConfig(), 'a@example.com', settings, lookup)).resolves.toMatchObject({ imap: '93.184.216.34' });
  });

  it('rejects hosts not on the allowlist', async () => {
    const c = testConfig({ ALLOWED_IMAP_HOSTS: 'imap.gmail.com' });
    await expect(guardMailSettings(c, 'a@example.com', settings, publicLookup)).rejects.toThrow(/not allowed/);
  });

  it('rejects an allowed domain whose host is not in ALLOWED_IMAP_HOSTS', async () => {
    const c = testConfig({ ALLOWED_EMAIL_DOMAINS: 'example.com', ALLOWED_IMAP_HOSTS: 'imap.example.com' });
    const attacker = { ...settings, imapHost: 'imap.attacker.net' };
    await expect(guardMailSettings(c, 'a@example.com', attacker, publicLookup)).rejects.toThrow(/not allowed/);
    await expect(guardMailSettings(c, 'a@example.com', settings, publicLookup)).resolves.toBeDefined();
  });

  it('rejects hosts resolving to private addresses', async () => {
    const lookup = async (h: string) => [{ address: h === 'smtp.example.com' ? '10.1.1.1' : '93.184.216.34' }];
    await expect(guardMailSettings(testConfig(), 'a@example.com', settings, lookup)).rejects.toThrow(GuardError);
  });

  it('rejects unresolvable hosts', async () => {
    const lookup = async () => { throw new Error('ENOTFOUND'); };
    await expect(guardMailSettings(testConfig(), 'a@example.com', settings, lookup)).rejects.toThrow(/resolve/);
  });

  it('rejects unencrypted connections unless private hosts are allowed', async () => {
    const plain = { ...settings, imapSecurity: 'none' as const };
    await expect(guardMailSettings(testConfig(), 'a@example.com', plain, publicLookup)).rejects.toThrow(/Unencrypted/);
    const lan = testConfig({ ALLOW_PRIVATE_HOSTS: 'true' });
    const privateLookup = async () => [{ address: '127.0.0.1' }];
    // Private hosts are allowed here, so nothing is resolved or pinned.
    await expect(guardMailSettings(lan, 'a@example.com', plain, privateLookup)).resolves.toEqual({});
  });
});

describe('isListedImapHost', () => {
  it('counts only hosts named in ALLOWED_IMAP_HOSTS, not the * wildcard', () => {
    expect(isListedImapHost(testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org' }), 'MAIL.custom.org')).toBe(true);
    expect(isListedImapHost(testConfig({ ALLOWED_IMAP_HOSTS: '*' }), 'mail.custom.org')).toBe(false);
    expect(isListedImapHost(testConfig({ ALLOWED_IMAP_HOSTS: undefined, ALLOWED_EMAIL_DOMAINS: 'custom.org' }), 'mail.custom.org')).toBe(false);
  });
});

describe('isTrustedServer', () => {
  const open = testConfig({ ALLOWED_IMAP_HOSTS: '*' });

  it('trusts discovered settings', () => {
    expect(isTrustedServer(open, 'a@custom.org', 'imap.anything.net', 'discovered')).toBe(true);
  });

  it('trusts hand-entered settings only for listed hosts', () => {
    expect(isTrustedServer(open, 'a@custom.org', 'imap.attacker.net', 'manual')).toBe(false);
    const listed = testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org' });
    expect(isTrustedServer(listed, 'a@custom.org', 'mail.custom.org', 'manual')).toBe(true);
  });

  it('trusts legacy accounts only when they match a built-in preset or a listed host', () => {
    expect(isTrustedServer(open, 'a@gmail.com', 'imap.gmail.com', 'legacy')).toBe(true);
    expect(isTrustedServer(open, 'a@gmail.com', 'imap.attacker.net', 'legacy')).toBe(false);
    expect(isTrustedServer(open, 'a@custom.org', 'mail.custom.org', 'legacy')).toBe(false);
    const listed = testConfig({ ALLOWED_IMAP_HOSTS: 'mail.custom.org' });
    expect(isTrustedServer(listed, 'a@custom.org', 'mail.custom.org', 'legacy')).toBe(true);
  });
});

describe('guardStoredUser', () => {
  it('refuses to connect for an account whose server is not trusted', async () => {
    const user = createTestUser(testDb(), { email: 'a@custom.org', imapHost: 'imap.attacker.net', settingsSource: 'manual' });
    await expect(guardStoredUser(testConfig(), user, publicLookup)).rejects.toThrow(GuardError);
  });

  it('applies the normal mail settings checks to trusted accounts', async () => {
    const user = createTestUser(testDb(), { email: 'a@example.com', settingsSource: 'discovered' });
    await expect(guardStoredUser(testConfig(), user, publicLookup)).resolves.not.toThrow();
    const c = testConfig({ ALLOWED_IMAP_HOSTS: 'imap.gmail.com' });
    await expect(guardStoredUser(c, user, publicLookup)).rejects.toThrow(/not allowed/);
  });
});
