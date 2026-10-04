import { describe, expect, it } from 'vitest';
import { GuardError, guardMailSettings, isEmailOrHostAllowed, isPublicAddress } from '../../src/guard.js';
import type { MailServerSettings } from '../../src/types.js';
import { testConfig } from '../helpers/config.js';

const settings: MailServerSettings = {
  imapHost: 'imap.example.com', imapPort: 993, imapSecurity: 'tls',
  smtpHost: 'smtp.example.com', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
};
const publicLookup = async () => [{ address: '93.184.216.34' }];

describe('isEmailOrHostAllowed', () => {
  it('matches domains, hosts, and wildcard', () => {
    const byDomain = testConfig({ ALLOWED_IMAP_HOSTS: undefined, ALLOWED_EMAIL_DOMAINS: 'example.com' });
    expect(isEmailOrHostAllowed(byDomain, 'a@example.com', 'imap.other.net')).toBe(true);
    expect(isEmailOrHostAllowed(byDomain, 'a@sub.example.com', 'imap.other.net')).toBe(false);
    const byHost = testConfig({ ALLOWED_IMAP_HOSTS: 'imap.gmail.com' });
    expect(isEmailOrHostAllowed(byHost, 'a@x.org', 'IMAP.gmail.com')).toBe(true);
    expect(isEmailOrHostAllowed(byHost, 'a@x.org', 'imap.x.org')).toBe(false);
    expect(isEmailOrHostAllowed(testConfig(), 'a@x.org', 'anything')).toBe(true);
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
  it('passes for allowed public hosts', async () => {
    await expect(guardMailSettings(testConfig(), 'a@example.com', settings, publicLookup)).resolves.toBeUndefined();
  });

  it('rejects hosts not on the allowlist', async () => {
    const c = testConfig({ ALLOWED_IMAP_HOSTS: 'imap.gmail.com' });
    await expect(guardMailSettings(c, 'a@example.com', settings, publicLookup)).rejects.toThrow(/not allowed/);
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
    await expect(guardMailSettings(lan, 'a@example.com', plain, privateLookup)).resolves.toBeUndefined();
  });
});
