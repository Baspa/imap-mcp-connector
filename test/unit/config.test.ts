import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, mcpUrl, signInUrl } from '../../src/config.js';
import { TEST_KEY, testEnv } from '../helpers/config.js';

describe('loadConfig', () => {
  it('parses ALLOWED_RECIPIENT_DOMAINS as a lowercased comma list', () => {
    const c = loadConfig(testEnv({ ALLOWED_RECIPIENT_DOMAINS: ' Example.com, Partner.org ,' }));
    expect(c.allowedRecipientDomains).toEqual(['example.com', 'partner.org']);
  });

  it('loads a valid environment with defaults', () => {
    const c = loadConfig(testEnv());
    expect(c.publicUrl.href).toBe('http://localhost:3000/');
    expect(c.encryptionKey.equals(TEST_KEY)).toBe(true);
    expect(c.allowedImapHosts).toEqual(['*']);
    expect(c.allowedEmailDomains).toEqual([]);
    expect(c.allowPrivateHosts).toBe(false);
    expect(c.defaultSendLimitPerHour).toBe(20);
    expect(c.allowedRecipientDomains).toEqual([]);
    expect(c.dataDir).toBe('/data');
    expect(c.port).toBe(3000);
    expect(c.isProduction).toBe(false);
  });

  it('parses comma lists, lowercases and trims them', () => {
    const c = loadConfig(testEnv({ ALLOWED_IMAP_HOSTS: undefined, ALLOWED_EMAIL_DOMAINS: ' Example.com, b.org ,' }));
    expect(c.allowedEmailDomains).toEqual(['example.com', 'b.org']);
  });

  it('requires PUBLIC_URL', () => {
    expect(() => loadConfig(testEnv({ PUBLIC_URL: undefined }))).toThrow(ConfigError);
  });

  it('rejects http PUBLIC_URL in production but allows it in development', () => {
    expect(() => loadConfig(testEnv({ NODE_ENV: 'production' }))).toThrow(/https/);
    expect(loadConfig(testEnv({ NODE_ENV: 'development' })).isProduction).toBe(false);
    expect(loadConfig(testEnv({ NODE_ENV: 'production', PUBLIC_URL: 'https://mail.example.com' })).isProduction).toBe(true);
  });

  it('rejects a PUBLIC_URL with a path', () => {
    expect(() => loadConfig(testEnv({ PUBLIC_URL: 'http://localhost:3000/mail' }))).toThrow(/path/);
  });

  it('rejects an encryption key that is not 32 bytes', () => {
    expect(() => loadConfig(testEnv({ ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') }))).toThrow(/32 bytes/);
    expect(() => loadConfig(testEnv({ ENCRYPTION_KEY: undefined }))).toThrow(ConfigError);
  });

  it('requires a session secret of at least 32 chars', () => {
    expect(() => loadConfig(testEnv({ SESSION_SECRET: 'short' }))).toThrow(/SESSION_SECRET/);
  });

  it('requires an allowlist', () => {
    expect(() => loadConfig(testEnv({ ALLOWED_IMAP_HOSTS: undefined }))).toThrow(/ALLOWED_/);
  });

  it('parses ALLOW_PRIVATE_HOSTS, limits and port', () => {
    const c = loadConfig(testEnv({ ALLOW_PRIVATE_HOSTS: 'true', DEFAULT_SEND_LIMIT_PER_HOUR: '5', PORT: '8080', DATA_DIR: './data' }));
    expect(c.allowPrivateHosts).toBe(true);
    expect(c.defaultSendLimitPerHour).toBe(5);
    expect(c.port).toBe(8080);
    expect(c.dataDir).toBe('./data');
    expect(() => loadConfig(testEnv({ DEFAULT_SEND_LIMIT_PER_HOUR: '0' }))).toThrow(/positive integer/);
  });

  it('builds the MCP and sign-in URLs', () => {
    const c = loadConfig(testEnv({ NODE_ENV: 'production', PUBLIC_URL: 'https://mail.example.com/' }));
    expect(mcpUrl(c).href).toBe('https://mail.example.com/mcp');
    expect(signInUrl(c)).toBe('https://mail.example.com/login');
  });
});
