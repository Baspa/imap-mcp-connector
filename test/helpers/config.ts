import { loadConfig, type Config } from '../../src/config.js';

export const TEST_KEY = Buffer.alloc(32, 7);

export function testEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    PUBLIC_URL: 'http://localhost:3000',
    ENCRYPTION_KEY: TEST_KEY.toString('base64'),
    SESSION_SECRET: 'x'.repeat(32),
    ALLOWED_IMAP_HOSTS: '*',
    ...overrides,
  };
}

export function testConfig(overrides: Record<string, string | undefined> = {}): Config {
  return loadConfig(testEnv(overrides));
}
