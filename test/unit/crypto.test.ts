import { describe, expect, it } from 'vitest';
import { DecryptError, decryptSecret, encryptSecret, hashToken, randomToken } from '../../src/crypto.js';
import { TEST_KEY } from '../helpers/config.js';

describe('encryptSecret / decryptSecret', () => {
  it('round-trips unicode secrets', () => {
    const enc = encryptSecret(TEST_KEY, 'pässwörd-🔑');
    expect(enc.startsWith('v1:')).toBe(true);
    expect(decryptSecret(TEST_KEY, enc)).toBe('pässwörd-🔑');
  });

  it('produces a different ciphertext each time', () => {
    expect(encryptSecret(TEST_KEY, 'same')).not.toBe(encryptSecret(TEST_KEY, 'same'));
  });

  it('detects tampering', () => {
    const [v, n, c, t] = encryptSecret(TEST_KEY, 'secret').split(':');
    const flipped = Buffer.from(c, 'base64');
    flipped[0] ^= 1;
    expect(() => decryptSecret(TEST_KEY, [v, n, flipped.toString('base64'), t].join(':'))).toThrow(DecryptError);
  });

  it('fails with the wrong key', () => {
    const enc = encryptSecret(TEST_KEY, 'secret');
    expect(() => decryptSecret(Buffer.alloc(32, 9), enc)).toThrow(DecryptError);
  });

  it('rejects unknown versions and malformed values', () => {
    expect(() => decryptSecret(TEST_KEY, 'v2:a:b:c')).toThrow(DecryptError);
    expect(() => decryptSecret(TEST_KEY, 'garbage')).toThrow(DecryptError);
  });
});

describe('hashToken / randomToken', () => {
  it('hashes deterministically to 64 hex chars', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken('abc')).not.toBe(hashToken('abd'));
  });

  it('creates unique url-safe tokens', () => {
    const a = randomToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken()).not.toBe(a);
    expect(randomToken(16)).toHaveLength(22);
  });
});
