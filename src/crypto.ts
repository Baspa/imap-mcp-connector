import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const VERSION = 'v1';

export class DecryptError extends Error {
  override name = 'DecryptError';
}

export function encryptSecret(key: Buffer, plaintext: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, nonce.toString('base64'), ciphertext.toString('base64'), tag.toString('base64')].join(':');
}

export function decryptSecret(key: Buffer, value: string): string {
  const parts = value.split(':');
  if (parts.length !== 4 || parts[0] !== VERSION) throw new DecryptError('Unsupported secret format');
  const [, nonce, ciphertext, tag] = parts;
  try {
    const nonceBuffer = Buffer.from(nonce, 'base64');
    const tagBuffer = Buffer.from(tag, 'base64');

    if (nonceBuffer.length !== 12) throw new DecryptError('Invalid nonce length');
    if (tagBuffer.length !== 16) throw new DecryptError('Invalid auth tag length');

    const decipher = createDecipheriv('aes-256-gcm', key, nonceBuffer, { authTagLength: 16 });
    decipher.setAuthTag(tagBuffer);
    return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]).toString('utf8');
  } catch (error) {
    if (error instanceof DecryptError) throw error;
    throw new DecryptError('Secret could not be decrypted');
  }
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
