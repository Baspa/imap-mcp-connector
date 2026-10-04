import { ImapFlow } from 'imapflow';
import type { Security } from '../types.js';
import { toMailError } from './errors.js';

export interface ImapTarget {
  email: string;
  imapHost: string;
  imapPort: number;
  imapSecurity: Security;
}

export type ImapFactory = (target: ImapTarget, password: string) => ImapFlow;

export function imapSecurityOptions(security: Security): { secure: boolean; doSTARTTLS?: boolean } {
  if (security === 'tls') return { secure: true };
  if (security === 'starttls') return { secure: false, doSTARTTLS: true };
  return { secure: false, doSTARTTLS: false };
}

export const defaultImapFactory: ImapFactory = (target, password) =>
  new ImapFlow({
    host: target.imapHost,
    port: target.imapPort,
    ...imapSecurityOptions(target.imapSecurity),
    auth: { user: target.email, pass: password },
    logger: false,
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 60_000,
  });

export type VerifyResult = 'ok' | 'bad_credentials' | 'unavailable';

export async function verifyImapLogin(
  target: ImapTarget,
  password: string,
  factory: ImapFactory = defaultImapFactory,
): Promise<VerifyResult> {
  const client = factory(target, password);
  client.on('error', () => undefined);
  try {
    await client.connect();
    await client.logout();
    return 'ok';
  } catch (err) {
    return toMailError(err)?.code === 'AUTH_FAILED' ? 'bad_credentials' : 'unavailable';
  } finally {
    client.close();
  }
}
