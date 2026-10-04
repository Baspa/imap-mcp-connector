import request from 'supertest';
import { createApp, type AppDeps } from '../../src/app.js';
import { SqliteOAuthProvider } from '../../src/auth/oauth-provider.js';
import { signInUrl } from '../../src/config.js';
import { MailPool } from '../../src/mail/pool.js';
import { defaultSmtpFactory } from '../../src/mail/smtp.js';
import { testConfig } from './config.js';
import { testDb } from './db.js';

export function testApp(overrides: Partial<AppDeps> = {}, env: Record<string, string | undefined> = {}) {
  const config = testConfig(env);
  const db = testDb();
  const deps: AppDeps = {
    config,
    db,
    pool: new MailPool({ db, key: config.encryptionKey, signInUrl: signInUrl(config) }),
    provider: new SqliteOAuthProvider(db),
    smtpFactory: defaultSmtpFactory,
    discover: async () => ({
      imapHost: 'imap.x.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false,
    }),
    verifyImap: async (_target, password) => (password === 'right' ? 'ok' : 'bad_credentials'),
    guard: async () => undefined,
    ...overrides,
  };
  return { app: createApp(deps), deps };
}

export type Agent = ReturnType<typeof request.agent>;

export function csrfFrom(html: string): string {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  if (!match) throw new Error('No CSRF token in page');
  return match[1];
}

export async function signIn(agent: Agent, email = 'alice@x.org', next?: string) {
  const page = await agent.get(next ? `/login?next=${encodeURIComponent(next)}` : '/login');
  return agent
    .post('/login')
    .type('form')
    .send({ _csrf: csrfFrom(page.text), email, password: 'right', next: next ?? '' });
}
