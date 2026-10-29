import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { insertClient, insertToken } from '../../src/db/oauth.js';
import { findUserByEmail, setNeedsReauth } from '../../src/db/users.js';
import { GuardError } from '../../src/guard.js';
import type { MailPool } from '../../src/mail/pool.js';
import { csrfFrom, signIn, testApp } from '../helpers/app.js';

describe('web', () => {
  it('serves a health check', async () => {
    const { app } = testApp();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('redirects anonymous users to sign in', async () => {
    const { app } = testApp();
    expect((await request(app).get('/')).headers.location).toBe('/login');
    expect((await request(app).get('/settings')).headers.location).toBe('/login?next=%2Fsettings');
  });

  it('registers on first sign-in and shows settings', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    const res = await signIn(agent);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings?welcome=1');
    expect(res.headers['set-cookie']?.[0]).toMatch(/HttpOnly/i);
    expect(res.headers['set-cookie']?.[0]).toMatch(/SameSite=Lax/i);
    const page = await agent.get('/settings');
    expect(page.status).toBe(200);
    expect(page.text).toContain('alice@x.org');
    expect(page.text).toContain('http://localhost:3000/mcp');
    expect(page.text).toMatch(/value="draft"[^>]*checked/);
    expect(findUserByEmail(deps.db, 'alice@x.org')).toBeDefined();
  });

  it('drops the cached mail connection after sign-in', async () => {
    const close = vi.fn(async () => undefined);
    const { app, deps } = testApp({ pool: { close } as unknown as MailPool });
    const agent = request.agent(app);
    const res = await signIn(agent);
    expect(res.status).toBe(302);
    const user = findUserByEmail(deps.db, 'alice@x.org')!;
    expect(close).toHaveBeenCalledWith(user.id);
  });

  it('shows an error for a wrong password', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    const page = await agent.get('/login');
    const res = await agent.post('/login').type('form').send({ _csrf: csrfFrom(page.text), email: 'a@x.org', password: 'wrong' });
    expect(res.status).toBe(400);
    expect(res.text).toContain('Email or password incorrect');
  });

  it('rejects posts without a valid CSRF token', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    await agent.get('/login');
    const res = await agent.post('/login').type('form').send({ email: 'a@x.org', password: 'right' });
    expect(res.status).toBe(403);
  });

  it('asks for manual server settings when discovery fails', async () => {
    const { app, deps } = testApp({ discover: async () => null }, { ALLOWED_IMAP_HOSTS: 'mail.custom.org' });
    const agent = request.agent(app);
    const page = await agent.get('/login');
    const first = await agent.post('/login').type('form').send({ _csrf: csrfFrom(page.text), email: 'a@custom.org', password: 'right' });
    expect(first.text).toContain('name="imap_host"');
    const second = await agent.post('/login').type('form').send({
      _csrf: csrfFrom(first.text), email: 'a@custom.org', password: 'right',
      imap_host: 'mail.custom.org', imap_port: '993', imap_security: 'tls',
      smtp_host: 'mail.custom.org', smtp_port: '587', smtp_security: 'starttls',
    });
    expect(second.status).toBe(302);
    expect(findUserByEmail(deps.db, 'a@custom.org')).toMatchObject({ imapHost: 'mail.custom.org', smtpPort: 587 });
  });

  it('refuses a non-mail port in manual settings, so the connector cannot be used to probe ports', async () => {
    const { app, deps } = testApp({ discover: async () => null }, { ALLOWED_IMAP_HOSTS: 'mail.custom.org' });
    const agent = request.agent(app);
    const page = await agent.get('/login');
    const first = await agent.post('/login').type('form').send({ _csrf: csrfFrom(page.text), email: 'a@custom.org', password: 'right' });
    const second = await agent.post('/login').type('form').send({
      _csrf: csrfFrom(first.text), email: 'a@custom.org', password: 'right',
      imap_host: 'mail.custom.org', imap_port: '22', imap_security: 'tls',
      smtp_host: 'mail.custom.org', smtp_port: '587', smtp_security: 'starttls',
    });
    expect(second.status).toBe(400);
    expect(findUserByEmail(deps.db, 'a@custom.org')).toBeUndefined();
  });

  it('honors a safe next URL and ignores unsafe ones', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    const csrf = csrfFrom((await agent.get('/settings')).text);
    await agent.post('/logout').type('form').send({ _csrf: csrf });
    expect((await signIn(agent, 'alice@x.org', '/settings?tab=1')).headers.location).toBe('/settings?tab=1');
    const other = request.agent(app);
    expect((await signIn(other, 'alice@x.org', '//evil.example')).headers.location).toBe('/settings');
  });

  it('changes the permission level', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    const csrf = csrfFrom((await agent.get('/settings')).text);
    const res = await agent.post('/settings/permission').type('form').send({ _csrf: csrf, level: 'full' });
    expect(res.headers.location).toBe('/settings?saved=permission');
    expect(findUserByEmail(deps.db, 'alice@x.org')?.permissionLevel).toBe('full');
    expect((await agent.post('/settings/permission').type('form').send({ _csrf: csrf, level: 'root' })).status).toBe(400);
  });

  it('updates SMTP settings and reports guard rejections', async () => {
    let reject = false;
    const { app, deps } = testApp(
      { guard: async () => { if (reject) throw new GuardError('smtp.lan resolves to a private or reserved address'); } },
      { ALLOWED_IMAP_HOSTS: '*,smtp.other.org,smtp.lan' },
    );
    const agent = request.agent(app);
    await signIn(agent);
    const csrf = csrfFrom((await agent.get('/settings')).text);
    const form = { _csrf: csrf, smtp_host: 'smtp.other.org', smtp_port: '587', smtp_security: 'starttls', smtp_username: 'alice', smtp_password: 'smtp-secret' };
    expect((await agent.post('/settings/smtp').type('form').send(form)).headers.location).toBe('/settings?saved=smtp');
    const user = findUserByEmail(deps.db, 'alice@x.org')!;
    expect(user).toMatchObject({ smtpHost: 'smtp.other.org', smtpPort: 587, smtpSecurity: 'starttls', smtpUsername: 'alice' });
    expect(user.smtpPasswordEnc).not.toBeNull();
    reject = true;
    const bad = await agent.post('/settings/smtp').type('form').send({ ...form, smtp_host: 'smtp.lan' });
    expect(bad.status).toBe(400);
    expect(bad.text).toContain('private or reserved');
    reject = false;
    const reset = await agent.post('/settings/smtp').type('form').send({ ...form, use_imap_password: 'on' });
    expect(reset.status).toBe(302);
    expect(findUserByEmail(deps.db, 'alice@x.org')?.smtpPasswordEnc).toBeNull();
  });

  it('refuses an SMTP server that is neither the IMAP host nor listed, but accepts unchanged settings', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    const csrf = csrfFrom((await agent.get('/settings')).text);
    const form = { _csrf: csrf, smtp_host: 'smtp.attacker.net', smtp_port: '587', smtp_security: 'starttls', smtp_username: 'alice', use_imap_password: 'on' };
    const bad = await agent.post('/settings/smtp').type('form').send(form);
    expect(bad.status).toBe(400);
    expect(bad.text).toContain('not allowed on this instance');
    expect(findUserByEmail(deps.db, 'alice@x.org')?.smtpHost).toBe('smtp.x.org');
    const same = await agent.post('/settings/smtp').type('form').send({ ...form, smtp_host: 'SMTP.x.org', smtp_password: 'new-secret', use_imap_password: undefined });
    expect(same.headers.location).toBe('/settings?saved=smtp');
    const imapHost = await agent.post('/settings/smtp').type('form').send({ ...form, smtp_host: 'imap.x.org' });
    expect(imapHost.headers.location).toBe('/settings?saved=smtp');
  });

  it('sends hardening headers, and HSTS only in production', async () => {
    const dev = await request(testApp().app).get('/healthz');
    expect(dev.headers['x-content-type-options']).toBe('nosniff');
    expect(dev.headers['referrer-policy']).toBe('no-referrer');
    expect(dev.headers['x-frame-options']).toBe('DENY');
    expect(dev.headers['strict-transport-security']).toBeUndefined();
    const prod = await request(testApp({}, { NODE_ENV: 'production', PUBLIC_URL: 'https://mail.x.org' }).app).get('/healthz');
    expect(prod.headers['strict-transport-security']).toBe('max-age=31536000');
  });

  it('lists connected apps and revokes them', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    const user = findUserByEmail(deps.db, 'alice@x.org')!;
    insertClient(deps.db, { client_id: 'c1', client_name: 'Claude', redirect_uris: ['https://claude.ai/cb'] } as OAuthClientInformationFull, 1);
    insertToken(deps.db, { tokenHash: 'r', kind: 'refresh', grantId: 'g1', clientId: 'c1', userId: user.id, scopes: [], createdAt: Date.now(), expiresAt: Date.now() + 1e9 });
    const page = await agent.get('/settings');
    expect(page.text).toContain('Claude');
    await agent.post('/settings/revoke').type('form').send({ _csrf: csrfFrom(page.text), grant_id: 'g1' });
    expect((await agent.get('/settings')).text).not.toContain('Claude</');
  });

  it('shows a re-auth banner', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    setNeedsReauth(deps.db, findUserByEmail(deps.db, 'alice@x.org')!.id, true);
    expect((await agent.get('/settings')).text).toContain('Your mail password stopped working');
  });

  it('logs out and deletes the account', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);
    await signIn(agent);
    const csrf = csrfFrom((await agent.get('/settings')).text);
    const res = await agent.post('/settings/delete').type('form').send({ _csrf: csrf });
    expect(res.headers.location).toBe('/login?deleted=1');
    expect(findUserByEmail(deps.db, 'alice@x.org')).toBeUndefined();
    expect((await agent.get('/settings')).status).toBe(302);
  });

  it('ends every session of a deleted account and never reuses its id', async () => {
    const { app, deps } = testApp();
    const a = request.agent(app);
    const b = request.agent(app);
    await signIn(a);
    await signIn(b);
    const user = findUserByEmail(deps.db, 'alice@x.org')!;
    const csrf = csrfFrom((await a.get('/settings')).text);
    await a.post('/settings/delete').type('form').send({ _csrf: csrf });
    const rows = deps.db.prepare("SELECT sid FROM sessions WHERE json_extract(data, '$.userId') = ?").all(user.id);
    expect(rows).toEqual([]);
    const c = request.agent(app);
    await signIn(c, 'mallory@x.org');
    expect(findUserByEmail(deps.db, 'mallory@x.org')!.id).not.toBe(user.id);
    const res = await b.get('/settings');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login?next=%2Fsettings');
  });

  it.each(['/logout', '/settings/permission', '/settings/smtp', '/settings/revoke', '/settings/delete'])(
    'rejects POST %s without a valid CSRF token',
    async (path) => {
      const { app, deps } = testApp();
      const agent = request.agent(app);
      await signIn(agent);
      await agent.get('/settings');
      const missing = await agent.post(path).type('form').send({ level: 'full' });
      expect(missing.status).toBe(403);
      const wrong = await agent.post(path).type('form').send({ _csrf: 'wrong', level: 'full' });
      expect(wrong.status).toBe(403);
      expect(findUserByEmail(deps.db, 'alice@x.org')).toBeDefined();
    },
  );

  it('answers 413 for an oversized form body', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    const page = await agent.get('/login');
    const res = await agent
      .post('/login')
      .type('form')
      .send({ _csrf: csrfFrom(page.text), email: 'a@x.org', password: 'x'.repeat(200_000) });
    expect(res.status).toBe(413);
  });

  it('still signs in when closing the cached mail connection fails', async () => {
    const close = vi.fn(async () => { throw new Error('imap down'); });
    const { app } = testApp({ pool: { close } as unknown as MailPool });
    const agent = request.agent(app);
    const res = await signIn(agent);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings?welcome=1');
    expect(close).toHaveBeenCalled();
    expect((await agent.get('/settings')).status).toBe(200);
  });
});
