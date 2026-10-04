import pkceChallenge from 'pkce-challenge';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { csrfFrom, testApp } from '../helpers/app.js';

const REDIRECT = 'http://localhost:9999/callback';

describe('OAuth flow', () => {
  it('publishes discovery metadata', async () => {
    const { app } = testApp();
    const as = await request(app).get('/.well-known/oauth-authorization-server');
    expect(as.status).toBe(200);
    expect(as.body).toMatchObject({
      authorization_endpoint: 'http://localhost:3000/authorize',
      token_endpoint: 'http://localhost:3000/token',
      registration_endpoint: 'http://localhost:3000/register',
      code_challenge_methods_supported: ['S256'],
    });
    const pr = await request(app).get('/.well-known/oauth-protected-resource/mcp');
    expect(pr.status).toBe(200);
    expect(pr.body.resource).toBe('http://localhost:3000/mcp');
  });

  it('runs register → authorize (signed out) → sign in → consent → token → refresh → revoke', async () => {
    const { app, deps } = testApp();
    const agent = request.agent(app);

    const reg = await agent.post('/register').send({
      redirect_uris: [REDIRECT], client_name: 'Test AI', token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    });
    expect(reg.status).toBe(201);
    const clientId: string = reg.body.client_id;

    const { code_verifier, code_challenge } = await pkceChallenge();
    const authorize = await agent.get('/authorize').query({
      response_type: 'code', client_id: clientId, redirect_uri: REDIRECT,
      code_challenge, code_challenge_method: 'S256', state: 'xyz',
    });
    expect(authorize.status).toBe(302);
    const consentUrl: string = authorize.headers.location;
    expect(consentUrl).toMatch(/^\/consent\?req=/);

    // Signed out: consent bounces to login with next, login returns to the same consent page.
    const bounce = await agent.get(consentUrl);
    expect(bounce.headers.location).toBe(`/login?next=${encodeURIComponent(consentUrl)}`);
    const loginPage = await agent.get(bounce.headers.location);
    const signedIn = await agent.post('/login').type('form').send({
      _csrf: csrfFrom(loginPage.text), email: 'alice@x.org', password: 'right', next: consentUrl,
    });
    expect(signedIn.headers.location).toBe(consentUrl);

    const consent = await agent.get(consentUrl);
    expect(consent.status).toBe(200);
    expect(consent.text).toContain('Test AI');
    expect(consent.text).toContain('alice@x.org');
    expect(consent.text).toContain('Read and draft');
    expect(consent.text).toContain('localhost:9999');

    const approved = await agent.post('/consent').type('form').send({
      _csrf: csrfFrom(consent.text), req: new URL(consentUrl, 'http://x').searchParams.get('req'), decision: 'approve',
    });
    const callback = new URL(approved.headers.location);
    expect(callback.origin + callback.pathname).toBe(REDIRECT);
    expect(callback.searchParams.get('state')).toBe('xyz');
    const code = callback.searchParams.get('code')!;

    const badPkce = await agent.post('/token').type('form').send({
      grant_type: 'authorization_code', code, code_verifier: 'x'.repeat(43), client_id: clientId, redirect_uri: REDIRECT,
    });
    expect(badPkce.status).toBe(400);
    expect(badPkce.body.error).toBe('invalid_grant');

    const token = await agent.post('/token').type('form').send({
      grant_type: 'authorization_code', code, code_verifier, client_id: clientId, redirect_uri: REDIRECT,
    });
    expect(token.status).toBe(200);
    expect(token.body).toMatchObject({ token_type: expect.stringMatching(/bearer/i), expires_in: 3600 });
    const info = await deps.provider.verifyAccessToken(token.body.access_token);
    expect(info.extra?.userId).toBeTypeOf('number');

    const refreshed = await agent.post('/token').type('form').send({
      grant_type: 'refresh_token', refresh_token: token.body.refresh_token, client_id: clientId,
    });
    expect(refreshed.status).toBe(200);
    const reused = await agent.post('/token').type('form').send({
      grant_type: 'refresh_token', refresh_token: token.body.refresh_token, client_id: clientId,
    });
    expect(reused.status).toBe(400);
    await expect(deps.provider.verifyAccessToken(refreshed.body.access_token)).rejects.toThrow();
  });

  it('denies access when the user says no', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    const reg = await agent.post('/register').send({ redirect_uris: [REDIRECT], client_name: 'Test AI', token_endpoint_auth_method: 'none' });
    const { code_challenge } = await pkceChallenge();
    const authorize = await agent.get('/authorize').query({
      response_type: 'code', client_id: reg.body.client_id, redirect_uri: REDIRECT, code_challenge, code_challenge_method: 'S256', state: 's1',
    });
    const consentUrl: string = authorize.headers.location;
    const loginPage = await agent.get(`/login?next=${encodeURIComponent(consentUrl)}`);
    await agent.post('/login').type('form').send({ _csrf: csrfFrom(loginPage.text), email: 'alice@x.org', password: 'right', next: consentUrl });
    const consent = await agent.get(consentUrl);
    const denied = await agent.post('/consent').type('form').send({
      _csrf: csrfFrom(consent.text), req: new URL(consentUrl, 'http://x').searchParams.get('req'), decision: 'deny',
    });
    const callback = new URL(denied.headers.location);
    expect(callback.searchParams.get('error')).toBe('access_denied');
    expect(callback.searchParams.get('state')).toBe('s1');
  });

  it('rejects a redirect URI that was not registered', async () => {
    const { app } = testApp();
    const reg = await request(app).post('/register').send({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    const { code_challenge } = await pkceChallenge();
    const res = await request(app).get('/authorize').query({
      response_type: 'code', client_id: reg.body.client_id, redirect_uri: 'https://evil.example/cb',
      code_challenge, code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
  });

  it('shows an error page for an unknown consent request', async () => {
    const { app } = testApp();
    const agent = request.agent(app);
    const loginPage = await agent.get('/login');
    await agent.post('/login').type('form').send({ _csrf: csrfFrom(loginPage.text), email: 'alice@x.org', password: 'right' });
    const res = await agent.get('/consent?req=does-not-exist');
    expect(res.status).toBe(400);
    expect(res.text).toContain('expired');
  });
});
