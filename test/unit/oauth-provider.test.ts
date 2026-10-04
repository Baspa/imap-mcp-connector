import type { Response } from 'express';
import { describe, expect, it } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { listActiveGrants } from '../../src/db/oauth.js';
import { SqliteOAuthProvider } from '../../src/auth/oauth-provider.js';
import { createTestUser, testDb } from '../helpers/db.js';

function setup() {
  const db = testDb();
  const user = createTestUser(db);
  let now = 1_000_000;
  const provider = new SqliteOAuthProvider(db, () => now);
  return { db, user, provider, advance: (ms: number) => (now += ms) };
}

async function register(provider: SqliteOAuthProvider): Promise<OAuthClientInformationFull> {
  return provider.clientsStore.registerClient!({
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    client_name: 'Claude',
    token_endpoint_auth_method: 'none',
  } as OAuthClientInformationFull);
}

async function authorize(provider: SqliteOAuthProvider, client: OAuthClientInformationFull): Promise<string> {
  let location = '';
  const res = { redirect: (url: string) => { location = url; } } as unknown as Response;
  await provider.authorize(client, { redirectUri: client.redirect_uris[0], codeChallenge: 'challenge-123', state: 'st', scopes: [] }, res);
  const id = new URL(location, 'http://x').searchParams.get('req');
  if (!location.startsWith('/consent?req=') || !id) throw new Error(`unexpected redirect ${location}`);
  return id;
}

async function codeFor(provider: SqliteOAuthProvider, client: OAuthClientInformationFull, userId: number): Promise<string> {
  const id = await authorize(provider, client);
  const url = new URL(provider.approve(id, userId)!);
  expect(url.searchParams.get('state')).toBe('st');
  return url.searchParams.get('code')!;
}

describe('SqliteOAuthProvider', () => {
  it('registers and returns clients', async () => {
    const { provider } = setup();
    const client = await register(provider);
    expect(client.client_id).toMatch(/[0-9a-f-]{36}/);
    expect(await provider.clientsStore.getClient(client.client_id)).toMatchObject({ client_name: 'Claude' });
  });

  it('describes pending requests for the consent page', async () => {
    const { provider } = setup();
    const client = await register(provider);
    const id = await authorize(provider, client);
    expect(provider.describePending(id)).toMatchObject({ clientName: 'Claude', pending: { codeChallenge: 'challenge-123' } });
    expect(provider.describePending('nope')).toBeNull();
  });

  it('expires pending requests after 10 minutes', async () => {
    const { provider, user, advance } = setup();
    const client = await register(provider);
    const id = await authorize(provider, client);
    advance(11 * 60_000);
    expect(provider.describePending(id)).toBeNull();
    expect(provider.approve(id, user.id)).toBeNull();
  });

  it('issues tokens for a valid code once', async () => {
    const { provider, user } = setup();
    const client = await register(provider);
    const code = await codeFor(provider, client, user.id);
    expect(await provider.challengeForAuthorizationCode(client, code)).toBe('challenge-123');
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, client.redirect_uris[0]);
    expect(tokens).toMatchObject({ token_type: 'Bearer', expires_in: 3600 });
    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(info).toMatchObject({ clientId: client.client_id, extra: { userId: user.id } });
    await expect(provider.exchangeAuthorizationCode(client, code)).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects codes from another client, expired codes and wrong redirect URIs', async () => {
    const { provider, user, advance } = setup();
    const client = await register(provider);
    const other = await register(provider);
    const code = await codeFor(provider, client, user.id);
    await expect(provider.challengeForAuthorizationCode(other, code)).rejects.toBeInstanceOf(InvalidGrantError);
    await expect(provider.exchangeAuthorizationCode(client, code, undefined, 'https://evil.example/cb')).rejects.toBeInstanceOf(InvalidGrantError);
    const code2 = await codeFor(provider, client, user.id);
    advance(61_000);
    await expect(provider.exchangeAuthorizationCode(client, code2)).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rotates refresh tokens and revokes the grant on reuse', async () => {
    const { provider, user } = setup();
    const client = await register(provider);
    const first = await provider.exchangeAuthorizationCode(client, await codeFor(provider, client, user.id));
    const second = await provider.exchangeRefreshToken(client, first.refresh_token!);
    expect(second.refresh_token).not.toBe(first.refresh_token);
    await expect(provider.verifyAccessToken(second.access_token)).resolves.toBeDefined();
    await expect(provider.exchangeRefreshToken(client, first.refresh_token!)).rejects.toBeInstanceOf(InvalidGrantError);
    await expect(provider.verifyAccessToken(second.access_token)).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(provider.exchangeRefreshToken(client, second.refresh_token!)).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('expires access tokens after an hour', async () => {
    const { provider, user, advance } = setup();
    const client = await register(provider);
    const tokens = await provider.exchangeAuthorizationCode(client, await codeFor(provider, client, user.id));
    advance(3_600_001);
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(provider.verifyAccessToken('garbage')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('revokes a grant via the revocation endpoint and lists active grants', async () => {
    const { db, provider, user } = setup();
    const client = await register(provider);
    const tokens = await provider.exchangeAuthorizationCode(client, await codeFor(provider, client, user.id));
    expect(listActiveGrants(db, user.id, 1_000_000)).toHaveLength(1);
    await provider.revokeToken!(client, { token: tokens.refresh_token! });
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toBeInstanceOf(InvalidTokenError);
    expect(listActiveGrants(db, user.id, 1_000_000)).toHaveLength(0);
  });

  it('builds a deny redirect with access_denied', async () => {
    const { provider } = setup();
    const client = await register(provider);
    const id = await authorize(provider, client);
    const url = new URL(provider.deny(id)!);
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('state')).toBe('st');
    expect(provider.describePending(id)).toBeNull();
  });
});
