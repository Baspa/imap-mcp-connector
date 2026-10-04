import type { Response } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { SqliteOAuthProvider } from '../../src/auth/oauth-provider.js';

export async function issueAccessToken(provider: SqliteOAuthProvider, userId: number): Promise<string> {
  const client = await provider.clientsStore.registerClient!({
    redirect_uris: ['http://localhost/cb'],
    client_name: 'Test AI',
    token_endpoint_auth_method: 'none',
  } as OAuthClientInformationFull);
  let location = '';
  const res = { redirect: (url: string) => { location = url; } } as unknown as Response;
  await provider.authorize(client, { redirectUri: 'http://localhost/cb', codeChallenge: 'unused', scopes: [] }, res);
  const reqId = new URL(location, 'http://x').searchParams.get('req')!;
  const code = new URL(provider.approve(reqId, userId)!).searchParams.get('code')!;
  return (await provider.exchangeAuthorizationCode(client, code)).access_token;
}
