import { randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { InvalidClientError, InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { hashToken, randomToken } from '../crypto.js';
import type { Db } from '../db/index.js';
import {
  deletePending, getClient, getCode, getPending, getToken, insertClient, insertCode, insertPending, insertToken,
  markCodeUsed, revokeGrant, revokeTokenRecord, touchToken, type PendingAuthorization,
} from '../db/oauth.js';
import { findUserById } from '../db/users.js';

export const ACCESS_TTL_MS = 60 * 60 * 1000;
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const CODE_TTL_MS = 60 * 1000;
export const PENDING_TTL_MS = 10 * 60 * 1000;

type RegisterClientInput = Parameters<NonNullable<OAuthRegisteredClientsStore['registerClient']>>[0];

/** True when `host` is the listed host or a subdomain of it, so "notclaude.ai" never matches "claude.ai". */
function hostMatches(host: string, allowed: string): boolean {
  return host === allowed || host.endsWith(`.${allowed}`);
}

export class SqliteOAuthProvider implements OAuthServerProvider {
  constructor(
    private readonly db: Db,
    private readonly now: () => number = Date.now,
    /** Hosts that may receive an authorization code. Empty means any, as dynamic registration intends. */
    private readonly allowedRedirectHosts: string[] = [],
  ) {}

  /**
   * Registration is open by design, and the consent page shows the client's own name, so a client calling
   * itself "ChatGPT" can point at a look-alike host. Listing hosts makes that a refusal rather than a
   * decision the user has to get right while reading a redirect URI.
   */
  private assertRedirectHostsAllowed(redirectUris: unknown): void {
    if (this.allowedRedirectHosts.length === 0) return;
    const uris = Array.isArray(redirectUris) ? redirectUris : [];
    for (const uri of uris) {
      let host: string;
      try {
        host = new URL(String(uri)).host.toLowerCase();
      } catch {
        throw new InvalidClientError(`Redirect URI "${String(uri)}" is not a valid URL.`);
      }
      if (!this.allowedRedirectHosts.some((allowed) => hostMatches(host, allowed))) {
        throw new InvalidClientError(
          `This connector only registers clients that redirect to ${this.allowedRedirectHosts.join(', ')}. "${host}" is not one of them.`,
        );
      }
    }
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId: string) => getClient(this.db, clientId),
      registerClient: (client: RegisterClientInput) => {
        const given = client as Partial<OAuthClientInformationFull>;
        this.assertRedirectHostsAllowed(given.redirect_uris);
        const full: OAuthClientInformationFull = {
          ...client,
          client_id: given.client_id ?? randomUUID(),
          client_id_issued_at: given.client_id_issued_at ?? Math.floor(this.now() / 1000),
        };
        insertClient(this.db, full, this.now());
        return full;
      },
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const id = randomToken(24);
    insertPending(this.db, {
      id,
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state ?? null,
      scopes: params.scopes ?? [],
      resource: params.resource?.href ?? null,
      expiresAt: this.now() + PENDING_TTL_MS,
    });
    res.redirect(`/consent?req=${encodeURIComponent(id)}`);
  }

  describePending(id: string): { pending: PendingAuthorization; clientName: string } | null {
    const pending = getPending(this.db, id);
    if (!pending || pending.expiresAt < this.now()) return null;
    const client = getClient(this.db, pending.clientId);
    return { pending, clientName: client?.client_name ?? 'An AI application' };
  }

  approve(pendingId: string, userId: number): string | null {
    const described = this.describePending(pendingId);
    if (!described) return null;
    const { pending } = described;
    deletePending(this.db, pendingId);
    const code = randomToken();
    insertCode(this.db, {
      codeHash: hashToken(code),
      clientId: pending.clientId,
      userId,
      codeChallenge: pending.codeChallenge,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes,
      resource: pending.resource,
      expiresAt: this.now() + CODE_TTL_MS,
    });
    const url = new URL(pending.redirectUri);
    url.searchParams.set('code', code);
    if (pending.state) url.searchParams.set('state', pending.state);
    return url.href;
  }

  deny(pendingId: string): string | null {
    const described = this.describePending(pendingId);
    if (!described) return null;
    deletePending(this.db, pendingId);
    const url = new URL(described.pending.redirectUri);
    url.searchParams.set('error', 'access_denied');
    if (described.pending.state) url.searchParams.set('state', described.pending.state);
    return url.href;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const code = getCode(this.db, hashToken(authorizationCode));
    if (!code || code.clientId !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const hash = hashToken(authorizationCode);
    const code = getCode(this.db, hash);
    if (!code || code.clientId !== client.client_id || code.expiresAt < this.now()) {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    if (redirectUri && redirectUri !== code.redirectUri) throw new InvalidGrantError('redirect_uri does not match');
    if (!markCodeUsed(this.db, hash)) throw new InvalidGrantError('Authorization code already used');
    return this.issue(code.clientId, code.userId, code.scopes, randomUUID());
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    const hash = hashToken(refreshToken);
    const token = getToken(this.db, hash);
    const now = this.now();
    if (!token || token.kind !== 'refresh' || token.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid refresh token');
    }
    if (token.revokedAt !== null || !revokeTokenRecord(this.db, hash, now)) {
      // Reuse of a rotated or revoked refresh token: assume theft and kill the whole grant.
      revokeGrant(this.db, token.grantId, now);
      throw new InvalidGrantError('Refresh token has been revoked');
    }
    if (token.expiresAt < now) throw new InvalidGrantError('Refresh token expired');
    if (!findUserById(this.db, token.userId)) throw new InvalidGrantError('Account no longer exists');
    return this.issue(token.clientId, token.userId, token.scopes, token.grantId);
  }

  async verifyAccessToken(accessToken: string): Promise<AuthInfo> {
    const hash = hashToken(accessToken);
    const token = getToken(this.db, hash);
    const now = this.now();
    if (!token || token.kind !== 'access' || token.revokedAt !== null || token.expiresAt < now) {
      throw new InvalidTokenError('Invalid or expired access token');
    }
    touchToken(this.db, hash, now);
    return {
      token: accessToken,
      clientId: token.clientId,
      scopes: token.scopes,
      expiresAt: Math.floor(token.expiresAt / 1000),
      extra: { userId: token.userId },
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const token = getToken(this.db, hashToken(request.token));
    if (token && token.clientId === client.client_id) revokeGrant(this.db, token.grantId, this.now());
  }

  private issue(clientId: string, userId: number, scopes: string[], grantId: string): OAuthTokens {
    const now = this.now();
    const accessToken = randomToken();
    const refreshToken = randomToken();
    insertToken(this.db, { tokenHash: hashToken(accessToken), kind: 'access', grantId, clientId, userId, scopes, createdAt: now, expiresAt: now + ACCESS_TTL_MS });
    insertToken(this.db, { tokenHash: hashToken(refreshToken), kind: 'refresh', grantId, clientId, userId, scopes, createdAt: now, expiresAt: now + REFRESH_TTL_MS });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_MS / 1000,
      refresh_token: refreshToken,
      ...(scopes.length ? { scope: scopes.join(' ') } : {}),
    };
  }
}
