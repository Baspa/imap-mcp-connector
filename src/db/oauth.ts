import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Db } from './index.js';

const splitScopes = (s: string): string[] => (s ? s.split(' ') : []);

export function insertClient(db: Db, client: OAuthClientInformationFull, now = Date.now()): void {
  db.prepare('INSERT INTO oauth_clients (client_id, client_name, metadata, created_at) VALUES (?, ?, ?, ?)').run(
    client.client_id,
    client.client_name ?? null,
    JSON.stringify(client),
    now,
  );
}

export function getClient(db: Db, clientId: string): OAuthClientInformationFull | undefined {
  const row = db.prepare('SELECT metadata FROM oauth_clients WHERE client_id = ?').get(clientId) as
    | { metadata: string }
    | undefined;
  return row ? (JSON.parse(row.metadata) as OAuthClientInformationFull) : undefined;
}

export interface PendingAuthorization {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  scopes: string[];
  resource: string | null;
  expiresAt: number;
}

export function insertPending(db: Db, p: PendingAuthorization): void {
  db.prepare(
    `INSERT INTO oauth_pending (id, client_id, redirect_uri, code_challenge, state, scopes, resource, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(p.id, p.clientId, p.redirectUri, p.codeChallenge, p.state, p.scopes.join(' '), p.resource, p.expiresAt);
}

export function getPending(db: Db, id: string): PendingAuthorization | undefined {
  const r = db.prepare('SELECT * FROM oauth_pending WHERE id = ?').get(id) as
    | { id: string; client_id: string; redirect_uri: string; code_challenge: string; state: string | null; scopes: string; resource: string | null; expires_at: number }
    | undefined;
  return (
    r && {
      id: r.id,
      clientId: r.client_id,
      redirectUri: r.redirect_uri,
      codeChallenge: r.code_challenge,
      state: r.state,
      scopes: splitScopes(r.scopes),
      resource: r.resource,
      expiresAt: r.expires_at,
    }
  );
}

export function deletePending(db: Db, id: string): void {
  db.prepare('DELETE FROM oauth_pending WHERE id = ?').run(id);
}

export interface AuthCode {
  codeHash: string;
  clientId: string;
  userId: number;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string | null;
  expiresAt: number;
  used: boolean;
  /** Set when the code is redeemed, so a replay can revoke what the first redemption issued. */
  grantId: string | null;
}

export function insertCode(db: Db, c: Omit<AuthCode, 'used' | 'grantId'>): void {
  db.prepare(
    `INSERT INTO oauth_codes (code_hash, client_id, user_id, code_challenge, redirect_uri, scopes, resource, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(c.codeHash, c.clientId, c.userId, c.codeChallenge, c.redirectUri, c.scopes.join(' '), c.resource, c.expiresAt);
}

export function getCode(db: Db, codeHash: string): AuthCode | undefined {
  const r = db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(codeHash) as
    | { code_hash: string; client_id: string; user_id: number; code_challenge: string; redirect_uri: string; scopes: string; resource: string | null; expires_at: number; used: number; grant_id: string | null }
    | undefined;
  return (
    r && {
      codeHash: r.code_hash,
      clientId: r.client_id,
      userId: r.user_id,
      codeChallenge: r.code_challenge,
      redirectUri: r.redirect_uri,
      scopes: splitScopes(r.scopes),
      resource: r.resource,
      expiresAt: r.expires_at,
      used: r.used === 1,
      grantId: r.grant_id,
    }
  );
}

/** Claims the code for one grant. Returns true only for the first caller; later calls return false. */
export function markCodeUsed(db: Db, codeHash: string, grantId: string): boolean {
  return (
    db.prepare('UPDATE oauth_codes SET used = 1, grant_id = ? WHERE code_hash = ? AND used = 0').run(grantId, codeHash).changes === 1
  );
}

export interface TokenRecord {
  tokenHash: string;
  kind: 'access' | 'refresh';
  grantId: string;
  clientId: string;
  userId: number;
  scopes: string[];
  createdAt: number;
  expiresAt: number;
  revokedAt: number | null;
  lastUsedAt: number | null;
}

export function insertToken(db: Db, t: Omit<TokenRecord, 'revokedAt' | 'lastUsedAt'>): void {
  db.prepare(
    `INSERT INTO oauth_tokens (token_hash, kind, grant_id, client_id, user_id, scopes, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(t.tokenHash, t.kind, t.grantId, t.clientId, t.userId, t.scopes.join(' '), t.createdAt, t.expiresAt);
}

export function getToken(db: Db, tokenHash: string): TokenRecord | undefined {
  const r = db.prepare('SELECT * FROM oauth_tokens WHERE token_hash = ?').get(tokenHash) as
    | { token_hash: string; kind: 'access' | 'refresh'; grant_id: string; client_id: string; user_id: number; scopes: string; created_at: number; expires_at: number; revoked_at: number | null; last_used_at: number | null }
    | undefined;
  return (
    r && {
      tokenHash: r.token_hash,
      kind: r.kind,
      grantId: r.grant_id,
      clientId: r.client_id,
      userId: r.user_id,
      scopes: splitScopes(r.scopes),
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      revokedAt: r.revoked_at,
      lastUsedAt: r.last_used_at,
    }
  );
}

/** Returns true only if this call revoked the token. */
export function revokeTokenRecord(db: Db, tokenHash: string, now: number): boolean {
  return (
    db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').run(now, tokenHash)
      .changes === 1
  );
}

export function revokeGrant(db: Db, grantId: string, now: number): void {
  db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL').run(now, grantId);
}

export function touchToken(db: Db, tokenHash: string, now: number): void {
  db.prepare('UPDATE oauth_tokens SET last_used_at = ? WHERE token_hash = ?').run(now, tokenHash);
}

export interface GrantSummary {
  grantId: string;
  clientId: string;
  clientName: string | null;
  connectedAt: number;
  lastUsedAt: number | null;
}

/** A grant is active while it has an unrevoked, unexpired refresh token. */
export function listActiveGrants(db: Db, userId: number, now: number): GrantSummary[] {
  const rows = db
    .prepare(
      `SELECT t.grant_id, t.client_id, c.client_name, MIN(t.created_at) AS connected_at, MAX(t.last_used_at) AS last_used_at
       FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
       WHERE t.user_id = ?
       GROUP BY t.grant_id
       HAVING SUM(CASE WHEN t.kind = 'refresh' AND t.revoked_at IS NULL AND t.expires_at > ? THEN 1 ELSE 0 END) > 0
       ORDER BY connected_at`,
    )
    .all(userId, now) as { grant_id: string; client_id: string; client_name: string | null; connected_at: number; last_used_at: number | null }[];
  return rows.map((r) => ({
    grantId: r.grant_id,
    clientId: r.client_id,
    clientName: r.client_name,
    connectedAt: r.connected_at,
    lastUsedAt: r.last_used_at,
  }));
}

export function revokeAllUserGrants(db: Db, userId: number, now: number): void {
  db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(now, userId);
}

export function revokeUserGrant(db: Db, userId: number, grantId: string, now: number): void {
  db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE grant_id = ? AND user_id = ? AND revoked_at IS NULL').run(
    now,
    grantId,
    userId,
  );
}
