import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { openDb } from '../../src/db/index.js';
import { migrations } from '../../src/db/migrations.js';
import {
  deleteUser, findUserByEmail, findUserById, recordLogin, setNeedsReauth, setPermissionLevel, updateSmtpSettings,
} from '../../src/db/users.js';
import {
  getCode, getPending, getToken, insertClient, insertCode, insertPending, insertToken, listActiveGrants,
  markCodeUsed, revokeGrant, revokeTokenRecord, revokeUserGrant, getClient, deletePending,
} from '../../src/db/oauth.js';
import { loginFailuresSince, recordLoginFailure, recordSend, sendsSince } from '../../src/db/counters.js';
import { purgeExpired } from '../../src/db/purge.js';
import { createTestUser, testDb } from '../helpers/db.js';

const client = { client_id: 'c1', client_name: 'Claude', redirect_uris: ['https://claude.ai/cb'] };

function token(db: ReturnType<typeof testDb>, userId: number, hash: string, kind: 'access' | 'refresh', grantId: string, expiresAt = 10_000) {
  insertToken(db, { tokenHash: hash, kind, grantId, clientId: 'c1', userId, scopes: [], createdAt: 1, expiresAt });
}

describe('migrations', () => {
  it('can open the same file twice', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'imc-')), 'db.sqlite');
    openDb(file).close();
    const db = openDb(file);
    expect(db.pragma('user_version', { simple: true })).toBe(migrations.length);
    db.close();
  });

  it('marks accounts created before settings sources were recorded as legacy', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'imc-')), 'db.sqlite');
    const old = new Database(file);
    old.exec(migrations[0]);
    old.pragma('user_version = 1');
    old.prepare(
      `INSERT INTO users (email, imap_host, imap_port, imap_security, imap_password_enc, smtp_host, smtp_port,
         smtp_security, smtp_username, created_at) VALUES ('a@custom.org', 'imap.attacker.net', 993, 'tls', 'x',
         'smtp.attacker.net', 465, 'tls', 'a@custom.org', 1)`,
    ).run();
    old.close();
    const db = openDb(file);
    expect(findUserByEmail(db, 'a@custom.org')!.settingsSource).toBe('legacy');
    expect(createTestUser(db).settingsSource).toBe('discovered');
    db.close();
  });
});

describe('users', () => {
  it('creates and finds users with normalized email', () => {
    const db = testDb();
    const u = createTestUser(db, { email: 'Alice@Example.com' });
    expect(u.email).toBe('alice@example.com');
    expect(u.permissionLevel).toBe('draft');
    expect(u.needsReauth).toBe(false);
    expect(findUserByEmail(db, '  ALICE@example.COM ')?.id).toBe(u.id);
    expect(findUserById(db, u.id)?.imapSecurity).toBe('tls');
  });

  it('recordLogin replaces the password and clears needs_reauth', () => {
    const db = testDb();
    const u = createTestUser(db);
    setNeedsReauth(db, u.id, true);
    expect(findUserById(db, u.id)?.needsReauth).toBe(true);
    recordLogin(db, u.id, 'v1:new', 500);
    const after = findUserById(db, u.id)!;
    expect(after.needsReauth).toBe(false);
    expect(after.imapPasswordEnc).toBe('v1:new');
    expect(after.lastLoginAt).toBe(500);
  });

  it('updates smtp settings and permission level', () => {
    const db = testDb();
    const u = createTestUser(db);
    updateSmtpSettings(db, u.id, { smtpHost: 'smtp.x.org', smtpPort: 587, smtpSecurity: 'starttls', smtpUsername: 'me', smtpPasswordEnc: 'v1:x' });
    setPermissionLevel(db, u.id, 'full');
    const after = findUserById(db, u.id)!;
    expect(after).toMatchObject({ smtpHost: 'smtp.x.org', smtpPort: 587, smtpSecurity: 'starttls', smtpUsername: 'me', smtpPasswordEnc: 'v1:x', permissionLevel: 'full' });
  });

  it('deleting a user cascades to tokens', () => {
    const db = testDb();
    const u = createTestUser(db);
    insertClient(db, client, 1);
    token(db, u.id, 'h1', 'access', 'g1');
    deleteUser(db, u.id);
    expect(findUserById(db, u.id)).toBeUndefined();
    expect(getToken(db, 'h1')).toBeUndefined();
  });

  it('never reuses the id of a deleted user', () => {
    const db = testDb();
    const u = createTestUser(db);
    deleteUser(db, u.id);
    const next = createTestUser(db);
    expect(next.id).not.toBe(u.id);
  });
});

describe('oauth', () => {
  it('stores clients as full metadata', () => {
    const db = testDb();
    insertClient(db, client, 1);
    expect(getClient(db, 'c1')).toEqual(client);
    expect(getClient(db, 'nope')).toBeUndefined();
  });

  it('stores pending authorizations', () => {
    const db = testDb();
    insertClient(db, client, 1);
    insertPending(db, { id: 'p1', clientId: 'c1', redirectUri: 'https://claude.ai/cb', codeChallenge: 'ch', state: 's', scopes: ['a'], resource: null, expiresAt: 99 });
    expect(getPending(db, 'p1')).toEqual({ id: 'p1', clientId: 'c1', redirectUri: 'https://claude.ai/cb', codeChallenge: 'ch', state: 's', scopes: ['a'], resource: null, expiresAt: 99 });
    deletePending(db, 'p1');
    expect(getPending(db, 'p1')).toBeUndefined();
  });

  it('marks a code used exactly once', () => {
    const db = testDb();
    const u = createTestUser(db);
    insertClient(db, client, 1);
    insertCode(db, { codeHash: 'ch1', clientId: 'c1', userId: u.id, codeChallenge: 'x', redirectUri: 'https://claude.ai/cb', scopes: [], resource: null, expiresAt: 99 });
    expect(getCode(db, 'ch1')?.used).toBe(false);
    expect(markCodeUsed(db, 'ch1')).toBe(true);
    expect(markCodeUsed(db, 'ch1')).toBe(false);
  });

  it('revokes tokens once and whole grants', () => {
    const db = testDb();
    const u = createTestUser(db);
    insertClient(db, client, 1);
    token(db, u.id, 'a1', 'access', 'g1');
    token(db, u.id, 'r1', 'refresh', 'g1');
    expect(revokeTokenRecord(db, 'r1', 5)).toBe(true);
    expect(revokeTokenRecord(db, 'r1', 6)).toBe(false);
    revokeGrant(db, 'g1', 7);
    expect(getToken(db, 'a1')?.revokedAt).toBe(7);
  });

  it('lists active grants and revokes them per user', () => {
    const db = testDb();
    const u = createTestUser(db);
    const other = createTestUser(db);
    insertClient(db, client, 1);
    token(db, u.id, 'a1', 'access', 'g1');
    token(db, u.id, 'r1', 'refresh', 'g1');
    token(db, u.id, 'r2', 'refresh', 'g2', 50);
    const grants = listActiveGrants(db, u.id, 100);
    expect(grants.map((g) => g.grantId)).toEqual(['g1']);
    expect(grants[0]).toMatchObject({ clientId: 'c1', clientName: 'Claude', connectedAt: 1 });
    revokeUserGrant(db, other.id, 'g1', 200);
    expect(listActiveGrants(db, u.id, 100)).toHaveLength(1);
    revokeUserGrant(db, u.id, 'g1', 200);
    expect(listActiveGrants(db, u.id, 100)).toHaveLength(0);
  });
});

describe('counters and purge', () => {
  it('counts sends in a window and reports the oldest', () => {
    const db = testDb();
    const u = createTestUser(db);
    recordSend(db, u.id, 100);
    recordSend(db, u.id, 200);
    recordSend(db, u.id, 300);
    expect(sendsSince(db, u.id, 150)).toEqual({ count: 2, oldest: 200 });
    expect(sendsSince(db, u.id, 400)).toEqual({ count: 0, oldest: null });
  });

  it('counts login failures per key', () => {
    const db = testDb();
    recordLoginFailure(db, 'ip:1.2.3.4', 100);
    recordLoginFailure(db, 'ip:1.2.3.4', 200);
    recordLoginFailure(db, 'email:a@b.c', 200);
    expect(loginFailuresSince(db, 'ip:1.2.3.4', 150)).toBe(1);
    expect(loginFailuresSince(db, 'ip:1.2.3.4', 0)).toBe(2);
  });

  it('purges expired rows', () => {
    const db = testDb();
    const u = createTestUser(db);
    insertClient(db, client, 1);
    const DAY = 24 * 60 * 60 * 1000;
    const now = 3 * DAY;
    token(db, u.id, 'old', 'access', 'g1', 10);
    token(db, u.id, 'new', 'access', 'g1', now + DAY);
    recordLoginFailure(db, 'k', 1);
    recordLoginFailure(db, 'recent', now - 1000);
    purgeExpired(db, now);
    expect(getToken(db, 'old')).toBeUndefined();
    expect(getToken(db, 'new')).toBeDefined();
    expect(loginFailuresSince(db, 'k', 0)).toBe(0);
    expect(loginFailuresSince(db, 'recent', 0)).toBe(1);
  });
});
