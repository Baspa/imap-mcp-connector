import session from 'express-session';
import type { Db } from '../db/index.js';

declare module 'express-session' {
  interface SessionData {
    userId?: number;
    csrfToken?: string;
  }
}

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function expiresAt(sess: session.SessionData): number {
  const expires = sess.cookie?.expires;
  return expires ? new Date(expires).getTime() : Date.now() + DEFAULT_TTL_MS;
}

export class SqliteSessionStore extends session.Store {
  constructor(private readonly db: Db) {
    super();
  }

  override get(sid: string, cb: (err: unknown, session?: session.SessionData | null) => void): void {
    try {
      const row = this.db.prepare('SELECT data, expires_at FROM sessions WHERE sid = ?').get(sid) as
        | { data: string; expires_at: number }
        | undefined;
      if (!row || row.expires_at < Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.data) as session.SessionData);
    } catch (err) {
      cb(err);
    }
  }

  override set(sid: string, sess: session.SessionData, cb?: (err?: unknown) => void): void {
    try {
      this.db
        .prepare(
          `INSERT INTO sessions (sid, data, expires_at) VALUES (?, ?, ?)
           ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
        )
        .run(sid, JSON.stringify(sess), expiresAt(sess));
      cb?.();
    } catch (err) {
      cb?.(err);
    }
  }

  override destroy(sid: string, cb?: (err?: unknown) => void): void {
    try {
      this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      cb?.();
    } catch (err) {
      cb?.(err);
    }
  }

  override touch(sid: string, sess: session.SessionData, cb?: (err?: unknown) => void): void {
    try {
      this.db.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?').run(expiresAt(sess), sid);
      cb?.();
    } catch (err) {
      cb?.(err);
    }
  }
}

export function deleteSessionsForUser(db: Db, userId: number): void {
  db.prepare("DELETE FROM sessions WHERE json_extract(data, '$.userId') = ?").run(userId);
}
