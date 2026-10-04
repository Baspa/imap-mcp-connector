import type { Db } from './index.js';

export function recordSend(db: Db, userId: number, now: number): void {
  db.prepare('INSERT INTO send_log (user_id, sent_at) VALUES (?, ?)').run(userId, now);
}

export function sendsSince(db: Db, userId: number, since: number): { count: number; oldest: number | null } {
  const row = db
    .prepare('SELECT COUNT(*) AS count, MIN(sent_at) AS oldest FROM send_log WHERE user_id = ? AND sent_at > ?')
    .get(userId, since) as { count: number; oldest: number | null };
  return { count: row.count, oldest: row.oldest };
}

export function recordLoginFailure(db: Db, key: string, now: number): void {
  db.prepare('INSERT INTO login_attempts (key, attempted_at) VALUES (?, ?)').run(key, now);
}

export function loginFailuresSince(db: Db, key: string, since: number): number {
  const row = db
    .prepare('SELECT COUNT(*) AS count FROM login_attempts WHERE key = ? AND attempted_at > ?')
    .get(key, since) as { count: number };
  return row.count;
}
