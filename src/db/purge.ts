import type { Db } from './index.js';

const DAY = 24 * 60 * 60;

export function purgeExpired(db: Db, now: number): void {
  db.transaction(() => {
    db.prepare('DELETE FROM oauth_pending WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM oauth_codes WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM oauth_tokens WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM send_log WHERE sent_at < ?').run(now - DAY);
    db.prepare('DELETE FROM login_attempts WHERE attempted_at < ?').run(now - DAY);
  })();
}
