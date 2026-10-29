import type { Db } from './index.js';

const DAY = 24 * 60 * 60 * 1000;
/** A registration this old with nothing attached was never completed; a real sign-in follows within minutes. */
const ABANDONED_CLIENT_MS = 7 * DAY;

export function purgeExpired(db: Db, now: number): void {
  db.transaction(() => {
    db.prepare('DELETE FROM oauth_pending WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM oauth_codes WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM oauth_tokens WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM send_log WHERE sent_at < ?').run(now - DAY);
    db.prepare('DELETE FROM login_attempts WHERE attempted_at < ?').run(now - DAY);
    // Anyone may register a client, so drop the ones that never led to a connection rather than keep them forever.
    db.prepare(
      `DELETE FROM oauth_clients
       WHERE created_at < ?
         AND client_id NOT IN (SELECT client_id FROM oauth_tokens)
         AND client_id NOT IN (SELECT client_id FROM oauth_codes)
         AND client_id NOT IN (SELECT client_id FROM oauth_pending)`,
    ).run(now - ABANDONED_CLIENT_MS);
  })();
}
