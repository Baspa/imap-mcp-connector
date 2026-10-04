import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { createApp } from './app.js';
import { SqliteOAuthProvider } from './auth/oauth-provider.js';
import { ConfigError, loadConfig, signInUrl, type Config } from './config.js';
import { openDb } from './db/index.js';
import { purgeExpired } from './db/purge.js';
import { discoverSettings } from './discovery/index.js';
import { guardMailSettings } from './guard.js';
import { log } from './log.js';
import { verifyImapLogin } from './mail/imap.js';
import { MailPool } from './mail/pool.js';
import { defaultSmtpFactory } from './mail/smtp.js';

function loadConfigOrExit(): Config {
  try {
    return loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`Configuration error: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}

const config = loadConfigOrExit();
mkdirSync(config.dataDir, { recursive: true });
const db = openDb(path.join(config.dataDir, 'imap-connector.db'));
const pool = new MailPool({ db, key: config.encryptionKey, signInUrl: signInUrl(config) });

const app = createApp({
  config,
  db,
  pool,
  provider: new SqliteOAuthProvider(db),
  smtpFactory: defaultSmtpFactory,
  discover: (email) => discoverSettings(email),
  verifyImap: (target, password) => verifyImapLogin(target, password),
  guard: (email, settings) => guardMailSettings(config, email, settings),
});

purgeExpired(db, Date.now());
setInterval(() => purgeExpired(db, Date.now()), 60 * 60 * 1000).unref();

const server = app.listen(config.port, (err?: Error) => {
  if (err) {
    log('error', 'listen failed', { port: config.port, error: err.message });
    process.exit(1);
  }
  log('info', 'listening', { port: config.port, publicUrl: config.publicUrl.href });
});

function shutdown(): void {
  log('info', 'shutting down');
  const closed = new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
  closed
    .then(() => pool.closeAll())
    .then(() => {
      db.close();
      process.exit(0);
    })
    .catch((err: unknown) => {
      log('error', 'shutdown failed', { error: err instanceof Error ? err.message : String(err) });
      process.exit(1);
    });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
