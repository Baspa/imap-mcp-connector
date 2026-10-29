import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import express, { type ErrorRequestHandler, type RequestHandler } from 'express';
import session from 'express-session';
import type { LoginDeps } from './auth/login.js';
import type { SqliteOAuthProvider } from './auth/oauth-provider.js';
import { SqliteSessionStore } from './auth/session.js';
import { mcpUrl, type Config } from './config.js';
import type { Db } from './db/index.js';
import type { User } from './db/users.js';
import type { PinnedAddresses } from './guard.js';
import { log } from './log.js';
import type { MailPool } from './mail/pool.js';
import type { SmtpFactory } from './mail/smtp.js';
import { mcpRouter } from './mcp/http.js';
import { consentRouter } from './web/consent.js';
import { webRouter } from './web/routes.js';

export interface AppDeps {
  config: Config;
  db: Db;
  pool: MailPool;
  provider: SqliteOAuthProvider;
  smtpFactory: SmtpFactory;
  discover: LoginDeps['discover'];
  verifyImap: LoginDeps['verifyImap'];
  guard: LoginDeps['guard'];
  /** Re-checks a stored user's mail settings before SMTP connections (IMAP is guarded by the pool). */
  mailGuard?: (user: User) => Promise<PinnedAddresses | void>;
}

const VIEWS_DIR = fileURLToPath(new URL('../views', import.meta.url));

export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ANONYMOUS_SESSION_TTL_MS = 60 * 60 * 1000;

const requestId: RequestHandler = (_req, res, next) => {
  res.locals.requestId = randomUUID();
  res.setHeader('X-Request-Id', res.locals.requestId);
  next();
};

const securityHeaders = (config: Config): RequestHandler => (_req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (config.isProduction) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
};

function clientErrorStatus(err: unknown): number | undefined {
  const e = err as { status?: unknown; statusCode?: unknown } | null;
  for (const value of [e?.status, e?.statusCode]) {
    if (typeof value === 'number' && value >= 400 && value <= 499) return value;
  }
  return undefined;
}

// Express recognises error handlers by their four-argument arity, so `_next` must stay.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  log('error', 'request failed', {
    requestId: res.locals.requestId,
    path: req.path,
    error: err instanceof Error ? err.message : String(err),
  });
  if (res.headersSent) return;
  const status = clientErrorStatus(err);
  if (status) {
    res.status(status).render('error', { title: 'Request rejected', message: 'The request could not be processed.' });
    return;
  }
  res.status(500).render('error', { title: 'Something went wrong', message: `Request id: ${res.locals.requestId}` });
};

export function createApp(deps: AppDeps): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.set('view engine', 'ejs');
  app.set('views', VIEWS_DIR);

  app.use(requestId);
  app.use(securityHeaders(deps.config));
  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });

  app.use(
    mcpAuthRouter({
      provider: deps.provider,
      issuerUrl: new URL(deps.config.publicUrl.origin),
      resourceServerUrl: mcpUrl(deps.config),
      resourceName: 'IMAP Connector',
    }),
  );

  app.use(mcpRouter(deps));

  app.use(
    session({
      store: new SqliteSessionStore(deps.db),
      secret: deps.config.sessionSecret,
      name: 'imc.sid',
      resave: false,
      saveUninitialized: false,
      // Short by default: the login page mints a CSRF token, so anyone who loads it gets a stored session.
      // Signing in extends it to SESSION_TTL_MS.
      cookie: { httpOnly: true, secure: deps.config.isProduction, sameSite: 'lax', maxAge: ANONYMOUS_SESSION_TTL_MS },
    }),
  );
  app.use(express.urlencoded({ extended: false, limit: '100kb' }));
  app.use(webRouter(deps));
  app.use(consentRouter(deps));
  app.use((_req, res) => {
    res.status(404).render('error', { title: 'Not found', message: 'This page does not exist.' });
  });
  app.use(errorHandler);
  return app;
}
