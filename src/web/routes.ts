import { Router, type Request, type Response } from 'express';
import type { AppDeps } from '../app.js';
import { login, type LoginDeps } from '../auth/login.js';
import { deleteSessionsForUser } from '../auth/session.js';
import { mcpUrl } from '../config.js';
import { encryptSecret } from '../crypto.js';
import { listActiveGrants, revokeUserGrant } from '../db/oauth.js';
import { deleteUser, serverSettingsOf, setPermissionLevel, updateSmtpSettings, type User } from '../db/users.js';
import { GuardError, isAllowedSmtpHost } from '../guard.js';
import { log } from '../log.js';
import type { MailServerSettings, PermissionLevel, Security } from '../types.js';
import { csrfToken, verifyCsrf } from './csrf.js';
import { LEVELS } from './levels.js';
import { requireUser, safeNext } from './middleware.js';

type Body = Record<string, string | undefined>;
const SECURITIES: Security[] = ['tls', 'starttls', 'none'];

// Hand-entered settings make the server connect where the visitor says, so only real mail ports are
// accepted; any port would turn sign-in into a port scanner against third parties.
const IMAP_PORTS = [993, 143];
const SMTP_PORTS = [465, 587, 25];
const isPort = (n: number, allowed: number[]) => allowed.includes(n);
const isSecurity = (s: string | undefined): s is Security => SECURITIES.includes(s as Security);

function parseManual(b: Body): MailServerSettings | undefined {
  const imapPort = Number(b.imap_port);
  const smtpPort = Number(b.smtp_port);
  if (!b.imap_host?.trim() || !b.smtp_host?.trim() || !isPort(imapPort, IMAP_PORTS) || !isPort(smtpPort, SMTP_PORTS)) return undefined;
  if (!isSecurity(b.imap_security) || !isSecurity(b.smtp_security)) return undefined;
  return {
    imapHost: b.imap_host.trim(),
    imapPort,
    imapSecurity: b.imap_security,
    smtpHost: b.smtp_host.trim(),
    smtpPort,
    smtpSecurity: b.smtp_security,
    autoSavesSent: false,
  };
}

interface LoginView {
  email?: string;
  error?: string | null;
  needsSettings?: boolean;
  manual?: Body;
  next?: unknown;
  status?: number;
}

function renderLogin(req: Request, res: Response, view: LoginView): void {
  res.status(view.status ?? 200).render('login', {
    title: 'Sign in',
    csrf: csrfToken(req),
    next: safeNext(view.next ?? req.query.next, ''),
    email: view.email ?? '',
    error: view.error ?? null,
    needsSettings: view.needsSettings ?? false,
    manual: view.manual ?? {},
    deleted: req.query.deleted === '1',
  });
}

function renderSettings(deps: AppDeps, req: Request, res: Response, error: string | null = null, status = 200): void {
  const user = res.locals.user as User;
  res.status(status).render('settings', {
    title: 'Settings',
    user,
    csrf: csrfToken(req),
    connectorUrl: mcpUrl(deps.config).href,
    grants: listActiveGrants(deps.db, user.id, Date.now()),
    levels: LEVELS,
    saved: typeof req.query.saved === 'string' ? req.query.saved : null,
    welcome: req.query.welcome === '1',
    error,
  });
}

export function webRouter(deps: AppDeps): Router {
  const router = Router();
  const auth = requireUser(deps.db);
  const loginDeps: LoginDeps = {
    db: deps.db,
    config: deps.config,
    discover: deps.discover,
    verifyImap: deps.verifyImap,
    guard: deps.guard,
  };

  router.get('/', (req, res) => res.redirect(req.session.userId ? '/settings' : '/login'));

  router.get('/login', (req, res) => renderLogin(req, res, {}));

  router.post('/login', verifyCsrf, async (req, res) => {
    const body = req.body as Body;
    const manual = body.imap_host !== undefined ? parseManual(body) : undefined;
    if (body.imap_host !== undefined && !manual) {
      return renderLogin(req, res, { email: body.email, error: 'Check the server settings.', needsSettings: true, manual: body, next: body.next, status: 400 });
    }
    const result = await login(loginDeps, { email: body.email ?? '', password: body.password ?? '', ip: req.ip ?? 'unknown', manual });
    if (result.status === 'needs_settings') {
      return renderLogin(req, res, { email: body.email, error: result.message, needsSettings: true, next: body.next });
    }
    if (result.status === 'error') {
      return renderLogin(req, res, { email: body.email, error: result.message, needsSettings: Boolean(manual), manual: body, next: body.next, status: 400 });
    }
    const fallback = result.isNew ? '/settings?welcome=1' : '/settings';
    const next = safeNext(body.next, fallback);
    try {
      await deps.pool.close(result.user.id);
    } catch (err) {
      log('warn', 'closing cached mail connection failed', {
        userId: result.user.id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    await new Promise<void>((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));
    req.session.userId = result.user.id;
    res.redirect(next);
  });

  router.post('/logout', verifyCsrf, (req, res, next) => {
    req.session.destroy((err) => (err ? next(err) : res.redirect('/login')));
  });

  router.get('/settings', auth, (req, res) => renderSettings(deps, req, res));

  router.post('/settings/permission', auth, verifyCsrf, (req, res) => {
    const level = (req.body as Body).level as PermissionLevel;
    if (!LEVELS.some((l) => l.value === level)) return renderSettings(deps, req, res, 'Choose a valid permission level.', 400);
    setPermissionLevel(deps.db, (res.locals.user as User).id, level);
    res.redirect('/settings?saved=permission');
  });

  router.post('/settings/smtp', auth, verifyCsrf, async (req, res) => {
    const user = res.locals.user as User;
    const b = req.body as Body;
    const smtpPort = Number(b.smtp_port);
    if (!b.smtp_host?.trim() || !isPort(smtpPort, SMTP_PORTS) || !isSecurity(b.smtp_security) || !b.smtp_username?.trim()) {
      return renderSettings(deps, req, res, 'Check the SMTP settings.', 400);
    }
    const smtp = { smtpHost: b.smtp_host.trim(), smtpPort, smtpSecurity: b.smtp_security };
    // The IMAP password is the default SMTP password, so only the current server, the IMAP host or a listed host is allowed.
    if (smtp.smtpHost.toLowerCase() !== user.smtpHost.toLowerCase() && !isAllowedSmtpHost(deps.config, user.imapHost, smtp.smtpHost)) {
      return renderSettings(deps, req, res, 'This SMTP server is not allowed on this instance. Ask the administrator to list it in ALLOWED_IMAP_HOSTS.', 400);
    }
    try {
      await deps.guard(user.email, { ...serverSettingsOf(user), ...smtp });
    } catch (err) {
      if (err instanceof GuardError) return renderSettings(deps, req, res, err.message, 400);
      throw err;
    }
    const smtpPasswordEnc =
      b.use_imap_password === 'on'
        ? null
        : b.smtp_password
          ? encryptSecret(deps.config.encryptionKey, b.smtp_password)
          : user.smtpPasswordEnc;
    updateSmtpSettings(deps.db, user.id, { ...smtp, smtpUsername: b.smtp_username.trim(), smtpPasswordEnc });
    res.redirect('/settings?saved=smtp');
  });

  router.post('/settings/revoke', auth, verifyCsrf, (req, res) => {
    const grantId = (req.body as Body).grant_id;
    if (grantId) revokeUserGrant(deps.db, (res.locals.user as User).id, grantId, Date.now());
    res.redirect('/settings?saved=revoked');
  });

  router.post('/settings/delete', auth, verifyCsrf, async (req, res, next) => {
    const user = res.locals.user as User;
    await deps.pool.close(user.id);
    deleteUser(deps.db, user.id);
    deleteSessionsForUser(deps.db, user.id);
    req.session.destroy((err) => (err ? next(err) : res.redirect('/login?deleted=1')));
  });

  return router;
}
