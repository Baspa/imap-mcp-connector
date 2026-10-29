import { Router, type Response } from 'express';
import type { AppDeps } from '../app.js';
import type { User } from '../db/users.js';
import { audit } from '../log.js';
import { csrfToken, verifyCsrf } from './csrf.js';
import { levelLabel } from './levels.js';
import { requireUser } from './middleware.js';

function expired(res: Response): void {
  res.status(400).render('error', {
    title: 'Request expired',
    message: 'This connection request expired or was already used. Start connecting again from Claude or ChatGPT.',
  });
}

export function consentRouter(deps: AppDeps): Router {
  const router = Router();
  const auth = requireUser(deps.db);

  router.get('/consent', auth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const reqId = String(req.query.req ?? '');
    const described = deps.provider.describePending(reqId);
    if (!described) return expired(res);
    const user = res.locals.user as User;
    res.render('consent', {
      title: 'Approve access',
      csrf: csrfToken(req),
      reqId,
      clientName: described.clientName,
      redirectHost: new URL(described.pending.redirectUri).host,
      user,
      level: levelLabel(user.permissionLevel),
    });
  });

  router.post('/consent', auth, verifyCsrf, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const reqId = typeof body.req === 'string' ? body.req : '';
    const user = res.locals.user as User;
    if (body.decision === 'approve') {
      const described = deps.provider.describePending(reqId);
      const url = deps.provider.approve(reqId, user.id);
      if (!url) return expired(res);
      audit('app_connected', {
        userId: user.id,
        clientName: described?.clientName ?? null,
        redirectHost: described ? new URL(described.pending.redirectUri).host : null,
        level: user.permissionLevel,
      });
      return res.redirect(url);
    }
    const url = deps.provider.deny(reqId);
    if (!url) return expired(res);
    res.redirect(url);
  });

  return router;
}
