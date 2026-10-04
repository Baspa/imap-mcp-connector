import { timingSafeEqual } from 'node:crypto';
import type { Request, RequestHandler } from 'express';
import { randomToken } from '../crypto.js';

export function csrfToken(req: Request): string {
  if (!req.session.csrfToken) req.session.csrfToken = randomToken();
  return req.session.csrfToken;
}

function equal(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export const verifyCsrf: RequestHandler = (req, res, next) => {
  const sent = (req.body as Record<string, unknown> | undefined)?._csrf;
  const expected = req.session.csrfToken;
  if (!expected || typeof sent !== 'string' || !equal(sent, expected)) {
    res.status(403).render('error', { title: 'Form expired', message: 'Please go back, reload the page and try again.' });
    return;
  }
  next();
};
