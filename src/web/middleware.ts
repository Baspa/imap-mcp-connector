import type { RequestHandler } from 'express';
import type { Db } from '../db/index.js';
import { findUserById } from '../db/users.js';

export function safeNext(value: unknown, fallback = '/settings'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) {
    return fallback;
  }
  return value;
}

export function requireUser(db: Db): RequestHandler {
  return (req, res, next) => {
    const user = req.session.userId ? findUserById(db, req.session.userId) : undefined;
    if (!user) {
      res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
      return;
    }
    res.locals.user = user;
    next();
  };
}
