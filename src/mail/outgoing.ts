import { randomUUID } from 'node:crypto';
import { decryptSecret } from '../crypto.js';
import { deleteSend, recordSend, sendsSince } from '../db/counters.js';
import type { Db } from '../db/index.js';
import type { User } from '../db/users.js';
import { buildMime, loadReplySource, type ComposeInput } from './compose.js';
import { MailError, toMailError } from './errors.js';
import { buildReplyHeaders } from './format.js';
import { appendToRole } from './ops/actions.js';
import { runGuard, type MailPool } from './pool.js';
import type { SmtpFactory } from './smtp.js';

const HOUR = 60 * 60 * 1000;

export interface ComposeRequest {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject?: string;
  body: string;
  replyToUid?: number;
  replyToFolder?: string;
}

export interface OutgoingDeps {
  db: Db;
  key: Buffer;
  pool: MailPool;
  smtpFactory: SmtpFactory;
  defaultSendLimitPerHour: number;
  signInUrl: string;
  /** Re-checks the instance allowlist and network rules before connecting to SMTP; throws GuardError to refuse. */
  guard?: (user: User) => Promise<void>;
  now?: () => number;
}

async function prepare(deps: OutgoingDeps, user: User, req: ComposeRequest, now: number): Promise<ComposeInput> {
  const reply =
    req.replyToUid !== undefined
      ? buildReplyHeaders(await deps.pool.withImap(user, (c) => loadReplySource(c, req.replyToFolder ?? 'INBOX', req.replyToUid!)))
      : undefined;
  const subject = req.subject?.trim() || reply?.subject;
  if (!subject) throw new MailError('INVALID_INPUT', 'subject is required unless replying to a message.');
  const domain = user.email.slice(user.email.lastIndexOf('@') + 1);
  return {
    from: user.email,
    to: req.to,
    cc: req.cc ?? [],
    bcc: req.bcc ?? [],
    subject,
    body: req.body,
    messageId: `<${randomUUID()}@${domain}>`,
    date: new Date(now),
    inReplyTo: reply?.inReplyTo,
    references: reply?.references,
  };
}

export async function createDraft(deps: OutgoingDeps, user: User, req: ComposeRequest) {
  const input = await prepare(deps, user, req, deps.now?.() ?? Date.now());
  const raw = await buildMime(input, { keepBcc: true });
  const saved = await deps.pool.withImap(user, (c) => appendToRole(c, 'drafts', raw, ['\\Draft', '\\Seen']));
  return { ...saved, messageId: input.messageId };
}

function smtpPassword(deps: OutgoingDeps, user: User): string {
  try {
    return decryptSecret(deps.key, user.smtpPasswordEnc ?? user.imapPasswordEnc);
  } catch {
    throw new MailError('AUTH_FAILED', `The stored SMTP password is unreadable. Update SMTP settings at ${deps.signInUrl}.`);
  }
}

async function deliver(deps: OutgoingDeps, user: User, req: ComposeRequest, now: number): Promise<ComposeInput> {
  const recipients = [...req.to, ...(req.cc ?? []), ...(req.bcc ?? [])];
  const input = await prepare(deps, user, req, now);
  const wire = await buildMime(input, { keepBcc: false });
  await runGuard(deps.guard, user);
  const transport = deps.smtpFactory(user, smtpPassword(deps, user));
  try {
    await transport.sendMail({ envelope: { from: user.email, to: recipients }, raw: wire });
  } catch (err) {
    const mailError = toMailError(err);
    if (mailError?.code === 'AUTH_FAILED') {
      throw new MailError('AUTH_FAILED', `The SMTP server rejected the login. Update SMTP settings at ${deps.signInUrl}.`);
    }
    throw mailError ?? err;
  } finally {
    transport.close();
  }
  return input;
}

export async function sendEmail(deps: OutgoingDeps, user: User, req: ComposeRequest) {
  const now = deps.now?.() ?? Date.now();
  if (req.to.length === 0) throw new MailError('INVALID_INPUT', 'At least one "to" recipient is required.');

  const limit = user.sendLimitPerHour ?? deps.defaultSendLimitPerHour;
  const recent = sendsSince(deps.db, user.id, now - HOUR);
  if (recent.count >= limit) {
    const next = new Date((recent.oldest ?? now) + HOUR).toISOString();
    throw new MailError('RATE_LIMITED', `Send limit of ${limit} emails per hour reached. Next send allowed after ${next}.`);
  }
  // Reserve the slot synchronously after the check so concurrent sends cannot exceed the limit;
  // release it if the message is not delivered.
  const reservation = recordSend(deps.db, user.id, now);

  let input: ComposeInput;
  try {
    input = await deliver(deps, user, req, now);
  } catch (err) {
    deleteSend(deps.db, reservation);
    throw err;
  }

  let savedToSent = false;
  if (!user.autoSavesSent) {
    try {
      const copy = await buildMime(input, { keepBcc: true });
      await deps.pool.withImap(user, (c) => appendToRole(c, 'sent', copy, ['\\Seen']));
      savedToSent = true;
    } catch {
      savedToSent = false;
    }
  }
  return { messageId: input.messageId, savedToSent };
}
