import type { ImapFlow } from 'imapflow';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import { MailError } from './errors.js';
import { parseMessageIds, type ReplySource } from './format.js';
import { resolveFolder } from './ops/folders.js';

export interface ComposeInput {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  body: string;
  messageId: string;
  date: Date;
  inReplyTo?: string;
  references?: string;
}

export function buildMime(input: ComposeInput, opts: { keepBcc: boolean }): Promise<Buffer> {
  const node = new MailComposer({
    from: input.from,
    to: input.to,
    cc: input.cc,
    bcc: input.bcc,
    subject: input.subject,
    text: input.body,
    messageId: input.messageId,
    date: input.date,
    inReplyTo: input.inReplyTo,
    references: input.references,
  }).compile();
  (node as unknown as { keepBcc: boolean }).keepBcc = opts.keepBcc;
  return new Promise((resolve, reject) => node.build((err, buf) => (err ? reject(err) : resolve(buf))));
}

export async function loadReplySource(client: ImapFlow, folderInput: string, uid: number): Promise<ReplySource> {
  const folder = await resolveFolder(client, folderInput);
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    const msg = await client.fetchOne(String(uid), { uid: true, envelope: true, headers: ['references'] }, { uid: true });
    if (!msg) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    return {
      messageId: msg.envelope?.messageId ?? null,
      references: parseMessageIds(msg.headers?.toString('utf8') ?? ''),
      subject: msg.envelope?.subject ?? '',
    };
  } finally {
    lock.release();
  }
}
