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

function assertNoLineBreaks(input: ComposeInput): void {
  const fields: [string, string | undefined][] = [
    ['from', input.from],
    ...input.to.map((v): [string, string] => ['to', v]),
    ...input.cc.map((v): [string, string] => ['cc', v]),
    ...input.bcc.map((v): [string, string] => ['bcc', v]),
    ['subject', input.subject],
    ['messageId', input.messageId],
    ['inReplyTo', input.inReplyTo],
    ['references', input.references],
  ];
  for (const [name, value] of fields) {
    if (value !== undefined && /[\r\n]/.test(value)) throw new MailError('INVALID_INPUT', `${name} must not contain line breaks.`);
  }
}

export async function buildMime(input: ComposeInput, opts: { keepBcc: boolean }): Promise<Buffer> {
  assertNoLineBreaks(input);
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
