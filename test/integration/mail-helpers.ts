import { randomUUID } from 'node:crypto';
import { ImapFlow } from 'imapflow';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import { inject } from 'vitest';
import type { MailServerSettings } from '../../src/types.js';

export function greenmail() {
  return inject('greenmail');
}

export async function createMailUser(): Promise<{ email: string; password: string }> {
  const email = `u${randomUUID().slice(0, 8)}@test.local`;
  const password = `pw-${randomUUID().slice(0, 8)}`;
  const { host, apiPort } = greenmail();
  const res = await fetch(`http://${host}:${apiPort}/api/user`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, login: email, password }),
  });
  if (!res.ok) throw new Error(`GreenMail user creation failed: ${res.status} ${await res.text()}`);
  return { email, password };
}

export function greenmailSettings(): MailServerSettings {
  const { host, imapPort, smtpPort } = greenmail();
  return {
    imapHost: host,
    imapPort,
    imapSecurity: 'none',
    smtpHost: host,
    smtpPort,
    smtpSecurity: 'none',
    autoSavesSent: false,
  };
}

export async function connectImap(email: string, password: string): Promise<ImapFlow> {
  const { host, imapPort } = greenmail();
  const client = new ImapFlow({
    host,
    port: imapPort,
    secure: false,
    doSTARTTLS: false,
    auth: { user: email, pass: password },
    logger: false,
  });
  client.on('error', () => undefined);
  await client.connect();
  return client;
}

export async function createFolders(client: ImapFlow, names = ['Drafts', 'Sent', 'Trash', 'Archive']): Promise<void> {
  for (const name of names) await client.mailboxCreate(name).catch(() => undefined);
}

export interface SeedMessage {
  from?: string;
  to?: string;
  subject: string;
  text?: string;
  html?: string;
  date?: Date;
  messageId?: string;
  inReplyTo?: string;
  references?: string[];
  attachments?: { filename: string; content: string | Buffer; contentType: string }[];
  flags?: string[];
}

export async function appendMessage(client: ImapFlow, folder: string, msg: SeedMessage): Promise<void> {
  const node = new MailComposer({
    from: msg.from ?? 'Sender <sender@example.com>',
    to: msg.to ?? 'me@test.local',
    subject: msg.subject,
    text: msg.text,
    html: msg.html,
    date: msg.date ?? new Date(),
    messageId: msg.messageId,
    inReplyTo: msg.inReplyTo,
    references: msg.references,
    attachments: msg.attachments,
  }).compile();
  const raw = await new Promise<Buffer>((resolve, reject) =>
    node.build((err, buf) => (err ? reject(err) : resolve(buf))),
  );
  await client.append(folder, raw, msg.flags ?? [], msg.date);
}

export async function appendRaw(client: ImapFlow, folder: string, raw: Buffer): Promise<void> {
  await client.append(folder, raw, []);
}

export async function findUid(client: ImapFlow, folder: string, subject: string): Promise<number> {
  const lock = await client.getMailboxLock(folder);
  try {
    const uids = (await client.search({ subject }, { uid: true })) || [];
    if (uids.length === 0) throw new Error(`No message with subject "${subject}" in ${folder}`);
    return uids[uids.length - 1];
  } finally {
    lock.release();
  }
}
