import type { ImapFlow } from 'imapflow';
import { MailError } from '../errors.js';
import { parseMessageIds } from '../format.js';
import { resolveFolder, resolveRole } from './folders.js';
import { readMessage, type MessageDetail } from './message.js';

const MAX_IDS = 20;

interface Location {
  folder: string;
  uid: number;
}

async function withFolder<T>(client: ImapFlow, folder: string, fn: () => Promise<T>): Promise<T> {
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    return await fn();
  } finally {
    lock.release();
  }
}

async function gmailThread(client: ImapFlow, folder: string, uid: number): Promise<Location[]> {
  const threadId = await withFolder(client, folder, async () => {
    const msg = await client.fetchOne(String(uid), { uid: true, threadId: true }, { uid: true });
    if (!msg) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    return msg.threadId;
  });
  if (!threadId) return [{ folder, uid }];
  const allMail = await resolveRole(client, 'all');
  const uids = await withFolder(client, allMail, async () => (await client.search({ threadId }, { uid: true })) || []);
  return uids.map((u) => ({ folder: allMail, uid: u }));
}

async function headerThread(client: ImapFlow, folder: string, uid: number): Promise<Location[]> {
  const ids = await withFolder(client, folder, async () => {
    const msg = await client.fetchOne(String(uid), { uid: true, envelope: true, headers: ['references'] }, { uid: true });
    if (!msg) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    const refs = parseMessageIds(msg.headers?.toString('utf8') ?? '');
    const set = new Set([...refs, msg.envelope?.inReplyTo, msg.envelope?.messageId].filter((v): v is string => Boolean(v)));
    return [...set].slice(-MAX_IDS);
  });
  if (ids.length === 0) return [{ folder, uid }];

  const folders = [folder];
  const sent = await resolveRole(client, 'sent').catch(() => null);
  if (sent && sent !== folder) folders.push(sent);

  const found: Location[] = [{ folder, uid }];
  for (const f of folders) {
    await withFolder(client, f, async () => {
      for (const id of ids) {
        for (const header of ['message-id', 'references']) {
          const uids = (await client.search({ header: { [header]: id } }, { uid: true })) || [];
          uids.forEach((u) => found.push({ folder: f, uid: u }));
        }
      }
    });
  }
  return found;
}

export async function getThread(client: ImapFlow, folderInput: string, uid: number, max = 50): Promise<MessageDetail[]> {
  const folder = await resolveFolder(client, folderInput);
  const locations = client.capabilities.has('X-GM-EXT-1')
    ? await gmailThread(client, folder, uid)
    : await headerThread(client, folder, uid);

  const byFolder = new Map<string, Set<number>>();
  for (const loc of locations) {
    if (!byFolder.has(loc.folder)) byFolder.set(loc.folder, new Set());
    byFolder.get(loc.folder)!.add(loc.uid);
  }

  const messages: MessageDetail[] = [];
  for (const [f, uids] of byFolder) {
    await withFolder(client, f, async () => {
      for (const u of uids) {
        try {
          messages.push(await readMessage(client, f, u));
        } catch (err) {
          if (!(err instanceof MailError && err.code === 'NOT_FOUND')) throw err;
        }
      }
    });
  }
  if (messages.length === 0) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);

  const seen = new Set<string>();
  const unique = messages.filter((m) => {
    const key = m.messageId ?? `${m.folder}:${m.uid}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  unique.sort((a, b) => (a.date ?? '').localeCompare(b.date ?? ''));
  return unique.slice(-max);
}
