import type { ImapFlow, SearchObject } from 'imapflow';
import { MailError } from '../errors.js';
import { parseMessageIds, toIsoDate } from '../format.js';
import { resolveFolder, resolveRole, type FolderRole } from './folders.js';
import { readMessage, type MessageDetail } from './message.js';

const MAX_IDS = 20;

interface Location {
  folder: string;
  uid: number;
}

interface Candidate extends Location {
  messageId: string | null;
  date: string | null;
}

async function withFolder<T>(client: ImapFlow, folder: string, fn: () => Promise<T>): Promise<T> {
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    return await fn();
  } finally {
    lock.release();
  }
}

/** A role folder's path, or null when the mailbox has no such folder. */
async function optionalRole(client: ImapFlow, role: FolderRole): Promise<string | null> {
  try {
    return await resolveRole(client, role);
  } catch (err) {
    if (err instanceof MailError && err.code === 'NOT_FOUND') return null;
    throw err;
  }
}

async function gmailThread(client: ImapFlow, folder: string, uid: number): Promise<Location[]> {
  const allMail = await optionalRole(client, 'all');
  if (!allMail) return headerThread(client, folder, uid);
  const threadId = await withFolder(client, folder, async () => {
    const msg = await client.fetchOne(String(uid), { uid: true, threadId: true }, { uid: true });
    if (!msg) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    return msg.threadId;
  });
  if (!threadId) return [{ folder, uid }];
  const uids = await withFolder(client, allMail, async () => (await client.search({ threadId }, { uid: true })) || []);
  return [{ folder, uid }, ...uids.map((u) => ({ folder: allMail, uid: u }))];
}

async function headerThread(client: ImapFlow, folder: string, uid: number): Promise<Location[]> {
  const ids = await withFolder(client, folder, async () => {
    const msg = await client.fetchOne(String(uid), { uid: true, envelope: true, headers: ['references'] }, { uid: true });
    if (!msg) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    const refs = parseMessageIds(msg.headers?.toString('utf8') ?? '');
    const all = [...new Set([...refs, msg.envelope?.inReplyTo, msg.envelope?.messageId].filter((v): v is string => Boolean(v)))];
    // Keep the root (first reference) plus the newest ids so long threads still reach their start.
    return all.length > MAX_IDS ? [all[0], ...all.slice(-(MAX_IDS - 1))] : all;
  });
  if (ids.length === 0) return [{ folder, uid }];

  const folders = new Set([folder]);
  for (const role of ['inbox', 'sent'] as const) {
    const path = await optionalRole(client, role);
    if (path) folders.add(path);
  }

  const query: SearchObject = { or: ids.flatMap((id): SearchObject[] => [{ header: { 'message-id': id } }, { header: { references: id } }]) };
  const found: Location[] = [{ folder, uid }];
  for (const f of folders) {
    await withFolder(client, f, async () => {
      const uids = (await client.search(query, { uid: true })) || [];
      uids.forEach((u) => found.push({ folder: f, uid: u }));
    });
  }
  return found;
}

/** Envelope-only metadata for the candidate locations (one FETCH per folder), deduped by Message-ID with the first copy winning. */
async function loadCandidates(client: ImapFlow, locations: Location[]): Promise<Candidate[]> {
  const byFolder = new Map<string, Set<number>>();
  for (const loc of locations) {
    if (!byFolder.has(loc.folder)) byFolder.set(loc.folder, new Set());
    byFolder.get(loc.folder)!.add(loc.uid);
  }
  const meta = new Map<string, Candidate>();
  for (const [folder, uids] of byFolder) {
    await withFolder(client, folder, async () => {
      for await (const msg of client.fetch([...uids].join(','), { uid: true, envelope: true }, { uid: true })) {
        meta.set(`${folder}:${msg.uid}`, {
          folder,
          uid: msg.uid,
          messageId: msg.envelope?.messageId ?? null,
          date: toIsoDate(msg.envelope?.date),
        });
      }
    });
  }
  const seen = new Set<string>();
  const candidates: Candidate[] = [];
  for (const loc of locations) {
    const c = meta.get(`${loc.folder}:${loc.uid}`);
    if (!c) continue;
    const key = c.messageId ?? `${c.folder}:${c.uid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push(c);
  }
  return candidates;
}

/** Oldest first; messages without a date sort before dated ones. */
function compareDates(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export async function getThread(client: ImapFlow, folderInput: string, uid: number, max = 50): Promise<MessageDetail[]> {
  const folder = await resolveFolder(client, folderInput);
  const locations = client.capabilities.has('X-GM-EXT-1')
    ? await gmailThread(client, folder, uid)
    : await headerThread(client, folder, uid);

  const candidates = await loadCandidates(client, locations);
  if (candidates.length === 0) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
  candidates.sort((a, b) => compareDates(a.date, b.date));

  // Keep the newest `max`, but the requested message is always part of the result.
  const limit = Math.max(1, Math.floor(max));
  let kept = candidates.slice(-limit);
  const seed = candidates.find((c) => c.folder === folder && c.uid === uid);
  if (seed && !kept.includes(seed)) kept = [seed, ...kept.slice(1)];

  const keptByFolder = new Map<string, Candidate[]>();
  for (const c of kept) {
    if (!keptByFolder.has(c.folder)) keptByFolder.set(c.folder, []);
    keptByFolder.get(c.folder)!.push(c);
  }
  const details = new Map<Candidate, MessageDetail>();
  for (const [f, group] of keptByFolder) {
    await withFolder(client, f, async () => {
      for (const c of group) {
        try {
          details.set(c, await readMessage(client, f, c.uid));
        } catch (err) {
          if (!(err instanceof MailError && err.code === 'NOT_FOUND')) throw err;
        }
      }
    });
  }
  const messages = kept.flatMap((c) => details.get(c) ?? []);
  if (messages.length === 0) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
  return messages;
}
