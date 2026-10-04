import type { ImapFlow } from 'imapflow';
import { MailError } from '../errors.js';
import { resolveFolder, resolveRole } from './folders.js';

export const MAX_BATCH = 100;
export type FlagName = 'seen' | 'flagged';

const FLAGS: Record<FlagName, string> = { seen: '\\Seen', flagged: '\\Flagged' };

function uidSet(uids: number[]): string {
  if (uids.length === 0) throw new MailError('INVALID_INPUT', 'Provide at least one uid.');
  if (uids.length > MAX_BATCH) throw new MailError('INVALID_INPUT', `At most ${MAX_BATCH} uids per call.`);
  return uids.join(',');
}

export async function setFlags(
  client: ImapFlow,
  folderInput: string,
  uids: number[],
  add: FlagName[],
  remove: FlagName[],
): Promise<{ folder: string; updated: number }> {
  const set = uidSet(uids);
  const folder = await resolveFolder(client, folderInput);
  const lock = await client.getMailboxLock(folder);
  try {
    if (add.length) await client.messageFlagsAdd(set, add.map((f) => FLAGS[f]), { uid: true });
    if (remove.length) await client.messageFlagsRemove(set, remove.map((f) => FLAGS[f]), { uid: true });
    return { folder, updated: uids.length };
  } finally {
    lock.release();
  }
}

async function move(client: ImapFlow, from: string, to: string, uids: number[]): Promise<{ from: string; to: string; moved: number }> {
  const set = uidSet(uids);
  if (from === to) throw new MailError('INVALID_INPUT', 'Source and destination folders are the same.');
  const lock = await client.getMailboxLock(from);
  try {
    const result = await client.messageMove(set, to, { uid: true });
    const moved = result ? (result.uidMap?.size ?? uids.length) : 0;
    return { from, to, moved };
  } finally {
    lock.release();
  }
}

export async function moveMessages(client: ImapFlow, folderInput: string, uids: number[], destinationInput: string) {
  uidSet(uids);
  const from = await resolveFolder(client, folderInput);
  const to = await resolveFolder(client, destinationInput);
  return move(client, from, to, uids);
}

export async function deleteMessages(client: ImapFlow, folderInput: string, uids: number[]) {
  uidSet(uids);
  const from = await resolveFolder(client, folderInput);
  const trash = await resolveRole(client, 'trash');
  if (from === trash) {
    throw new MailError('INVALID_INPUT', 'These messages are already in Trash. Permanent deletion is not supported.');
  }
  return move(client, from, trash, uids);
}

export async function appendToRole(
  client: ImapFlow,
  role: 'drafts' | 'sent',
  raw: Buffer,
  flags: string[],
): Promise<{ folder: string; uid: number | null }> {
  const folder = await resolveRole(client, role);
  const result = await client.append(folder, raw, flags);
  return { folder, uid: result && typeof result === 'object' && result.uid ? result.uid : null };
}
