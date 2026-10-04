import type { ImapFlow } from 'imapflow';
import { MailError } from '../errors.js';
import { resolveFolder, resolveRole } from './folders.js';

export const MAX_BATCH = 100;
export type FlagName = 'seen' | 'flagged';

const FLAGS: Record<FlagName, string> = { seen: '\\Seen', flagged: '\\Flagged' };

/** Validates and de-duplicates a uid list. */
function checkUids(uids: number[]): number[] {
  if (uids.length === 0) throw new MailError('INVALID_INPUT', 'Provide at least one uid.');
  if (!uids.every((u) => Number.isInteger(u) && u > 0)) throw new MailError('INVALID_INPUT', 'uids must be positive integers.');
  const unique = [...new Set(uids)];
  if (unique.length > MAX_BATCH) throw new MailError('INVALID_INPUT', `At most ${MAX_BATCH} uids per call.`);
  return unique;
}

/** Which of the requested uids exist in the currently selected mailbox. Call while holding the mailbox lock. */
async function existingUids(client: ImapFlow, uids: number[]): Promise<number[]> {
  const found = new Set((await client.search({ uid: uids.join(',') }, { uid: true })) || []);
  return uids.filter((u) => found.has(u));
}

export async function setFlags(
  client: ImapFlow,
  folderInput: string,
  uids: number[],
  add: FlagName[],
  remove: FlagName[],
): Promise<{ folder: string; updated: number }> {
  const requested = checkUids(uids);
  const folder = await resolveFolder(client, folderInput);
  const lock = await client.getMailboxLock(folder);
  try {
    const existing = await existingUids(client, requested);
    if (existing.length === 0) return { folder, updated: 0 };
    const set = existing.join(',');
    if (add.length) await client.messageFlagsAdd(set, add.map((f) => FLAGS[f]), { uid: true });
    if (remove.length) await client.messageFlagsRemove(set, remove.map((f) => FLAGS[f]), { uid: true });
    return { folder, updated: existing.length };
  } finally {
    lock.release();
  }
}

async function move(client: ImapFlow, from: string, to: string, requested: number[]): Promise<{ from: string; to: string; moved: number }> {
  if (from === to) throw new MailError('INVALID_INPUT', 'Source and destination folders are the same.');
  const hasMove = client.capabilities.has('MOVE');
  if (!hasMove && !client.capabilities.has('UIDPLUS')) {
    throw new MailError('UPSTREAM_UNAVAILABLE', 'This mail server cannot move messages safely (no MOVE or UIDPLUS support).');
  }
  const lock = await client.getMailboxLock(from);
  try {
    const existing = await existingUids(client, requested);
    if (existing.length === 0) throw new MailError('NOT_FOUND', `None of those messages exist in ${from}.`);
    const set = existing.join(',');
    if (hasMove) {
      const result = await client.messageMove(set, to, { uid: true });
      if (!result) throw new MailError('UPSTREAM_UNAVAILABLE', 'The server refused to move the messages.');
      return { from, to, moved: result.uidMap?.size ?? existing.length };
    }
    // No MOVE: imapflow's own fallback expunges unconditionally, so copy, verify, then UID EXPUNGE only our set.
    const copied = await client.messageCopy(set, to, { uid: true });
    if (!copied) throw new MailError('UPSTREAM_UNAVAILABLE', 'The server refused to copy the messages; nothing was moved.');
    await client.messageDelete(set, { uid: true });
    return { from, to, moved: existing.length };
  } finally {
    lock.release();
  }
}

export async function moveMessages(client: ImapFlow, folderInput: string, uids: number[], destinationInput: string) {
  const requested = checkUids(uids);
  const from = await resolveFolder(client, folderInput);
  const to = await resolveFolder(client, destinationInput);
  return move(client, from, to, requested);
}

export async function deleteMessages(client: ImapFlow, folderInput: string, uids: number[]) {
  const requested = checkUids(uids);
  const from = await resolveFolder(client, folderInput);
  const trash = await resolveRole(client, 'trash');
  if (from === trash) {
    throw new MailError('INVALID_INPUT', 'These messages are already in Trash. Permanent deletion is not supported.');
  }
  return move(client, from, trash, requested);
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
