import type { FetchMessageObject, FetchQueryObject, ImapFlow, SearchObject } from 'imapflow';
import { simpleParser } from 'mailparser';
import { MailError } from '../errors.js';
import { formatAddress, htmlToText, snippet, toIsoDate } from '../format.js';
import { resolveFolder } from './folders.js';

export interface SearchInput {
  folder?: string;
  from?: string;
  to?: string;
  subject?: string;
  text?: string;
  since?: string;
  before?: string;
  unread?: boolean;
  flagged?: boolean;
  limit?: number;
  cursor?: string;
}

export interface MessageSummary {
  uid: number;
  from: string;
  to: string[];
  subject: string;
  date: string | null;
  flags: string[];
  snippet: string;
}

export function parseDateInput(value: string, field: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new MailError('INVALID_INPUT', `${field} must be a date like 2025-01-31.`);
  return date;
}

function buildQuery(input: SearchInput): SearchObject {
  const query: SearchObject = { all: true };
  if (input.from) query.from = input.from;
  if (input.to) query.to = input.to;
  if (input.subject) query.subject = input.subject;
  if (input.text) query.body = input.text;
  if (input.since) query.since = parseDateInput(input.since, 'since');
  if (input.before) query.before = parseDateInput(input.before, 'before');
  if (input.unread !== undefined) query.seen = !input.unread;
  if (input.flagged !== undefined) query.flagged = input.flagged;
  return query;
}

async function summarize(msg: FetchMessageObject): Promise<MessageSummary> {
  let preview = '';
  if (msg.source) {
    try {
      const parsed = await simpleParser(msg.source);
      preview = parsed.text ?? (parsed.html ? htmlToText(parsed.html) : '');
    } catch {
      preview = '';
    }
  }
  return {
    uid: msg.uid,
    from: formatAddress(msg.envelope?.from?.[0]),
    to: (msg.envelope?.to ?? []).map((a) => formatAddress(a)),
    subject: msg.envelope?.subject ?? '',
    date: toIsoDate(msg.envelope?.date),
    flags: [...(msg.flags ?? [])],
    snippet: snippet(preview),
  };
}

export async function searchMessages(
  client: ImapFlow,
  input: SearchInput,
): Promise<{ folder: string; messages: MessageSummary[]; nextCursor: string | null }> {
  const query = buildQuery(input);
  const limit = Math.min(Math.max(Math.trunc(Number.isFinite(input.limit) ? (input.limit as number) : 20), 1), 100);
  let cursor = Number.POSITIVE_INFINITY;
  if (input.cursor !== undefined) {
    cursor = Number(input.cursor);
    if (!Number.isInteger(cursor) || cursor <= 0) throw new MailError('INVALID_INPUT', 'Invalid cursor.');
  }
  const folder = await resolveFolder(client, input.folder ?? 'INBOX');

  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    const uids = ((await client.search(query, { uid: true })) || []).filter((u) => u < cursor).sort((a, b) => b - a);
    const page = uids.slice(0, limit);
    if (page.length === 0) return { folder, messages: [], nextCursor: null };

    const fetchQuery = { uid: true, envelope: true, flags: true, source: { maxLength: 8192 } } as unknown as FetchQueryObject;
    const byUid = new Map<number, MessageSummary>();
    for await (const msg of client.fetch(page.join(','), fetchQuery, { uid: true })) {
      byUid.set(msg.uid, await summarize(msg));
    }
    return {
      folder,
      messages: page.map((u) => byUid.get(u)).filter((m): m is MessageSummary => m !== undefined),
      nextCursor: uids.length > limit ? String(page[page.length - 1]) : null,
    };
  } finally {
    lock.release();
  }
}
