import type { ImapFlow, MessageStructureObject } from 'imapflow';
import { MailError } from '../errors.js';
import { formatAddress, htmlToText, plainTextDiffersFromHtml, toIsoDate, truncateUtf8 } from '../format.js';
import { resolveFolder } from './folders.js';

export interface AttachmentInfo {
  partId: string;
  filename: string;
  contentType: string;
  size: number;
  charset?: string;
}

export interface MessageDetail {
  folder: string;
  uid: number;
  messageId: string | null;
  from: string;
  to: string[];
  cc: string[];
  date: string | null;
  subject: string;
  flags: string[];
  body: string;
  bodyTruncated: boolean;
  /** True when the plain-text part carries content the HTML part does not, which a person would not see. */
  plainTextDiffersFromHtml: boolean;
  attachments: AttachmentInfo[];
}

interface StructureScan {
  text?: MessageStructureObject;
  html?: MessageStructureObject;
  attachments: AttachmentInfo[];
}

export function scanStructure(root: MessageStructureObject): StructureScan {
  const scan: StructureScan = { attachments: [] };
  const visit = (node: MessageStructureObject) => {
    const type = (node.type ?? '').toLowerCase();
    const part = node.part ?? '1';
    const filename = node.dispositionParameters?.filename ?? node.parameters?.name;
    const charset = node.parameters?.charset;
    if (type === 'message/rfc822') {
      scan.attachments.push({ partId: part, filename: filename ?? 'attached-message.eml', contentType: type, size: node.size ?? 0 });
      return;
    }
    if (node.childNodes?.length) {
      node.childNodes.forEach(visit);
      return;
    }
    const isAttachment = node.disposition?.toLowerCase() === 'attachment' || Boolean(filename);
    if (isAttachment) {
      scan.attachments.push({
        partId: part,
        filename: filename ?? `part-${part}`,
        contentType: type,
        size: node.size ?? 0,
        ...(charset ? { charset } : {}),
      });
    } else if (type === 'text/plain' && !scan.text) {
      scan.text = node;
    } else if (type === 'text/html' && !scan.html) {
      scan.html = node;
    }
  };
  visit(root);
  return scan;
}

export interface DownloadedPart {
  data: Buffer;
  /** Charset of `data`: imapflow converts inline text parts to UTF-8 and reports 'utf-8' for them. */
  charset?: string;
}

export async function downloadPart(client: ImapFlow, uid: number, part: string, maxBytes: number): Promise<DownloadedPart> {
  const { meta, content } = await client.download(String(uid), part, { uid: true, maxBytes });
  // imapflow resolves without content when the message or part is gone/empty.
  if (!content) return { data: Buffer.alloc(0) };
  const chunks: Buffer[] = [];
  for await (const chunk of content) chunks.push(chunk as Buffer);
  return { data: Buffer.concat(chunks), ...(meta?.charset ? { charset: meta.charset } : {}) };
}

/** Reads one message; the folder must already be selected (caller holds the mailbox lock). */
export async function readMessage(client: ImapFlow, folder: string, uid: number): Promise<MessageDetail> {
  const msg = await client.fetchOne(String(uid), { uid: true, envelope: true, flags: true, bodyStructure: true }, { uid: true });
  if (!msg || !msg.bodyStructure) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
  const scan = scanStructure(msg.bodyStructure);
  let body = '';
  let textPartDiverges = false;
  if (scan.text) {
    body = (await downloadPart(client, uid, scan.text.part ?? '1', 1_000_000)).data.toString('utf8');
    if (scan.html) {
      const html = (await downloadPart(client, uid, scan.html.part ?? '1', 1_000_000)).data.toString('utf8');
      textPartDiverges = plainTextDiffersFromHtml(body, htmlToText(html));
    }
  } else if (scan.html) {
    body = htmlToText((await downloadPart(client, uid, scan.html.part ?? '1', 1_000_000)).data.toString('utf8'));
  }
  const truncated = truncateUtf8(body);
  return {
    folder,
    uid,
    messageId: msg.envelope?.messageId ?? null,
    from: formatAddress(msg.envelope?.from?.[0]),
    to: (msg.envelope?.to ?? []).map((a) => formatAddress(a)),
    cc: (msg.envelope?.cc ?? []).map((a) => formatAddress(a)),
    date: toIsoDate(msg.envelope?.date),
    subject: msg.envelope?.subject ?? '',
    flags: [...(msg.flags ?? [])],
    body: truncated.text,
    bodyTruncated: truncated.truncated,
    plainTextDiffersFromHtml: textPartDiverges,
    attachments: scan.attachments,
  };
}

export async function getMessage(client: ImapFlow, folderInput: string, uid: number): Promise<MessageDetail> {
  const folder = await resolveFolder(client, folderInput);
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    return await readMessage(client, folder, uid);
  } finally {
    lock.release();
  }
}
