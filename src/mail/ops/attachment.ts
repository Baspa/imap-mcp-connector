import type { ImapFlow } from 'imapflow';
import { extractText, getDocumentProxy } from 'unpdf';
import { MailError } from '../errors.js';
import { htmlToText, truncateUtf8 } from '../format.js';
import { resolveFolder } from './folders.js';
import { downloadPart, scanStructure } from './message.js';

export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;

export interface AttachmentContent {
  filename: string;
  contentType: string;
  size: number;
  text: string | null;
  truncated: boolean;
  note?: string;
}

type TextKind = 'text' | 'html' | 'pdf';

function textKind(contentType: string, filename: string): TextKind | null {
  const type = contentType.toLowerCase();
  if (type === 'text/html') return 'html';
  if (type.startsWith('text/') || ['application/json', 'application/xml', 'application/csv'].includes(type)) return 'text';
  if (type === 'application/pdf' || filename.toLowerCase().endsWith('.pdf')) return 'pdf';
  return null;
}

async function pdfText(buf: Buffer): Promise<string> {
  const pdf = await getDocumentProxy(new Uint8Array(buf));
  const { text } = await extractText(pdf, { mergePages: true });
  return text;
}

export async function getAttachment(
  client: ImapFlow,
  folderInput: string,
  uid: number,
  partId: string,
): Promise<AttachmentContent> {
  const folder = await resolveFolder(client, folderInput);
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  try {
    const msg = await client.fetchOne(String(uid), { uid: true, bodyStructure: true }, { uid: true });
    if (!msg || !msg.bodyStructure) throw new MailError('NOT_FOUND', `Message ${uid} was not found in ${folder}.`);
    const info = scanStructure(msg.bodyStructure).attachments.find((a) => a.partId === partId);
    if (!info) throw new MailError('NOT_FOUND', `Attachment part ${partId} was not found. Use get_message to list attachments.`);
    if (info.size > MAX_ATTACHMENT_BYTES) {
      throw new MailError('TOO_LARGE', `Attachment is larger than the ${MAX_ATTACHMENT_BYTES / 1024 / 1024} MB limit.`);
    }
    const base = { filename: info.filename, contentType: info.contentType, size: info.size };
    const kind = textKind(info.contentType, info.filename);
    if (!kind) return { ...base, text: null, truncated: false, note: 'Binary attachment; content not extracted.' };

    const buf = await downloadPart(client, uid, partId, MAX_ATTACHMENT_BYTES);
    const raw = kind === 'pdf' ? await pdfText(buf) : kind === 'html' ? htmlToText(buf.toString('utf8')) : buf.toString('utf8');
    const { text, truncated } = truncateUtf8(raw);
    return { ...base, text, truncated };
  } finally {
    lock.release();
  }
}
