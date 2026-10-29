import type { ImapFlow } from 'imapflow';
import { getDocumentProxy } from 'unpdf';
import { MailError } from '../errors.js';
import { MAX_BODY_BYTES, htmlToText, truncateUtf8 } from '../format.js';
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

/**
 * A PDF of a few hundred KB can hold hundreds of MB of text once decompressed, which would take the whole
 * process down with it. Pages are read one at a time and the walk stops as soon as there is enough text.
 */
export const MAX_PDF_PAGES = 50;

async function pdfText(buf: Buffer): Promise<{ text: string; stoppedEarly: boolean }> {
  const pdf = await getDocumentProxy(new Uint8Array(buf));
  try {
    const pageCount = Math.min(pdf.numPages, MAX_PDF_PAGES);
    const pages: string[] = [];
    let bytes = 0;
    for (let pageNumber = 1; pageNumber <= pageCount; pageNumber++) {
      // Streamed, not fetched whole: a single page can hold hundreds of MB of text once decompressed, so
      // materialising the page before measuring it would already be too late. hasEOL keeps the line breaks
      // that make an invoice or a statement readable.
      const reader = (await pdf.getPage(pageNumber)).streamTextContent().getReader();
      const parts: string[] = [];
      let full = false;
      try {
        while (!full) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const item of value?.items ?? []) {
            if (!('str' in item)) continue;
            const piece = item.str + (item.hasEOL ? '\n' : '');
            parts.push(piece);
            bytes += Buffer.byteLength(piece, 'utf8');
            if (bytes >= MAX_BODY_BYTES) {
              full = true;
              break;
            }
          }
        }
      } finally {
        await reader.cancel().catch(() => undefined);
      }
      pages.push(parts.join(''));
      if (full) return { text: pages.join('\n'), stoppedEarly: true };
    }
    return { text: pages.join('\n'), stoppedEarly: pdf.numPages > pageCount };
  } finally {
    await pdf.loadingTask.destroy();
  }
}

/** Decodes bytes with the declared charset, falling back to UTF-8 for missing or unsupported labels. */
function decodeText(buf: Buffer, charset?: string): string {
  try {
    return new TextDecoder(charset || 'utf-8', { fatal: false }).decode(buf);
  } catch {
    return new TextDecoder('utf-8', { fatal: false }).decode(buf);
  }
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

    const { data, charset } = await downloadPart(client, uid, partId, MAX_ATTACHMENT_BYTES);
    let raw: string;
    let stoppedEarly = false;
    if (kind === 'pdf') {
      try {
        ({ text: raw, stoppedEarly } = await pdfText(data));
      } catch {
        return { ...base, text: null, truncated: false, note: 'PDF could not be read (corrupt or password-protected).' };
      }
    } else {
      // Use the charset imapflow reports for the downloaded bytes, not the declared one: imapflow has already
      // converted inline text parts to UTF-8 (and then reports 'utf-8'); attachments keep their declared charset.
      const decoded = decodeText(data, charset);
      raw = kind === 'html' ? htmlToText(decoded) : decoded;
    }
    const { text, truncated } = truncateUtf8(raw);
    return { ...base, text, truncated: truncated || stoppedEarly };
  } finally {
    lock.release();
  }
}
