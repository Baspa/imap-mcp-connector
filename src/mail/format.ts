import { convert } from 'html-to-text';

export const MAX_BODY_BYTES = 50_000;
const TAG = 'untrusted_email_content';

export function htmlToText(html: string): string {
  return convert(html, {
    wordwrap: false,
    selectors: [
      { selector: 'img', format: 'skip' },
      { selector: 'a', options: { hideLinkHrefIfSameAsText: true } },
    ],
  });
}

export function truncateUtf8(text: string, maxBytes = MAX_BODY_BYTES): { text: string; truncated: boolean } {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return { text, truncated: false };
  let cut = buf.subarray(0, maxBytes).toString('utf8');
  if (cut.endsWith('�')) cut = cut.slice(0, -1);
  return { text: `${cut}\n[… truncated]`, truncated: true };
}

export function snippet(text: string, max = 200): string {
  const collapsed = text.replace(/\s+/g, ' ').trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 1)}…` : collapsed;
}

export function wrapUntrusted(text: string): string {
  const safe = text.replace(/untrusted_email_content/gi, 'untrusted-email-content');
  return `<${TAG}>\n${safe}\n</${TAG}>`;
}

export function formatAddress(a?: { name?: string; address?: string }): string {
  if (!a) return '';
  if (a.name && a.address) return `${a.name} <${a.address}>`;
  return a.address ?? a.name ?? '';
}

/** ISO-8601 string for a date-like value, or null when missing or unparseable. */
export function toIsoDate(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  const d = value instanceof Date ? value : new Date(value as string | number);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function parseMessageIds(header: string): string[] {
  return header.match(/<[^<>\s]+>/g) ?? [];
}

export interface ReplySource {
  messageId: string | null;
  references: string[];
  subject: string;
}

export function buildReplyHeaders(src: ReplySource): { inReplyTo?: string; references?: string; subject: string } {
  const subject = /^re:/i.test(src.subject.trim()) ? src.subject : `Re: ${src.subject}`;
  if (!src.messageId) return { subject };
  const refs = [...new Set([...src.references, src.messageId])];
  return { inReplyTo: src.messageId, references: refs.join(' '), subject };
}
