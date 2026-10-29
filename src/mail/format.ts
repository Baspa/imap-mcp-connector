import { randomBytes } from 'node:crypto';
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

/** Lines shorter than this are greetings, signatures and separators: too common to be worth flagging. */
const MIN_DIVERGING_LINE = 25;

function comparable(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

/**
 * Whether the plain-text part says something the HTML part does not. Mail programs show the HTML part
 * while this connector reads text/plain, so a sender can put instructions where only the model looks.
 */
export function plainTextDiffersFromHtml(plain: string, htmlText: string): boolean {
  const htmlWords = comparable(htmlText);
  return plain
    .split(/\r?\n/)
    .map(comparable)
    .filter((line) => line.length >= MIN_DIVERGING_LINE)
    .some((line) => !htmlWords.includes(line));
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

/**
 * Wraps third-party text between tags carrying a random id. Embedded tag names are rewritten, and the id stops
 * look-alike closing tags (zero-width characters, homoglyphs, ...) from passing as the real end of the block.
 */
export function wrapUntrusted(text: string): string {
  const id = randomBytes(8).toString('hex');
  const safe = text.replace(/untrusted_email_content/gi, 'untrusted-email-content');
  return `<${TAG} id="${id}">\n${safe}\n</${TAG} id="${id}">`;
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
