import type { ImapFlow } from 'imapflow';
import { describe, expect, it } from 'vitest';
import { MAX_PDF_PAGES, getAttachment } from '../../src/mail/ops/attachment.js';
import { tinyPdfPages } from '../helpers/pdf.js';

function clientWithPdf(pdf: Buffer): ImapFlow {
  return {
    list: async () => [{ path: 'INBOX', flags: new Set(['\\Inbox']), specialUse: '\\Inbox', specialUseSource: 'extension', delimiter: '/' }],
    getMailboxLock: async () => ({ release: () => {} }),
    fetchOne: async () => ({
      bodyStructure: {
        type: 'multipart/mixed',
        childNodes: [
          { type: 'text/plain', part: '1' },
          { type: 'application/pdf', part: '2', disposition: 'attachment', dispositionParameters: { filename: 'report.pdf' }, size: pdf.length },
        ],
      },
    }),
    download: async () => ({
      meta: { charset: 'utf-8' },
      content: (async function* () {
        yield pdf;
      })(),
    }),
  } as unknown as ImapFlow;
}

describe('getAttachment with a PDF', () => {
  it('extracts text from every page of a small PDF', async () => {
    const client = clientWithPdf(tinyPdfPages(['Quarterly numbers', 'Second page']));
    const result = await getAttachment(client, 'INBOX', 1, '2');
    expect(result.text).toContain('Quarterly numbers');
    expect(result.text).toContain('Second page');
  });

  it('stops after a page limit, so a crafted PDF cannot exhaust memory', async () => {
    const pages = Array.from({ length: MAX_PDF_PAGES + 20 }, (_, i) => `Page ${i} marker`);
    const client = clientWithPdf(tinyPdfPages(pages));
    const result = await getAttachment(client, 'INBOX', 1, '2');
    expect(result.text).toContain('Page 0 marker');
    expect(result.text).not.toContain(`Page ${MAX_PDF_PAGES + 10} marker`);
    expect(result.truncated).toBe(true);
  });
});
