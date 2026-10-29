import type { ImapFlow } from 'imapflow';
import { describe, expect, it } from 'vitest';
import { downloadPart, readMessage } from '../../src/mail/ops/message.js';

describe('downloadPart', () => {
  it('returns an empty buffer when imapflow yields no content', async () => {
    const client = { download: async () => ({}) } as unknown as ImapFlow;
    const { data, charset } = await downloadPart(client, 1, '1', 100);
    expect(data).toBeInstanceOf(Buffer);
    expect(data.length).toBe(0);
    expect(charset).toBeUndefined();
  });
});

function alternativeClient(plain: string, html: string): ImapFlow {
  const parts: Record<string, string> = { '1': plain, '2': html };
  return {
    fetchOne: async () => ({
      envelope: { subject: 'Team lunch Friday', from: [{ address: 'a@x.org' }] },
      flags: new Set<string>(),
      bodyStructure: {
        type: 'multipart/alternative',
        childNodes: [
          { type: 'text/plain', part: '1' },
          { type: 'text/html', part: '2' },
        ],
      },
    }),
    download: async (_uid: string, part: string) => ({
      meta: { charset: 'utf-8' },
      content: (async function* () {
        yield Buffer.from(parts[part], 'utf8');
      })(),
    }),
  } as unknown as ImapFlow;
}

describe('readMessage with a multipart/alternative message', () => {
  it('says which part was read and that an HTML alternative exists', async () => {
    // A person reads the HTML part; this reads text/plain. Saying so beats guessing whether they differ.
    const client = alternativeClient('Team lunch Friday.', '<p>Something else entirely.</p>');
    const message = await readMessage(client, 'INBOX', 1);
    expect(message.body).toContain('Team lunch Friday.');
    expect(message.bodyPart).toBe('text/plain');
    expect(message.hasHtmlAlternative).toBe(true);
  });
});
