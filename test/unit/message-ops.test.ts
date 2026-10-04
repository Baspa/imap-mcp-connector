import type { ImapFlow } from 'imapflow';
import { describe, expect, it } from 'vitest';
import { downloadPart } from '../../src/mail/ops/message.js';

describe('downloadPart', () => {
  it('returns an empty buffer when imapflow yields no content', async () => {
    const client = { download: async () => ({}) } as unknown as ImapFlow;
    const buf = await downloadPart(client, 1, '1', 100);
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBe(0);
  });
});
