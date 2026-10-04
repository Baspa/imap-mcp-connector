import type { ImapFlow } from 'imapflow';
import { describe, expect, it } from 'vitest';
import { downloadPart } from '../../src/mail/ops/message.js';

describe('downloadPart', () => {
  it('returns an empty buffer when imapflow yields no content', async () => {
    const client = { download: async () => ({}) } as unknown as ImapFlow;
    const { data, charset } = await downloadPart(client, 1, '1', 100);
    expect(data).toBeInstanceOf(Buffer);
    expect(data.length).toBe(0);
    expect(charset).toBeUndefined();
  });
});
