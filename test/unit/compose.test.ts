import { simpleParser } from 'mailparser';
import { describe, expect, it } from 'vitest';
import { buildMime, type ComposeInput } from '../../src/mail/compose.js';

const input: ComposeInput = {
  from: 'alice@x.org',
  to: ['bob@y.org'],
  cc: ['carol@y.org'],
  bcc: ['secret@z.org'],
  subject: 'Re: Plans',
  body: 'Sounds good — see you then.',
  messageId: '<fixed@x.org>',
  date: new Date('2025-05-01T10:00:00Z'),
  inReplyTo: '<orig@y.org>',
  references: '<root@y.org> <orig@y.org>',
};

describe('buildMime', () => {
  it('builds a message with threading headers and fixed Message-ID', async () => {
    const parsed = await simpleParser(await buildMime(input, { keepBcc: false }));
    expect(parsed.messageId).toBe('<fixed@x.org>');
    expect(parsed.inReplyTo).toBe('<orig@y.org>');
    expect(parsed.references).toEqual(['<root@y.org>', '<orig@y.org>']);
    expect(parsed.subject).toBe('Re: Plans');
    expect(parsed.text?.trim()).toBe('Sounds good — see you then.');
    expect(parsed.bcc).toBeUndefined();
  });

  it('keeps Bcc only when asked (for Drafts/Sent copies)', async () => {
    const parsed = await simpleParser(await buildMime(input, { keepBcc: true }));
    const bcc = Array.isArray(parsed.bcc) ? parsed.bcc[0] : parsed.bcc;
    expect(bcc?.text).toContain('secret@z.org');
  });
});
