import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getAttachment } from '../../src/mail/ops/attachment.js';
import { getMessage } from '../../src/mail/ops/message.js';
import { tinyPdf } from '../helpers/pdf.js';
import { appendMessage, appendRaw, connectImap, createFolders, createMailUser, findUid } from './mail-helpers.js';

let client: ImapFlow;

beforeEach(async () => {
  const { email, password } = await createMailUser();
  client = await connectImap(email, password);
  await createFolders(client);
});

afterEach(async () => {
  await client.logout();
});

describe('getMessage', () => {
  it('returns headers and a plain text body', async () => {
    await appendMessage(client, 'INBOX', {
      subject: 'Plain', from: 'Ann <ann@x.org>', to: 'me@test.local', text: 'Hello there', messageId: '<plain@test>',
    });
    const uid = await findUid(client, 'INBOX', 'Plain');
    const m = await getMessage(client, 'INBOX', uid);
    expect(m).toMatchObject({
      folder: 'INBOX', uid, messageId: '<plain@test>', from: 'Ann <ann@x.org>', to: ['me@test.local'],
      subject: 'Plain', bodyTruncated: false, attachments: [],
    });
    expect(m.body.trim()).toBe('Hello there');
  });

  it('decodes encoded subject and latin1 body', async () => {
    const raw = Buffer.from(
      [
        'From: =?ISO-8859-1?Q?J=F6rg?= <jorg@example.com>',
        'To: me@test.local',
        'Subject: =?ISO-8859-1?Q?Gr=FC=DFe_aus_K=F6ln?=',
        'Message-ID: <latin1@test>',
        'Date: Mon, 1 Sep 2025 10:00:00 +0000',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=ISO-8859-1',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        'Sch=F6ne Gr=FC=DFe',
        '',
      ].join('\r\n'),
      'latin1',
    );
    await appendRaw(client, 'INBOX', raw);
    const uid = await findUid(client, 'INBOX', 'aus');
    const m = await getMessage(client, 'INBOX', uid);
    expect(m.subject).toBe('Grüße aus Köln');
    expect(m.from).toBe('Jörg <jorg@example.com>');
    expect(m.body.trim()).toBe('Schöne Grüße');
  });

  it('html-only and nested multipart', async () => {
    await appendMessage(client, 'INBOX', { subject: 'HtmlOnly', html: '<h1>Title</h1><p>Body <a href="https://x.org">link</a></p>' });
    const html = await getMessage(client, 'INBOX', await findUid(client, 'INBOX', 'HtmlOnly'));
    expect(html.body).toContain('Body');
    expect(html.body).not.toContain('<p>');

    await appendMessage(client, 'INBOX', {
      subject: 'Mixed',
      text: 'Text version',
      html: '<p>HTML version</p>',
      attachments: [
        { filename: 'notes.txt', content: 'attached notes', contentType: 'text/plain' },
        { filename: 'report.pdf', content: tinyPdf('Quarterly numbers'), contentType: 'application/pdf' },
        { filename: 'pixel.png', content: Buffer.from('89504e470d0a1a0a', 'hex'), contentType: 'image/png' },
      ],
    });
    const mixed = await getMessage(client, 'INBOX', await findUid(client, 'INBOX', 'Mixed'));
    expect(mixed.body.trim()).toBe('Text version');
    expect(mixed.attachments.map((a) => a.filename)).toEqual(['notes.txt', 'report.pdf', 'pixel.png']);
    expect(mixed.attachments.every((a) => /^\d+(\.\d+)*$/.test(a.partId))).toBe(true);
  });

  it('truncates very long bodies', async () => {
    await appendMessage(client, 'INBOX', { subject: 'Long', text: 'a'.repeat(80_000) });
    const m = await getMessage(client, 'INBOX', await findUid(client, 'INBOX', 'Long'));
    expect(m.bodyTruncated).toBe(true);
    expect(Buffer.byteLength(m.body)).toBeLessThan(50_100);
  });

  it('stale uid is NOT_FOUND', async () => {
    await appendMessage(client, 'INBOX', { subject: 'Gone', text: 'x' });
    const uid = await findUid(client, 'INBOX', 'Gone');
    const lock = await client.getMailboxLock('INBOX');
    await client.messageDelete(String(uid), { uid: true });
    lock.release();
    await expect(getMessage(client, 'INBOX', uid)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('getAttachment', () => {
  beforeEach(async () => {
    await appendMessage(client, 'INBOX', {
      subject: 'Files',
      text: 'see attached',
      attachments: [
        { filename: 'notes.txt', content: 'attached notes', contentType: 'text/plain' },
        { filename: 'page.html', content: '<p>Hello <b>html</b></p>', contentType: 'text/html' },
        { filename: 'report.pdf', content: tinyPdf('Quarterly numbers'), contentType: 'application/pdf' },
        { filename: 'pixel.png', content: Buffer.from('89504e470d0a1a0a', 'hex'), contentType: 'image/png' },
      ],
    });
  });

  async function parts() {
    const uid = await findUid(client, 'INBOX', 'Files');
    const m = await getMessage(client, 'INBOX', uid);
    return { uid, byName: Object.fromEntries(m.attachments.map((a) => [a.filename, a.partId])) };
  }

  it('extracts text, html and pdf content', async () => {
    const { uid, byName } = await parts();
    expect((await getAttachment(client, 'INBOX', uid, byName['notes.txt'])).text).toBe('attached notes');
    expect((await getAttachment(client, 'INBOX', uid, byName['page.html'])).text).toContain('Hello html');
    expect((await getAttachment(client, 'INBOX', uid, byName['report.pdf'])).text).toContain('Quarterly numbers');
  });

  it('returns metadata only for binary files', async () => {
    const { uid, byName } = await parts();
    const png = await getAttachment(client, 'INBOX', uid, byName['pixel.png']);
    expect(png).toMatchObject({ filename: 'pixel.png', contentType: 'image/png', text: null });
    expect(png.note).toMatch(/not extracted/);
  });

  it('rejects unknown parts and oversized attachments', async () => {
    const { uid } = await parts();
    await expect(getAttachment(client, 'INBOX', uid, '9.9')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await appendMessage(client, 'INBOX', {
      subject: 'Huge', text: 'big',
      attachments: [{ filename: 'big.txt', content: 'x'.repeat(6 * 1024 * 1024), contentType: 'text/plain' }],
    });
    const hugeUid = await findUid(client, 'INBOX', 'Huge');
    const huge = await getMessage(client, 'INBOX', hugeUid);
    await expect(getAttachment(client, 'INBOX', hugeUid, huge.attachments[0].partId)).rejects.toMatchObject({ code: 'TOO_LARGE' });
  });
});
