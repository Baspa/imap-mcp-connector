import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadReplySource } from '../../src/mail/compose.js';
import { appendToRole, deleteMessages, moveMessages, setFlags } from '../../src/mail/ops/actions.js';
import { searchMessages } from '../../src/mail/ops/search.js';
import { appendMessage, connectImap, createFolders, createMailUser, findUid } from './mail-helpers.js';

let client: ImapFlow;

beforeEach(async () => {
  const { email, password } = await createMailUser();
  client = await connectImap(email, password);
  await createFolders(client);
  await appendMessage(client, 'INBOX', { subject: 'A', text: 'a', messageId: '<a@test>', references: ['<root@test>'] });
  await appendMessage(client, 'INBOX', { subject: 'B', text: 'b' });
});

afterEach(async () => {
  await client.logout();
});

const subjects = async (folder: string) => (await searchMessages(client, { folder })).messages.map((m) => m.subject).sort();

describe('actions', () => {
  it('sets and clears flags', async () => {
    const uid = await findUid(client, 'INBOX', 'A');
    await setFlags(client, 'INBOX', [uid], ['seen', 'flagged'], []);
    let msg = (await searchMessages(client, { flagged: true })).messages;
    expect(msg.map((m) => m.subject)).toEqual(['A']);
    expect(msg[0].flags).toEqual(expect.arrayContaining(['\\Seen', '\\Flagged']));
    await setFlags(client, 'INBOX', [uid], [], ['seen']);
    msg = (await searchMessages(client, { unread: true })).messages;
    expect(msg.map((m) => m.subject).sort()).toEqual(['A', 'B']);
  });

  it('moves messages to a role folder or path', async () => {
    const a = await findUid(client, 'INBOX', 'A');
    const result = await moveMessages(client, 'INBOX', [a], 'archive');
    expect(result).toEqual({ from: 'INBOX', to: 'Archive', moved: 1 });
    expect(await subjects('Archive')).toEqual(['A']);
    expect(await subjects('INBOX')).toEqual(['B']);
    await expect(moveMessages(client, 'INBOX', [1], 'INBOX')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(moveMessages(client, 'INBOX', [1], 'Nowhere')).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('deletes by moving to Trash and refuses to delete from Trash', async () => {
    const b = await findUid(client, 'INBOX', 'B');
    expect(await deleteMessages(client, 'INBOX', [b])).toEqual({ from: 'INBOX', to: 'Trash', moved: 1 });
    expect(await subjects('Trash')).toEqual(['B']);
    const inTrash = await findUid(client, 'Trash', 'B');
    await expect(deleteMessages(client, 'Trash', [inTrash])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('validates batch sizes', async () => {
    await expect(setFlags(client, 'INBOX', [], ['seen'], [])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const many = Array.from({ length: 101 }, (_, i) => i + 1);
    await expect(moveMessages(client, 'INBOX', many, 'archive')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('appends drafts with the Draft flag', async () => {
    const raw = Buffer.from('From: me@test.local\r\nSubject: Draft one\r\n\r\nbody\r\n');
    const result = await appendToRole(client, 'drafts', raw, ['\\Draft', '\\Seen']);
    expect(result.folder).toBe('Drafts');
    const drafts = (await searchMessages(client, { folder: 'drafts' })).messages;
    expect(drafts.map((m) => m.subject)).toEqual(['Draft one']);
    expect(drafts[0].flags).toContain('\\Draft');
  });

  it('loads reply context from a message', async () => {
    const uid = await findUid(client, 'INBOX', 'A');
    expect(await loadReplySource(client, 'INBOX', uid)).toEqual({ messageId: '<a@test>', references: ['<root@test>'], subject: 'A' });
    await expect(loadReplySource(client, 'INBOX', 99999)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
