import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getThread } from '../../src/mail/ops/thread.js';
import { appendMessage, connectImap, createFolders, createMailUser, findUid } from './mail-helpers.js';

let client: ImapFlow;

beforeEach(async () => {
  const { email, password } = await createMailUser();
  client = await connectImap(email, password);
  await createFolders(client);
  await appendMessage(client, 'INBOX', {
    subject: 'Trip plans', text: 'Shall we go?', messageId: '<root@test>', date: new Date('2025-05-01T10:00:00Z'),
  });
  await appendMessage(client, 'Sent', {
    subject: 'Re: Trip plans', text: 'Yes!', messageId: '<r1@test>', inReplyTo: '<root@test>',
    references: ['<root@test>'], date: new Date('2025-05-01T11:00:00Z'),
  });
  await appendMessage(client, 'INBOX', {
    subject: 'Re: Trip plans (dates)', text: 'June works', messageId: '<r2@test>', inReplyTo: '<r1@test>',
    references: ['<root@test>', '<r1@test>'], date: new Date('2025-05-01T12:00:00Z'),
  });
  await appendMessage(client, 'INBOX', { subject: 'Unrelated', text: 'spam', messageId: '<other@test>' });
});

afterEach(async () => {
  await client.logout();
});

describe('getThread', () => {
  it('collects the conversation across INBOX and Sent, oldest first', async () => {
    const uid = await findUid(client, 'INBOX', 'dates');
    const thread = await getThread(client, 'INBOX', uid);
    expect(thread.map((m) => m.messageId)).toEqual(['<root@test>', '<r1@test>', '<r2@test>']);
    expect(thread.map((m) => m.folder)).toEqual(['INBOX', 'Sent', 'INBOX']);
  });

  it('finds replies when starting from the root message', async () => {
    // findUid would match replies too ("Re: Trip plans"), so look the root up by Message-ID.
    const lock = await client.getMailboxLock('INBOX');
    const [rootUid] = (await client.search({ header: { 'message-id': '<root@test>' } }, { uid: true })) || [];
    lock.release();
    const thread = await getThread(client, 'INBOX', rootUid);
    expect(thread.map((m) => m.messageId)).toEqual(['<root@test>', '<r1@test>', '<r2@test>']);
  });

  it('returns just the message when it has no thread', async () => {
    const uid = await findUid(client, 'INBOX', 'Unrelated');
    const thread = await getThread(client, 'INBOX', uid);
    expect(thread.map((m) => m.messageId)).toEqual(['<other@test>']);
  });

  it('is NOT_FOUND for a missing uid', async () => {
    await expect(getThread(client, 'INBOX', 99999)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('collects the whole conversation when starting from a reply in Sent', async () => {
    const uid = await findUid(client, 'Sent', 'Trip plans');
    const thread = await getThread(client, 'Sent', uid);
    expect(thread.map((m) => m.messageId)).toEqual(['<root@test>', '<r1@test>', '<r2@test>']);
  });

  it('returns only the newest `max` messages, including the requested one', async () => {
    const uid = await findUid(client, 'INBOX', 'dates');
    const thread = await getThread(client, 'INBOX', uid, 2);
    expect(thread.map((m) => m.messageId)).toEqual(['<r1@test>', '<r2@test>']);
  });

  it('always includes the requested message even when it falls outside `max`', async () => {
    const lock = await client.getMailboxLock('INBOX');
    const [rootUid] = (await client.search({ header: { 'message-id': '<root@test>' } }, { uid: true })) || [];
    lock.release();
    const thread = await getThread(client, 'INBOX', rootUid, 1);
    expect(thread.map((m) => m.messageId)).toEqual(['<root@test>']);
  });
});
