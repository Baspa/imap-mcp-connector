import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { listFolders, resolveFolder, resolveRole } from '../../src/mail/ops/folders.js';
import { searchMessages } from '../../src/mail/ops/search.js';
import { appendMessage, connectImap, createFolders, createMailUser } from './mail-helpers.js';

let client: ImapFlow;

beforeEach(async () => {
  const { email, password } = await createMailUser();
  client = await connectImap(email, password);
  await createFolders(client);
});

afterEach(async () => {
  await client.logout();
});

describe('folders', () => {
  it('lists folders with roles and counts', async () => {
    await appendMessage(client, 'INBOX', { subject: 'One', text: 'one' });
    await appendMessage(client, 'INBOX', { subject: 'Two', text: 'two', flags: ['\\Seen'] });
    const folders = await listFolders(client);
    const inbox = folders.find((f) => f.role === 'inbox');
    expect(inbox).toMatchObject({ path: 'INBOX', total: 2, unread: 1 });
    expect(folders.map((f) => f.path)).toEqual(expect.arrayContaining(['INBOX', 'Drafts', 'Sent', 'Trash', 'Archive']));
  });

  it('resolves roles by special-use or name, and folder paths case-insensitively', async () => {
    expect(await resolveRole(client, 'drafts')).toBe('Drafts');
    expect(await resolveFolder(client, 'trash')).toBe('Trash');
    expect(await resolveFolder(client, 'archive')).toBe('Archive');
    expect(await resolveFolder(client, 'inbox')).toBe('INBOX');
    expect(await resolveFolder(client, 'Sent')).toBe('Sent');
    await expect(resolveFolder(client, 'Nope')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(resolveRole(client, 'junk')).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('folder resolution edge cases', () => {
  it('falls back to case-insensitive paths and ignores nested folders for role names', async () => {
    await client.mailboxCreate('Projects');
    const delimiter = (await client.list()).find((f) => f.path === 'INBOX')?.delimiter ?? '/';
    await client.mailboxCreate(`Projects${delimiter}Sent`);
    expect(await resolveFolder(client, 'projects')).toBe('Projects');
    expect(await resolveFolder(client, 'Sent')).toBe('Sent');
    expect(await resolveRole(client, 'sent')).toBe('Sent');
    expect(await resolveFolder(client, `Projects${delimiter}Sent`)).toBe(`Projects${delimiter}Sent`);
  });
});

describe('localized folder names without SPECIAL-USE', () => {
  it('resolves a role from a localized top-level name, never from a nested one', async () => {
    const { email, password } = await createMailUser();
    const fresh = await connectImap(email, password);
    try {
      await createFolders(fresh, ['Drafts', 'Trash', 'Projekte']);
      const delimiter = (await fresh.list()).find((f) => f.path === 'INBOX')?.delimiter ?? '/';
      await fresh.mailboxCreate(`Projekte${delimiter}Gesendet`);
      // imapflow name-guesses the nested folder as \Sent; it must not become the Sent role.
      expect((await fresh.list()).find((f) => f.specialUse === '\\Sent')).toMatchObject({
        path: `Projekte${delimiter}Gesendet`, specialUseSource: 'name',
      });
      await expect(resolveRole(fresh, 'sent')).rejects.toMatchObject({ code: 'NOT_FOUND' });

      await fresh.mailboxCreate('Gesendet');
      expect((await fresh.list()).find((f) => f.specialUse === '\\Sent')).toMatchObject({ path: 'Gesendet', specialUseSource: 'name' });
      expect(await resolveRole(fresh, 'sent')).toBe('Gesendet');
    } finally {
      await fresh.logout();
    }
  });
});

describe('searchMessages', () => {
  it('filters by subject, sender and unread, newest first, with snippets', async () => {
    await appendMessage(client, 'INBOX', { subject: 'Invoice March', from: 'billing@shop.com', text: 'Your invoice total is 10 EUR' });
    await appendMessage(client, 'INBOX', { subject: 'Lunch?', from: 'friend@x.org', text: 'Lunch tomorrow', flags: ['\\Seen'] });
    await appendMessage(client, 'INBOX', { subject: 'Invoice April', from: 'billing@shop.com', html: '<p>Your <b>April</b> invoice</p>' });

    const invoices = await searchMessages(client, { subject: 'Invoice' });
    expect(invoices.folder).toBe('INBOX');
    expect(invoices.messages.map((m) => m.subject)).toEqual(['Invoice April', 'Invoice March']);
    expect(invoices.messages[0].snippet).toBe('Your April invoice');
    expect(invoices.messages[1].from).toBe('billing@shop.com');
    expect(invoices.nextCursor).toBeNull();

    expect((await searchMessages(client, { from: 'friend@x.org' })).messages).toHaveLength(1);
    expect((await searchMessages(client, { unread: true })).messages.map((m) => m.subject)).toEqual(['Invoice April', 'Invoice March']);
    expect((await searchMessages(client, { text: 'tomorrow' })).messages.map((m) => m.subject)).toEqual(['Lunch?']);
  });

  it('paginates with a uid cursor without duplicates when new mail arrives', async () => {
    for (let i = 0; i < 25; i++) await appendMessage(client, 'INBOX', { subject: `Msg ${i}`, text: `n${i}` });
    const page1 = await searchMessages(client, { limit: 10 });
    expect(page1.messages).toHaveLength(10);
    expect(page1.nextCursor).not.toBeNull();
    await appendMessage(client, 'INBOX', { subject: 'Late arrival', text: 'new' });
    const page2 = await searchMessages(client, { limit: 10, cursor: page1.nextCursor! });
    const page3 = await searchMessages(client, { limit: 10, cursor: page2.nextCursor! });
    expect(page3.messages).toHaveLength(5);
    expect(page3.nextCursor).toBeNull();
    const all = [...page1.messages, ...page2.messages, ...page3.messages].map((m) => m.uid);
    expect(new Set(all).size).toBe(25);
    expect(all).toEqual([...all].sort((a, b) => b - a));
  });

  it('caps the limit at 100, defaults non-finite limits, and validates input', async () => {
    for (let i = 0; i < 101; i++) await appendMessage(client, 'INBOX', { subject: `m${i}`, text: 'x' });
    const capped = await searchMessages(client, { limit: 1000 });
    expect(capped.messages).toHaveLength(100);
    expect(capped.nextCursor).not.toBeNull();
    expect((await searchMessages(client, { limit: Number.NaN })).messages).toHaveLength(20);
    await expect(searchMessages(client, { since: 'not a date' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(searchMessages(client, { cursor: 'abc' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(searchMessages(client, { folder: 'Missing' })).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('filters by date range', async () => {
    await appendMessage(client, 'INBOX', { subject: 'Old', text: 'o', date: new Date('2024-01-10T10:00:00Z') });
    await appendMessage(client, 'INBOX', { subject: 'New', text: 'n', date: new Date('2025-06-10T10:00:00Z') });
    const r = await searchMessages(client, { since: '2025-01-01' });
    expect(r.messages.map((m) => m.subject)).toEqual(['New']);
    const r2 = await searchMessages(client, { before: '2025-01-01' });
    expect(r2.messages.map((m) => m.subject)).toEqual(['Old']);
  });
});
