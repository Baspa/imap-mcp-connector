import type { ImapFlow } from 'imapflow';
import { describe, expect, it, vi } from 'vitest';
import { deleteMessages, moveMessages } from '../../src/mail/ops/actions.js';

function fakeClient(capabilities: string[], overrides: Record<string, unknown> = {}) {
  const folder = (path: string, specialUse?: string) => ({ path, name: path, flags: new Set<string>(), specialUse });
  const client = {
    capabilities: new Set(capabilities),
    list: vi.fn(async () => [folder('INBOX'), folder('Archive', '\\Archive'), folder('Trash', '\\Trash')]),
    getMailboxLock: vi.fn(async () => ({ release: vi.fn() })),
    search: vi.fn(async () => [1, 2]),
    messageMove: vi.fn(async () => ({ path: 'INBOX', destination: 'Archive', uidMap: new Map([[1, 11], [2, 12]]) })),
    messageCopy: vi.fn(async () => ({ path: 'INBOX', destination: 'Archive', uidMap: new Map([[1, 11], [2, 12]]) })),
    messageDelete: vi.fn(async () => true),
    ...overrides,
  };
  return client;
}
const asImap = (c: unknown) => c as ImapFlow;

describe('move without MOVE support', () => {
  it('copies then deletes only the copied uids when UIDPLUS is available', async () => {
    const client = fakeClient(['UIDPLUS']);
    const result = await moveMessages(asImap(client), 'INBOX', [1, 2], 'archive');
    expect(result).toEqual({ from: 'INBOX', to: 'Archive', moved: 2 });
    expect(client.messageMove).not.toHaveBeenCalled();
    expect(client.messageCopy).toHaveBeenCalledWith('1,2', 'Archive', { uid: true });
    expect(client.messageDelete).toHaveBeenCalledWith('1,2', { uid: true });
    expect(client.messageCopy.mock.invocationCallOrder[0]).toBeLessThan(client.messageDelete.mock.invocationCallOrder[0]);
  });

  it('never deletes when the copy fails', async () => {
    const client = fakeClient(['UIDPLUS'], { messageCopy: vi.fn(async () => false) });
    await expect(moveMessages(asImap(client), 'INBOX', [1, 2], 'archive')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(client.messageDelete).not.toHaveBeenCalled();
  });

  it('refuses before touching anything without MOVE or UIDPLUS', async () => {
    const client = fakeClient([]);
    await expect(deleteMessages(asImap(client), 'INBOX', [1])).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(client.messageMove).not.toHaveBeenCalled();
    expect(client.messageCopy).not.toHaveBeenCalled();
    expect(client.messageDelete).not.toHaveBeenCalled();
  });
});

describe('move with MOVE support', () => {
  it('moves only existing uids and reports the uidMap size', async () => {
    const client = fakeClient(['MOVE'], { search: vi.fn(async () => [2]), messageMove: vi.fn(async () => ({ uidMap: new Map([[2, 12]]) })) });
    const result = await moveMessages(asImap(client), 'INBOX', [2, 999], 'archive');
    expect(result.moved).toBe(1);
    expect(client.messageMove).toHaveBeenCalledWith('2', 'Archive', { uid: true });
  });

  it('throws when the server refuses the move', async () => {
    const client = fakeClient(['MOVE'], { messageMove: vi.fn(async () => false) });
    await expect(moveMessages(asImap(client), 'INBOX', [1, 2], 'archive')).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
  });

  it('throws NOT_FOUND when none of the uids exist', async () => {
    const client = fakeClient(['MOVE'], { search: vi.fn(async () => []) });
    await expect(moveMessages(asImap(client), 'INBOX', [5], 'archive')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(client.messageMove).not.toHaveBeenCalled();
  });
});
