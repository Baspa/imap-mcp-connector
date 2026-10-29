import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describe, expect, it, vi } from 'vitest';
import { setPermissionLevel } from '../../src/db/users.js';
import { MailPool } from '../../src/mail/pool.js';
import { defaultSmtpFactory } from '../../src/mail/smtp.js';
import { allows } from '../../src/mcp/levels.js';
import { registerTools } from '../../src/mcp/tools.js';
import { TEST_KEY, testConfig } from '../helpers/config.js';
import { createTestUser, testDb } from '../helpers/db.js';

type Handler = (args: unknown) => Promise<{ isError?: boolean; content: { text: string }[] }>;

describe('allows', () => {
  it('orders read < draft < full', () => {
    expect(allows('read', 'read')).toBe(true);
    expect(allows('read', 'draft')).toBe(false);
    expect(allows('draft', 'read')).toBe(true);
    expect(allows('draft', 'full')).toBe(false);
    expect(allows('full', 'draft')).toBe(true);
    expect(allows('full', 'full')).toBe(true);
  });
});

describe('registerTools', () => {
  it('re-checks the permission level inside each handler', async () => {
    const db = testDb();
    const user = createTestUser(db, { permissionLevel: 'draft' });
    const handlers = new Map<string, Handler>();
    const fake = { registerTool: (name: string, _config: unknown, cb: Handler) => handlers.set(name, cb) } as unknown as McpServer;
    const pool = new MailPool({ db, key: TEST_KEY, signInUrl: 'http://localhost:3000/login' });
    registerTools(fake, { db, config: testConfig(), pool, smtpFactory: defaultSmtpFactory, userId: user.id }, 'draft');
    expect([...handlers.keys()].sort()).toEqual(
      ['create_draft', 'get_attachment', 'get_message', 'get_thread', 'list_folders', 'move_messages', 'search_messages', 'set_flags'],
    );

    setPermissionLevel(db, user.id, 'read');
    const result = await handlers.get('create_draft')!({ to: [], subject: 's', body: 'x' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/^PERMISSION_DENIED: .*http:\/\/localhost:3000\/settings/);
  });

  it('marks folder names as untrusted, because the mail server chooses them', async () => {
    const db = testDb();
    const user = createTestUser(db, { permissionLevel: 'read' });
    const handlers = new Map<string, Handler>();
    const fake = { registerTool: (name: string, _config: unknown, cb: Handler) => handlers.set(name, cb) } as unknown as McpServer;
    const pool = { withImap: async () => [{ path: 'INBOX', role: 'inbox' }] } as unknown as MailPool;
    registerTools(fake, { db, config: testConfig(), pool, smtpFactory: defaultSmtpFactory, userId: user.id }, 'read');

    const result = await handlers.get('list_folders')!({});
    expect(result.content[0].text).toMatch(/^<untrusted_email_content id="[0-9a-f]{16}">/);
  });
});

describe('move_messages destinations', () => {
  const FOLDERS = [
    { path: 'INBOX', flags: new Set(['\\Inbox']), specialUse: '\\Inbox', specialUseSource: 'extension', delimiter: '/' },
    { path: 'Archive', flags: new Set(['\\Archive']), specialUse: '\\Archive', specialUseSource: 'extension', delimiter: '/' },
    { path: 'Junk', flags: new Set(['\\Junk']), specialUse: '\\Junk', specialUseSource: 'extension', delimiter: '/' },
    { path: 'Trash', flags: new Set(['\\Trash']), specialUse: '\\Trash', specialUseSource: 'extension', delimiter: '/' },
    { path: 'Projects', flags: new Set<string>(), delimiter: '/' },
  ];

  function moveHandler(level: 'draft' | 'full') {
    const db = testDb();
    const user = createTestUser(db, { permissionLevel: level });
    const handlers = new Map<string, Handler>();
    const fake = { registerTool: (name: string, _c: unknown, cb: Handler) => handlers.set(name, cb) } as unknown as McpServer;
    const client = {
      list: async () => FOLDERS,
      capabilities: new Set(['MOVE']),
      getMailboxLock: async () => ({ release: () => {} }),
      search: async () => [1],
      messageMove: async () => ({ uidMap: new Map([[1, 10]]) }),
    };
    const pool = { withImap: async (_u: unknown, fn: (c: unknown) => Promise<unknown>) => fn(client) } as unknown as MailPool;
    registerTools(fake, { db, config: testConfig(), pool, smtpFactory: defaultSmtpFactory, userId: user.id }, level);
    return handlers.get('move_messages')!;
  }

  it('refuses Junk at draft level, so mail cannot be hidden where it may be purged', async () => {
    const result = await moveHandler('draft')({ folder: 'INBOX', uids: [1], destination: 'Junk' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/^PERMISSION_DENIED/);
  });

  it('refuses an ordinary folder at draft level', async () => {
    const result = await moveHandler('draft')({ folder: 'INBOX', uids: [1], destination: 'Projects' });
    expect(result.isError).toBe(true);
  });

  it('allows Archive at draft level', async () => {
    const result = await moveHandler('draft')({ folder: 'INBOX', uids: [1], destination: 'Archive' });
    expect(result.isError).toBeFalsy();
  });

  it('allows Junk at full level', async () => {
    const result = await moveHandler('full')({ folder: 'INBOX', uids: [1], destination: 'Junk' });
    expect(result.isError).toBeFalsy();
  });
});

describe('audited tool calls', () => {
  it('records a move with its destination and count, but no message content', async () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((line: string) => void lines.push(line));
    const db = testDb();
    const user = createTestUser(db, { permissionLevel: 'draft' });
    const handlers = new Map<string, Handler>();
    const fake = { registerTool: (n: string, _c: unknown, cb: Handler) => handlers.set(n, cb) } as unknown as McpServer;
    const client = {
      list: async () => [
        { path: 'INBOX', flags: new Set(['\\Inbox']), specialUse: '\\Inbox', specialUseSource: 'extension', delimiter: '/' },
        { path: 'Archive', flags: new Set(['\\Archive']), specialUse: '\\Archive', specialUseSource: 'extension', delimiter: '/' },
      ],
      capabilities: new Set(['MOVE']),
      getMailboxLock: async () => ({ release: () => {} }),
      search: async () => [1, 2],
      messageMove: async () => ({ uidMap: new Map([[1, 10], [2, 11]]) }),
    };
    const pool = { withImap: async (_u: unknown, fn: (c: unknown) => Promise<unknown>) => fn(client) } as unknown as MailPool;
    registerTools(fake, { db, config: testConfig(), pool, smtpFactory: defaultSmtpFactory, userId: user.id }, 'draft');

    await handlers.get('move_messages')!({ folder: 'INBOX', uids: [1, 2], destination: 'Archive' });
    spy.mockRestore();

    const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((e) => e.msg === 'audit');
    expect(events).toContainEqual(expect.objectContaining({ event: 'move_messages', userId: user.id, destination: 'Archive', count: 2 }));
  });
});