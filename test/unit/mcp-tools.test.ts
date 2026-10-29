import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describe, expect, it } from 'vitest';
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
