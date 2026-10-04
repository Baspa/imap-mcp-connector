import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { encryptSecret } from '../../src/crypto.js';
import { createUser, findUserById, setPermissionLevel, type User } from '../../src/db/users.js';
import type { PermissionLevel } from '../../src/types.js';
import { testApp } from '../helpers/app.js';
import { issueAccessToken } from '../helpers/oauth.js';
import { appendMessage, connectImap, createFolders, createMailUser, findUid, greenmailSettings, waitForSubject } from './mail-helpers.js';

let server: Server;
let baseUrl: string;
let ctx: ReturnType<typeof testApp>;
let user: User;
let imap: ImapFlow;
let clients: Client[] = [];

beforeEach(async () => {
  ctx = testApp({}, { ALLOW_PRIVATE_HOSTS: 'true' });
  const mail = await createMailUser();
  user = createUser(ctx.deps.db, {
    ...greenmailSettings(), email: mail.email, smtpUsername: mail.email,
    imapPasswordEnc: encryptSecret(ctx.deps.config.encryptionKey, mail.password),
  });
  imap = await connectImap(mail.email, mail.password);
  await createFolders(imap);
  await appendMessage(imap, 'INBOX', { subject: 'Quarterly report', text: 'Numbers are up 10%', messageId: '<q@test>' });
  server = ctx.app.listen(0);
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await Promise.all(clients.map((c) => c.close()));
  clients = [];
  await imap.logout();
  await ctx.deps.pool.closeAll();
  await new Promise((r) => server.close(r));
});

async function connect(level: PermissionLevel): Promise<Client> {
  setPermissionLevel(ctx.deps.db, user.id, level);
  const token = await issueAccessToken(ctx.deps.provider, user.id);
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(transport);
  clients.push(client);
  return client;
}

function text(result: unknown): string {
  return ((result as { content: { type: string; text: string }[] }).content[0]).text;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test helper returns loosely-typed parsed JSON
function json(result: unknown): any {
  return JSON.parse(text(result).replace(/^<untrusted_email_content>\n/, '').replace(/\n<\/untrusted_email_content>$/, ''));
}

describe('MCP endpoint', () => {
  it('requires a bearer token and points to resource metadata', async () => {
    const res = await fetch(`${baseUrl}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('resource_metadata');
  });

  it('exposes tools by permission level with annotations', async () => {
    const names = async (level: PermissionLevel) => (await (await connect(level)).listTools()).tools.map((t) => t.name).sort();
    expect(await names('read')).toEqual(['get_attachment', 'get_message', 'get_thread', 'list_folders', 'search_messages']);
    expect(await names('draft')).toEqual(['create_draft', 'get_attachment', 'get_message', 'get_thread', 'list_folders', 'move_messages', 'search_messages', 'set_flags']);
    const full = (await (await connect('full')).listTools()).tools;
    expect(full).toHaveLength(10);
    expect(full.find((t) => t.name === 'send_email')?.annotations?.destructiveHint).toBe(true);
    expect(full.find((t) => t.name === 'search_messages')?.annotations?.readOnlyHint).toBe(true);
  });

  it('searches and reads mail with untrusted wrapping', async () => {
    const client = await connect('read');
    const search = await client.callTool({ name: 'search_messages', arguments: { subject: 'Quarterly' } });
    expect(text(search).startsWith('<untrusted_email_content>')).toBe(true);
    const { messages } = json(search);
    expect(messages[0].subject).toBe('Quarterly report');
    const msg = json(await client.callTool({ name: 'get_message', arguments: { folder: 'INBOX', uid: messages[0].uid } }));
    expect(msg.body.trim()).toBe('Numbers are up 10%');
    const folders = json(await client.callTool({ name: 'list_folders', arguments: {} }));
    expect(folders.map((f: { path: string }) => f.path)).toContain('INBOX');
  });

  it('creates drafts and enforces level changes on the next call', async () => {
    const client = await connect('draft');
    const draft = await client.callTool({ name: 'create_draft', arguments: { to: ['x@test.local'], subject: 'Draft via MCP', body: 'hello' } });
    expect(draft.isError).toBeFalsy();
    expect(await findUid(imap, 'Drafts', 'Draft via MCP')).toBeGreaterThan(0);

    // Each MCP request builds a fresh server for the user's *current* level, so a downgrade
    // removes the tool immediately; the SDK reports the call as an error (thrown or isError).
    setPermissionLevel(ctx.deps.db, user.id, 'read');
    expect((await client.listTools()).tools.map((t) => t.name)).not.toContain('create_draft');
    const outcome = await client
      .callTool({ name: 'create_draft', arguments: { to: [], subject: 'Nope', body: 'x' } })
      .then((r) => (r.isError ? 'error' : 'ok'), () => 'error');
    expect(outcome).toBe('error');
    await expect(findUid(imap, 'Drafts', 'Nope')).rejects.toThrow();
  });

  it('sends email and deletes to Trash at full level', async () => {
    const bob = await createMailUser();
    const client = await connect('full');
    const sent = await client.callTool({ name: 'send_email', arguments: { to: [bob.email], subject: 'From MCP', body: 'hi bob' } });
    expect(sent.isError).toBeFalsy();
    const bobImap = await connectImap(bob.email, bob.password);
    try {
      await waitForSubject(bobImap, 'INBOX', 'From MCP');
    } finally {
      await bobImap.logout();
    }
    const uid = await findUid(imap, 'INBOX', 'Quarterly');
    const del = json(await client.callTool({ name: 'delete_messages', arguments: { folder: 'INBOX', uids: [uid] } }));
    expect(del).toMatchObject({ to: 'Trash', moved: 1 });
  });

  it('returns AUTH_FAILED and flags the account when the stored password stops working', async () => {
    ctx.deps.db.prepare('UPDATE users SET imap_password_enc = ? WHERE id = ?').run(encryptSecret(ctx.deps.config.encryptionKey, 'wrong'), user.id);
    const client = await connect('read');
    const result = await client.callTool({ name: 'list_folders', arguments: {} });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/^AUTH_FAILED: .*http:\/\/localhost:3000\/login/);
    expect(findUserById(ctx.deps.db, user.id)?.needsReauth).toBe(true);
  });

  it('maps missing messages to NOT_FOUND', async () => {
    const client = await connect('read');
    const result = await client.callTool({ name: 'get_message', arguments: { folder: 'INBOX', uid: 99999 } });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/^NOT_FOUND/);
  });
});
