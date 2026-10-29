import type { ImapFlow } from 'imapflow';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { encryptSecret } from '../../src/crypto.js';
import type { Db } from '../../src/db/index.js';
import { createUser, type User } from '../../src/db/users.js';
import { getMessage } from '../../src/mail/ops/message.js';
import { createDraft, sendEmail, type OutgoingDeps } from '../../src/mail/outgoing.js';
import { MailPool } from '../../src/mail/pool.js';
import { defaultSmtpFactory } from '../../src/mail/smtp.js';
import { TEST_KEY } from '../helpers/config.js';
import { testDb } from '../helpers/db.js';
import { appendMessage, connectImap, createFolders, createMailUser, findUid, greenmailSettings, waitForSubject } from './mail-helpers.js';

let db: Db;
let alice: User;
let aliceImap: ImapFlow;
let bob: { email: string; password: string };
let deps: OutgoingDeps;

beforeEach(async () => {
  db = testDb();
  const a = await createMailUser();
  bob = await createMailUser();
  alice = createUser(db, { ...greenmailSettings(), email: a.email, smtpUsername: a.email, imapPasswordEnc: encryptSecret(TEST_KEY, a.password), settingsSource: 'discovered' });
  aliceImap = await connectImap(a.email, a.password);
  await createFolders(aliceImap);
  const pool = new MailPool({ db, key: TEST_KEY, signInUrl: 'http://localhost/login' });
  deps = { db, key: TEST_KEY, pool, smtpFactory: defaultSmtpFactory, defaultSendLimitPerHour: 20, allowedRecipientDomains: [], signInUrl: 'http://localhost/login' };
});

afterEach(async () => {
  await aliceImap.logout();
  await deps.pool.closeAll();
});

describe('createDraft', () => {
  it('saves a draft into Drafts', async () => {
    const r = await createDraft(deps, alice, { to: [bob.email], bcc: ['hidden@test.local'], subject: 'Draft subject', body: 'Draft body' });
    expect(r.folder).toBe('Drafts');
    const uid = await findUid(aliceImap, 'Drafts', 'Draft subject');
    const m = await getMessage(aliceImap, 'Drafts', uid);
    expect(m.flags).toContain('\\Draft');
    expect(m.flags).toContain('\\Seen');
    expect(m.body.trim()).toBe('Draft body');
    expect(m.messageId).toBe(r.messageId);
    const lock = await aliceImap.getMailboxLock('Drafts');
    try {
      const src = await aliceImap.fetchOne(String(uid), { uid: true, source: true }, { uid: true });
      expect(String(src && src.source)).toMatch(/^Bcc: .*hidden@test.local/im);
    } finally {
      lock.release();
    }
  });

  it('threads a reply draft to the original', async () => {
    await appendMessage(aliceImap, 'INBOX', { subject: 'Question', text: '?', messageId: '<q@test>', references: ['<root@test>'] });
    const uid = await findUid(aliceImap, 'INBOX', 'Question');
    await createDraft(deps, alice, { to: [bob.email], body: 'Answer', replyToUid: uid, replyToFolder: 'INBOX' });
    const draftUid = await findUid(aliceImap, 'Drafts', 'Re: Question');
    const lock = await aliceImap.getMailboxLock('Drafts');
    const msg = await aliceImap.fetchOne(String(draftUid), { uid: true, headers: ['in-reply-to', 'references'] }, { uid: true });
    lock.release();
    const headers = String(msg && msg.headers);
    expect(headers).toMatch(/^In-Reply-To: <q@test>\s*$/im);
    expect(headers).toContain('<root@test> <q@test>');
  });
});

describe('sendEmail', () => {
  it('delivers over SMTP and saves a copy to Sent', async () => {
    const r = await sendEmail(deps, alice, { to: [bob.email], subject: 'Hello Bob', body: 'Hi from Alice' });
    expect(r.savedToSent).toBe(true);
    const bobImap = await connectImap(bob.email, bob.password);
    try {
      const uid = await waitForSubject(bobImap, 'INBOX', 'Hello Bob');
      expect((await getMessage(bobImap, 'INBOX', uid)).body.trim()).toBe('Hi from Alice');
    } finally {
      await bobImap.logout();
    }
    const sentUid = await findUid(aliceImap, 'Sent', 'Hello Bob');
    const sentCopy = await getMessage(aliceImap, 'Sent', sentUid);
    expect(sentCopy.messageId).toBe(r.messageId);
    expect(sentCopy.flags).toContain('\\Seen');
  });

  it('skips the Sent copy for providers that save it themselves', async () => {
    const r = await sendEmail(deps, { ...alice, autoSavesSent: true }, { to: [bob.email], subject: 'No copy', body: 'x' });
    expect(r.savedToSent).toBe(false);
    await expect(findUid(aliceImap, 'Sent', 'No copy')).rejects.toThrow();
  });
});
