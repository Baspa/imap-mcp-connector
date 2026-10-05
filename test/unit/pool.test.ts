import { EventEmitter } from 'node:events';
import type { ImapFlow } from 'imapflow';
import { describe, expect, it } from 'vitest';
import { findUserById, setNeedsReauth, type User } from '../../src/db/users.js';
import { GuardError, type PinnedAddresses } from '../../src/guard.js';
import type { ImapTarget } from '../../src/mail/imap.js';
import { MailError } from '../../src/mail/errors.js';
import { imapSecurityOptions, verifyImapLogin } from '../../src/mail/imap.js';
import { MailPool } from '../../src/mail/pool.js';
import { TEST_KEY } from '../helpers/config.js';
import { createTestUser, testDb } from '../helpers/db.js';

class FakeClient extends EventEmitter {
  usable = false;
  closed = false;
  constructor(private readonly connectError?: Error) {
    super();
  }
  async connect() {
    if (this.connectError) throw this.connectError;
    this.usable = true;
  }
  async logout() {
    this.usable = false;
    this.closed = true;
  }
  close() {
    this.usable = false;
    this.closed = true;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const netError = () => Object.assign(new Error('reset'), { code: 'ECONNRESET' });
const authError = () => Object.assign(new Error('auth'), { authenticationFailed: true });

function setup(
  opts: { connectErrors?: (Error | undefined)[]; idleMs?: number; timeoutMs?: number; guard?: (user: User) => Promise<PinnedAddresses | void> } = {},
) {
  const db = testDb();
  const user = createTestUser(db);
  const clients: FakeClient[] = [];
  const targets: ImapTarget[] = [];
  const errors = [...(opts.connectErrors ?? [])];
  const pool = new MailPool({
    db,
    key: TEST_KEY,
    signInUrl: 'https://mail.example.com/login',
    idleMs: opts.idleMs ?? 60_000,
    timeoutMs: opts.timeoutMs ?? 1_000,
    guard: opts.guard,
    factory: (target) => {
      targets.push(target);
      const c = new FakeClient(errors.shift());
      clients.push(c);
      return c as unknown as ImapFlow;
    },
  });
  return { db, user, pool, clients, targets };
}

describe('MailPool', () => {
  it('reuses one connection across calls', async () => {
    const { user, pool, clients } = setup();
    await pool.withImap(user, async () => 1);
    await pool.withImap(user, async () => 2);
    expect(clients).toHaveLength(1);
  });

  it('serializes operations for the same user', async () => {
    const { user, pool } = setup();
    let active = 0;
    let maxActive = 0;
    const op = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await sleep(10);
      active--;
    };
    await Promise.all([pool.withImap(user, op), pool.withImap(user, op), pool.withImap(user, op)]);
    expect(maxActive).toBe(1);
  });

  it('keeps the queue going after a failed operation', async () => {
    const { user, pool } = setup();
    const failed = pool.withImap(user, async () => {
      throw new MailError('NOT_FOUND', 'nope');
    });
    const ok = pool.withImap(user, async () => 'ok');
    await expect(failed).rejects.toThrow('nope');
    await expect(ok).resolves.toBe('ok');
  });

  it('retries once on a connection error with a fresh client', async () => {
    const { user, pool, clients } = setup();
    await pool.withImap(user, async () => 'warm-up');
    let calls = 0;
    const result = await pool.withImap(user, async () => {
      calls++;
      if (calls === 1) throw netError();
      return 'ok';
    });
    expect(result).toBe('ok');
    expect(clients).toHaveLength(2);
    expect(clients[0].closed).toBe(true);
  });

  it('gives up after the second connection error', async () => {
    const { user, pool, clients } = setup();
    await pool.withImap(user, async () => 'warm-up');
    await expect(
      pool.withImap(user, async () => {
        throw netError();
      }),
    ).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(clients).toHaveLength(2);
  });

  it('does not retry when a freshly opened connection fails', async () => {
    const { user, pool, clients } = setup();
    let calls = 0;
    await expect(
      pool.withImap(user, async () => {
        calls++;
        throw netError();
      }),
    ).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(calls).toBe(1);
    expect(clients).toHaveLength(1);
  });

  it('does not retry when connect itself fails', async () => {
    const { user, pool, clients } = setup({ connectErrors: [netError()] });
    await expect(pool.withImap(user, async () => 1)).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(clients).toHaveLength(1);
  });

  it('marks the user for re-auth when the password is rejected', async () => {
    const { db, user, pool } = setup({ connectErrors: [authError()] });
    const err = await pool.withImap(user, async () => 1).catch((e) => e);
    expect(err).toBeInstanceOf(MailError);
    expect(err.code).toBe('AUTH_FAILED');
    expect(err.message).toContain('https://mail.example.com/login');
    expect(findUserById(db, user.id)?.needsReauth).toBe(true);
  });

  it('fails fast for users that need re-auth', async () => {
    const { db, user, pool, clients } = setup();
    setNeedsReauth(db, user.id, true);
    await expect(pool.withImap(findUserById(db, user.id)!, async () => 1)).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(clients).toHaveLength(0);
  });

  it('re-checks the guard before opening a new connection', async () => {
    const guard = async () => {
      throw new GuardError('This mail server is not allowed on this instance. Ask the administrator.');
    };
    const { db, user, pool, clients } = setup({ guard });
    const err = await pool.withImap(user, async () => 1).catch((e) => e);
    expect(err).toBeInstanceOf(MailError);
    expect(err.code).toBe('PERMISSION_DENIED');
    expect(err.message).toBe('This mail server is not allowed on this instance. Ask the administrator.');
    expect(clients).toHaveLength(0);
    expect(findUserById(db, user.id)?.needsReauth).toBe(false);
  });

  it('connects to the address the guard vetted, not a fresh DNS answer', async () => {
    const { user, pool, targets } = setup({ guard: async () => ({ imap: '93.184.216.34' }) });
    await pool.withImap(user, async () => 1);
    expect(targets[0]).toMatchObject({ imapHost: user.imapHost, connectAddress: '93.184.216.34' });
  });

  it('does not re-run the guard for a reused connection', async () => {
    let calls = 0;
    const { user, pool, clients } = setup({ guard: async () => void calls++ });
    await pool.withImap(user, async () => 1);
    await pool.withImap(user, async () => 2);
    expect(calls).toBe(1);
    expect(clients).toHaveLength(1);
  });

  it('treats an undecryptable password as an auth failure', async () => {
    const { db, pool } = setup();
    const broken = createTestUser(db);
    await expect(pool.withImap({ ...broken, imapPasswordEnc: 'v1:bad:bad:bad' }, async () => 1)).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(findUserById(db, broken.id)?.needsReauth).toBe(true);
  });

  it('times out slow operations and discards the connection', async () => {
    const { user, pool, clients } = setup({ timeoutMs: 20 });
    await expect(pool.withImap(user, () => new Promise(() => {}))).rejects.toMatchObject({ code: 'UPSTREAM_UNAVAILABLE' });
    expect(clients[0].closed).toBe(true);
  });

  it('closes idle connections', async () => {
    const { user, pool, clients } = setup({ idleMs: 10 });
    await pool.withImap(user, async () => 1);
    await sleep(40);
    expect(clients[0].closed).toBe(true);
    await pool.withImap(user, async () => 1);
    expect(clients).toHaveLength(2);
  });

  it('closeAll logs out every connection', async () => {
    const { user, pool, clients } = setup();
    await pool.withImap(user, async () => 1);
    await pool.closeAll();
    expect(clients[0].closed).toBe(true);
  });
});

describe('imap helpers', () => {
  it('maps security to imapflow options', () => {
    expect(imapSecurityOptions('tls')).toEqual({ secure: true });
    expect(imapSecurityOptions('starttls')).toEqual({ secure: false, doSTARTTLS: true });
    expect(imapSecurityOptions('none')).toEqual({ secure: false, doSTARTTLS: false });
  });

  it('verifyImapLogin classifies results', async () => {
    const target = { email: 'a@x.org', imapHost: 'h', imapPort: 993, imapSecurity: 'tls' as const };
    const make = (e?: Error) => () => new FakeClient(e) as unknown as ImapFlow;
    expect(await verifyImapLogin(target, 'pw', make())).toBe('ok');
    expect(await verifyImapLogin(target, 'pw', make(authError()))).toBe('bad_credentials');
    expect(await verifyImapLogin(target, 'pw', make(netError()))).toBe('unavailable');
  });
});
