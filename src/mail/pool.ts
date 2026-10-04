import type { ImapFlow } from 'imapflow';
import { decryptSecret } from '../crypto.js';
import type { Db } from '../db/index.js';
import { setNeedsReauth, type User } from '../db/users.js';
import { isConnectionError, MailError, OperationTimeoutError, toMailError } from './errors.js';
import { defaultImapFactory, type ImapFactory } from './imap.js';

export interface MailPoolOptions {
  db: Db;
  key: Buffer;
  signInUrl: string;
  factory?: ImapFactory;
  idleMs?: number;
  timeoutMs?: number;
}

interface Entry {
  client: ImapFlow;
  idleTimer?: NodeJS.Timeout;
}

interface Acquired {
  client: ImapFlow;
  /** True when the client came from the cache rather than being opened for this operation. */
  reused: boolean;
}

export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new OperationTimeoutError()), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** One cached IMAP connection per user; operations for a user run one at a time. */
export class MailPool {
  private readonly entries = new Map<number, Entry>();
  private readonly queues = new Map<number, Promise<unknown>>();
  private readonly factory: ImapFactory;
  private readonly idleMs: number;
  private readonly timeoutMs: number;

  constructor(private readonly opts: MailPoolOptions) {
    this.factory = opts.factory ?? defaultImapFactory;
    this.idleMs = opts.idleMs ?? 5 * 60_000;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  withImap<T>(user: User, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
    const previous = this.queues.get(user.id) ?? Promise.resolve();
    const run = previous.catch(() => undefined).then(() => this.runWithRetry(user, fn));
    this.queues.set(user.id, run);
    void run
      .catch(() => undefined)
      .finally(() => {
        if (this.queues.get(user.id) === run) this.queues.delete(user.id);
      });
    return run;
  }

  async close(userId: number): Promise<void> {
    const entry = this.entries.get(userId);
    if (!entry) return;
    this.entries.delete(userId);
    clearTimeout(entry.idleTimer);
    await entry.client.logout().catch(() => entry.client.close());
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.entries.keys()].map((id) => this.close(id)));
  }

  private async runWithRetry<T>(user: User, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
    if (user.needsReauth) throw this.reauthError();
    let reused = false;
    try {
      return await this.runOnce(user, fn, (wasReused) => {
        reused = wasReused;
      });
    } catch (err) {
      // Retry only when a cached connection failed: it may simply have gone stale while idle.
      // A connection opened for this operation that fails mid-command may mean the server already
      // executed a non-idempotent command (move, append), so retrying could duplicate it.
      if (!(reused && isConnectionError(err))) throw this.translate(user, err);
      try {
        return await this.runOnce(user, fn, () => undefined);
      } catch (retryErr) {
        throw this.translate(user, retryErr);
      }
    }
  }

  private async runOnce<T>(
    user: User,
    fn: (client: ImapFlow) => Promise<T>,
    onAcquired: (reused: boolean) => void,
  ): Promise<T> {
    const { client, reused } = await this.acquire(user);
    onAcquired(reused);
    try {
      return await withTimeout(fn(client), this.timeoutMs);
    } catch (err) {
      if (err instanceof OperationTimeoutError || isConnectionError(err) || !client.usable) {
        this.discard(user.id, client);
      }
      throw err;
    } finally {
      this.scheduleIdle(user.id, client);
    }
  }

  private async acquire(user: User): Promise<Acquired> {
    const existing = this.entries.get(user.id);
    if (existing?.client.usable) {
      clearTimeout(existing.idleTimer);
      return { client: existing.client, reused: true };
    }
    if (existing) this.discard(user.id, existing.client);

    let password: string;
    try {
      password = decryptSecret(this.opts.key, user.imapPasswordEnc);
    } catch {
      throw new MailError('AUTH_FAILED', 'The stored password could not be decrypted.');
    }
    const client = this.factory(user, password);
    client.on('error', () => this.discard(user.id, client));
    try {
      await withTimeout(client.connect(), this.timeoutMs);
    } catch (err) {
      client.close();
      throw err;
    }
    this.entries.set(user.id, { client });
    return { client, reused: false };
  }

  private discard(userId: number, client: ImapFlow): void {
    const entry = this.entries.get(userId);
    if (entry?.client === client) {
      clearTimeout(entry.idleTimer);
      this.entries.delete(userId);
    }
    try {
      client.close();
    } catch {
      // already closed
    }
  }

  private scheduleIdle(userId: number, client: ImapFlow): void {
    const entry = this.entries.get(userId);
    if (!entry || entry.client !== client) return;
    clearTimeout(entry.idleTimer);
    entry.idleTimer = setTimeout(() => void this.close(userId), this.idleMs);
    entry.idleTimer.unref();
  }

  private translate(user: User, err: unknown): unknown {
    const mailError = toMailError(err);
    if (!mailError) return err;
    if (mailError.code === 'AUTH_FAILED') {
      setNeedsReauth(this.opts.db, user.id, true);
      return this.reauthError();
    }
    return mailError;
  }

  private reauthError(): MailError {
    return new MailError(
      'AUTH_FAILED',
      `The mailbox password no longer works. Ask the user to sign in at ${this.opts.signInUrl} to update it.`,
    );
  }
}
