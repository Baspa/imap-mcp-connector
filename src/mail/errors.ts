export type MailErrorCode =
  | 'AUTH_FAILED'
  | 'NOT_FOUND'
  | 'PERMISSION_DENIED'
  | 'RATE_LIMITED'
  | 'TOO_LARGE'
  | 'UPSTREAM_UNAVAILABLE'
  | 'INVALID_INPUT';

export class MailError extends Error {
  override name = 'MailError';
  constructor(
    readonly code: MailErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export class OperationTimeoutError extends Error {
  override name = 'OperationTimeoutError';
  readonly code = 'EOPTIMEOUT';
  constructor() {
    super('Mail operation timed out');
  }
}

const CONNECTION_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'EHOSTUNREACH', 'ENETUNREACH',
  'NoConnection', 'ClosedAfterConnectText', 'ClosedAfterConnectTLS', 'ECONNECTION', 'ESOCKET', 'EDNS', 'ETIMEOUT',
]);

interface ErrorLike {
  code?: unknown;
  authenticationFailed?: unknown;
  serverResponseCode?: unknown;
}

function props(err: unknown): ErrorLike {
  return typeof err === 'object' && err !== null ? (err as ErrorLike) : {};
}

export function isConnectionError(err: unknown): boolean {
  const code = props(err).code;
  return typeof code === 'string' && CONNECTION_CODES.has(code);
}

export function toMailError(err: unknown): MailError | null {
  if (err instanceof MailError) return err;
  if (err instanceof OperationTimeoutError) {
    return new MailError('UPSTREAM_UNAVAILABLE', 'The mail server took too long to respond. Try again shortly.');
  }
  const e = props(err);
  if (e.authenticationFailed === true || e.serverResponseCode === 'AUTHENTICATIONFAILED' || e.code === 'EAUTH') {
    return new MailError('AUTH_FAILED', 'The mail server rejected the stored password.');
  }
  if (e.serverResponseCode === 'NONEXISTENT' || e.serverResponseCode === 'TRYCREATE') {
    return new MailError('NOT_FOUND', 'That folder does not exist.');
  }
  if (isConnectionError(err)) {
    return new MailError('UPSTREAM_UNAVAILABLE', 'Mail server unavailable, try again shortly.');
  }
  return null;
}
