import { describe, expect, it } from 'vitest';
import { isConnectionError, MailError, OperationTimeoutError, toMailError } from '../../src/mail/errors.js';

const err = (props: Record<string, unknown>) => Object.assign(new Error('x'), props);

describe('toMailError', () => {
  it('passes MailError through', () => {
    const e = new MailError('NOT_FOUND', 'gone');
    expect(toMailError(e)).toBe(e);
  });

  it('maps auth failures from imapflow and nodemailer', () => {
    expect(toMailError(err({ authenticationFailed: true }))?.code).toBe('AUTH_FAILED');
    expect(toMailError(err({ serverResponseCode: 'AUTHENTICATIONFAILED' }))?.code).toBe('AUTH_FAILED');
    expect(toMailError(err({ code: 'EAUTH' }))?.code).toBe('AUTH_FAILED');
  });

  it('maps missing folders', () => {
    expect(toMailError(err({ serverResponseCode: 'NONEXISTENT' }))?.code).toBe('NOT_FOUND');
    expect(toMailError(err({ serverResponseCode: 'TRYCREATE' }))?.code).toBe('NOT_FOUND');
  });

  it('maps connection errors and timeouts', () => {
    expect(toMailError(err({ code: 'ECONNRESET' }))?.code).toBe('UPSTREAM_UNAVAILABLE');
    expect(toMailError(err({ code: 'NoConnection' }))?.code).toBe('UPSTREAM_UNAVAILABLE');
    expect(toMailError(new OperationTimeoutError())?.code).toBe('UPSTREAM_UNAVAILABLE');
  });

  it('returns null for unexpected errors', () => {
    expect(toMailError(new TypeError('bug'))).toBeNull();
    expect(toMailError('string')).toBeNull();
  });
});

describe('isConnectionError', () => {
  it('detects network codes but not timeouts', () => {
    expect(isConnectionError(err({ code: 'ETIMEDOUT' }))).toBe(true);
    expect(isConnectionError(err({ code: 'ESOCKET' }))).toBe(true);
    expect(isConnectionError(new OperationTimeoutError())).toBe(false);
    expect(isConnectionError(new Error('plain'))).toBe(false);
  });
});
