export function log(level: 'info' | 'warn' | 'error', msg: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields });
  if (level === 'error') console.error(line);
  else console.log(line);
}

export type AuditEvent =
  | 'sign_in'
  | 'grants_revoked'
  | 'app_connected'
  | 'send_email'
  | 'move_messages'
  | 'delete_messages';

/**
 * Records who did what, so an incident can be reconstructed afterwards. Never pass passwords, tokens,
 * message content or full recipient addresses: this stream is meant to be safe to keep and to read.
 */
export function audit(event: AuditEvent, fields: Record<string, unknown> = {}): void {
  log('info', 'audit', { event, ...fields });
}
