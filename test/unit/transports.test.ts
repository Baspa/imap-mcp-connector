import { describe, expect, it } from 'vitest';
import { defaultImapFactory } from '../../src/mail/imap.js';
import { defaultSmtpFactory } from '../../src/mail/smtp.js';

// These read the libraries' own connection fields: what matters is where the socket goes and which name TLS checks.
describe('connection factories', () => {
  const imapTarget = { email: 'a@x.org', imapHost: 'imap.x.org', imapPort: 993, imapSecurity: 'tls' as const };
  const smtpTarget = { smtpHost: 'smtp.x.org', smtpPort: 465, smtpSecurity: 'tls' as const, smtpUsername: 'a@x.org' };

  it('IMAP connects to the vetted address and verifies TLS against the hostname', () => {
    const client = defaultImapFactory({ ...imapTarget, connectAddress: '93.184.216.34' }, 'pw') as unknown as { host: string; servername: string };
    expect(client.host).toBe('93.184.216.34');
    expect(client.servername).toBe('imap.x.org');
  });

  it('IMAP connects to the hostname when nothing was pinned', () => {
    const client = defaultImapFactory(imapTarget, 'pw') as unknown as { host: string; servername: string };
    expect(client.host).toBe('imap.x.org');
    expect(client.servername).toBe('imap.x.org');
  });

  it('SMTP connects to the vetted address and verifies TLS against the hostname', () => {
    const transport = defaultSmtpFactory({ ...smtpTarget, connectAddress: '93.184.216.35' }, 'pw') as unknown as {
      transporter: { options: { host: string; tls?: { servername?: string } } };
    };
    expect(transport.transporter.options).toMatchObject({ host: '93.184.216.35', tls: { servername: 'smtp.x.org' } });
  });

  it('SMTP connects to the hostname when nothing was pinned', () => {
    const transport = defaultSmtpFactory(smtpTarget, 'pw') as unknown as { transporter: { options: { host: string } } };
    expect(transport.transporter.options.host).toBe('smtp.x.org');
  });
});
