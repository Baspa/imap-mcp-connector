// Provider hosts, ports and domains adapted from nikolausm/imap-mcp-server
// (src/providers/email-providers.ts), MIT License, Copyright (c) 2024 Michael Nikolaus.
// See THIRD_PARTY_NOTICES.md.
import type { MailServerSettings } from '../types.js';

const tls = (imapHost: string, smtpHost: string, smtpPort = 465, autoSavesSent = false): MailServerSettings => ({
  imapHost,
  imapPort: 993,
  imapSecurity: 'tls',
  smtpHost,
  smtpPort,
  smtpSecurity: smtpPort === 465 ? 'tls' : 'starttls',
  autoSavesSent,
});

const PROVIDERS: { settings: MailServerSettings; domains: string[] }[] = [
  { settings: tls('imap.gmail.com', 'smtp.gmail.com', 465, true), domains: ['gmail.com', 'googlemail.com'] },
  { settings: tls('imap.mail.me.com', 'smtp.mail.me.com', 587), domains: ['icloud.com', 'me.com', 'mac.com'] },
  { settings: tls('imap.mail.yahoo.com', 'smtp.mail.yahoo.com'), domains: ['yahoo.com', 'yahoo.de', 'yahoo.co.uk', 'ymail.com'] },
  { settings: tls('imap.aol.com', 'smtp.aol.com'), domains: ['aol.com', 'aol.de'] },
  { settings: tls('imap.fastmail.com', 'smtp.fastmail.com'), domains: ['fastmail.com', 'fastmail.fm'] },
  { settings: tls('imap.zoho.com', 'smtp.zoho.com'), domains: ['zoho.com', 'zohomail.com'] },
  { settings: tls('imap.gmx.net', 'mail.gmx.net', 587), domains: ['gmx.net', 'gmx.de', 'gmx.at', 'gmx.ch', 'gmx.com'] },
  { settings: tls('imap.web.de', 'smtp.web.de', 587), domains: ['web.de'] },
  { settings: tls('imap.ionos.de', 'smtp.ionos.de', 587), domains: ['ionos.de', '1und1.de', '1and1.com'] },
  { settings: tls('imap.mailbox.org', 'smtp.mailbox.org', 587), domains: ['mailbox.org'] },
  { settings: tls('posteo.de', 'posteo.de', 587), domains: ['posteo.de', 'posteo.net'] },
];

export const PRESETS: Record<string, MailServerSettings> = Object.fromEntries(
  PROVIDERS.flatMap((p) => p.domains.map((d) => [d, p.settings])),
);
