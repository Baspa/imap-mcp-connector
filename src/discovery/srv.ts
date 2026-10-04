import { promises as dns, type SrvRecord } from 'node:dns';
import type { MailServerSettings, Security } from '../types.js';

type Resolver = (name: string) => Promise<SrvRecord[]>;

async function best(resolve: Resolver, name: string): Promise<SrvRecord | null> {
  try {
    const records = (await resolve(name)).filter((r) => r.name && r.name !== '.');
    records.sort((a, b) => a.priority - b.priority || b.weight - a.weight);
    return records[0] ?? null;
  } catch {
    return null;
  }
}

const host = (name: string) => name.replace(/\.$/, '');

export async function resolveSrvSettings(
  domain: string,
  resolve: Resolver = (n) => dns.resolveSrv(n),
): Promise<MailServerSettings | null> {
  const imap = await best(resolve, `_imaps._tcp.${domain}`);
  if (!imap) return null;
  let smtp = await best(resolve, `_submissions._tcp.${domain}`);
  let smtpSecurity: Security = 'tls';
  if (!smtp) {
    smtp = await best(resolve, `_submission._tcp.${domain}`);
    smtpSecurity = 'starttls';
  }
  if (!smtp) return null;
  return {
    imapHost: host(imap.name),
    imapPort: imap.port,
    imapSecurity: 'tls',
    smtpHost: host(smtp.name),
    smtpPort: smtp.port,
    smtpSecurity,
    autoSavesSent: false,
  };
}
