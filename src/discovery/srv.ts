import { promises as dns, NODATA, NOTFOUND, type SrvRecord } from 'node:dns';
import type { DiscoveryResult, Security } from '../types.js';

type Resolver = (name: string) => Promise<SrvRecord[]>;
type Lookup = { status: 'found'; record: SrvRecord } | { status: 'not_found' } | { status: 'error' };

// Only these answers mean the record definitively does not exist; anything else (SERVFAIL, timeouts,
// refused connections, ...) is a failed lookup that must not be mistaken for "nothing published".
const DEFINITIVE = new Set<unknown>([NOTFOUND, NODATA]);

async function best(resolve: Resolver, name: string): Promise<Lookup> {
  let records: SrvRecord[];
  try {
    records = await resolve(name);
  } catch (err) {
    return DEFINITIVE.has((err as { code?: unknown } | null)?.code) ? { status: 'not_found' } : { status: 'error' };
  }
  const usable = records.filter((r) => r.name && r.name !== '.');
  usable.sort((a, b) => a.priority - b.priority || b.weight - a.weight);
  return usable[0] ? { status: 'found', record: usable[0] } : { status: 'not_found' };
}

const host = (name: string) => name.replace(/\.$/, '');

export async function resolveSrvSettings(
  domain: string,
  resolve: Resolver = (n) => dns.resolveSrv(n),
): Promise<DiscoveryResult> {
  const imap = await best(resolve, `_imaps._tcp.${domain}`);
  if (imap.status !== 'found') return imap;
  let smtp = await best(resolve, `_submissions._tcp.${domain}`);
  let smtpSecurity: Security = 'tls';
  if (smtp.status === 'not_found') {
    smtp = await best(resolve, `_submission._tcp.${domain}`);
    smtpSecurity = 'starttls';
  }
  if (smtp.status !== 'found') return smtp;
  return {
    status: 'found',
    settings: {
      imapHost: host(imap.record.name),
      imapPort: imap.record.port,
      imapSecurity: 'tls',
      smtpHost: host(smtp.record.name),
      smtpPort: smtp.record.port,
      smtpSecurity,
      autoSavesSent: false,
    },
  };
}
