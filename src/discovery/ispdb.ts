import { XMLParser } from 'fast-xml-parser';
import type { MailServerSettings, Security } from '../types.js';

interface XmlServer {
  '@_type'?: string;
  hostname?: string;
  port?: number | string;
  socketType?: string;
}

const SOCKET: Record<string, Security> = { SSL: 'tls', STARTTLS: 'starttls' };

function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isValidHostname(hostname: string): boolean {
  return hostname.length > 0 && !hostname.includes('%');
}

function pick(servers: XmlServer[] | undefined, type: string, domain?: string): { host: string; port: number; security: Security } | null {
  const candidates = (servers ?? [])
    .filter((s) => s['@_type'] === type && s.hostname && s.socketType && SOCKET[s.socketType])
    .map((s) => {
      let hostname = String(s.hostname);
      if (domain) {
        hostname = hostname.replace('%EMAILDOMAIN%', domain);
      }
      return {
        host: hostname,
        port: Number(s.port),
        security: SOCKET[s.socketType!],
      };
    })
    .filter((s) => isValidPort(s.port) && isValidHostname(s.host));
  return candidates.find((c) => c.security === 'tls') ?? candidates[0] ?? null;
}

export function parseIspdb(xml: string, domain?: string): MailServerSettings | null {
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      isArray: (name) => name === 'incomingServer' || name === 'outgoingServer',
    });
    const doc = parser.parse(xml);
    const provider = doc?.clientConfig?.emailProvider;
    if (!provider) return null;
    const imap = pick(provider.incomingServer, 'imap', domain);
    const smtp = pick(provider.outgoingServer, 'smtp', domain);
    if (!imap || !smtp) return null;
    return {
      imapHost: imap.host,
      imapPort: imap.port,
      imapSecurity: imap.security,
      smtpHost: smtp.host,
      smtpPort: smtp.port,
      smtpSecurity: smtp.security,
      autoSavesSent: false,
    };
  } catch {
    return null;
  }
}

export async function fetchIspdb(domain: string, fetchFn: typeof fetch = fetch): Promise<MailServerSettings | null> {
  try {
    const res = await fetchFn(`https://autoconfig.thunderbird.net/v1.1/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return parseIspdb(await res.text(), domain);
  } catch {
    return null;
  }
}
