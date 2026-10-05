import { XMLParser, XMLValidator } from 'fast-xml-parser';
import type { DiscoveryResult, MailServerSettings, Security } from '../types.js';

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

/** True when the body is well-formed XML with a clientConfig root, i.e. a real ISPDB answer rather than an error page. */
function isClientConfig(xml: string): boolean {
  try {
    return XMLValidator.validate(xml) === true && new XMLParser().parse(xml)?.clientConfig !== undefined;
  } catch {
    return false;
  }
}

export async function fetchIspdb(domain: string, fetchFn: typeof fetch = fetch): Promise<DiscoveryResult> {
  try {
    const res = await fetchFn(`https://autoconfig.thunderbird.net/v1.1/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(5000),
    });
    // Only a 404 means the ISPDB has no entry; rate limiting, outages and the like are failed lookups.
    if (res.status === 404) return { status: 'not_found' };
    if (!res.ok) return { status: 'error' };
    const body = await res.text();
    if (!isClientConfig(body)) return { status: 'error' };
    const settings = parseIspdb(body, domain);
    return settings ? { status: 'found', settings } : { status: 'not_found' };
  } catch {
    return { status: 'error' };
  }
}
