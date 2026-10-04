import { promises as dns } from 'node:dns';
import ipaddr from 'ipaddr.js';
import type { Config } from './config.js';
import type { MailServerSettings } from './types.js';

export class GuardError extends Error {
  override name = 'GuardError';
}

export type LookupAll = (host: string) => Promise<{ address: string }[]>;

const defaultLookup: LookupAll = (host) => dns.lookup(host, { all: true });

export function isEmailOrHostAllowed(config: Config, email: string, imapHost: string): boolean {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  const host = imapHost.toLowerCase();
  return (
    config.allowedEmailDomains.includes(domain) ||
    config.allowedImapHosts.includes('*') ||
    config.allowedImapHosts.includes(host)
  );
}

export function isPublicAddress(addr: string): boolean {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(addr);
  } catch {
    return false;
  }
  if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
    parsed = (parsed as ipaddr.IPv6).toIPv4Address();
  }
  return parsed.range() === 'unicast';
}

async function assertPublicHost(host: string, lookup: LookupAll): Promise<void> {
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host);
  } catch {
    throw new GuardError(`Could not resolve ${host}.`);
  }
  if (addresses.length === 0 || addresses.some((a) => !isPublicAddress(a.address))) {
    throw new GuardError(`${host} resolves to a private or reserved address, which this instance does not allow.`);
  }
}

export async function guardMailSettings(
  config: Config,
  email: string,
  settings: MailServerSettings,
  lookup: LookupAll = defaultLookup,
): Promise<void> {
  if (!isEmailOrHostAllowed(config, email, settings.imapHost)) {
    throw new GuardError('This mail server is not allowed on this instance. Ask the administrator.');
  }
  if (config.allowPrivateHosts) return;
  if (settings.imapSecurity === 'none' || settings.smtpSecurity === 'none') {
    throw new GuardError('Unencrypted mail connections are not allowed on this instance.');
  }
  for (const host of new Set([settings.imapHost, settings.smtpHost])) {
    await assertPublicHost(host, lookup);
  }
}
