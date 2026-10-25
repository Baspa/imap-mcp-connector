import { promises as dns } from 'node:dns';
import { isIPv4 } from 'node:net';
import ipaddr from 'ipaddr.js';
import type { Config } from './config.js';
import { serverSettingsOf, type User } from './db/users.js';
import { PRESETS } from './discovery/presets.js';
import type { MailServerSettings, SettingsSource } from './types.js';

export class GuardError extends Error {
  override name = 'GuardError';
}

export type LookupAll = (host: string) => Promise<{ address: string }[]>;

const defaultLookup: LookupAll = (host) => dns.lookup(host, { all: true });

/**
 * Both allowlists must pass: a set ALLOWED_EMAIL_DOMAINS restricts who may sign in, and a set
 * ALLOWED_IMAP_HOSTS (other than "*") restricts which servers they may use. An empty list does not restrict.
 */
export function isAllowed(config: Config, email: string, imapHost: string): boolean {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  const host = imapHost.toLowerCase();
  const domains = config.allowedEmailDomains;
  const hosts = config.allowedImapHosts;
  const domainOk = domains.length === 0 || domains.includes(domain);
  const hostOk = hosts.length === 0 || hosts.includes('*') || hosts.includes(host);
  return domainOk && hostOk;
}

/**
 * Whether a hand-entered or changed SMTP server may be used. The IMAP password is sent to the SMTP server by default,
 * so it must be the account's own IMAP host or a host the administrator listed by name ("*" does not count).
 */
export function isAllowedSmtpHost(config: Config, imapHost: string, smtpHost: string): boolean {
  const smtp = smtpHost.toLowerCase();
  return smtp === imapHost.toLowerCase() || config.allowedImapHosts.some((h) => h !== '*' && h === smtp);
}

/** True when ALLOWED_IMAP_HOSTS names this host; the "*" wildcard does not count. */
export function isListedImapHost(config: Config, imapHost: string): boolean {
  return config.allowedImapHosts.includes(imapHost.toLowerCase());
}

/**
 * Whether an account's stored IMAP server may receive the account owner's password. Discovered settings come from
 * the domain itself. Hand-entered ones are trusted only for servers the administrator listed by name: otherwise
 * whoever signs in first with an address decides where its real owner's password is sent. Legacy accounts (created
 * before the source was recorded) are trusted here only when they match a built-in preset or a listed server.
 */
export function isTrustedServer(config: Config, email: string, imapHost: string, source: SettingsSource): boolean {
  if (source === 'discovered' || isListedImapHost(config, imapHost)) return true;
  if (source === 'manual') return false;
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  return Object.hasOwn(PRESETS, domain) && PRESETS[domain].imapHost === imapHost.toLowerCase();
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

/** Resolves a host, requires every address to be public, and returns the one to connect to (IPv4 preferred). */
async function vetPublicHost(host: string, lookup: LookupAll): Promise<string> {
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host);
  } catch {
    throw new GuardError(`Could not resolve ${host}.`);
  }
  if (addresses.length === 0 || addresses.some((a) => !isPublicAddress(a.address))) {
    throw new GuardError(`${host} resolves to a private or reserved address, which this instance does not allow.`);
  }
  return (addresses.find((a) => isIPv4(a.address)) ?? addresses[0]).address;
}

/**
 * Addresses the guard vetted. Connections must use these instead of resolving the hostname again: a second DNS
 * answer could point somewhere private (DNS rebinding). Empty when private hosts are allowed and nothing was checked.
 */
export interface PinnedAddresses {
  imap?: string;
  smtp?: string;
}

export async function guardMailSettings(
  config: Config,
  email: string,
  settings: MailServerSettings,
  lookup: LookupAll = defaultLookup,
): Promise<PinnedAddresses> {
  if (!isAllowed(config, email, settings.imapHost)) {
    throw new GuardError('This mail server is not allowed on this instance. Ask the administrator.');
  }
  if (config.allowPrivateHosts) return {};
  if (settings.imapSecurity === 'none' || settings.smtpSecurity === 'none') {
    throw new GuardError('Unencrypted mail connections are not allowed on this instance.');
  }
  const imap = await vetPublicHost(settings.imapHost, lookup);
  const smtp = settings.smtpHost === settings.imapHost ? imap : await vetPublicHost(settings.smtpHost, lookup);
  return { imap, smtp };
}

/** Checks a stored account before a new mail connection: its server must be trusted and pass guardMailSettings. */
export async function guardStoredUser(config: Config, user: User, lookup: LookupAll = defaultLookup): Promise<PinnedAddresses> {
  if (!isTrustedServer(config, user.email, user.imapHost, user.settingsSource)) {
    throw new GuardError("This account's mail server is not approved on this instance. Ask the user to sign in again.");
  }
  return guardMailSettings(config, user.email, serverSettingsOf(user), lookup);
}
