import type { DiscoveryResult, MailServerSettings } from '../types.js';
import { fetchIspdb } from './ispdb.js';
import { PRESETS } from './presets.js';
import { resolveSrvSettings } from './srv.js';

export interface DiscoveryDeps {
  ispdb(domain: string): Promise<DiscoveryResult>;
  srv(domain: string): Promise<DiscoveryResult>;
}

/** A lookup failed (timeout, outage, DNS error), so we cannot tell whether the domain publishes settings. */
export class DiscoveryUnavailableError extends Error {
  constructor() {
    super('Mail server settings lookup failed');
    this.name = 'DiscoveryUnavailableError';
  }
}

const defaultDeps: DiscoveryDeps = {
  ispdb: (d) => fetchIspdb(d),
  srv: (d) => resolveSrvSettings(d),
};

/**
 * Returns the domain's published settings, or null when every source definitively has none.
 * Throws DiscoveryUnavailableError when nothing was found but some source failed, so callers never
 * mistake a failed lookup for "nothing published" (and e.g. fall back to user-supplied settings).
 */
export async function discoverSettings(
  email: string,
  deps: DiscoveryDeps = defaultDeps,
): Promise<MailServerSettings | null> {
  const at = email.lastIndexOf('@');
  if (at < 0) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  if (!domain) return null;
  if (Object.hasOwn(PRESETS, domain)) return { ...PRESETS[domain] };
  let failed = false;
  for (const lookup of [deps.ispdb, deps.srv]) {
    let result: DiscoveryResult;
    try {
      result = await lookup(domain);
    } catch {
      failed = true;
      continue;
    }
    if (result.status === 'found') return result.settings;
    if (result.status === 'error') failed = true;
  }
  if (failed) throw new DiscoveryUnavailableError();
  return null;
}
