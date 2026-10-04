import type { MailServerSettings } from '../types.js';
import { fetchIspdb } from './ispdb.js';
import { PRESETS } from './presets.js';
import { resolveSrvSettings } from './srv.js';

export interface DiscoveryDeps {
  ispdb(domain: string): Promise<MailServerSettings | null>;
  srv(domain: string): Promise<MailServerSettings | null>;
}

const defaultDeps: DiscoveryDeps = {
  ispdb: (d) => fetchIspdb(d),
  srv: (d) => resolveSrvSettings(d),
};

export async function discoverSettings(
  email: string,
  deps: DiscoveryDeps = defaultDeps,
): Promise<MailServerSettings | null> {
  const at = email.lastIndexOf('@');
  if (at < 0) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  if (!domain) return null;
  if (Object.hasOwn(PRESETS, domain)) return { ...PRESETS[domain] };
  for (const lookup of [deps.ispdb, deps.srv]) {
    try {
      const found = await lookup(domain);
      if (found) return found;
    } catch {
      // try the next source
    }
  }
  return null;
}
