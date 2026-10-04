import { describe, expect, it, vi } from 'vitest';
import { discoverSettings } from '../../src/discovery/index.js';
import { fetchIspdb, parseIspdb } from '../../src/discovery/ispdb.js';
import { resolveSrvSettings } from '../../src/discovery/srv.js';

const ISPDB_XML = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="pop3"><hostname>pop.example.org</hostname><port>995</port><socketType>SSL</socketType></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>STARTTLS</socketType></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;

describe('parseIspdb', () => {
  it('prefers SSL IMAP and maps socket types', () => {
    expect(parseIspdb(ISPDB_XML)).toEqual({
      imapHost: 'imap.example.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.example.org', smtpPort: 587, smtpSecurity: 'starttls',
      autoSavesSent: false,
    });
  });

  it('returns null when only plaintext servers exist', () => {
    const xml = ISPDB_XML.replace(/SSL|STARTTLS/g, 'plain');
    expect(parseIspdb(xml)).toBeNull();
  });

  it('returns null for invalid XML', () => {
    expect(parseIspdb('not xml')).toBeNull();
  });

  it('skips candidates with missing or non-numeric port', () => {
    const xml = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port></port><socketType>SSL</socketType></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;
    expect(parseIspdb(xml)).toEqual({
      imapHost: 'imap.example.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.example.org', smtpPort: 587, smtpSecurity: 'starttls',
      autoSavesSent: false,
    });
  });

  it('substitutes %EMAILDOMAIN% placeholder when domain is provided', () => {
    const xml = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="imap"><hostname>imap.%EMAILDOMAIN%</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.%EMAILDOMAIN%</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;
    expect(parseIspdb(xml, 'example.org')).toEqual({
      imapHost: 'imap.example.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.example.org', smtpPort: 587, smtpSecurity: 'starttls',
      autoSavesSent: false,
    });
  });

  it('skips hostname with other placeholders', () => {
    const xml = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="imap"><hostname>%EMAILLOCALPART%.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;
    expect(parseIspdb(xml)).toEqual({
      imapHost: 'imap.example.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.example.org', smtpPort: 587, smtpSecurity: 'starttls',
      autoSavesSent: false,
    });
  });

  it('selects STARTTLS IMAP over plain IMAP when no SSL available', () => {
    const xml = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>plain</socketType></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>STARTTLS</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>SSL</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;
    expect(parseIspdb(xml)).toEqual({
      imapHost: 'imap.example.org', imapPort: 143, imapSecurity: 'starttls',
      smtpHost: 'smtp.example.org', smtpPort: 587, smtpSecurity: 'tls',
      autoSavesSent: false,
    });
  });

  it('returns null when only IMAP is plaintext but SMTP has security', () => {
    const xml = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>plain</socketType></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
  </emailProvider>
</clientConfig>`;
    expect(parseIspdb(xml)).toBeNull();
  });
});

describe('fetchIspdb', () => {
  it('fetches from the Thunderbird ISPDB', async () => {
    const fetchFn = vi.fn(async () => new Response(ISPDB_XML, { status: 200 }));
    expect((await fetchIspdb('example.org', fetchFn as unknown as typeof fetch))?.imapHost).toBe('imap.example.org');
    expect(fetchFn).toHaveBeenCalledWith('https://autoconfig.thunderbird.net/v1.1/example.org', expect.anything());
  });

  it('returns null on 404 or network error', async () => {
    expect(await fetchIspdb('x.org', (async () => new Response('', { status: 404 })) as unknown as typeof fetch)).toBeNull();
    expect(await fetchIspdb('x.org', (async () => { throw new Error('down'); }) as unknown as typeof fetch)).toBeNull();
  });
});

describe('resolveSrvSettings', () => {
  it('uses _imaps and _submissions/_submission records', async () => {
    const records: Record<string, { name: string; port: number; priority: number; weight: number }[]> = {
      '_imaps._tcp.x.org': [{ name: 'mail.x.org.', port: 993, priority: 10, weight: 0 }],
      '_submission._tcp.x.org': [{ name: 'smtp.x.org', port: 587, priority: 5, weight: 0 }],
    };
    const resolve = async (name: string) => {
      if (!records[name]) throw new Error('ENOTFOUND');
      return records[name];
    };
    expect(await resolveSrvSettings('x.org', resolve)).toEqual({
      imapHost: 'mail.x.org', imapPort: 993, imapSecurity: 'tls',
      smtpHost: 'smtp.x.org', smtpPort: 587, smtpSecurity: 'starttls', autoSavesSent: false,
    });
  });

  it('returns null without an IMAPS record', async () => {
    expect(await resolveSrvSettings('x.org', async () => { throw new Error('ENOTFOUND'); })).toBeNull();
  });
});

describe('discoverSettings', () => {
  const none = { ispdb: async () => null, srv: async () => null };

  it('uses presets first (gmail auto-saves sent mail)', async () => {
    const s = await discoverSettings('Someone@Gmail.com', none);
    expect(s).toMatchObject({ imapHost: 'imap.gmail.com', imapPort: 993, autoSavesSent: true });
  });

  it('falls back to ISPDB then SRV', async () => {
    const ispdbHit = { imapHost: 'i', imapPort: 993, imapSecurity: 'tls', smtpHost: 's', smtpPort: 465, smtpSecurity: 'tls', autoSavesSent: false } as const;
    expect(await discoverSettings('a@x.org', { ispdb: async () => ispdbHit, srv: async () => null })).toEqual(ispdbHit);
    expect(await discoverSettings('a@x.org', { ispdb: async () => null, srv: async () => ispdbHit })).toEqual(ispdbHit);
  });

  it('returns null when nothing is found or the lookup throws', async () => {
    expect(await discoverSettings('a@x.org', none)).toBeNull();
    expect(await discoverSettings('a@x.org', { ispdb: async () => { throw new Error('x'); }, srv: async () => null })).toBeNull();
    expect(await discoverSettings('no-at-sign', none)).toBeNull();
  });

  it('covers borrowed presets such as GMX and Posteo', async () => {
    expect(await discoverSettings('a@gmx.de', none)).toMatchObject({ imapHost: 'imap.gmx.net', smtpHost: 'mail.gmx.net', smtpPort: 587, smtpSecurity: 'starttls' });
    expect(await discoverSettings('a@posteo.net', none)).toMatchObject({ imapHost: 'posteo.de' });
  });

  it('protects against prototype pollution (constructor, __proto__)', async () => {
    expect(await discoverSettings('a@constructor', none)).toBeNull();
    expect(await discoverSettings('a@__proto__', none)).toBeNull();
  });

  it('returns copies of preset settings so callers cannot mutate the table', async () => {
    const result1 = await discoverSettings('Someone@Gmail.com', none);
    if (result1) result1.imapHost = 'mutated.example.org';
    const result2 = await discoverSettings('Someone@Gmail.com', none);
    expect(result2?.imapHost).toBe('imap.gmail.com');
  });
});
