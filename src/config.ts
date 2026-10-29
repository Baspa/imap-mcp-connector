export interface Config {
  publicUrl: URL;
  encryptionKey: Buffer;
  sessionSecret: string;
  allowedEmailDomains: string[];
  allowedImapHosts: string[];
  allowedRecipientDomains: string[];
  allowedRedirectHosts: string[];
  allowPrivateHosts: boolean;
  defaultSendLimitPerHour: number;
  dataDir: string;
  port: number;
  isProduction: boolean;
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function positiveInt(name: string, value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new ConfigError(`${name} must be a positive integer`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const nodeEnv = env.NODE_ENV ?? 'production';
  const isProduction = nodeEnv !== 'development' && nodeEnv !== 'test';

  if (!env.PUBLIC_URL) throw new ConfigError('PUBLIC_URL is required');
  let publicUrl: URL;
  try {
    publicUrl = new URL(env.PUBLIC_URL);
  } catch {
    throw new ConfigError('PUBLIC_URL must be a valid URL');
  }
  if (publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) {
    throw new ConfigError('PUBLIC_URL must not contain a path (use the origin, e.g. https://mail.example.com)');
  }
  if (isProduction && publicUrl.protocol !== 'https:') {
    throw new ConfigError('PUBLIC_URL must use https:// in production');
  }

  if (!env.ENCRYPTION_KEY) throw new ConfigError('ENCRYPTION_KEY is required (32 random bytes, base64)');
  const encryptionKey = Buffer.from(env.ENCRYPTION_KEY, 'base64');
  if (encryptionKey.length !== 32) throw new ConfigError('ENCRYPTION_KEY must decode to exactly 32 bytes');

  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    throw new ConfigError('SESSION_SECRET is required (at least 32 characters)');
  }

  const allowedEmailDomains = list(env.ALLOWED_EMAIL_DOMAINS);
  const allowedImapHosts = list(env.ALLOWED_IMAP_HOSTS);
  if (allowedEmailDomains.length === 0 && allowedImapHosts.length === 0) {
    throw new ConfigError(
      'Set ALLOWED_EMAIL_DOMAINS or ALLOWED_IMAP_HOSTS (ALLOWED_IMAP_HOSTS=* allows any public mail server)',
    );
  }

  return {
    publicUrl,
    encryptionKey,
    sessionSecret: env.SESSION_SECRET,
    allowedEmailDomains,
    allowedImapHosts,
    allowedRecipientDomains: list(env.ALLOWED_RECIPIENT_DOMAINS),
    allowedRedirectHosts: list(env.ALLOWED_REDIRECT_HOSTS),
    allowPrivateHosts: env.ALLOW_PRIVATE_HOSTS === 'true',
    defaultSendLimitPerHour: positiveInt('DEFAULT_SEND_LIMIT_PER_HOUR', env.DEFAULT_SEND_LIMIT_PER_HOUR, 20),
    dataDir: env.DATA_DIR || '/data',
    port: positiveInt('PORT', env.PORT, 3000),
    isProduction,
  };
}

export function mcpUrl(config: Config): URL {
  return new URL('/mcp', config.publicUrl);
}

export function signInUrl(config: Config): string {
  return new URL('/login', config.publicUrl).href;
}
