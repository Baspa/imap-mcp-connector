export type PermissionLevel = 'read' | 'draft' | 'full';
export type Security = 'tls' | 'starttls' | 'none';
/** Where an account's server settings came from; 'legacy' accounts were created before this was recorded. */
export type SettingsSource = 'discovered' | 'manual' | 'legacy';

export interface MailServerSettings {
  imapHost: string;
  imapPort: number;
  imapSecurity: Security;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  autoSavesSent: boolean;
}

/** Outcome of one discovery source: settings, a definitive "nothing published", or a failed lookup. */
export type DiscoveryResult =
  | { status: 'found'; settings: MailServerSettings }
  | { status: 'not_found' }
  | { status: 'error' };
