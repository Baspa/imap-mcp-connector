export type PermissionLevel = 'read' | 'draft' | 'full';
export type Security = 'tls' | 'starttls' | 'none';

export interface MailServerSettings {
  imapHost: string;
  imapPort: number;
  imapSecurity: Security;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  autoSavesSent: boolean;
}
