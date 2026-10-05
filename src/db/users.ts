import type { Db } from './index.js';
import type { MailServerSettings, PermissionLevel, Security, SettingsSource } from '../types.js';

export interface User {
  id: number;
  email: string;
  imapHost: string;
  imapPort: number;
  imapSecurity: Security;
  imapPasswordEnc: string;
  settingsSource: SettingsSource;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  smtpUsername: string;
  smtpPasswordEnc: string | null;
  autoSavesSent: boolean;
  permissionLevel: PermissionLevel;
  sendLimitPerHour: number | null;
  needsReauth: boolean;
  createdAt: number;
  lastLoginAt: number | null;
}

export interface NewUser extends MailServerSettings {
  email: string;
  imapPasswordEnc: string;
  smtpUsername: string;
  settingsSource: Exclude<SettingsSource, 'legacy'>;
}

export interface SmtpSettings {
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  smtpUsername: string;
  smtpPasswordEnc: string | null;
}

interface UserRow {
  id: number;
  email: string;
  imap_host: string;
  imap_port: number;
  imap_security: Security;
  imap_password_enc: string;
  settings_source: SettingsSource;
  smtp_host: string;
  smtp_port: number;
  smtp_security: Security;
  smtp_username: string;
  smtp_password_enc: string | null;
  auto_saves_sent: number;
  permission_level: PermissionLevel;
  send_limit_per_hour: number | null;
  needs_reauth: number;
  created_at: number;
  last_login_at: number | null;
}

function toUser(r: UserRow): User {
  return {
    id: r.id,
    email: r.email,
    imapHost: r.imap_host,
    imapPort: r.imap_port,
    imapSecurity: r.imap_security,
    imapPasswordEnc: r.imap_password_enc,
    settingsSource: r.settings_source,
    smtpHost: r.smtp_host,
    smtpPort: r.smtp_port,
    smtpSecurity: r.smtp_security,
    smtpUsername: r.smtp_username,
    smtpPasswordEnc: r.smtp_password_enc,
    autoSavesSent: r.auto_saves_sent === 1,
    permissionLevel: r.permission_level,
    sendLimitPerHour: r.send_limit_per_hour,
    needsReauth: r.needs_reauth === 1,
    createdAt: r.created_at,
    lastLoginAt: r.last_login_at,
  };
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function findUserByEmail(db: Db, email: string): User | undefined {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizeEmail(email)) as UserRow | undefined;
  return row && toUser(row);
}

export function findUserById(db: Db, id: number): User | undefined {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  return row && toUser(row);
}

export function createUser(db: Db, u: NewUser, now = Date.now()): User {
  const info = db
    .prepare(
      `INSERT INTO users (email, imap_host, imap_port, imap_security, imap_password_enc, settings_source,
         smtp_host, smtp_port, smtp_security, smtp_username, auto_saves_sent, created_at, last_login_at)
       VALUES (@email, @imapHost, @imapPort, @imapSecurity, @imapPasswordEnc, @settingsSource,
         @smtpHost, @smtpPort, @smtpSecurity, @smtpUsername, @autoSavesSent, @now, @now)`,
    )
    .run({
      email: normalizeEmail(u.email),
      imapHost: u.imapHost,
      imapPort: u.imapPort,
      imapSecurity: u.imapSecurity,
      imapPasswordEnc: u.imapPasswordEnc,
      settingsSource: u.settingsSource,
      smtpHost: u.smtpHost,
      smtpPort: u.smtpPort,
      smtpSecurity: u.smtpSecurity,
      smtpUsername: u.smtpUsername,
      autoSavesSent: u.autoSavesSent ? 1 : 0,
      now,
    });
  return findUserById(db, Number(info.lastInsertRowid))!;
}

export function recordLogin(db: Db, id: number, imapPasswordEnc: string, now = Date.now()): void {
  db.prepare('UPDATE users SET imap_password_enc = ?, needs_reauth = 0, last_login_at = ? WHERE id = ?').run(
    imapPasswordEnc,
    now,
    id,
  );
}

export function updateSmtpSettings(db: Db, id: number, s: SmtpSettings): void {
  db.prepare(
    `UPDATE users SET smtp_host = ?, smtp_port = ?, smtp_security = ?, smtp_username = ?, smtp_password_enc = ?
     WHERE id = ?`,
  ).run(s.smtpHost, s.smtpPort, s.smtpSecurity, s.smtpUsername, s.smtpPasswordEnc, id);
}

export function setPermissionLevel(db: Db, id: number, level: PermissionLevel): void {
  db.prepare('UPDATE users SET permission_level = ? WHERE id = ?').run(level, id);
}

export function setSettingsSource(db: Db, id: number, source: SettingsSource): void {
  db.prepare('UPDATE users SET settings_source = ? WHERE id = ?').run(source, id);
}

export function setNeedsReauth(db: Db, id: number, value: boolean): void {
  db.prepare('UPDATE users SET needs_reauth = ? WHERE id = ?').run(value ? 1 : 0, id);
}

export function deleteUser(db: Db, id: number): void {
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
}

export function serverSettingsOf(u: User): MailServerSettings {
  return {
    imapHost: u.imapHost,
    imapPort: u.imapPort,
    imapSecurity: u.imapSecurity,
    smtpHost: u.smtpHost,
    smtpPort: u.smtpPort,
    smtpSecurity: u.smtpSecurity,
    autoSavesSent: u.autoSavesSent,
  };
}
