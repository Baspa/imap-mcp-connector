import nodemailer from 'nodemailer';
import type { Security } from '../types.js';

export interface SmtpTarget {
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  smtpUsername: string;
}

export interface SmtpClient {
  sendMail(opts: { envelope: { from: string; to: string[] }; raw: Buffer }): Promise<unknown>;
  close(): void;
}

export type SmtpFactory = (target: SmtpTarget, password: string) => SmtpClient;

export const defaultSmtpFactory: SmtpFactory = (target, password) =>
  nodemailer.createTransport({
    host: target.smtpHost,
    port: target.smtpPort,
    secure: target.smtpSecurity === 'tls',
    requireTLS: target.smtpSecurity === 'starttls',
    ignoreTLS: target.smtpSecurity === 'none',
    auth: { user: target.smtpUsername, pass: password },
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 30_000,
  }) as unknown as SmtpClient;
