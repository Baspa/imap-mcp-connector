import nodemailer from 'nodemailer';
import type { Security } from '../types.js';
import { tlsServername } from './imap.js';

export interface SmtpTarget {
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: Security;
  smtpUsername: string;
  /** Address the guard vetted for smtpHost; connect here instead of resolving the hostname again. */
  connectAddress?: string;
}

export interface SmtpClient {
  sendMail(opts: { envelope: { from: string; to: string[] }; raw: Buffer }): Promise<unknown>;
  close(): void;
}

export type SmtpFactory = (target: SmtpTarget, password: string) => SmtpClient;

export const defaultSmtpFactory: SmtpFactory = (target, password) =>
  nodemailer.createTransport({
    host: target.connectAddress ?? target.smtpHost,
    // nodemailer copies tls.* into both the implicit-TLS and the STARTTLS handshake.
    tls: { servername: tlsServername(target.smtpHost) },
    port: target.smtpPort,
    secure: target.smtpSecurity === 'tls',
    requireTLS: target.smtpSecurity === 'starttls',
    ignoreTLS: target.smtpSecurity === 'none',
    auth: { user: target.smtpUsername, pass: password },
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 30_000,
  }) as unknown as SmtpClient;
