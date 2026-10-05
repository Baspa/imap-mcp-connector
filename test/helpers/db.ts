import { encryptSecret } from '../../src/crypto.js';
import { openDb, type Db } from '../../src/db/index.js';
import {
  createUser, findUserById, setPermissionLevel, setSettingsSource, type NewUser, type User,
} from '../../src/db/users.js';
import type { PermissionLevel, SettingsSource } from '../../src/types.js';
import { TEST_KEY } from './config.js';

let counter = 0;

export function testDb(): Db {
  return openDb(':memory:');
}

export function createTestUser(
  db: Db,
  opts: Partial<Omit<NewUser, 'settingsSource'>> & {
    password?: string;
    permissionLevel?: PermissionLevel;
    settingsSource?: SettingsSource;
  } = {},
): User {
  const { password = 'mail-password', permissionLevel, settingsSource = 'discovered', ...rest } = opts;
  const email = rest.email ?? `user${++counter}@example.com`;
  const user = createUser(db, {
    imapHost: 'imap.example.com',
    imapPort: 993,
    imapSecurity: 'tls',
    smtpHost: 'smtp.example.com',
    smtpPort: 465,
    smtpSecurity: 'tls',
    autoSavesSent: false,
    smtpUsername: email,
    imapPasswordEnc: encryptSecret(TEST_KEY, password),
    ...rest,
    email,
    settingsSource: settingsSource === 'manual' ? 'manual' : 'discovered',
  });
  if (permissionLevel) setPermissionLevel(db, user.id, permissionLevel);
  if (settingsSource === 'legacy') setSettingsSource(db, user.id, 'legacy');
  return findUserById(db, user.id)!;
}
