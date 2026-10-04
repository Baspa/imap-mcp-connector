import type { ImapFlow, ListResponse } from 'imapflow';
import { MailError } from '../errors.js';

export type FolderRole = 'inbox' | 'drafts' | 'sent' | 'trash' | 'archive' | 'junk' | 'all';
export const FOLDER_ROLES: FolderRole[] = ['inbox', 'drafts', 'sent', 'trash', 'archive', 'junk', 'all'];

export interface FolderInfo {
  path: string;
  name: string;
  role: FolderRole | null;
  total: number;
  unread: number;
}

const SPECIAL_USE: Record<string, FolderRole> = {
  '\\Inbox': 'inbox',
  '\\Drafts': 'drafts',
  '\\Sent': 'sent',
  '\\Trash': 'trash',
  '\\Archive': 'archive',
  '\\Junk': 'junk',
  '\\All': 'all',
};

const NAME_FALLBACK: Record<FolderRole, string[]> = {
  inbox: ['inbox'],
  drafts: ['drafts', 'draft'],
  sent: ['sent', 'sent items', 'sent mail', 'sent messages'],
  trash: ['trash', 'deleted items', 'deleted messages', 'bin'],
  archive: ['archive', 'archives', 'all mail'],
  junk: ['junk', 'spam', 'junk e-mail'],
  all: ['all mail'],
};

function roleOf(folder: ListResponse): FolderRole | null {
  if (folder.specialUse && SPECIAL_USE[folder.specialUse]) return SPECIAL_USE[folder.specialUse];
  if (folder.path.toUpperCase() === 'INBOX') return 'inbox';
  return null;
}

export async function listFolders(client: ImapFlow): Promise<FolderInfo[]> {
  const folders = await client.list({ statusQuery: { messages: true, unseen: true } });
  return folders
    .filter((f) => !f.flags.has('\\Noselect'))
    .map((f) => ({
      path: f.path,
      name: f.name,
      role: roleOf(f),
      total: f.status?.messages ?? 0,
      unread: f.status?.unseen ?? 0,
    }));
}

export async function resolveRole(client: ImapFlow, role: FolderRole): Promise<string> {
  const folders = (await client.list()).filter((f) => !f.flags.has('\\Noselect'));
  // imapflow also guesses specialUse from folder names (source 'name'); those are handled by the top-level name fallback below.
  const bySpecialUse = folders.find((f) => roleOf(f) === role && f.specialUseSource !== 'name');
  if (bySpecialUse) return bySpecialUse.path;
  const names = NAME_FALLBACK[role];
  const byName = folders.find((f) => names.includes(f.path.toLowerCase()));
  if (byName) return byName.path;
  throw new MailError('NOT_FOUND', `This mailbox has no ${role} folder.`);
}

/** Accepts a folder path from list_folders, or a role name like "trash". Exact paths win over roles. */
export async function resolveFolder(client: ImapFlow, nameOrRole: string): Promise<string> {
  const lower = nameOrRole.toLowerCase();
  const folders = (await client.list()).filter((f) => !f.flags.has('\\Noselect'));
  const exact = folders.find((f) => f.path === nameOrRole);
  if (exact) return exact.path;
  if ((FOLDER_ROLES as string[]).includes(lower)) return resolveRole(client, lower as FolderRole);
  const match = folders.find((f) => f.path.toLowerCase() === lower);
  if (!match) throw new MailError('NOT_FOUND', `Folder "${nameOrRole}" does not exist. Use list_folders to see folder paths.`);
  return match.path;
}
