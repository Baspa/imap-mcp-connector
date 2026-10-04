import type { PermissionLevel } from '../types.js';

export const LEVELS: { value: PermissionLevel; label: string; description: string }[] = [
  { value: 'read', label: 'Read only', description: 'Search and read mail. The AI cannot change anything.' },
  {
    value: 'draft',
    label: 'Read and draft (recommended)',
    description: 'Also flag, move and archive mail, and save drafts that you review and send yourself.',
  },
  {
    value: 'full',
    label: 'Full access',
    description:
      'Also send email and move messages to Trash. Warning: a malicious email could try to trick the AI into sending mail on your behalf.',
  },
];

export function levelLabel(level: PermissionLevel): string {
  return LEVELS.find((l) => l.value === level)?.label ?? level;
}
