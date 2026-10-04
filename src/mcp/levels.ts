import type { PermissionLevel } from '../types.js';

const RANK: Record<PermissionLevel, number> = { read: 0, draft: 1, full: 2 };

export function allows(level: PermissionLevel, required: PermissionLevel): boolean {
  return RANK[level] >= RANK[required];
}
