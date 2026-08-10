import type { HostProvenanceKind } from '../types';

type ResourceRow = {
  owner_user_id?: unknown;
  meta?: { managed_by?: unknown } | null;
};

export interface ResourceProvenance {
  kind: HostProvenanceKind;
  managedBy: string | null;
}

export function deriveResourceProvenance(row: ResourceRow): ResourceProvenance {
  const managedBy = typeof row.meta?.managed_by === 'string' ? row.meta.managed_by.trim() : '';
  if (managedBy) return {kind: 'automation', managedBy};

  const ownerId = row.owner_user_id == null ? '' : String(row.owner_user_id).trim();
  if (ownerId) return {kind: 'human', managedBy: null};

  return {kind: 'system', managedBy: null};
}
