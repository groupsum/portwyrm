import type { ResourceProvenanceKind } from '../types';

type ResourceRow = {
  owner_user_id?: unknown;
  meta?: { managed_by?: unknown } | null;
};

export interface ResourceProvenance {
  kind: ResourceProvenanceKind;
  managedBy: string | null;
}

export function deriveResourceProvenance(row: ResourceRow): ResourceProvenance {
  const managedBy = typeof row.meta?.managed_by === 'string' ? row.meta.managed_by.trim() : '';
  if (managedBy) return {kind: 'automation', managedBy};

  const ownerId = row.owner_user_id == null ? '' : String(row.owner_user_id).trim();
  if (ownerId) return {kind: 'human', managedBy: null};

  return {kind: 'unassigned', managedBy: null};
}

export function provenanceCaption(provenance: ResourceProvenance, ownerName: string): string {
  const kind = provenance.kind.toUpperCase();
  if (!provenance.managedBy || provenance.managedBy === ownerName) return kind;
  return `${kind} · ${provenance.managedBy}`;
}
