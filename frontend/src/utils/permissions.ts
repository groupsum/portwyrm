import type { CrudPermission, HostType, PermissionAction, PermissionResource, User, UserPermissions } from '../types';

export const PERMISSION_RESOURCES: Array<{id: PermissionResource; label: string; shortLabel: string}> = [
  {id: 'proxy_hosts', label: 'HTTP Proxy Hosts', shortLabel: 'Proxy'},
  {id: 'redirection_hosts', label: 'Redirect Hosts', shortLabel: 'Redirect'},
  {id: 'dead_hosts', label: '404 Hosts', shortLabel: '404'},
  {id: 'streams', label: 'TCP/UDP Streams', shortLabel: 'Streams'},
  {id: 'access_lists', label: 'Access Lists', shortLabel: 'ACLs'},
  {id: 'certificates', label: 'TLS Certificates', shortLabel: 'Certs'},
];

export const PERMISSION_ACTIONS: PermissionAction[] = ['create', 'read', 'update', 'delete'];
export const HOST_PERMISSION_RESOURCES: PermissionResource[] = ['proxy_hosts', 'redirection_hosts', 'dead_hosts', 'streams'];

export function emptyGrant(): CrudPermission {
  return {create: false, read: false, update: false, delete: false};
}

export function fullGrant(): CrudPermission {
  return {create: true, read: true, update: true, delete: true};
}

export function readGrant(): CrudPermission {
  return {create: false, read: true, update: false, delete: false};
}

export function normalizeGrant(value: unknown): CrudPermission {
  if (value === 'manage') return fullGrant();
  if (value === 'view') return readGrant();
  if (!value || value === 'hidden' || typeof value !== 'object') return emptyGrant();
  const grant = value as Record<string, unknown>;
  return {
    create: grant.create === true,
    read: grant.read === true,
    update: grant.update === true,
    delete: grant.delete === true,
  };
}

export function normalizePermissions(value: unknown, isAdmin = false): UserPermissions {
  const source = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return Object.fromEntries(PERMISSION_RESOURCES.map(resource => [resource.id, isAdmin ? fullGrant() : normalizeGrant(source[resource.id])])) as UserPermissions;
}

export function can(user: User, resource: PermissionResource, action: PermissionAction): boolean {
  return user.role === 'Administrator' || user.permissions[resource]?.[action] === true;
}

export function hostPermissionResource(type: HostType): PermissionResource {
  return ({proxy: 'proxy_hosts', redirect: 'redirection_hosts', '404': 'dead_hosts', stream: 'streams'} as const)[type];
}

export function grantSummary(grant: CrudPermission): string {
  const enabled = PERMISSION_ACTIONS.filter(action => grant[action]);
  if (enabled.length === 4) return 'CRUD';
  if (enabled.length === 0) return 'None';
  return enabled.map(action => action[0].toUpperCase()).join('');
}
