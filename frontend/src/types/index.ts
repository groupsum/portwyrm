export type HostType = 'proxy' | 'redirect' | '404' | 'stream';

export type HostStatus =
  | 'online'
  | 'applying'
  | 'pending'
  | 'disabled'
  | 'degraded'
  | 'failed'
  | 'rolledback'
  | 'drifted'
  | 'unknown';

export interface Host {
  id: string;
  ownerId: string;
  ownerName: string;
  provenance: string; // 'human' or 'npmctl · site-name'
  type: HostType;
  source: string; // domain names or port (e.g., 'app.example.com' or 'TCP :5432')
  destination: string; // Upstream scheme/host/port, Redirect target, "Returns 404", or stream target
  sslId: string | null;
  sslName: string;
  accessListId: string | null;
  accessListIds: string[];
  accessListName: string;
  status: HostStatus;
  created: string; // ISO String
  modified: string; // ISO String
  websocket: boolean;
  caching: boolean;
  blockExploits: boolean;
  http2: boolean;
  forwardSsl: boolean;
  lastError: string | null;
  activeGeneration: number;
  forceHttps?: boolean;
  hsts?: boolean;
  hstsSubdomains?: boolean;
  customNginxConfig?: string;
}

export type CertificateStatus =
  | 'valid'
  | 'expiring_soon'
  | 'expired'
  | 'issuing'
  | 'renewal_scheduled'
  | 'renewal_failed'
  | 'validation_failed'
  | 'not_assigned';

export interface Certificate {
  id: string;
  name: string;
  domains: string[];
  provider: "Let's Encrypt" | 'Custom Upload';
  ownerName: string;
  status: CertificateStatus;
  expiration: string; // ISO String
  autoRenewal: boolean;
  lastRenewal: string | null; // ISO String
  created: string; // ISO String
  modified: string; // ISO String
}

export interface BasicAuthUser {
  username: string;
  passwordHint: string;
}

export interface IpRule {
  type: 'allow' | 'deny';
  subnet: string;
}

export interface AccessList {
  id: string;
  name: string;
  ownerName: string;
  usersCount: number;
  rulesCount: number;
  policyComposition: 'satisfy_all' | 'satisfy_any';
  forwardHeader: boolean;
  created: string; // ISO String
  modified: string; // ISO String
  identityIds: string[];
  users: BasicAuthUser[];
  rules: IpRule[];
}

export type UserRole = 'Administrator' | 'Operator' | 'Viewer';

export type PermissionAction = 'create' | 'read' | 'update' | 'delete';
export type PermissionResource = 'proxy_hosts' | 'redirection_hosts' | 'dead_hosts' | 'streams' | 'access_lists' | 'certificates';
export type CrudPermission = Record<PermissionAction, boolean>;
export type UserPermissions = Record<PermissionResource, CrudPermission>;

export interface User {
  id: string;
  displayName: string;
  username: string;
  email: string;
  password: string;
  role: UserRole;
  visibility: 'all' | 'owned';
  permissions: UserPermissions;
  mfa: boolean;
  status: 'Active' | 'Disabled';
  lastActivity: string; // ISO String
  created: string; // ISO String
  modified: string; // ISO String
}

export interface AuditLog {
  id: string;
  timestamp: string; // ISO String
  actor: string; // e.g., '@alex'
  action: string; // e.g., 'Create Host'
  resource: string; // e.g., 'app.example.com'
  outcome: 'Success' | 'Failure' | 'Rolled Back';
  summary: string;
  details: string; // detailed changes, Nginx config files, or raw logs
}

export interface SystemHealth {
  nginxState: 'Active' | 'Reloading' | 'Degraded' | 'Stopped';
  activeConnections: number;
  reading: number;
  writing: number;
  waiting: number;
  version: string;
  databaseBackend: string;
  currentGeneration: number;
  driftDetected: boolean;
  pendingApplies: number;
  schedulerState: 'Active' | 'Idling' | 'Running Job';
}
