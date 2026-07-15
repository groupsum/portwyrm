import type { AccessList, AccessToken, AuditLog, Certificate, CreatedAccessToken, Host, HostConfigVersion, HostType, SystemHealth, User } from '../types';
import { can, hostPermissionResource, normalizePermissions } from '../utils/permissions';
import { generateNginxConfig } from '../utils/nginxConfig';

type Listener = () => void;
type Json = Record<string, any>;

const hostFamily: Record<HostType, string> = {
  proxy: 'proxy-hosts', redirect: 'redirection-hosts', '404': 'dead-hosts', stream: 'streams',
};

const hostTypeByFamily: Record<string, HostType> = {
  'proxy-hosts': 'proxy', 'redirection-hosts': 'redirect', 'dead-hosts': '404', streams: 'stream',
};

function csrfToken(): string | undefined {
  const cookie = document.cookie.split('; ').find(value => value.startsWith('portwyrm_csrf='));
  return cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : undefined;
}

async function api(path: string, options: RequestInit = {}): Promise<any> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method)) {
    const csrf = csrfToken();
    if (csrf) headers.set('X-CSRF-Token', csrf);
  }
  const response = await fetch(path, {...options, headers, credentials: 'same-origin'});
  const result = response.status === 204 ? null : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result?.detail || `${response.status} ${response.statusText}`);
  return result;
}

function splitHostId(id: string): [string, string] {
  const [family, resourceId] = id.split(':');
  return [family, resourceId];
}

function displayOwner(row: Json, users: User[]): string {
  return users.find(user => user.id === String(row.owner_user_id))?.displayName || row.meta?.owner || 'System';
}

function mapUser(row: Json): User {
  const permissions = row.permissions || {};
  const normalizedPermissions = normalizePermissions(permissions, Boolean(row.is_admin));
  const hasMutationGrant = Object.values(normalizedPermissions).some(
    grant => grant.create || grant.update || grant.delete,
  );
  return {
    id: String(row.id),
    displayName: row.name || row.nickname || row.email,
    username: row.nickname ? `@${String(row.nickname).replace(/^@/, '')}` : `@${String(row.email).split('@')[0]}`,
    email: row.email || '',
    password: '',
    role: row.is_admin ? 'Administrator' : hasMutationGrant ? 'Operator' : 'Viewer',
    visibility: row.visibility === 'all' ? 'all' : 'owned',
    permissions: normalizedPermissions,
    mfa: Boolean(row.mfa_enabled),
    status: row.is_disabled ? 'Disabled' : 'Active',
    lastActivity: row.last_login_on || row.modified_on || row.created_on,
    created: row.created_on,
    modified: row.modified_on,
  };
}

function mapAccessToken(row: Json): AccessToken {
  return {
    id: String(row.id),
    name: String(row.name || 'Unnamed token'),
    userId: String(row.user_id),
    scopes: Array.isArray(row.scopes) ? row.scopes.map(String) : [],
    createdAt: Number(row.created_at),
    expiresAt: row.expires_at == null ? null : Number(row.expires_at),
    lastUsedAt: row.last_used_at == null ? null : Number(row.last_used_at),
    revokedAt: row.revoked_at == null ? null : Number(row.revoked_at),
  };
}

function mapHost(row: Json, family: string, users: User[], certs: Certificate[], acls: AccessList[]): Host {
  const type = ({'proxy-hosts': 'proxy', 'redirection-hosts': 'redirect', 'dead-hosts': '404', streams: 'stream'} as Record<string, HostType>)[family];
  let source = (row.domain_names || []).join(', ');
  let destination = 'Returns 404';
  if (family === 'proxy-hosts') destination = `${row.forward_scheme || 'http'}://${row.forward_host}:${row.forward_port}`;
  if (family === 'redirection-hosts') destination = `${row.forward_scheme || 'auto'}://${row.forward_domain_name} (${row.forward_http_code || 301}${row.preserve_path ? ', preserve path' : ''})`;
  if (family === 'streams') {
    const protocol = row.udp_forwarding && !row.tcp_forwarding ? 'UDP' : row.udp_forwarding ? 'TCP/UDP' : 'TCP';
    source = `${protocol} :${row.incoming_port}`;
    destination = `${row.forwarding_host}:${row.forwarding_port}`;
  }
  const certificate = certs.find(item => item.id === String(row.certificate_id));
  const accessListIds = Array.isArray(row.access_list_ids)
    ? row.access_list_ids.map(String)
    : row.access_list_id ? [String(row.access_list_id)] : [];
  const selectedAccessLists = accessListIds
    .map(id => acls.find(item => item.id === id))
    .filter((item): item is AccessList => Boolean(item));
  return {
    id: `${family}:${row.id}`, ownerId: String(row.owner_user_id || ''), ownerName: displayOwner(row, users),
    provenance: row.meta?.managed_by === 'npmctl' ? `npmctl · ${row.meta?.owner || 'managed'}` : 'human',
    type, source, destination, sslId: certificate?.id || null, sslName: certificate?.name || 'None',
    accessListId: accessListIds[0] || null,
    accessListIds,
    accessListName: selectedAccessLists.length
      ? selectedAccessLists.map(item => item.name).join(', ')
      : (type === 'stream' ? 'Network only' : 'Public'),
    status: row.enabled ? 'online' : 'disabled', created: row.created_on, modified: row.modified_on,
    websocket: Boolean(row.allow_websocket_upgrade), caching: Boolean(row.caching_enabled),
    blockExploits: Boolean(row.block_exploits), http2: Boolean(row.http2_support), forwardSsl: row.forward_scheme === 'https',
    lastError: row.last_error || null, activeGeneration: Number(row.generation || 0), forceHttps: Boolean(row.ssl_forced),
    hsts: Boolean(row.hsts_enabled), hstsSubdomains: Boolean(row.hsts_subdomains), customNginxConfig: row.advanced_config || '',
  };
}

function hostPayload(host: Partial<Host>): Json {
  const domains = String(host.source || '').split(',').map(value => value.trim()).filter(Boolean);
  const accessListIds = host.accessListIds || (host.accessListId ? [host.accessListId] : []);
  const base: Json = {enabled: 1, certificate_id: Number(host.sslId || 0), access_list_id: Number(accessListIds[0] || 0), access_list_ids: accessListIds.map(Number), ssl_forced: host.forceHttps ? 1 : 0, hsts_enabled: host.hsts ? 1 : 0, hsts_subdomains: host.hstsSubdomains ? 1 : 0, advanced_config: host.customNginxConfig || ''};
  if (host.type === 'proxy') {
    const match = String(host.destination).match(/^([^:]+):\/\/([^:]+):(\d+)$/);
    return {...base, domain_names: domains, forward_scheme: match?.[1] || 'http', forward_host: match?.[2] || '', forward_port: Number(match?.[3] || 80), allow_websocket_upgrade: host.websocket ? 1 : 0, caching_enabled: host.caching ? 1 : 0, block_exploits: host.blockExploits ? 1 : 0, http2_support: host.http2 ? 1 : 0};
  }
  if (host.type === 'redirect') {
    const match = String(host.destination).match(/^([^:]+):\/\/([^\s(]+)(?: \((\d+))?/);
    return {...base, domain_names: domains, forward_scheme: match?.[1] || 'auto', forward_domain_name: match?.[2] || '', forward_http_code: Number(match?.[3] || 301), preserve_path: String(host.destination).includes('preserve path') ? 1 : 0};
  }
  if (host.type === 'stream') {
    const source = String(host.source).match(/(TCP\/UDP|TCP|UDP)\s+:(\d+)/i);
    const target = String(host.destination).match(/^(.+):(\d+)$/);
    return {...base, incoming_port: Number(source?.[2] || 0), forwarding_host: target?.[1] || '', forwarding_port: Number(target?.[2] || 0), tcp_forwarding: source?.[1].toUpperCase().includes('TCP') ? 1 : 0, udp_forwarding: source?.[1].toUpperCase().includes('UDP') ? 1 : 0};
  }
  return {...base, domain_names: domains};
}

export class PortwyrmStore {
  hosts: Host[] = [];
  certificates: Certificate[] = [];
  accessLists: AccessList[] = [];
  users: User[] = [];
  auditLogs: AuditLog[] = [];
  hostConfigVersions: HostConfigVersion[] = [];
  health: SystemHealth = {nginxState: 'Stopped', activeConnections: null, reading: null, writing: null, waiting: null, version: '-', databaseBackend: '-', currentGeneration: null, driftDetected: false, pendingApplies: 0, schedulerState: 'Idling'};
  authenticated = false;
  setupRequired = false;
  loading = true;
  error = '';
  private currentUser: User | null = null;
  private listeners = new Set<Listener>();

  subscribe(listener: Listener): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  private emit(): void { this.listeners.forEach(listener => listener()); }
  getCurrentUser(): User { return this.currentUser || {id: '', displayName: 'Portwyrm', username: '@portwyrm', email: '', password: '', role: 'Viewer', visibility: 'owned', permissions: normalizePermissions({}), mfa: false, status: 'Active', lastActivity: '', created: '', modified: ''}; }

  async initialize(): Promise<void> {
    this.loading = true; this.emit();
    try {
      const setup = await api('/api/setup');
      this.setupRequired = !setup.setup;
      if (!this.setupRequired) {
        const me = await api('/api/v2/me');
        this.authenticated = true;
        this.currentUser = mapUser(me);
        await this.refresh();
      }
    } catch (error) { this.authenticated = false; this.error = error instanceof Error ? error.message : 'Unable to load Portwyrm'; }
    finally { this.loading = false; this.emit(); }
  }

  async login(email: string, password: string): Promise<'ok' | 'mfa'> {
    if (this.setupRequired) await api('/api/setup', {method: 'POST', body: JSON.stringify({email, password})});
    const result = await api('/api/v2/browser/login', {method: 'POST', body: JSON.stringify({identity: email, secret: password, scope: 'user'})});
    if (result.result?.scope === 'mfa') return 'mfa';
    this.setupRequired = false; this.authenticated = true; await this.initialize(); return 'ok';
  }
  async completeMfa(code: string): Promise<void> { await api('/api/v2/browser/2fa', {method: 'POST', body: JSON.stringify({code})}); this.authenticated = true; await this.initialize(); }
  async signOut(): Promise<void> { await api('/api/v2/browser/session', {method: 'DELETE'}); this.authenticated = false; this.currentUser = null; this.emit(); }

  async updateMyAccount(data: Json): Promise<void> {
    await api('/api/v2/me', {method: 'PUT', body: JSON.stringify({name: data.displayName, nickname: String(data.username || '').replace(/^@/, ''), email: data.email})});
    if (data.password) await api(`/api/users/${this.getCurrentUser().id}/auth`, {method: 'PUT', body: JSON.stringify({current: data.currentPassword, password: data.password})});
    this.currentUser = mapUser(await api('/api/v2/me'));
    await this.refresh();
  }

  async listAccessTokens(): Promise<AccessToken[]> {
    const rows = await api('/api/v2/tokens');
    return rows.map(mapAccessToken).filter((token: AccessToken) => token.userId === this.getCurrentUser().id);
  }

  async createAccessToken(data: {name: string; scopes: string[]; expiresAt: number | null}): Promise<CreatedAccessToken> {
    const row = await api('/api/v2/tokens', {method: 'POST', body: JSON.stringify({name: data.name, scopes: data.scopes, expires_at: data.expiresAt})});
    return {...mapAccessToken(row), token: String(row.token)};
  }

  async rotateAccessToken(id: string): Promise<CreatedAccessToken> {
    const row = await api(`/api/v2/tokens/${encodeURIComponent(id)}/rotate`, {method: 'POST'});
    return {...mapAccessToken(row), token: String(row.token)};
  }

  async revokeAccessToken(id: string): Promise<void> {
    await api(`/api/v2/tokens/${encodeURIComponent(id)}`, {method: 'DELETE'});
  }

  async previewPortableImport(bundle: Json, replace: boolean): Promise<Json> {
    return api(`/api/v2/import/preview?replace=${replace}`, {method: 'POST', body: JSON.stringify(bundle)});
  }

  async applyPortableImport(bundle: Json, replace: boolean): Promise<Json> {
    const result = await api(`/api/v2/import?replace=${replace}`, {method: 'POST', body: JSON.stringify(bundle)});
    await this.refresh();
    return result;
  }

  async refresh(): Promise<void> {
    const hostFamilies = ['proxy-hosts', 'redirection-hosts', 'dead-hosts', 'streams'];
    const [users, certRows, aclRows, auditRows, health, version, ...hostRows] = await Promise.all([
      this.currentUser?.role === 'Administrator' ? api('/api/users') : Promise.resolve([]),
      this.currentUser && can(this.currentUser, 'certificates', 'read') ? api('/api/nginx/certificates') : Promise.resolve([]),
      this.currentUser && can(this.currentUser, 'access_lists', 'read') ? api('/api/nginx/access-lists') : Promise.resolve([]),
      this.currentUser?.role === 'Administrator' ? api('/api/audit-log') : Promise.resolve([]),
      api('/api/v2/system/status'), api('/version'), ...hostFamilies.map(family => {
        const type = hostTypeByFamily[family];
        return this.currentUser && can(this.currentUser, hostPermissionResource(type), 'read') ? api(`/api/nginx/${family}`) : Promise.resolve([]);
      }),
    ]);
    this.users = users.map(mapUser);
    if (this.currentUser && !this.users.some(user => user.id === this.currentUser!.id)) this.users.unshift(this.currentUser);
    this.certificates = certRows.map((row: Json) => ({id: String(row.id), name: row.nice_name || (row.domain_names || []).join(', '), domains: row.domain_names || [], provider: row.provider === 'letsencrypt' ? "Let's Encrypt" : 'Custom Upload', ownerName: displayOwner(row, this.users), status: row.expires_on && new Date(row.expires_on) < new Date() ? 'expired' : 'valid', expiration: row.expires_on || '', autoRenewal: row.provider === 'letsencrypt', lastRenewal: row.renewed_on || null, created: row.created_on, modified: row.modified_on}));
    this.accessLists = aclRows.map((row: Json) => {
      const identityIds = Array.isArray(row.identity_ids) ? row.identity_ids.map(String) : [];
      return {id: String(row.id), name: row.name, ownerName: displayOwner(row, this.users), usersCount: identityIds.length + (row.items || []).length, rulesCount: (row.clients || []).length, policyComposition: row.satisfy_any ? 'satisfy_any' : 'satisfy_all', forwardHeader: Boolean(row.pass_auth), created: row.created_on, modified: row.modified_on, identityIds, users: (row.items || []).map((item: Json) => ({username: item.username, passwordHint: ''})), rules: (row.clients || []).map((item: Json) => ({type: item.directive === 'deny' ? 'deny' : 'allow', subnet: item.address}))};
    });
    this.hosts = hostFamilies.flatMap((family, index) => hostRows[index].map((row: Json) => mapHost(row, family, this.users, this.certificates, this.accessLists)));
    this.auditLogs = auditRows.map((row: Json) => ({id: String(row.id), timestamp: row.created_on, actor: row.actor || row.user_email || 'System', action: row.action || row.event || 'Changed', resource: row.object_type || row.resource_type || 'Resource', outcome: row.outcome === 'failure' ? 'Failure' : row.outcome === 'rolled_back' ? 'Rolled Back' : 'Success', summary: row.summary || row.action || '', details: JSON.stringify(row, null, 2)}));
    const versionCounts = new Map<string, number>();
    this.hostConfigVersions = auditRows.flatMap((row: Json) => {
      if (row.action !== 'configuration.applied' || !hostTypeByFamily[row.object_type] || !row.meta?.snapshot) return [];
      const host = mapHost(row.meta.snapshot, row.object_type, this.users, this.certificates, this.accessLists);
      const version = (versionCounts.get(host.id) || 0) + 1;
      versionCounts.set(host.id, version);
      return [{id: String(row.id), hostId: host.id, version, timestamp: row.created_on, actor: row.actor || row.user_email || 'System', generation: String(row.meta.generation || ''), config: generateNginxConfig(host)}];
    });
    this.applySystemStatus(health, version.version || '-');
    this.emit();
  }

  private applySystemStatus(status: Json, version = this.health.version): void {
    const nginx = status.components?.nginx || {};
    const connections = nginx.connections || {};
    this.health = {
      nginxState: nginx.status === 'ok' ? 'Active' : 'Degraded',
      activeConnections: Number.isFinite(connections.active) ? Number(connections.active) : null,
      reading: Number.isFinite(connections.reading) ? Number(connections.reading) : null,
      writing: Number.isFinite(connections.writing) ? Number(connections.writing) : null,
      waiting: Number.isFinite(connections.waiting) ? Number(connections.waiting) : null,
      version,
      databaseBackend: status.components?.database?.backend || 'unknown',
      currentGeneration: typeof nginx.active_generation === 'string' && nginx.active_generation ? nginx.active_generation : null,
      driftDetected: false,
      pendingApplies: 0,
      schedulerState: status.components?.certificate_scheduler?.enabled ? 'Active' : 'Idling',
    };
  }

  async refreshHealth(): Promise<void> {
    try {
      this.applySystemStatus(await api('/api/v2/system/status'));
      this.emit();
    } catch {
      this.health = {...this.health, nginxState: 'Degraded', activeConnections: null, reading: null, writing: null, waiting: null};
      this.emit();
    }
  }

  async addHost(data: Partial<Host>, progress: (phase: string) => void): Promise<void> { progress('Validating configuration'); try { await api(`/api/nginx/${hostFamily[data.type || 'proxy']}`, {method: 'POST', body: JSON.stringify(hostPayload(data))}); progress('Reloading Nginx'); await this.refresh(); progress('Complete'); } catch (error) { progress('Rolled back'); throw error; } }
  async updateHost(id: string, data: Partial<Host>, progress: (phase: string) => void): Promise<void> { const [family, resourceId] = splitHostId(id); progress('Validating configuration'); try { await api(`/api/nginx/${family}/${resourceId}`, {method: 'PUT', body: JSON.stringify(hostPayload({...data, type: data.type || this.hosts.find(item => item.id === id)?.type}))}); progress('Reloading Nginx'); await this.refresh(); progress('Complete'); } catch (error) { progress('Rolled back'); throw error; } }
  async deleteHost(id: string): Promise<void> { const [family, resourceId] = splitHostId(id); await api(`/api/nginx/${family}/${resourceId}`, {method: 'DELETE'}); await this.refresh(); }
  async toggleHostStatus(id: string): Promise<void> { const host = this.hosts.find(item => item.id === id); if (!host) return; const [family, resourceId] = splitHostId(id); await api(`/api/nginx/${family}/${resourceId}`, {method: 'PUT', body: JSON.stringify({...hostPayload(host), enabled: host.status === 'online' ? 0 : 1})}); await this.refresh(); }

  async addCertificate(data: Json): Promise<void> { await api('/api/nginx/certificates/upload', {method: 'POST', body: JSON.stringify({nice_name: data.name, certificate: data.certificate, private_key: data.privateKey, intermediate_certificate: data.intermediateCertificate})}); await this.refresh(); }
  async requestLetsEncrypt(name: string, domains: string[], challengeType: string, progress: (message: string, done: boolean, error?: string) => void): Promise<void> { try { progress('Requesting certificate', false); await api('/api/nginx/certificates/request', {method: 'POST', body: JSON.stringify({nice_name: name, provider: 'letsencrypt', domain_names: domains, challenge_type: challengeType})}); await this.refresh(); progress('Certificate issued', true); } catch (error) { progress('Certificate request failed', true, error instanceof Error ? error.message : 'Request failed'); } }
  async renewCertificate(id: string, progress: (message: string, done: boolean, error?: string) => void): Promise<void> { try { progress('Renewing certificate', false); await api(`/api/nginx/certificates/${id}/renew?force=true`, {method: 'POST'}); await this.refresh(); progress('Certificate renewed', true); } catch (error) { progress('Renewal failed', true, error instanceof Error ? error.message : 'Renewal failed'); } }
  deleteCertificate(id: string): {success: boolean; attachedHostsCount: number} { const attachedHostsCount = this.hosts.filter(host => host.sslId === id).length; if (attachedHostsCount) return {success: false, attachedHostsCount}; void api(`/api/nginx/certificates/${id}`, {method: 'DELETE'}).then(() => this.refresh()); return {success: true, attachedHostsCount: 0}; }

  private accessPayload(data: Json): Json { return {name: data.name, satisfy_any: data.policyComposition === 'satisfy_any' ? 1 : 0, pass_auth: data.forwardHeader ? 1 : 0, identity_ids: (data.identityIds || []).map(Number), items: [], clients: (data.rules || []).map((rule: Json) => ({directive: rule.type, address: rule.subnet}))}; }
  async addAccessList(data: Json): Promise<void> { await api('/api/nginx/access-lists', {method: 'POST', body: JSON.stringify(this.accessPayload(data))}); await this.refresh(); }
  async updateAccessList(id: string, data: Json): Promise<void> { await api(`/api/nginx/access-lists/${id}`, {method: 'PUT', body: JSON.stringify(this.accessPayload(data))}); await this.refresh(); }
  deleteAccessList(id: string): {success: boolean; attachedHostsCount: number} { const attachedHostsCount = this.hosts.filter(host => host.accessListIds.includes(id)).length; if (attachedHostsCount) return {success: false, attachedHostsCount}; void api(`/api/nginx/access-lists/${id}`, {method: 'DELETE'}).then(() => this.refresh()); return {success: true, attachedHostsCount: 0}; }

  private userPayload(data: Json): Json { return {name: data.displayName, nickname: String(data.username || '').replace(/^@/, ''), email: data.email, password: data.password || undefined, is_admin: data.role === 'Administrator' ? 1 : 0, is_disabled: data.status === 'Disabled' ? 1 : 0, visibility: data.visibility, permissions: data.permissions || normalizePermissions({})}; }
  private async syncUserAccessLists(userId: string, selectedIds: string[]): Promise<void> {
    const selected = new Set(selectedIds);
    await Promise.all(this.accessLists.map(accessList => {
      const identityIds = accessList.identityIds.filter(id => id !== userId);
      if (selected.has(accessList.id)) identityIds.push(userId);
      if (identityIds.length === accessList.identityIds.length && identityIds.every((id, index) => id === accessList.identityIds[index])) return Promise.resolve();
      return api(`/api/nginx/access-lists/${accessList.id}`, {method: 'PUT', body: JSON.stringify(this.accessPayload({...accessList, identityIds}))});
    }));
  }
  async addUser(data: Json, aclIds: string[] = []): Promise<void> { const created = await api('/api/users', {method: 'POST', body: JSON.stringify(this.userPayload(data))}); await this.syncUserAccessLists(String(created.id), aclIds); await this.refresh(); }
  async updateUser(id: string, data: Json): Promise<void> { const payload = this.userPayload(data); await api(`/api/users/${id}`, {method: 'PUT', body: JSON.stringify(payload)}); if (data.password) await api(`/api/users/${id}/auth`, {method: 'PUT', body: JSON.stringify({current: data.currentPassword, password: data.password})}); await this.syncUserAccessLists(id, data.aclIds || []); await this.refresh(); }
  deleteUser(id: string): boolean { if (this.currentUser?.id === id) return false; void api(`/api/users/${id}`, {method: 'DELETE'}).then(() => this.refresh()); return true; }

  resolveDrift(): void { void this.refresh(); }
}

export const portwyrmStore = new PortwyrmStore();
