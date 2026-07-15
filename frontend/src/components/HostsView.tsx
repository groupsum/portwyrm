import React, { useState, useMemo, useEffect } from 'react';
import { Host, HostType, HostStatus, Certificate, AccessList, HostConfigVersion, User } from '../types';
import { formatDate } from '../utils/formatting';
import {
  Search,
  Lock,
  Unlock,
  RefreshCw,
  Trash2,
  Edit3,
  Plus,
  Globe,
  MoreVertical,
  Sliders,
  Sparkles,
  Layers,
  X,
  AlertTriangle,
  Copy,
  FileCode,
  History,
  Check,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown
} from 'lucide-react';
import CertificatesView from './CertificatesView';
import ActionModal from './ActionModal';
import { can, hostPermissionResource } from '../utils/permissions';
import { useFeedback } from './Feedback';
import { diffConfig, generateNginxConfig } from '../utils/nginxConfig';

interface HostsViewProps {
  hosts: Host[];
  certificates: Certificate[];
  accessLists: AccessList[];
  currentUser: User;
  configVersions: HostConfigVersion[];
  onAddHost: () => void;
  onEditHost: (host: Host) => void;
  onDeleteHost: (id: string) => void;
  onToggleHostStatus: (id: string) => void;

  // Certificates integration props
  defaultSubTab?: 'hosts' | 'certificates';
  onAddCert: (cert: any) => void;
  onRequestLetsEncrypt: (name: string, domains: string[], challengeType: string, onProgress: (msg: string, done: boolean, error?: string) => void) => void;
  onRenewCert: (id: string, onProgress: (msg: string, done: boolean, error?: string) => void) => void;
  onDeleteCert: (id: string) => { success: boolean; attachedHostsCount: number };
  onDuplicateHost?: (host: Host) => void;
}

export default function HostsView({
  hosts,
  certificates,
  accessLists,
  currentUser,
  configVersions,
  onAddHost,
  onEditHost,
  onDeleteHost,
  onToggleHostStatus,

  defaultSubTab = 'hosts',
  onAddCert,
  onRequestLetsEncrypt,
  onRenewCert,
  onDeleteCert,
  onDuplicateHost
}: HostsViewProps) {
  const feedback = useFeedback();

  // Sub-workspace tab control
  const [activeSubTab, setActiveSubTab] = useState<'hosts' | 'certificates'>(defaultSubTab);

  // Sync subtab if props change
  useEffect(() => {
    setActiveSubTab(defaultSubTab);
  }, [defaultSubTab]);

  // Host Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [hostTypeFilter, setHostTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [ownerFilter, setOwnerFilter] = useState<string>('all');
  const [sslFilter, setSslFilter] = useState<string>('all');
  const [accessFilter, setAccessFilter] = useState<string>('all');

  // Sorting state
  const [sortField, setSortField] = useState<'source' | 'destination' | 'sslName' | 'status' | 'ownerName' | 'modified'>('source');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  // Extra Row Actions modals
  const [copiedHostId, setCopiedHostId] = useState<string | null>(null);
  const [copiedDomainKey, setCopiedDomainKey] = useState<string | null>(null);
  const [inspectedConfigHost, setInspectedConfigHost] = useState<Host | null>(null);
  const [inspectedAuditHost, setInspectedAuditHost] = useState<Host | null>(null);
  const [viewVersionId, setViewVersionId] = useState('');
  const [compareFromId, setCompareFromId] = useState('');
  const [compareToId, setCompareToId] = useState('');

  // Triple-dot action dialog selection
  const [openActionMenuId, setOpenActionMenuId] = useState<string | null>(null);
  const actionHost = hosts.find(host => host.id === openActionMenuId) ?? null;

  // Reset page when search or filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, hostTypeFilter, statusFilter, ownerFilter, sslFilter, accessFilter]);

  // Handle Copy Domains helper
  const handleCopyDomains = (hostId: string, domainsText: string) => {
    void navigator.clipboard.writeText(domainsText);
    setCopiedHostId(hostId);
    setTimeout(() => setCopiedHostId(null), 1500);
  };

  const handleCopyDomain = (hostId: string, domain: string) => {
    const key = `${hostId}:${domain}`;
    void navigator.clipboard.writeText(domain);
    setCopiedDomainKey(key);
    setTimeout(() => setCopiedDomainKey(current => current === key ? null : current), 1500);
  };

  const sourceDomainHref = (host: Host, domain: string) => {
    const value = domain.trim();
    if (host.type === 'stream' || !value || /\s/.test(value)) return null;
    if (/^https?:\/\//i.test(value)) return value;
    const navigableDomain = value.replace(/^\*\./, '');
    const scheme = host.sslId || host.forceHttps ? 'https' : 'http';
    return `${scheme}://${navigableDomain}`;
  };

  const versionsForHost = (host: Host) => configVersions.filter(version => version.hostId === host.id);
  const openHostHistory = (host: Host) => {
    const versions = versionsForHost(host);
    setInspectedAuditHost(host);
    setViewVersionId(versions.at(-1)?.id || '');
    setCompareFromId(versions.at(-2)?.id || versions.at(-1)?.id || '');
    setCompareToId(versions.at(-1)?.id || '');
  };

  // Header Sort Toggle helper
  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // --- FILTER & SORT LOGIC ---
  const filteredHosts = useMemo(() => {
    let result = [...hosts];

    // Scoped operator visibility constraint
    if (currentUser.visibility === 'owned') {
      result = result.filter(h => h.ownerId === currentUser.id);
    }

    // Search query
    if (searchTerm.trim() !== '') {
      const q = searchTerm.toLowerCase();
      result = result.filter(h =>
        h.source.toLowerCase().includes(q) ||
        h.destination.toLowerCase().includes(q) ||
        h.ownerName.toLowerCase().includes(q) ||
        h.sslName.toLowerCase().includes(q) ||
        h.accessListName.toLowerCase().includes(q) ||
        h.provenance.toLowerCase().includes(q)
      );
    }

    // Host type filters
    if (hostTypeFilter !== 'all') {
      result = result.filter(h => h.type === hostTypeFilter);
    }

    // Status filter
    if (statusFilter !== 'all') {
      result = result.filter(h => h.status === statusFilter);
    }

    // Owner filter
    if (ownerFilter !== 'all') {
      result = result.filter(h => h.ownerName === ownerFilter);
    }

    // SSL filter
    if (sslFilter !== 'all') {
      if (sslFilter === 'none') {
        result = result.filter(h => !h.sslId);
      } else {
        result = result.filter(h => h.sslId === sslFilter);
      }
    }

    // Access list filter
    if (accessFilter !== 'all') {
      if (accessFilter === 'public') {
        result = result.filter(h => h.accessListIds.length === 0);
      } else {
        result = result.filter(h => h.accessListIds.includes(accessFilter));
      }
    }

    // Sort
    result.sort((a, b) => {
      let valA = a[sortField] ? String(a[sortField]).toLowerCase() : '';
      let valB = b[sortField] ? String(b[sortField]).toLowerCase() : '';

      if (sortField === 'modified') {
        valA = a.modified || '';
        valB = b.modified || '';
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [hosts, currentUser, searchTerm, hostTypeFilter, statusFilter, ownerFilter, sslFilter, accessFilter, sortField, sortOrder]);

  // Paginated Sliced list
  const paginatedHosts = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredHosts.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredHosts, currentPage]);

  const totalPages = Math.ceil(filteredHosts.length / itemsPerPage) || 1;

  // Unique list of owners for filters
  const uniqueOwners = useMemo(() => {
    return Array.from(new Set(hosts.map(h => h.ownerName))).filter(Boolean);
  }, [hosts]);

  // Generates an Nginx configuration preview based on the host properties
  const generateSimulatedNginxConfig = (host: Host) => {
    const cleanSource = host.source.split(',').map(d => d.trim()).filter(Boolean);
    const primaryDomain = cleanSource[0] || 'example.com';
    const serverNameDirective = cleanSource.join(' ');

    if (host.type === 'stream') {
      const [ip, port] = host.destination.split(':');
      const protocol = host.destination.startsWith('udp://') ? 'udp' : 'tcp';
      const destPort = port || '80';

      let customDirectives = '';
      if (host.customNginxConfig) {
        customDirectives = `\n        # Custom Advanced Nginx Directives\n        ${host.customNginxConfig.split('\n').map(line => '        ' + line).join('\n')}\n`;
      }

      return `stream {
    # Portwyrm Custom Stream Upstream Definition
    upstream stream_backend_${host.id.slice(0,6)} {
        server ${ip}:${destPort};
    }

    server {
        listen ${host.source.split(':').pop() || '12345'} ${protocol === 'udp' ? 'udp' : ''};
        proxy_pass stream_backend_${host.id.slice(0,6)};
        proxy_timeout 10m;
        proxy_connect_timeout 30s;${customDirectives}
    }
}`;
    }

    if (host.type === 'redirect') {
      let customDirectives = '';
      if (host.customNginxConfig) {
        customDirectives = `\n    # Custom Advanced Nginx Directives\n    ${host.customNginxConfig.split('\n').map(line => '    ' + line).join('\n')}\n`;
      }
      return `server {
    listen 80;
    listen [::]:80;
    server_name ${serverNameDirective};
${customDirectives}
    # Permanent or Temporary HTTP Redirection Gate
    return ${host.destination.includes('permanent') || host.destination.includes('301') ? '301' : '302'} ${host.destination.replace(/^(301|302)\s+/, '')};
}`;
    }

    if (host.type === '404') {
      let customDirectives = '';
      if (host.customNginxConfig) {
        customDirectives = `\n    # Custom Advanced Nginx Directives\n    ${host.customNginxConfig.split('\n').map(line => '    ' + line).join('\n')}\n`;
      }
      return `server {
    listen 80;
    listen [::]:80;
    server_name ${serverNameDirective};
${customDirectives}
    # Consolidated Dead-End Error Handler
    location / {
        return 404 "<h1>404 Not Found</h1><p>Dead-end target host offline or disabled.</p>";
        default_type text/html;
    }
}`;
    }

    // Default Proxy HTTP type
    let config = `server {
    listen 80;
    listen [::]:80;
    server_name ${serverNameDirective};
`;

    if (host.sslId) {
      config += `
    # TLS Secure Protection Configuration
    listen 443 ssl ${host.http2 ? 'http2' : ''};
    listen [::]:443 ssl ${host.http2 ? 'http2' : ''};

    ssl_certificate /etc/letsencrypt/live/${primaryDomain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${primaryDomain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
`;
    }

    if (host.accessListIds.length) {
      config += `
    # Combined Access Control Lists (IDs: ${host.accessListIds.join(', ')})
    satisfy all;
    auth_basic "Protected Area";
    auth_basic_user_file /data/access/${host.accessListIds.length > 1 ? `proxy-host-${host.id.split(':').pop()}` : host.accessListIds[0]};
`;
    }

    if (host.customNginxConfig) {
      config += `
    # Custom Advanced Nginx Directives
    ${host.customNginxConfig.split('\n').map(line => '    ' + line).join('\n')}
`;
    }

    config += `
    # Reverse Proxy Traffic Gateway Passage
    location / {
        proxy_pass ${host.destination};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
`;

    if (host.websocket) {
      config += `
        # WebSockets Core Protocol Upgrades Enabled
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
`;
    }

    config += `    }
}`;
    return config;
  };

  // Status Badge Component
  const HostStatusBadge = ({ status }: { status: HostStatus }) => {
    const config = {
      online: { bg: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20', dot: 'bg-emerald-500', text: 'Online' },
      applying: { bg: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20', dot: 'bg-amber-500 animate-spin', text: 'Applying' },
      pending: { bg: 'bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border-indigo-500/20', dot: 'bg-indigo-500', text: 'Pending' },
      disabled: { bg: 'bg-slate-500/10 text-slate-700 dark:text-zinc-400 border-slate-500/20', dot: 'bg-slate-400', text: 'Disabled' },
      degraded: { bg: 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20', dot: 'bg-rose-500 animate-pulse', text: 'Degraded' },
      failed: { bg: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20', dot: 'bg-red-500', text: 'Failed' },
      rolledback: { bg: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20', dot: 'bg-orange-500 animate-pulse', text: 'Rolled Back' },
      drifted: { bg: 'bg-red-500/15 text-red-800 dark:text-red-400 border-red-500/30', dot: 'bg-red-500', text: 'Drifted' },
      unknown: { bg: 'bg-gray-500/10 text-gray-700 dark:text-gray-400 border-gray-500/20', dot: 'bg-gray-400', text: 'Unknown' },
    }[status] || { bg: 'bg-gray-500/10 text-gray-700 border-gray-500/20', dot: 'bg-gray-400', text: 'Unknown' };

    return (
      <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold border ${config.bg}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`}></span>
        <span>{config.text}</span>
      </span>
    );
  };

  return (
    <div className="space-y-6" id="hosts-workspace-container">

      {/* Workspace Selector Switcher Sub-tabs */}
      <div className="flex border-b border-slate-200 dark:border-zinc-800" id="workspace-tabs-bar">
        <button
          onClick={() => setActiveSubTab('hosts')}
          className={`px-5 py-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
            activeSubTab === 'hosts'
              ? 'border-indigo-600 text-indigo-600 dark:border-indigo-400 dark:text-indigo-400 font-extrabold'
              : 'border-transparent text-slate-500 dark:text-zinc-400 hover:text-slate-800 dark:hover:text-zinc-200'
          }`}
          id="tab-routing-hosts"
        >
          Proxy & Stream Hosts
        </button>
        <button
          onClick={() => setActiveSubTab('certificates')}
          className={`px-5 py-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
            activeSubTab === 'certificates'
              ? 'border-indigo-600 text-indigo-600 dark:border-indigo-400 dark:text-indigo-400 font-extrabold'
              : 'border-transparent text-slate-500 dark:text-zinc-400 hover:text-slate-800 dark:hover:text-zinc-200'
          }`}
          id="tab-tls-certificates"
        >
          TLS Certificates
        </button>
      </div>

      {/* RENDER TLS CERTIFICATES SUB-TAB WORKSPACE */}
      {activeSubTab === 'certificates' ? (
        <CertificatesView
          certificates={certificates}
          hosts={hosts}
          currentUser={currentUser}
          onAddCert={onAddCert}
          onRequestLetsEncrypt={onRequestLetsEncrypt}
          onRenewCert={onRenewCert}
          onDeleteCert={onDeleteCert}
        />
      ) : (
        <div className="space-y-6 animate-in fade-in duration-200" id="routing-hosts-view-container">

          {/* HEADER SECTION */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
            <div>
              <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
                Reverse Proxy Hosts
              </h2>
              <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">
                Configure HTTP proxies, secure redirections, 404 fallbacks, and TCP/UDP streams
              </p>
            </div>

            {(['proxy_hosts', 'redirection_hosts', 'dead_hosts', 'streams'] as const).some(resource => can(currentUser, resource, 'create')) && (
              <button
                onClick={onAddHost}
                className="px-4.5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-bold flex items-center gap-1.5 shadow-xs cursor-pointer transition-all"
                id="btn-new-host"
              >
                <Plus className="h-4.5 w-4.5" /> New Host
              </button>
            )}
          </div>

          {/* SEARCH & FILTERS CONTROLS BOX */}
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4.5 shadow-3xs space-y-4">

            {/* Search Input bar */}
            <div className="relative">
              <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search routing domain, target destination, owner, provenance..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden focus:border-indigo-500"
              />
            </div>

            {/* Segmented Filter Pills for Router Type */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-slate-100 dark:border-zinc-800/85">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider shrink-0">Traffic Routing:</span>
              {[
                { id: 'all', label: 'All Routing' },
                { id: 'proxy', label: 'Proxy' },
                { id: 'redirect', label: 'Redirect' },
                { id: '404', label: '404' },
                { id: 'stream', label: 'TCP' },
                { id: 'udp', label: 'UDP' },
              ].map(type => (
                <button
                  key={type.id}
                  onClick={() => setHostTypeFilter(type.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all whitespace-nowrap cursor-pointer ${
                    hostTypeFilter === type.id
                      ? 'bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-sm'
                      : 'bg-slate-50 hover:bg-slate-100 text-slate-600 dark:bg-zinc-950 dark:hover:bg-zinc-800 dark:text-zinc-400'
                  }`}
                >
                  {type.label}
                </button>
              ))}
            </div>

            {/* Sub-selectors row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 pt-1">

              {/* Operational status filter */}
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Operational Status</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
                >
                  <option value="all">All States</option>
                  <option value="online">Online</option>
                  <option value="applying">Applying</option>
                  <option value="disabled">Disabled</option>
                  <option value="degraded">Degraded</option>
                  <option value="failed">Failed</option>
                  <option value="rolledback">Rolled Back</option>
                </select>
              </div>

              {/* Owner controller filter */}
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Owner / Controller</span>
                <select
                  value={ownerFilter}
                  onChange={(e) => setOwnerFilter(e.target.value)}
                  className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
                >
                  <option value="all">All Owners</option>
                  {uniqueOwners.map(o => (
                    <option key={o} value={o}>{o}</option>
                  ))}
                </select>
              </div>

              {/* TLS Profiles */}
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">TLS Certificate Scope</span>
                <select
                  value={sslFilter}
                  onChange={(e) => setSslFilter(e.target.value)}
                  className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
                >
                  <option value="all">All TLS Profiles</option>
                  <option value="none">HTTP Only (No TLS)</option>
                  {certificates.map(c => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                  ))}
                </select>
              </div>

              {/* Access restrictions */}
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Access Control Filter</span>
                <select
                  value={accessFilter}
                  onChange={(e) => setAccessFilter(e.target.value)}
                  className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
                >
                  <option value="all">All Access</option>
                  <option value="public">Public (None)</option>
                  {accessLists.map(a => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
              </div>

            </div>

          </div>

          {/* UNIFIED ROUTING HOSTS INVENTORY TABLE */}
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl overflow-hidden shadow-3xs" id="hosts-table-container">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm text-slate-500 dark:text-zinc-400">
                <thead className="bg-slate-50/50 dark:bg-zinc-900/60 text-slate-700 dark:text-zinc-300 text-xs uppercase font-extrabold border-b border-slate-200/80 dark:border-zinc-800">
                  <tr>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('ownerName')}>
                      <div className="flex items-center gap-1.5">
                        Controller / Owner
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('source')}>
                      <div className="flex items-center gap-1.5">
                        Source Route
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('destination')}>
                      <div className="flex items-center gap-1.5">
                        Target Upstream
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('sslName')}>
                      <div className="flex items-center gap-1.5">
                        SSL Certificate
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4">Access List</th>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('status')}>
                      <div className="flex items-center gap-1.5">
                        Applied Status
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('modified')}>
                      <div className="flex items-center gap-1.5">
                        Last Modified
                        <ArrowUpDown className="h-3 w-3 text-slate-400" />
                      </div>
                    </th>
                    <th scope="col" className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                  {paginatedHosts.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-6 py-12 text-center text-slate-400 dark:text-zinc-500 font-semibold">
                        No reverse proxy routing hosts matched search filters.
                      </td>
                    </tr>
                  ) : (
                    paginatedHosts.map((host) => {
                      const domains = host.source.split(',').map(d => d.trim()).filter(Boolean);
                      const isStream = host.type === 'stream';

                      return (
                        <tr key={host.id} className="hover:bg-slate-50/30 dark:hover:bg-zinc-800/10 transition-colors">

                          {/* Owner details */}
                          <td className="px-6 py-4">
                            <div className="flex flex-col">
                              <span className="font-extrabold text-slate-900 dark:text-zinc-100">{host.ownerName}</span>
                              <span className="text-[10px] text-indigo-600 dark:text-indigo-400 font-mono tracking-wider mt-0.5 uppercase">
                                {host.provenance}
                              </span>
                            </div>
                          </td>

                          {/* Source domain route with chipタグ optimization & copy controls */}
                          <td className="px-6 py-4 max-w-xs">
                            <div className="flex flex-col space-y-1.5">
                              <div className="flex flex-wrap gap-1.5 items-center">
                                {domains.map((dom) => {
                                  const href = sourceDomainHref(host, dom);
                                  const copyKey = `${host.id}:${dom}`;
                                  return (
                                    <span key={dom} className="inline-flex min-w-0 items-center overflow-hidden rounded-md border border-slate-200 bg-slate-50 font-mono text-xs font-bold text-slate-800 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-200">
                                      {href ? (
                                        <a
                                          href={href}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="max-w-52 truncate px-2 py-1 text-indigo-700 underline-offset-2 hover:bg-indigo-50 hover:underline focus:outline-none focus:ring-2 focus:ring-inset focus:ring-indigo-500 dark:text-indigo-300 dark:hover:bg-indigo-950/30"
                                          title={`Open ${dom}`}
                                        >
                                          {dom}
                                        </a>
                                      ) : (
                                        <span className="max-w-52 truncate px-2 py-1" title={dom}>{dom}</span>
                                      )}
                                      <button
                                        type="button"
                                        onClick={() => handleCopyDomain(host.id, dom)}
                                        className="self-stretch border-l border-slate-200 px-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-indigo-500 dark:border-zinc-800 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
                                        title={`Copy ${dom}`}
                                        aria-label={`Copy source domain ${dom}`}
                                      >
                                        {copiedDomainKey === copyKey ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                                      </button>
                                    </span>
                                  );
                                })}
                              </div>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => handleCopyDomains(host.id, host.source)}
                                  className="text-slate-400 hover:text-slate-600 dark:hover:text-zinc-200 text-[10px] font-bold flex items-center gap-1 cursor-pointer"
                                  title="Copy all domains to clipboard"
                                >
                                  {copiedHostId === host.id ? (
                                    <>
                                      <Check className="h-3 w-3 text-emerald-500" />
                                      <span className="text-emerald-600">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="h-3 w-3" />
                                      <span>Copy domains</span>
                                    </>
                                  )}
                                </button>
                                <span className={`px-1.5 py-0.2 rounded-xs font-bold text-[8px] uppercase tracking-wide border ${
                                  isStream
                                    ? 'bg-amber-100 dark:bg-amber-950/40 border-amber-200 text-amber-700 dark:text-amber-400'
                                    : 'bg-indigo-100 dark:bg-indigo-950/40 border-indigo-200 text-indigo-700 dark:text-indigo-400'
                                }`}>
                                  {host.type}
                                </span>
                              </div>
                            </div>
                          </td>

                          {/* Upstream target destination */}
                          <td className="px-6 py-4">
                            <span className="font-mono text-xs font-semibold text-slate-700 dark:text-zinc-300 bg-slate-50 dark:bg-zinc-950 border border-slate-100 dark:border-zinc-800 px-2 py-1 rounded select-all break-all">
                              {host.destination}
                            </span>
                          </td>

                          {/* SSL Protection scope */}
                          <td className="px-6 py-4">
                            <div className="flex flex-col text-xs font-medium">
                              <span className="text-slate-800 dark:text-zinc-200 font-semibold">{host.sslName}</span>
                              {host.sslId && (
                                <span className="text-[10px] text-slate-400 flex items-center gap-1 mt-0.5">
                                  {host.http2 && <span className="bg-indigo-50 dark:bg-zinc-800 px-1 py-0.2 rounded text-[8px] border border-indigo-100/50 dark:border-zinc-700/50">HTTP/2</span>}
                                  {host.websocket && <span className="bg-emerald-50 dark:bg-zinc-800 px-1 py-0.2 rounded text-[8px] border border-emerald-100/50 dark:border-zinc-700/50">WebSockets</span>}
                                </span>
                              )}
                            </div>
                          </td>

                          {/* Access Restrictions */}
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center gap-1 text-xs font-semibold ${host.accessListIds.length ? 'text-indigo-600 dark:text-indigo-400 font-bold' : 'text-slate-500'}`}>
                              {host.accessListIds.length ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                              {host.accessListName}
                            </span>
                          </td>

                          {/* Applied Status */}
                          <td className="px-6 py-4">
                            <HostStatusBadge status={host.status} />
                          </td>

                          {/* Mod date */}
                          <td className="px-6 py-4 text-xs font-semibold font-mono text-slate-400">
                            {formatDate(host.modified)}
                          </td>

                          {/* TRIPLE DOT ACTIONS MENU */}
                          <td className="px-6 py-4 text-right">
                            {(can(currentUser, hostPermissionResource(host.type), 'update') || can(currentUser, hostPermissionResource(host.type), 'delete')) && (
                              <button
                                onClick={() => setOpenActionMenuId(host.id)}
                                className="p-1.5 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg text-slate-500 dark:text-zinc-400 cursor-pointer"
                                title="Actions"
                                aria-label={`Actions for ${host.source}`}
                              >
                                <MoreVertical className="h-4 w-4" />
                              </button>
                            )}
                          </td>

                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* TABLE PAGINATION PANEL FOOTER */}
            <div className="px-6 py-4 bg-slate-50/50 dark:bg-zinc-900/40 border-t border-slate-200/80 dark:border-zinc-800/80 flex items-center justify-between">
              <span className="text-xs text-slate-500 dark:text-zinc-400 font-semibold">
                Showing <strong className="text-slate-700 dark:text-zinc-200">{(currentPage - 1) * itemsPerPage + 1}</strong> to <strong className="text-slate-700 dark:text-zinc-200">{Math.min(currentPage * itemsPerPage, filteredHosts.length)}</strong> of <strong className="text-slate-700 dark:text-zinc-200">{filteredHosts.length}</strong> hosts
              </span>

              <div className="flex gap-1.5">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="p-1.5 bg-white dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 rounded-lg disabled:opacity-40 transition-colors cursor-pointer"
                  title="Previous Page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>

                {Array.from({ length: totalPages }, (_, i) => i + 1).map(num => (
                  <button
                    key={num}
                    onClick={() => setCurrentPage(num)}
                    className={`w-8 h-8 rounded-lg text-xs font-bold border transition-colors cursor-pointer ${
                      currentPage === num
                        ? 'bg-slate-900 border-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:border-zinc-100'
                        : 'bg-white dark:bg-zinc-950 border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-900'
                    }`}
                  >
                    {num}
                  </button>
                ))}

                <button
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="p-1.5 bg-white dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 rounded-lg disabled:opacity-40 transition-colors cursor-pointer"
                  title="Next Page"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>

          </div>

          <ActionModal
            open={Boolean(actionHost)}
            title={actionHost ? `Host actions — ${actionHost.source.split(',')[0]}` : 'Host actions'}
            description={actionHost?.destination}
            onClose={() => setOpenActionMenuId(null)}
          >
            {actionHost && <>
              {can(currentUser, hostPermissionResource(actionHost.type), 'update') && <button onClick={() => { setOpenActionMenuId(null); onToggleHostStatus(actionHost.id); }} className="hover:bg-slate-50 dark:hover:bg-zinc-800 text-slate-700 dark:text-zinc-300"><RefreshCw className="h-4 w-4" />{actionHost.status === 'disabled' ? 'Enable Host' : 'Disable Host'}</button>}
              {can(currentUser, hostPermissionResource(actionHost.type), 'update') && <button onClick={() => { setOpenActionMenuId(null); onEditHost(actionHost); }} className="hover:bg-slate-50 dark:hover:bg-zinc-800 text-slate-700 dark:text-zinc-300"><Edit3 className="h-4 w-4" />Configure & Edit</button>}
              {can(currentUser, hostPermissionResource(actionHost.type), 'create') && <button onClick={() => { setOpenActionMenuId(null); if (onDuplicateHost) onDuplicateHost(actionHost); else feedback.toast(`Unable to duplicate ${actionHost.source}.`, 'error'); }} className="hover:bg-slate-50 dark:hover:bg-zinc-800 text-slate-700 dark:text-zinc-300"><Copy className="h-4 w-4" />Duplicate Host</button>}
              <button onClick={() => { setOpenActionMenuId(null); setInspectedConfigHost(actionHost); }} className="hover:bg-slate-50 dark:hover:bg-zinc-800 text-slate-700 dark:text-zinc-300"><FileCode className="h-4 w-4" />View Applied Config</button>
              <button onClick={() => { setOpenActionMenuId(null); openHostHistory(actionHost); }} className="hover:bg-slate-50 dark:hover:bg-zinc-800 text-slate-700 dark:text-zinc-300"><History className="h-4 w-4" />View Config History</button>
              {actionHost.sslId && can(currentUser, 'certificates', 'update') && <button onClick={() => { setOpenActionMenuId(null); onRenewCert(actionHost.sslId!, (message, done, error) => { if (done) feedback.toast(error || message, error ? 'error' : 'success'); }); }} className="text-indigo-600 hover:bg-indigo-50 dark:text-indigo-400 dark:hover:bg-indigo-950/20"><RefreshCw className="h-4 w-4" />Renew SSL Cert</button>}
              {can(currentUser, hostPermissionResource(actionHost.type), 'delete') && <button onClick={() => { setOpenActionMenuId(null); onDeleteHost(actionHost.id); }} className="text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"><Trash2 className="h-4 w-4" />Delete Host</button>}
            </>}
          </ActionModal>

          {/* SIMULATED APPLIED CONFIG INSPECTION MODAL */}
          {inspectedConfigHost && (
            <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
              <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col animate-in fade-in zoom-in-95 duration-150">
                <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
                  <div className="flex items-center gap-2">
                    <FileCode className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                    <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">
                      Nginx Configuration Profile — {inspectedConfigHost.source.split(',')[0]}
                    </h3>
                  </div>
                  <button onClick={() => setInspectedConfigHost(null)} className="text-slate-400 hover:text-slate-600">
                    <X className="h-5 w-5" />
                  </button>
                </div>

                <div className="p-6 space-y-4">
                  <p className="text-xs text-slate-500 dark:text-zinc-400 leading-relaxed">
                    This is the dynamically compiled nginx server block file managed and hotloaded onto the active container proxy layer:
                  </p>

                  <div className="relative">
                    <pre className="p-4 bg-slate-900 text-zinc-100 rounded-xl text-xs font-mono overflow-x-auto border border-zinc-800 leading-relaxed select-all">
                      {versionsForHost(inspectedConfigHost).at(-1)?.config || generateNginxConfig(inspectedConfigHost)}
                    </pre>
                  </div>
                </div>

                <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-end">
                  <button
                    onClick={() => setInspectedConfigHost(null)}
                    className="px-4 py-2 bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 rounded-lg text-xs font-bold cursor-pointer"
                  >
                    Close Inspection
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* SIMULATED AUDIT TRAIL LOG MODAL FOR SINGLE HOST */}
          {inspectedAuditHost && (
            <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
              <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col animate-in fade-in zoom-in-95 duration-150">
                <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
                  <div className="flex items-center gap-2">
                    <History className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                    <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">
                      Audit Logs History — {inspectedAuditHost.source.split(',')[0]}
                    </h3>
                  </div>
                  <button onClick={() => setInspectedAuditHost(null)} className="text-slate-400 hover:text-slate-600">
                    <X className="h-5 w-5" />
                  </button>
                </div>

                <div className="max-h-[72vh] space-y-5 overflow-y-auto p-6">
                  {versionsForHost(inspectedAuditHost).length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center text-xs text-slate-500 dark:border-zinc-700">No applied configuration versions have been recorded for this host yet.</div> : <>
                    <div className="grid gap-4 sm:grid-cols-2">
                      <label className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">View version<select value={viewVersionId} onChange={event => setViewVersionId(event.target.value)} className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white p-2.5 text-xs text-slate-800 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100">{versionsForHost(inspectedAuditHost).map(version => <option key={version.id} value={version.id}>v{version.version} · {formatDate(version.timestamp)} · {version.actor}</option>)}</select></label>
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-[10px] text-slate-500 dark:border-zinc-800 dark:bg-zinc-950">Generation <strong className="block truncate font-mono text-slate-800 dark:text-zinc-200">{versionsForHost(inspectedAuditHost).find(version => version.id === viewVersionId)?.generation}</strong></div>
                    </div>
                    <pre className="max-h-72 overflow-auto rounded-xl bg-slate-950 p-4 text-[11px] leading-relaxed text-zinc-100">{versionsForHost(inspectedAuditHost).find(version => version.id === viewVersionId)?.config}</pre>
                    <div className="border-t border-slate-200 pt-5 dark:border-zinc-800">
                      <h4 className="text-xs font-extrabold text-slate-800 dark:text-zinc-100">Compare any two applied versions</h4>
                      <div className="mt-3 grid gap-3 sm:grid-cols-2"><select aria-label="Compare from version" value={compareFromId} onChange={event => setCompareFromId(event.target.value)} className="rounded-lg border border-slate-200 bg-white p-2.5 text-xs dark:border-zinc-700 dark:bg-zinc-950">{versionsForHost(inspectedAuditHost).map(version => <option key={version.id} value={version.id}>From v{version.version}</option>)}</select><select aria-label="Compare to version" value={compareToId} onChange={event => setCompareToId(event.target.value)} className="rounded-lg border border-slate-200 bg-white p-2.5 text-xs dark:border-zinc-700 dark:bg-zinc-950">{versionsForHost(inspectedAuditHost).map(version => <option key={version.id} value={version.id}>To v{version.version}</option>)}</select></div>
                      <pre className="mt-3 max-h-80 overflow-auto rounded-xl bg-slate-950 p-4 text-[11px] leading-relaxed">{diffConfig(versionsForHost(inspectedAuditHost).find(version => version.id === compareFromId)?.config || '', versionsForHost(inspectedAuditHost).find(version => version.id === compareToId)?.config || '').map((entry, index) => <span key={`${entry.type}-${index}`} className={`block ${entry.type === 'add' ? 'bg-emerald-500/15 text-emerald-300' : entry.type === 'remove' ? 'bg-red-500/15 text-red-300' : 'text-zinc-400'}`}>{entry.type === 'add' ? '+' : entry.type === 'remove' ? '-' : ' '} {entry.line}</span>)}</pre>
                    </div>
                  </>}
                </div>

                <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-end">
                  <button
                    onClick={() => setInspectedAuditHost(null)}
                    className="px-4 py-2 bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 rounded-lg text-xs font-bold cursor-pointer"
                  >
                    Close History
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
