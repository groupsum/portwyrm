import React, { useState, useMemo, useEffect } from 'react';
import { Certificate, User, Host } from '../types';
import { formatDate } from '../utils/formatting';
import {
  Search,
  RefreshCw,
  Trash2,
  Plus,
  Upload,
  X,
  Loader2,
  CheckCircle2,
  MoreVertical,
  AlertTriangle,
  Key,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown
} from 'lucide-react';
import ActionModal from './ActionModal';

interface CertificatesViewProps {
  certificates: Certificate[];
  hosts: Host[];
  currentUser: User;
  onAddCert: (cert: any) => void;
  onRequestLetsEncrypt: (name: string, domains: string[], challengeType: string, onProgress: (msg: string, done: boolean, error?: string) => void) => void;
  onRenewCert: (id: string, onProgress: (msg: string, done: boolean, error?: string) => void) => void;
  onDeleteCert: (id: string) => { success: boolean; attachedHostsCount: number };
}

export default function CertificatesView({
  certificates,
  hosts,
  currentUser,
  onAddCert,
  onRequestLetsEncrypt,
  onRenewCert,
  onDeleteCert
}: CertificatesViewProps) {

  // Search & Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [providerFilter, setProviderFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expiryFilter, setExpiryFilter] = useState('all');
  const [assignmentFilter, setAssignmentFilter] = useState('all');

  // Sorting
  const [sortField, setSortField] = useState<'name' | 'provider' | 'status' | 'expiration'>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Modals state
  const [isCertModalOpen, setIsCertModalOpen] = useState(false);
  const [certModalType, setCertModalType] = useState<'request' | 'upload'>('request');
  const [newCertName, setNewCertName] = useState('');
  const [newCertDomains, setNewCertDomains] = useState('');
  const [challengeType, setChallengeType] = useState('http-01');
  const [certActionProgress, setCertActionProgress] = useState('');
  const [certActionLoading, setCertActionLoading] = useState(false);
  const [certActionError, setCertActionError] = useState<string | null>(null);

  // Triple-dot action dialog selection
  const [openActionMenuId, setOpenActionMenuId] = useState<string | null>(null);
  const actionCertificate = certificates.find(cert => cert.id === openActionMenuId) ?? null;

  // Deletion warnings
  const [deletionWarning, setDeletionWarning] = useState<{ id: string; msg: string; attachedCount: number } | null>(null);

  // Reset pagination on filter change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, providerFilter, statusFilter, expiryFilter, assignmentFilter]);

  // Handle sorting toggle
  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const filteredCerts = useMemo(() => {
    let result = [...certificates];

    if (searchTerm.trim() !== '') {
      const q = searchTerm.toLowerCase();
      result = result.filter(c =>
        c.name.toLowerCase().includes(q) ||
        c.domains.some(d => d.toLowerCase().includes(q)) ||
        c.provider.toLowerCase().includes(q)
      );
    }

    if (providerFilter !== 'all') {
      result = result.filter(c => c.provider === providerFilter);
    }

    if (statusFilter !== 'all') {
      result = result.filter(c => c.status === statusFilter);
    }

    // Expiry Range Filter
    if (expiryFilter !== 'all') {
      const now = Date.now();
      const fourteenDays = 14 * 24 * 60 * 60 * 1000;
      const thirtyDays = 30 * 24 * 60 * 60 * 1000;
      result = result.filter(c => {
        const expTime = new Date(c.expiration).getTime();
        const diff = expTime - now;
        if (expiryFilter === 'expired') return diff <= 0;
        if (expiryFilter === '14_days') return diff > 0 && diff <= fourteenDays;
        if (expiryFilter === '30_days') return diff > 0 && diff <= thirtyDays;
        return true;
      });
    }

    // Assignment Filter
    if (assignmentFilter !== 'all') {
      result = result.filter(c => {
        const isAssigned = hosts.some(h => h.sslId === c.id);
        return assignmentFilter === 'assigned' ? isAssigned : !isAssigned;
      });
    }

    // Sort sorting
    result.sort((a, b) => {
      let valA = String(a[sortField]).toLowerCase();
      let valB = String(b[sortField]).toLowerCase();

      if (sortField === 'expiration') {
        valA = a.expiration;
        valB = b.expiration;
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [certificates, hosts, searchTerm, providerFilter, statusFilter, expiryFilter, assignmentFilter, sortField, sortOrder]);

  // Paginated certificates
  const paginatedCerts = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredCerts.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredCerts, currentPage]);

  const totalPages = Math.ceil(filteredCerts.length / itemsPerPage) || 1;

  const handleCertSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCertActionError(null);

    const domainsArr = newCertDomains.split(',').map(d => d.trim()).filter(Boolean);
    if (!newCertName.trim() || domainsArr.length === 0) {
      setCertActionError('Please fill in certificate friendly profile name and at least one coverage domain.');
      return;
    }

    if (certModalType === 'upload') {
      onAddCert({
        name: newCertName,
        domains: domainsArr,
        provider: 'Custom Upload',
        expiration: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        autoRenewal: false,
        lastRenewal: null,
      });
      setIsCertModalOpen(false);
      resetCertForm();
    } else {
      setCertActionLoading(true);
      onRequestLetsEncrypt(newCertName, domainsArr, challengeType, (msg, done, err) => {
        setCertActionProgress(msg);
        if (err) {
          setCertActionError(err);
          setCertActionLoading(false);
        }
        if (done && !err) {
          setCertActionLoading(false);
          setIsCertModalOpen(false);
          resetCertForm();
        }
      });
    }
  };

  const resetCertForm = () => {
    setNewCertName('');
    setNewCertDomains('');
    setCertActionProgress('');
    setCertActionError(null);
  };

  const triggerDeleteCert = (id: string, name: string) => {
    const check = onDeleteCert(id);
    if (!check.success) {
      setDeletionWarning({
        id,
        attachedCount: check.attachedHostsCount,
        msg: `The TLS certificate profile "${name}" cannot be deleted because it is currently assigned to protect ${check.attachedHostsCount} active routing host(s). Please replace or disable TLS on these hosts first.`
      });
    }
    setOpenActionMenuId(null);
  };

  const triggerForceRenew = (id: string) => {
    setOpenActionMenuId(null);
    onRenewCert(id, (msg, done, err) => {
      alert(msg);
    });
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200" id="certificates-tab-workspace">

      {/* HEADER CONTROLS */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
        <div>
          <h2 className="text-xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
            TLS Profiles & Security Credentials
          </h2>
          <p className="text-xs text-slate-500 dark:text-zinc-400 mt-1">
            Manage Let's Encrypt automated CA authorities and custom private certificate keychains
          </p>
        </div>

        {currentUser.permissions.certificates === 'manage' && (
          <div className="flex gap-2 shrink-0">
            <button
              onClick={() => {
                setCertModalType('request');
                setIsCertModalOpen(true);
              }}
              className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-xs cursor-pointer transition-all animate-in"
              id="btn-request-le"
            >
              <Plus className="h-4 w-4" /> Request Let's Encrypt
            </button>
            <button
              onClick={() => {
                setCertModalType('upload');
                setIsCertModalOpen(true);
              }}
              className="px-3.5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-slate-700 dark:text-zinc-200 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-xs cursor-pointer transition-all"
              id="btn-upload-custom-pem"
            >
              <Upload className="h-4 w-4" /> Upload Custom PEM
            </button>
          </div>
        )}
      </div>

      {/* COMPREHENSIVE FILTER BOX */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4.5 shadow-3xs space-y-3">

        {/* Search row */}
        <div className="relative">
          <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search certificate profile name, domains covered..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden focus:border-indigo-500"
          />
        </div>

        {/* 4 Filters dropdown line */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">

          {/* Provider */}
          <div className="space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Authority / Provider</span>
            <select
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
              className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
            >
              <option value="all">All Authorities</option>
              <option value="Let's Encrypt">Let's Encrypt</option>
              <option value="Custom Upload">Custom Upload</option>
            </select>
          </div>

          {/* Operational State */}
          <div className="space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Operational State</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
            >
              <option value="all">All States</option>
              <option value="valid">Active & Valid</option>
              <option value="expiring_soon">Expiring Soon</option>
              <option value="expired">Expired</option>
              <option value="renewal_failed">Renewal Failed</option>
            </select>
          </div>

          {/* Expiry filter */}
          <div className="space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Expiry Horizon</span>
            <select
              value={expiryFilter}
              onChange={(e) => setExpiryFilter(e.target.value)}
              className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
            >
              <option value="all">Any Horizon</option>
              <option value="expired">Already Expired</option>
              <option value="14_days">Expires in 14 days</option>
              <option value="30_days">Expires in 30 days</option>
            </select>
          </div>

          {/* Assignment */}
          <div className="space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Host Assignment</span>
            <select
              value={assignmentFilter}
              onChange={(e) => setAssignmentFilter(e.target.value)}
              className="w-full p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-xs font-semibold text-slate-700 dark:text-zinc-300"
            >
              <option value="all">All Assignments</option>
              <option value="assigned">Assigned to Active Hosts</option>
              <option value="unassigned">Unassigned (Orphaned)</option>
            </select>
          </div>

        </div>

      </div>

      {/* CERTIFICATES INVENTORY TABLE (DESKTOP) */}
      <div className="hidden lg:block bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl overflow-hidden shadow-3xs" id="certificates-table-container">
        <table className="w-full border-collapse text-left text-sm text-slate-500 dark:text-zinc-400">
          <thead className="bg-slate-50/50 dark:bg-zinc-900/60 text-slate-700 dark:text-zinc-300 text-xs uppercase font-extrabold border-b border-slate-200/80 dark:border-zinc-800">
            <tr>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('name')}>
                <div className="flex items-center gap-1.5">
                  Friendly Profile Name
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4">Domains Protected</th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('provider')}>
                <div className="flex items-center gap-1.5">
                  Certificate Authority
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('status')}>
                <div className="flex items-center gap-1.5">
                  Applied State
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-zinc-800/50 select-none" onClick={() => handleSort('expiration')}>
                <div className="flex items-center gap-1.5">
                  Expiration / Auto-Renew
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4">Assignment Usage</th>
              <th scope="col" className="px-6 py-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
            {paginatedCerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-400 dark:text-zinc-500 font-semibold">
                  No TLS Certificate profiles matched active search filters.
                </td>
              </tr>
            ) : (
              paginatedCerts.map((cert) => {
                const assignedHosts = hosts.filter(h => h.sslId === cert.id);
                const isAssigned = assignedHosts.length > 0;

                const certStatusConfig = {
                  valid: { bg: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20', text: 'Active & Valid' },
                  expiring_soon: { bg: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20', text: 'Expiring Soon' },
                  expired: { bg: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20', text: 'Expired' },
                  issuing: { bg: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/20', text: 'Renewing/Issuing' },
                  renewal_scheduled: { bg: 'bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border-indigo-500/20', text: 'Scheduled' },
                  renewal_failed: { bg: 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border-rose-500/30', text: 'Auto-Renewal Failed' },
                  validation_failed: { bg: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20', text: 'Auth Fail' },
                  not_assigned: { bg: 'bg-slate-500/10 text-slate-700 dark:text-zinc-400 border-slate-500/20', text: 'Not Assigned' },
                }[cert.status] || { bg: 'bg-gray-500/10 text-gray-700 border-gray-500/20', text: 'Unknown' };

                return (
                  <tr key={cert.id} className="hover:bg-slate-50/30 dark:hover:bg-zinc-800/10 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="font-extrabold text-slate-900 dark:text-zinc-100">{cert.name}</span>
                        <span className="text-[10px] text-slate-400 mt-0.5">Profile Owner: {cert.ownerName}</span>
                      </div>
                    </td>

                    <td className="px-6 py-4 max-w-xs font-mono text-xs text-slate-700 dark:text-zinc-300">
                      <div className="flex flex-wrap gap-1">
                        {cert.domains.map(d => (
                          <span key={d} className="px-1.5 py-0.5 bg-slate-50 dark:bg-zinc-950 border border-slate-100 dark:border-zinc-800 rounded font-bold">
                            {d}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="px-6 py-4">
                      <span className="font-semibold text-xs text-slate-800 dark:text-zinc-200">
                        {cert.provider}
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border ${certStatusConfig.bg}`}>
                        {certStatusConfig.text}
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex flex-col text-xs font-medium">
                        <span className={`font-bold ${cert.status === 'expired' ? 'text-red-600' : cert.status === 'expiring_soon' ? 'text-amber-600' : 'text-slate-800 dark:text-zinc-200'}`}>
                          {formatDate(cert.expiration)}
                        </span>
                        <span className="text-[10px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                          {cert.autoRenewal ? (
                            <span className="text-emerald-600 font-bold flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Auto-Renew On
                            </span>
                          ) : (
                            <span>Manual Renewal Only</span>
                          )}
                        </span>
                      </div>
                    </td>

                    {/* Dynamic Host Assignment information */}
                    <td className="px-6 py-4 text-xs font-medium text-slate-700 dark:text-zinc-300">
                      {isAssigned ? (
                        <div className="flex flex-col space-y-0.5">
                          <span className="text-indigo-600 dark:text-indigo-400 font-bold">{assignedHosts.length} protect route(s)</span>
                          <span className="text-[10px] text-slate-400 truncate max-w-[150px]" title={assignedHosts.map(h => h.source).join(', ')}>
                            {assignedHosts.map(h => h.source.split(',')[0]).join(', ')}
                          </span>
                        </div>
                      ) : (
                        <span className="text-slate-400 italic">Unassigned (Orphaned)</span>
                      )}
                    </td>

                    <td className="px-6 py-4 text-right">
                      {currentUser.permissions.certificates === 'manage' && (
                        <button
                          onClick={() => setOpenActionMenuId(cert.id)}
                          className="p-1.5 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg text-slate-500 dark:text-zinc-400 cursor-pointer"
                          title="Actions"
                          aria-label={`Actions for ${cert.name}`}
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

        {/* TABLE PAGINATION FOOTER */}
        <div className="px-6 py-4 bg-slate-50/50 dark:bg-zinc-900/40 border-t border-slate-200/80 dark:border-zinc-800/80 flex items-center justify-between">
          <span className="text-xs text-slate-500 dark:text-zinc-400 font-semibold">
            Showing <strong className="text-slate-700 dark:text-zinc-200">{(currentPage - 1) * itemsPerPage + 1}</strong> to <strong className="text-slate-700 dark:text-zinc-200">{Math.min(currentPage * itemsPerPage, filteredCerts.length)}</strong> of <strong className="text-slate-700 dark:text-zinc-200">{filteredCerts.length}</strong> certificate profiles
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

      {/* CERTIFICATES CARDS (MOBILE RESPONSIVE LISTING) */}
      <div className="lg:hidden grid grid-cols-1 gap-3">
        {filteredCerts.length === 0 ? (
          <div className="p-8 text-center text-slate-400 dark:text-zinc-500 font-semibold bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl">
            No matching certificate profiles.
          </div>
        ) : (
          filteredCerts.map((cert) => (
            <div key={cert.id} className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4.5 space-y-4 shadow-3xs relative">
              <div className="flex justify-between items-start gap-4">
                <div className="flex flex-col">
                  <span className="font-extrabold text-sm text-slate-900 dark:text-zinc-100">{cert.name}</span>
                  <span className="text-[10px] text-slate-400 mt-0.5">CA Provider: {cert.provider}</span>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="inline-flex px-2 py-0.5 rounded-full text-[10px] font-bold border bg-slate-100 text-slate-600 dark:bg-zinc-800 dark:text-zinc-300">
                    {cert.status}
                  </span>

                  {currentUser.permissions.certificates === 'manage' && (
                    <button
                      onClick={() => setOpenActionMenuId(cert.id)}
                      className="p-1 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded cursor-pointer"
                      aria-label={`Actions for ${cert.name}`}
                    >
                      <MoreVertical className="h-4 w-4 text-slate-500" />
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-1.5 font-mono text-xs p-3 bg-slate-50 dark:bg-zinc-950 border border-slate-100 dark:border-zinc-800 rounded-xl">
                <span className="text-[9px] font-bold text-slate-400 uppercase">Domains Covered:</span>
                <div className="text-slate-800 dark:text-zinc-200 font-bold truncate">
                  {cert.domains.join(', ')}
                </div>
              </div>

              <div className="text-[10px] text-slate-400 font-medium flex justify-between">
                <span>Expires: {formatDate(cert.expiration)}</span>
                <span>{cert.autoRenewal ? 'Auto-Renew' : 'Manual'}</span>
              </div>
            </div>
          ))
        )}
      </div>

      <ActionModal
        open={Boolean(actionCertificate)}
        title={actionCertificate ? `Certificate actions — ${actionCertificate.name}` : 'Certificate actions'}
        description={actionCertificate?.domains.join(', ')}
        onClose={() => setOpenActionMenuId(null)}
      >
        {actionCertificate && <>
          <button onClick={() => { setOpenActionMenuId(null); triggerForceRenew(actionCertificate.id); }} className="text-slate-700 hover:bg-slate-50 dark:text-zinc-300 dark:hover:bg-zinc-800"><RefreshCw className="h-4 w-4" />Force Renew</button>
          <button onClick={() => { setOpenActionMenuId(null); triggerDeleteCert(actionCertificate.id, actionCertificate.name); }} className="text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"><Trash2 className="h-4 w-4" />Delete Certificate</button>
        </>}
      </ActionModal>

      {/* ADD / ISSUE CERTIFICATE DIALOG (Unified collapsed modal) */}
      {isCertModalOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl flex flex-col animate-in fade-in zoom-in-95 duration-150">

            <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
              <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">
                {certModalType === 'request' ? "Issue Let's Encrypt Certificate" : 'Upload Custom TLS Certificate'}
              </h3>
              <button onClick={() => setIsCertModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCertSubmit} className="p-6 space-y-4">
              {certActionLoading ? (
                <div className="py-12 flex flex-col items-center justify-center space-y-4">
                  <Loader2 className="h-10 w-10 text-indigo-600 dark:text-indigo-400 animate-spin" />
                  <p className="text-xs font-semibold text-slate-500 animate-pulse">{certActionProgress}</p>
                </div>
              ) : (
                <>
                  {certActionError && (
                    <div className="p-3 bg-red-50 border border-red-100 rounded-lg text-xs font-bold text-red-700">
                      {certActionError}
                    </div>
                  )}

                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Friendly Profile Name</label>
                    <input
                      type="text"
                      placeholder="e.g. My Website Wildcard"
                      value={newCertName}
                      onChange={(e) => setNewCertName(e.target.value)}
                      className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                      required
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Domains Protected</label>
                    <input
                      type="text"
                      placeholder="e.g. example.com, *.example.com"
                      value={newCertDomains}
                      onChange={(e) => setNewCertDomains(e.target.value)}
                      className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                      required
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">Comma separate multiple subdomains. Wildcards are accepted.</span>
                  </div>

                  {certModalType === 'request' ? (
                    <div className="space-y-3.5 border-t border-slate-100 dark:border-zinc-800 pt-4">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">ACME Challenge Protocol</span>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setChallengeType('http-01')}
                          className={`p-3 border rounded-xl text-left cursor-pointer transition-all ${
                            challengeType === 'http-01'
                              ? 'bg-slate-900 border-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:border-zinc-100 font-bold'
                              : 'border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-slate-700'
                          }`}
                        >
                          <div className="text-xs font-bold">HTTP-01 Challenge</div>
                          <p className="text-[10px] opacity-80 mt-1">Requires public port 80 to be routeable to this container.</p>
                        </button>
                        <button
                          type="button"
                          onClick={() => setChallengeType('dns-01')}
                          className={`p-3 border rounded-xl text-left cursor-pointer transition-all ${
                            challengeType === 'dns-01'
                              ? 'bg-slate-900 border-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:border-zinc-100 font-bold'
                              : 'border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-slate-700'
                          }`}
                        >
                          <div className="text-xs font-bold">DNS-01 Provider APIs</div>
                          <p className="text-[10px] opacity-80 mt-1">Challenge verified via automated TXT DNS registers.</p>
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3 border-t border-slate-100 dark:border-zinc-800 pt-4 text-xs">
                      <div className="p-3 bg-amber-50 dark:bg-zinc-800 rounded-xl border border-amber-200/50">
                        <span className="font-bold text-amber-900 block">Write-Only Key Material Policy</span>
                        <p className="text-[10px] text-amber-800 mt-1">
                          Private keys are processed locally inside Nginx core and never reappear on UI screens or client API payloads after initial encryption save.
                        </p>
                      </div>

                      <div className="grid grid-cols-1 gap-2.5">
                        <div className="p-4.5 border border-dashed border-slate-300 dark:border-zinc-700 rounded-xl text-center bg-slate-50/50 cursor-pointer">
                          <CheckCircle2 className="h-6 w-6 text-indigo-500 mx-auto mb-1" />
                          <span className="text-xs font-bold block">Upload Certificate PEM File</span>
                          <span className="text-[10px] text-slate-400 block mt-0.5">Drag & drop or click to pick certificate.pem</span>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end gap-2.5 pt-4 border-t border-slate-100 dark:border-zinc-800">
                    <button
                      type="button"
                      onClick={() => setIsCertModalOpen(false)}
                      className="px-4 py-2 bg-slate-200 text-slate-700 rounded-lg text-xs font-bold cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold cursor-pointer"
                    >
                      {certModalType === 'request' ? 'Issue Free SSL' : 'Save Certificate'}
                    </button>
                  </div>
                </>
              )}
            </form>

          </div>
        </div>
      )}

      {/* SAFETY WARNING DIALOG */}
      {deletionWarning && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-red-200 dark:border-red-950 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl animate-in fade-in zoom-in duration-100">
            <div className="p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-6 w-6 text-red-500 shrink-0" />
                <div>
                  <h4 className="font-extrabold text-base text-slate-900 dark:text-zinc-100">Safety Check Rejection</h4>
                  <p className="text-xs text-slate-600 dark:text-zinc-400 mt-2 leading-relaxed">
                    {deletionWarning.msg}
                  </p>
                </div>
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => setDeletionWarning(null)}
                  className="px-4.5 py-2 bg-slate-900 hover:bg-slate-800 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-xl text-xs font-bold transition-colors cursor-pointer"
                >
                  Understood
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
