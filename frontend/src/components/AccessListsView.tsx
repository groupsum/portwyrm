import React, { useState, useMemo } from 'react';
import { AccessList, Host, User } from '../types';
import { formatDate } from '../utils/formatting';
import {
  Shield,
  Users,
  Lock,
  Trash2,
  Edit3,
  Plus,
  HelpCircle,
  Network,
  Check,
  X,
  AlertTriangle,
  Info,
  MoreVertical,
  Search,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown
} from 'lucide-react';
import ActionModal from './ActionModal';
import MultiSelect from './MultiSelect';
import { can } from '../utils/permissions';

interface AccessListsViewProps {
  accessLists: AccessList[];
  hosts: Host[];
  users: User[];
  currentUser: User;
  onAddAccessList: (acl: any) => void;
  onUpdateAccessList: (id: string, updates: any) => void;
  onDeleteAccessList: (id: string) => { success: boolean; attachedHostsCount: number };
}

export default function AccessListsView({
  accessLists,
  hosts,
  users: identities,
  currentUser,
  onAddAccessList,
  onUpdateAccessList,
  onDeleteAccessList
}: AccessListsViewProps) {

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<'name' | 'modified'>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 6;

  // Action dialog selection
  const [openActionMenuId, setOpenActionMenuId] = useState<string | null>(null);
  const actionAccessList = accessLists.find(acl => acl.id === openActionMenuId) ?? null;

  // Editor modal
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [policyComposition, setPolicyComposition] = useState<'satisfy_all' | 'satisfy_any'>('satisfy_all');
  const [forwardHeader, setForwardHeader] = useState(true);

  // Lists inside the ACL
  const [identityIds, setIdentityIds] = useState<string[]>([]);
  const [rules, setRules] = useState<{ type: 'allow' | 'deny'; subnet: string }[]>([]);

  // Temporary inputs
  const [newRuleType, setNewRuleType] = useState<'allow' | 'deny'>('allow');
  const [newRuleSubnet, setNewRuleSubnet] = useState('');

  // Delete warnings
  const [warningMessage, setWarningMessage] = useState<string | null>(null);

  // Filter and sorting logic
  const filteredAcls = useMemo(() => {
    let result = [...accessLists];

    if (searchTerm.trim() !== '') {
      const q = searchTerm.toLowerCase();
      result = result.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.ownerName.toLowerCase().includes(q) ||
        a.identityIds.some(id => identities.find(identity => identity.id === id)?.displayName.toLowerCase().includes(q)) ||
        a.rules.some(r => r.subnet.toLowerCase().includes(q))
      );
    }

    result.sort((a, b) => {
      let valA = a[sortField].toLowerCase();
      let valB = b[sortField].toLowerCase();
      if (sortField === 'modified') {
        valA = a.modified;
        valB = b.modified;
      }
      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [accessLists, identities, searchTerm, sortField, sortOrder]);

  // Paginated Slicing
  const paginatedAcls = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredAcls.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredAcls, currentPage]);

  const totalPages = Math.ceil(filteredAcls.length / itemsPerPage) || 1;

  const openNewAcl = () => {
    setEditingId(null);
    setName('');
    setPolicyComposition('satisfy_all');
    setForwardHeader(true);
    setIdentityIds([]);
    setRules([]);
    setIsEditorOpen(true);
  };

  const openEditAcl = (acl: AccessList) => {
    setEditingId(acl.id);
    setName(acl.name);
    setPolicyComposition(acl.policyComposition);
    setForwardHeader(acl.forwardHeader);
    setIdentityIds([...acl.identityIds]);
    setRules([...acl.rules]);
    setIsEditorOpen(true);
  };

  const handleAddRule = () => {
    if (!newRuleSubnet.trim()) return;
    setRules(prev => [...prev, { type: newRuleType, subnet: newRuleSubnet }]);
    setNewRuleSubnet('');
  };

  const handleRemoveRule = (idx: number) => {
    setRules(prev => prev.filter((_, i) => i !== idx));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const payload = {
      name,
      policyComposition,
      forwardHeader,
      identityIds,
      users: [],
      rules
    };

    if (editingId) {
      onUpdateAccessList(editingId, payload);
    } else {
      onAddAccessList(payload);
    }

    setIsEditorOpen(false);
  };

  const handleDeleteTrigger = (acl: AccessList) => {
    const res = onDeleteAccessList(acl.id);
    if (!res.success) {
      const affectedHosts = hosts.filter(h => h.accessListIds.includes(acl.id)).map(h => h.source);
      setWarningMessage(
        `This Access Control List (ACL) cannot be deleted because it is protecting traffic for ${res.attachedHostsCount} active routing host(s):\n\n` +
        affectedHosts.join(', ') +
        `\n\nPlease switch these hosts to Public or another access list before deleting this firewall policy.`
      );
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200" id="access-lists-view-container">

      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
            Access Control Lists (ACL)
          </h2>
          <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">
            Data-plane security layers connecting basic auth users with IP CIDR firewall constraints
          </p>
        </div>

        {can(currentUser, 'access_lists', 'create') && (
          <button
            onClick={openNewAcl}
            className="px-4.5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-bold flex items-center gap-1.5 shadow-xs cursor-pointer transition-all"
            id="btn-new-acl"
          >
            <Plus className="h-4.5 w-4.5" />
            Create Access List
          </button>
        )}
      </div>

      {/* FILTER BAR */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4 shadow-3xs flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search access list names, rules, assigned usernames..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden focus:border-indigo-500"
          />
        </div>

        <div className="shrink-0 flex gap-1.5">
          <button
            onClick={() => {
              setSortField('name');
              setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
            }}
            className="px-4 py-2 bg-slate-50 hover:bg-slate-100 dark:bg-zinc-950 dark:hover:bg-zinc-800 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs font-bold text-slate-700 dark:text-zinc-300 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            Sort by Name <ArrowUpDown className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* ACL INVENTORY CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5" id="acl-cards-grid">
        {paginatedAcls.length === 0 ? (
          <div className="col-span-full p-12 text-center text-slate-400 dark:text-zinc-500 font-semibold bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl">
            No access control lists matched active search parameters.
          </div>
        ) : (
          paginatedAcls.map((acl) => {
            const attachedHosts = hosts.filter(h => h.accessListIds.includes(acl.id));
            const attachedHostsCount = attachedHosts.length;
            return (
              <div key={acl.id} className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-5 shadow-3xs hover:border-slate-300 dark:hover:border-zinc-700 transition-all flex flex-col justify-between space-y-4">

                <div className="space-y-3">
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 bg-indigo-50 dark:bg-indigo-950/40 rounded-lg text-indigo-600 dark:text-indigo-400">
                        <Shield className="h-5 w-5" />
                      </div>
                      <div>
                        <h3 className="font-extrabold text-slate-900 dark:text-zinc-100 text-sm leading-tight">{acl.name}</h3>
                        <span className="text-[10px] text-slate-400 block mt-0.5">Author: {acl.ownerName}</span>
                      </div>
                    </div>
                  </div>

                  <span className="inline-block text-[9px] font-bold px-2 py-0.5 bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-300 rounded border border-slate-200/50 dark:border-zinc-700 font-mono uppercase tracking-wide">
                    {acl.policyComposition === 'satisfy_all' ? 'AND Policy (Satisfy All)' : 'OR Policy (Satisfy Any)'}
                  </span>

                  {/* ACL Details counters */}
                  <div className="grid grid-cols-3 gap-2 pt-1 text-center font-mono">
                    <div className="p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs">
                      <span className="text-[9px] text-slate-400 uppercase font-bold block">Auth Users</span>
                      <strong className="text-slate-800 dark:text-zinc-200 text-sm">{acl.usersCount}</strong>
                    </div>
                    <div className="p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs">
                      <span className="text-[9px] text-slate-400 uppercase font-bold block">CIDR Subnets</span>
                      <strong className="text-slate-800 dark:text-zinc-200 text-sm">{acl.rulesCount}</strong>
                    </div>
                    <div className="p-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs">
                      <span className="text-[9px] text-slate-400 uppercase font-bold block">Hosts</span>
                      <strong className="text-indigo-600 dark:text-indigo-400 text-sm" title={attachedHosts.map(h => h.source).join(', ')}>{attachedHostsCount}</strong>
                    </div>
                  </div>

                  {/* Subnet rules snapshot preview */}
                  <div className="text-xs space-y-1 pt-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Subnet Rules Preview</span>
                    {acl.rules.length === 0 ? (
                      <span className="text-slate-400 italic block text-[11px]">No IP constraints. Basic auth only.</span>
                    ) : (
                      <div className="flex flex-wrap gap-1 font-mono text-[9px]">
                        {acl.rules.slice(0, 2).map((r, i) => (
                          <span key={i} className={`px-1.5 py-0.5 border rounded-sm font-semibold ${
                            r.type === 'allow'
                              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-100 dark:border-emerald-900 text-emerald-700 dark:text-emerald-400'
                              : 'bg-red-50 dark:bg-red-950/30 border-red-100 dark:border-red-900 text-red-700 dark:text-red-400'
                          }`}>
                            {r.type === 'allow' ? 'Allow' : 'Deny'}: {r.subnet}
                          </span>
                        ))}
                        {acl.rules.length > 2 && <span className="text-slate-400 font-bold">+{acl.rules.length - 2} more</span>}
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions row */}
                <div className="flex justify-between items-center pt-3 border-t border-slate-100 dark:border-zinc-800/80 text-xs">
                  <span className="text-slate-400 font-medium">Modified: {formatDate(acl.modified)}</span>

                  {(can(currentUser, 'access_lists', 'update') || can(currentUser, 'access_lists', 'delete')) && (
                    <button
                      type="button"
                      onClick={() => setOpenActionMenuId(acl.id)}
                      className="p-1.5 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg text-slate-500 dark:text-zinc-400 cursor-pointer"
                      title="Actions"
                      aria-label={`Actions for ${acl.name}`}
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  )}
                </div>

              </div>
            );
          })
        )}
      </div>

      {/* PAGINATION PANEL */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between bg-white dark:bg-zinc-900 p-4 border border-slate-200 dark:border-zinc-800 rounded-2xl">
          <span className="text-xs text-slate-400 font-semibold">
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex gap-1.5">
            <button
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              className="p-1.5 bg-slate-50 hover:bg-slate-100 dark:bg-zinc-950 dark:hover:bg-zinc-800 rounded-lg disabled:opacity-40 transition-colors cursor-pointer"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage === totalPages}
              className="p-1.5 bg-slate-50 hover:bg-slate-100 dark:bg-zinc-950 dark:hover:bg-zinc-800 rounded-lg disabled:opacity-40 transition-colors cursor-pointer"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      <ActionModal
        open={Boolean(actionAccessList)}
        title={actionAccessList ? `Access list actions — ${actionAccessList.name}` : 'Access list actions'}
        description={actionAccessList ? `${actionAccessList.rules.length} configured rule${actionAccessList.rules.length === 1 ? '' : 's'}` : undefined}
        onClose={() => setOpenActionMenuId(null)}
      >
        {actionAccessList && <>
          {can(currentUser, 'access_lists', 'update') && <button type="button" onClick={() => { setOpenActionMenuId(null); openEditAcl(actionAccessList); }} className="text-slate-700 hover:bg-slate-50 dark:text-zinc-300 dark:hover:bg-zinc-800"><Edit3 className="h-4 w-4" />Edit Policy</button>}
          {can(currentUser, 'access_lists', 'delete') && <button type="button" onClick={() => { setOpenActionMenuId(null); handleDeleteTrigger(actionAccessList); }} className="text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"><Trash2 className="h-4 w-4" />Delete Policy</button>}
        </>}
      </ActionModal>

      {/* --- ACL EDITOR MODAL --- */}
      {isEditorOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">

            <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
              <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">
                {editingId ? 'Modify Access Control List' : 'Create Access Control List'}
              </h3>
              <button onClick={() => setIsEditorOpen(false)} className="text-slate-400 hover:text-slate-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="flex-1 p-6 overflow-y-auto space-y-6">

              {/* General details */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Access List Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Production Team Only"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Policy Composition Logic</label>
                  <select
                    value={policyComposition}
                    onChange={(e) => setPolicyComposition(e.target.value as any)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100"
                  >
                    <option value="satisfy_all">AND - Satisfy All (Auth AND IP match)</option>
                    <option value="satisfy_any">OR - Satisfy Any (Auth OR IP match)</option>
                  </select>
                </div>
              </div>

              {/* Policy Composition Help box */}
              <div className="p-3 bg-slate-50 dark:bg-zinc-800 border border-slate-200 dark:border-zinc-700 rounded-xl flex gap-2.5">
                <Info className="h-5 w-5 text-indigo-500 shrink-0 mt-0.5" />
                <div className="text-xs text-slate-600 dark:text-zinc-300">
                  {policyComposition === 'satisfy_all' ? (
                    <p>
                      <strong>AND Composition (Satisfy All):</strong> Visitors MUST provide valid Basic Auth credentials <strong>AND</strong> connect from an allowed IP subnet ruleset. Best for critical internal databases.
                    </p>
                  ) : (
                    <p>
                      <strong>OR Composition (Satisfy Any):</strong> Visitors can access either by entering a valid user login <strong>OR</strong> simply by visiting from an allowed office IP subnet. Allows zero-credentials office pass-throughs.
                    </p>
                  )}
                </div>
              </div>

              {/* Portwyrm identities */}
              <div className="space-y-3.5 border-t border-slate-100 pt-5 dark:border-zinc-800">
                <MultiSelect
                  id="access-list-identities"
                  label={`Authorized identities (${identityIds.length})`}
                  options={identities.filter(identity => identity.status === 'Active').map(identity => ({
                    value: identity.id,
                    label: identity.displayName,
                    description: `${identity.username} · ${identity.email}`,
                  }))}
                  values={identityIds}
                  onChange={setIdentityIds}
                  placeholder="None"
                  noResultsText="No matching identities"
                />
                <p className="text-[10px] leading-relaxed text-slate-500">
                  Selected identities use their existing Portwyrm credentials. Passwords remain write-only and are never displayed here.
                </p>
              </div>

              {/* Firewall subnet rules */}
              <div className="space-y-3.5 border-t border-slate-100 dark:border-zinc-800 pt-5">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Allow / Deny Network Subnets ({rules.length})</span>

                <div className="flex gap-2.5">
                  <select
                    value={newRuleType}
                    onChange={(e) => setNewRuleType(e.target.value as any)}
                    className="p-2 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-700"
                  >
                    <option value="allow">Allow IP</option>
                    <option value="deny">Deny IP</option>
                  </select>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.1.0/24, 203.0.113.42/32"
                    value={newRuleSubnet}
                    onChange={(e) => setNewRuleSubnet(e.target.value)}
                    className="p-2 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm flex-1 font-mono focus:outline-hidden"
                  />
                  <button
                    type="button"
                    onClick={handleAddRule}
                    className="px-3.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer"
                  >
                    <Plus className="h-3.5 w-3.5" /> Add
                  </button>
                </div>

                {rules.length > 0 && (
                  <div className="border border-slate-200 dark:border-zinc-800 rounded-xl overflow-hidden divide-y divide-slate-200 dark:divide-zinc-800 text-xs font-mono bg-slate-50/40">
                    {rules.map((r, i) => (
                      <div key={i} className="p-2.5 flex justify-between items-center">
                        <span className={`font-bold px-1.5 py-0.2 rounded border ${
                          r.type === 'allow'
                            ? 'bg-emerald-100 border-emerald-200 text-emerald-800'
                            : 'bg-red-100 border-red-200 text-red-800'
                        }`}>
                          {r.type === 'allow' ? 'Allow' : 'Deny'}: {r.subnet}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleRemoveRule(i)}
                          className="text-red-500 hover:text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Header forwarding */}
              <div className="flex items-start gap-2.5 border-t border-slate-100 dark:border-zinc-800 pt-5 text-xs">
                <input
                  type="checkbox"
                  id="forward-header"
                  checked={forwardHeader}
                  onChange={(e) => setForwardHeader(e.target.checked)}
                  className="rounded border-slate-300 dark:border-zinc-800 focus:ring-indigo-500 mt-0.5"
                />
                <div>
                  <label htmlFor="forward-header" className="font-bold text-slate-800 dark:text-zinc-200 block">Forward Authorization Header</label>
                  <span className="text-slate-400">Allows downstream proxy clients or apps to read the authorization tokens if required.</span>
                </div>
              </div>

            </form>

            <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-end gap-2.5">
              <button
                type="button"
                onClick={() => setIsEditorOpen(false)}
                className="px-4 py-2 bg-slate-200 text-slate-700 rounded-lg text-xs font-bold cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmit}
                className="px-4.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold cursor-pointer"
              >
                Save Policy
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Safety Rejection Dialog */}
      {warningMessage && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-red-200 dark:border-red-950 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-6 w-6 text-red-500 shrink-0" />
                <div>
                  <h4 className="font-extrabold text-base text-slate-900 dark:text-zinc-100">Deletion Safety Rejection</h4>
                  <p className="text-xs text-slate-600 dark:text-zinc-400 mt-2 leading-relaxed whitespace-pre-wrap font-sans">
                    {warningMessage}
                  </p>
                </div>
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => setWarningMessage(null)}
                  className="px-4.5 py-2 bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 rounded-xl text-xs font-bold cursor-pointer"
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
