import React, { useState, useMemo, useEffect } from 'react';
import { User, UserRole, AccessList, PermissionAction, PermissionResource, UserPermissions } from '../types';
import { formatDate } from '../utils/formatting';
import { grantSummary, normalizePermissions, PERMISSION_ACTIONS, PERMISSION_RESOURCES, readGrant } from '../utils/permissions';
import {
  Users,
  UserCheck,
  ShieldAlert,
  CheckCircle2,
  Trash2,
  Edit3,
  Plus,
  X,
  Key,
  AlertTriangle,
  Lock,
  Unlock,
  Sliders,
  Mail,
  Shield,
  MoreVertical,
  Search,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown
} from 'lucide-react';
import ActionModal from './ActionModal';
import MultiSelect from './MultiSelect';
import { useFeedback } from './Feedback';

interface UsersViewProps {
  users: User[];
  accessLists: AccessList[];
  currentUser: User;
  onAddUser: (user: any, aclIds: string[]) => void;
  onUpdateUser: (id: string, updates: any) => void;
  onDeleteUser: (id: string) => boolean;
}

export default function UsersView({
  users,
  accessLists,
  currentUser,
  onAddUser,
  onUpdateUser,
  onDeleteUser
}: UsersViewProps) {
  const feedback = useFeedback();

  // Search & Sorting state
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<'displayName' | 'role' | 'status' | 'lastActivity'>('displayName');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Editor Modal
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Fields
  const [displayName, setDisplayName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<UserRole>('Operator');
  const [visibility, setVisibility] = useState<'all' | 'owned'>('owned');
  const [status, setStatus] = useState<'Active' | 'Disabled'>('Active');
  const [selectedAclIds, setSelectedAclIds] = useState<string[]>([]);

  const [permissionMatrix, setPermissionMatrix] = useState<UserPermissions>(() => normalizePermissions({proxy_hosts: 'manage', streams: 'view', certificates: 'view'}));

  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Triple-dot action dialog
  const [openActionMenuId, setOpenActionMenuId] = useState<string | null>(null);
  const actionUser = users.find(user => user.id === openActionMenuId) ?? null;

  // Reset pagination on filter change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm]);

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const setPermission = (resource: PermissionResource, action: PermissionAction, enabled: boolean) => {
    setPermissionMatrix(current => ({
      ...current,
      [resource]: {...current[resource], [action]: enabled},
    }));
  };

  const applyRolePreset = (nextRole: UserRole) => {
    setRole(nextRole);
    if (nextRole === 'Administrator') {
      setVisibility('all');
      setPermissionMatrix(normalizePermissions({}, true));
    } else if (nextRole === 'Viewer') {
      setPermissionMatrix(Object.fromEntries(PERMISSION_RESOURCES.map(resource => [resource.id, readGrant()])) as UserPermissions);
    } else {
      setPermissionMatrix(normalizePermissions({proxy_hosts: 'manage', redirection_hosts: 'manage', dead_hosts: 'manage', streams: 'view', access_lists: 'view', certificates: 'view'}));
    }
  };

  const openNewUser = () => {
    setEditingId(null);
    setDisplayName('');
    setUsername('');
    setEmail('');
    setPassword('');
    setCurrentPassword('');
    setConfirmPassword('');
    setRole('Operator');
    setVisibility('owned');
    setStatus('Active');
    setPermissionMatrix(normalizePermissions({proxy_hosts: 'manage', redirection_hosts: 'manage', dead_hosts: 'manage', streams: 'view', access_lists: 'view', certificates: 'view'}));
    setSelectedAclIds([]);
    setErrorMessage(null);
    setIsEditorOpen(true);
  };

  const openEditUser = (u: User) => {
    setEditingId(u.id);
    setDisplayName(u.displayName);
    setUsername(u.username);
    setEmail(u.email || '');
    setPassword('');
    setCurrentPassword('');
    setConfirmPassword('');
    setRole(u.role);
    setVisibility(u.visibility);
    setStatus(u.status);
    setPermissionMatrix(u.permissions);

    // Compute current ACL associations
    const userAcls = accessLists
      .filter(acl => acl.identityIds.includes(u.id))
      .map(acl => acl.id);
    setSelectedAclIds(userAcls);

    setErrorMessage(null);
    setIsEditorOpen(true);
    setOpenActionMenuId(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!displayName.trim() || !username.trim() || !email.trim()) {
      setErrorMessage('Please fill in the operator name, handle, and email.');
      return;
    }

    if (!editingId && !password.trim()) {
      setErrorMessage('A password is required when creating an operator.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('New passwords do not match.');
      return;
    }

    if (editingId === currentUser.id && password && !currentPassword) {
      setErrorMessage('Enter your current password to set a new password.');
      return;
    }

    if (!username.startsWith('@')) {
      setErrorMessage('Username handle must begin with @ symbol (e.g. @developer).');
      return;
    }

    const payload = {
      displayName,
      username,
      email,
      password,
      currentPassword,
      role,
      visibility,
      status,
      permissions: permissionMatrix,
      aclIds: selectedAclIds
    };

    if (editingId) {
      onUpdateUser(editingId, payload);
    } else {
      onAddUser(payload, selectedAclIds);
    }

    setIsEditorOpen(false);
  };

  const handleDeleteTrigger = (id: string) => {
    setOpenActionMenuId(null);
    setErrorMessage(null);
    const success = onDeleteUser(id);
    if (!success) {
      feedback.toast('You cannot delete your own active administrator profile.', 'error');
    }
  };

  // Filter & sorting pipeline
  const filteredUsers = useMemo(() => {
    let result = [...users];

    if (searchTerm.trim() !== '') {
      const q = searchTerm.toLowerCase();
      result = result.filter(u =>
        u.displayName.toLowerCase().includes(q) ||
        u.username.toLowerCase().includes(q) ||
        (u.email && u.email.toLowerCase().includes(q)) ||
        u.role.toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      let valA = String(a[sortField]).toLowerCase();
      let valB = String(b[sortField]).toLowerCase();

      if (sortField === 'lastActivity') {
        valA = a.lastActivity;
        valB = b.lastActivity;
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [users, searchTerm, sortField, sortOrder]);

  const paginatedUsers = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredUsers.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredUsers, currentPage]);

  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage) || 1;

  return (
    <div className="space-y-6 animate-in fade-in duration-200" id="users-view-container">

      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
            Control-Plane Identity & Access
          </h2>
          <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">
            Human Operator Accounts, Scoped Roles, & Credentials
          </p>
        </div>

        {currentUser.role === 'Administrator' && (
          <button
            onClick={openNewUser}
            className="px-4.5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-bold flex items-center gap-1.5 shadow-xs cursor-pointer transition-all"
            id="btn-new-user"
          >
            <Plus className="h-4.5 w-4.5" />
            Add User Account
          </button>
        )}
      </div>

      {/* FILTER BAR */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4 shadow-3xs">
        <div className="relative">
          <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search operator display name, handle username, email role..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden focus:border-indigo-500"
          />
        </div>
      </div>

      {/* USER LIST TABLE */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl overflow-hidden shadow-3xs" id="users-table-container">
        <table className="w-full border-collapse text-left text-sm text-slate-500 dark:text-zinc-400">
          <thead className="bg-slate-50/50 dark:bg-zinc-900/60 text-slate-700 dark:text-zinc-300 text-xs uppercase font-extrabold border-b border-slate-200/80 dark:border-zinc-800">
            <tr>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 select-none" onClick={() => handleSort('displayName')}>
                <div className="flex items-center gap-1.5">
                  User
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 select-none" onClick={() => handleSort('role')}>
                <div className="flex items-center gap-1.5">
                  Role
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4">Credentials</th>
              <th scope="col" className="px-6 py-4">Permissions</th>
              <th scope="col" className="px-6 py-4">MFA</th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 select-none" onClick={() => handleSort('status')}>
                <div className="flex items-center gap-1.5">
                  Status
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
              <th scope="col" className="px-6 py-4 cursor-pointer hover:bg-slate-100/50 select-none" onClick={() => handleSort('lastActivity')}>
                <div className="flex items-center gap-1.5">
                  Activity
                  <ArrowUpDown className="h-3 w-3 text-slate-400" />
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
            {paginatedUsers.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-400 dark:text-zinc-500 font-semibold">
                  No operator accounts matched active search criteria.
                </td>
              </tr>
            ) : (
              paginatedUsers.map((user) => {
                const isSelf = user.id === currentUser.id;
                const associatedAcls = accessLists.filter(acl => acl.identityIds.includes(user.id));

                return (
                  <tr key={user.id} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/20 transition-colors">

                    {/* Identity Profile */}
                    <td className="px-6 py-4.5">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 font-bold text-xs flex items-center justify-center border border-slate-200 dark:border-zinc-700">
                          {user.displayName.split(' ').map(n => n[0]).join('')}
                        </div>
                        <div className="flex flex-col">
                          <span className="font-extrabold text-slate-900 dark:text-zinc-100 flex items-center gap-1.5">
                            {user.displayName}
                            {isSelf && (
                              <span className="bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-400 font-bold text-[9px] px-1.5 py-0.2 rounded border border-indigo-100 dark:border-indigo-900 uppercase">
                                Self
                              </span>
                            )}
                          </span>
                          <span className="text-[10px] text-slate-600 dark:text-zinc-400 font-mono mt-0.5">{user.username}</span>
                        </div>
                      </div>
                    </td>

                    {/* Role & Bounds */}
                    <td className="px-6 py-4.5">
                      <div className="flex flex-col gap-1 items-start">
                        <span className={`inline-block px-2.5 py-0.5 text-[10px] font-bold border rounded-md uppercase tracking-wider ${
                          user.role === 'Administrator'
                            ? 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-900 text-red-700 dark:text-red-400'
                            : user.role === 'Operator'
                            ? 'bg-indigo-50 dark:bg-indigo-950/20 border-indigo-200 dark:border-indigo-900 text-indigo-700 dark:text-indigo-400'
                            : 'bg-slate-100 dark:bg-zinc-800 border-slate-200 dark:border-zinc-700 text-slate-700 dark:text-zinc-300'
                        }`}>
                          {user.role}
                        </span>
                        <span className="text-[10px] font-semibold text-slate-600 dark:text-zinc-400">
                          {user.visibility === 'all' ? 'All Resources' : 'Owned Resources'}
                        </span>
                      </div>
                    </td>

                    {/* Credentials & ACLs */}
                    <td className="px-6 py-4.5">
                      <div className="flex flex-col gap-1 text-xs">
                        <span className="font-semibold text-slate-700 dark:text-zinc-300 flex items-center gap-1.5">
                          <Mail className="h-3 w-3 text-slate-400" /> {user.email || 'N/A'}
                        </span>
                        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-600 dark:text-zinc-400">
                          <Lock className="h-3 w-3" /> Password: write-only
                        </div>
                        {associatedAcls.length > 0 && (
                          <div className="flex items-center gap-1 mt-0.5 text-[9px] font-bold text-indigo-600 dark:text-indigo-400 font-mono">
                            <Shield className="h-2.5 w-2.5" />
                            Synced ACLs: {associatedAcls.map(a => a.name).join(', ')}
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Permission Summary blueprint box */}
                    <td className="px-6 py-4.5">
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[10px] font-mono text-slate-600 dark:text-zinc-400 font-semibold">
                        {PERMISSION_RESOURCES.map(resource => {
                          const summary = grantSummary(user.permissions[resource.id]);
                          return <div key={resource.id} className="flex justify-between gap-2"><span>{resource.shortLabel}</span><strong className={summary === 'CRUD' ? 'text-emerald-700 dark:text-emerald-400' : summary === 'None' ? 'text-red-600 dark:text-red-400' : 'text-indigo-700 dark:text-indigo-400'}>{summary}</strong></div>;
                        })}
                      </div>
                    </td>

                    {/* MFA Status */}
                    <td className="px-6 py-4.5">
                      <span className={`inline-flex items-center gap-1.5 text-xs font-bold ${user.mfa ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-600 dark:text-zinc-400'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${user.mfa ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`}></span>
                        {user.mfa ? 'MFA Enabled' : 'MFA Off'}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-6 py-4.5">
                      <span className={`px-2 py-0.5 text-[10px] font-bold border rounded-md uppercase tracking-wider ${
                        user.status === 'Active'
                          ? 'bg-emerald-50 border-emerald-100 text-emerald-700'
                          : 'bg-slate-100 border-slate-200 text-slate-500'
                      }`}>
                        {user.status}
                      </span>
                    </td>

                    {/* Last Activity */}
                    <td className="px-6 py-4.5 text-xs font-medium font-mono text-slate-600 dark:text-zinc-400">
                      <div className="flex items-center justify-between gap-3">
                        <span>{formatDate(user.lastActivity)}</span>
                        {currentUser.role === 'Administrator' && (
                          <button
                            onClick={() => setOpenActionMenuId(user.id)}
                            className="p-1.5 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg text-slate-500 dark:text-slate-400 cursor-pointer"
                            title="Actions"
                            aria-label={`Actions for ${user.displayName || user.username}`}
                          >
                            <MoreVertical className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>

                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {/* PAGINATION PANEL */}
        <div className="px-6 py-4 bg-slate-50/50 dark:bg-zinc-900/40 border-t border-slate-200/80 dark:border-zinc-800/80 flex items-center justify-between">
          <span className="text-xs text-slate-500 dark:text-zinc-400 font-semibold">
            Showing <strong className="text-slate-700 dark:text-zinc-200">{(currentPage - 1) * itemsPerPage + 1}</strong> to <strong className="text-slate-700 dark:text-zinc-200">{Math.min(currentPage * itemsPerPage, filteredUsers.length)}</strong> of <strong className="text-slate-700 dark:text-zinc-200">{filteredUsers.length}</strong> operator accounts
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
        open={Boolean(actionUser)}
        title={actionUser ? `User actions — ${actionUser.displayName || actionUser.username}` : 'User actions'}
        description={actionUser?.email}
        onClose={() => setOpenActionMenuId(null)}
      >
        {actionUser && <>
          <button onClick={() => { setOpenActionMenuId(null); openEditUser(actionUser); }} className="text-slate-700 hover:bg-slate-50 dark:text-zinc-300 dark:hover:bg-zinc-800"><Edit3 className="h-4 w-4" />Configure Profile</button>
          {actionUser.id !== currentUser.id && <button onClick={() => { setOpenActionMenuId(null); handleDeleteTrigger(actionUser.id); }} className="text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"><Trash2 className="h-4 w-4" />Revoke Account</button>}
        </>}
      </ActionModal>

      {/* --- ENROLL / MODIFY USER DIALOG --- */}
      {isEditorOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-4xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">

            <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
              <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">
                {editingId ? 'Modify Operator Identity' : 'Enroll Operator Identity'}
              </h3>
              <button onClick={() => setIsEditorOpen(false)} className="text-slate-400 hover:text-slate-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="flex-1 p-6 overflow-y-auto space-y-5">

              {errorMessage && (
                <div className="p-3.5 bg-red-50 border border-red-100 rounded-xl text-xs font-bold text-red-700">
                  {errorMessage}
                </div>
              )}

              {/* General inputs: name, username */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Full Display Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Alexis Morgan"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">User Handle (@username)</label>
                  <input
                    type="text"
                    placeholder="e.g. @alexis"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                    required
                  />
                </div>
              </div>

              {/* Credentials inputs */}
              <div className="grid grid-cols-1 gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 dark:border-zinc-800">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Email Address</label>
                  <input
                    type="email"
                    placeholder="e.g. alexis@portwyrm.internal"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                    required
                  />
                </div>

                {editingId === currentUser.id && <div className="space-y-1">
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400">Current password</label>
                  <input
                    type="password"
                    autoComplete="current-password"
                    placeholder="Required when changing your password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                    required={Boolean(password)}
                  />
                </div>}
                <div className="space-y-1">
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400">{editingId && editingId !== currentUser.id ? 'Reset password (Optional)' : editingId ? 'New password (Optional)' : 'Initial password'}</label>
                  <input type="password" autoComplete="new-password" minLength={8} placeholder={editingId ? 'Leave blank to keep current password' : 'Set user password'} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-lg border border-slate-200 bg-white p-2.5 font-mono text-sm text-slate-800 focus:outline-hidden dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100" required={!editingId} />
                </div>
                <div className="space-y-1">
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400">Confirm new password</label>
                  <input type="password" autoComplete="new-password" minLength={8} placeholder="Enter the new password again" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full rounded-lg border border-slate-200 bg-white p-2.5 font-mono text-sm text-slate-800 focus:outline-hidden dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100" required={Boolean(password) || !editingId} />
                </div>
              </div>

              {/* Access list associations */}
              <div className="space-y-2 border-t border-slate-100 pt-4 dark:border-zinc-800">
                <MultiSelect
                  id="identity-access-lists"
                  label="Access control lists"
                  options={accessLists.map(acl => ({
                    value: acl.id,
                    label: acl.name,
                    description: `${acl.usersCount} identities · ${acl.rulesCount} network rules`,
                  }))}
                  values={selectedAclIds}
                  onChange={setSelectedAclIds}
                  placeholder="None"
                  noResultsText="No matching access lists"
                />
                <p className="text-[10px] leading-relaxed text-slate-500">Assign this identity to one or more access policies without copying usernames or passwords.</p>
              </div>

              {/* Role & Visibility Scope */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-slate-100 dark:border-zinc-800 pt-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">System Role Profile</label>
                  <select
                    value={role}
                    onChange={(e) => applyRolePreset(e.target.value as UserRole)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100"
                  >
                    <option value="Administrator">Administrator (Full Access)</option>
                    <option value="Operator">Operator (Scoped Actions)</option>
                    <option value="Viewer">Viewer (Read-Only Diagnostics)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Visibility Bound</label>
                  <select
                    value={visibility}
                    disabled={role === 'Administrator'}
                    onChange={(e) => setVisibility(e.target.value as any)}
                    className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100 disabled:opacity-50"
                  >
                    <option value="all">View All Database Resources</option>
                    <option value="owned">View Only Owned/Authored Resources</option>
                  </select>
                </div>
              </div>

              {/* Permissions Blueprint matrix */}
              <div className="space-y-3 border-t border-slate-100 dark:border-zinc-800 pt-4">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Fine-Grained Permissions Blueprint</span>

                <div className="overflow-x-auto rounded-xl border border-slate-200 bg-slate-50 dark:border-zinc-800 dark:bg-zinc-950">
                  <table className="w-full min-w-[560px] text-xs">
                    <thead className="border-b border-slate-200 bg-slate-100/70 text-[10px] uppercase tracking-wider text-slate-500 dark:border-zinc-800 dark:bg-zinc-900">
                      <tr><th className="px-3 py-2 text-left">Capability</th>{PERMISSION_ACTIONS.map(action => <th key={action} className="px-3 py-2 text-center">{action}</th>)}</tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-zinc-800">
                      {PERMISSION_RESOURCES.map(resource => <tr key={resource.id}>
                        <th scope="row" className="px-3 py-2.5 text-left font-bold text-slate-800 dark:text-zinc-200">{resource.label}</th>
                        {PERMISSION_ACTIONS.map(action => {
                          const forced = role === 'Administrator' || (role === 'Viewer' && action !== 'read');
                          const checked = role === 'Administrator' ? true : role === 'Viewer' && action !== 'read' ? false : permissionMatrix[resource.id][action];
                          return <td key={action} className="px-3 py-2.5 text-center"><input type="checkbox" checked={checked} disabled={forced} onChange={event => setPermission(resource.id, action, event.target.checked)} aria-label={`${resource.label}: allow ${action}`} className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:opacity-50" /></td>;
                        })}
                      </tr>)}
                    </tbody>
                  </table>
                </div>
                <p className="text-[10px] leading-relaxed text-slate-500">Create, read, update, and delete are enforced independently by the API. Visibility still limits which records a non-administrator may read or mutate.</p>
              </div>

              {/* Status Toggle */}
              <div className="flex items-start gap-2.5 border-t border-slate-100 dark:border-zinc-800 pt-4 text-xs">
                <input
                  type="checkbox"
                  id="status"
                  checked={status === 'Active'}
                  disabled={editingId === currentUser.id}
                  onChange={(e) => setStatus(e.target.checked ? 'Active' : 'Disabled')}
                  className="rounded border-slate-300 dark:border-zinc-800 focus:ring-indigo-500 mt-0.5"
                />
                <div>
                  <label htmlFor="status" className="font-bold text-slate-800 dark:text-zinc-200 block">Account Status Active</label>
                  <span className="text-slate-400">Disabled accounts are locked out of Portwyrm immediately.</span>
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
                Save Identity
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
