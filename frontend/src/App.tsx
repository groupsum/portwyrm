import React, { useEffect, useState } from 'react';
import { Globe, LoaderCircle } from 'lucide-react';
import { portwyrmStore } from './store';
import type { Host } from './types';
import Layout from './components/Layout';
import OverviewView from './components/OverviewView';
import HostsView from './components/HostsView';
import AccessListsView from './components/AccessListsView';
import UsersView from './components/UsersView';
import AuditView from './components/AuditView';
import SettingsView from './components/SettingsView';
import HostDialog from './components/HostDialog';
import { useFeedback } from './components/Feedback';

function AuthScreen() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [needsMfa, setNeedsMfa] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError('');
    try {
      if (needsMfa) await portwyrmStore.completeMfa(mfaCode);
      else setNeedsMfa((await portwyrmStore.login(email, password)) === 'mfa');
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Authentication failed'); }
    finally { setBusy(false); }
  };

  return (
    <main className="min-h-screen bg-slate-50 dark:bg-zinc-950 grid place-items-center p-4 text-slate-900 dark:text-zinc-100">
      <form onSubmit={submit} aria-busy={busy} className="w-full max-w-md bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl shadow-xl p-7 space-y-5">
        <div className="flex items-center gap-3"><div className="p-2.5 rounded-xl bg-slate-900 dark:bg-zinc-100 text-white dark:text-zinc-900"><Globe className="h-6 w-6" /></div><div><h1 className="font-extrabold text-xl">Portwyrm</h1><p className="text-xs text-slate-500 dark:text-zinc-400">Reverse Proxy Plane</p></div></div>
        <div><h2 className="font-extrabold text-2xl">{portwyrmStore.setupRequired ? 'Create administrator' : needsMfa ? 'Verify sign in' : 'Welcome back'}</h2><p className="text-sm text-slate-500 mt-1">{portwyrmStore.setupRequired ? 'Create the first Portwyrm administrator.' : needsMfa ? 'Enter your authenticator or recovery code.' : 'Sign in to manage this self-hosted Portwyrm.'}</p></div>
        {!needsMfa && <><label className="block text-xs font-bold">Email<input className="mt-1.5 w-full p-3 rounded-xl border border-slate-200 dark:border-zinc-700 bg-white dark:bg-zinc-950" type="email" autoComplete="username" required value={email} onChange={event => setEmail(event.target.value)} /></label><label className="block text-xs font-bold">Password<input className="mt-1.5 w-full p-3 rounded-xl border border-slate-200 dark:border-zinc-700 bg-white dark:bg-zinc-950" type="password" minLength={8} autoComplete={portwyrmStore.setupRequired ? 'new-password' : 'current-password'} required value={password} onChange={event => setPassword(event.target.value)} /></label></>}
        {needsMfa && <label className="block text-xs font-bold">Authentication code<input className="mt-1.5 w-full p-3 rounded-xl border border-slate-200 dark:border-zinc-700 bg-white dark:bg-zinc-950" inputMode="numeric" autoComplete="one-time-code" required value={mfaCode} onChange={event => setMfaCode(event.target.value)} /></label>}
        {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
        <button disabled={busy} className="w-full py-3 rounded-xl bg-slate-900 dark:bg-zinc-100 text-white dark:text-zinc-900 font-bold flex justify-center gap-2">{busy && <LoaderCircle className="h-5 w-5 animate-spin" />}{busy ? 'Working…' : portwyrmStore.setupRequired ? 'Create administrator' : needsMfa ? 'Verify' : 'Sign in'}</button>
      </form>
    </main>
  );
}

export default function App() {
  const feedback = useFeedback();
  const [, setTick] = useState(0);
  const [isCreateHostOpen, setIsCreateHostOpen] = useState(false);
  const [editingHost, setEditingHost] = useState<Host | null>(null);
  const [currentTab, setCurrentTab] = useState('overview');

  useEffect(() => portwyrmStore.subscribe(() => setTick(value => value + 1)), []);
  useEffect(() => { void portwyrmStore.initialize(); }, []);
  useEffect(() => {
    const parseHash = () => {
      const route = window.location.hash.replace('#', '').split('?')[0] || 'overview';
      if (['overview', 'hosts', 'certificates', 'access-lists', 'users', 'audit', 'settings'].includes(route)) setCurrentTab(route);
    };
    parseHash(); window.addEventListener('hashchange', parseHash); return () => window.removeEventListener('hashchange', parseHash);
  }, []);

  if (portwyrmStore.loading) return <div className="min-h-screen grid place-items-center bg-slate-50 dark:bg-zinc-950"><LoaderCircle className="h-8 w-8 animate-spin text-indigo-600" aria-label="Loading Portwyrm" /></div>;
  if (!portwyrmStore.authenticated) return <AuthScreen />;

  const currentUser = portwyrmStore.getCurrentUser();
  const navigate = (tab: string) => { window.location.hash = tab; };
  const openCreate = () => { setEditingHost(null); setIsCreateHostOpen(true); };
  const openEdit = (host: Host) => { setEditingHost(host); setIsCreateHostOpen(true); };
  const deleteHost = (id: string) => { const host = portwyrmStore.hosts.find(item => item.id === id); if (!host) return; void feedback.confirm({title: 'Delete routing host?', description: `Permanently delete ${host.source}? This removes its active Nginx configuration.`, confirmLabel: 'Delete host', destructive: true}).then(accepted => { if (accepted) void portwyrmStore.deleteHost(id); }); };
  const renew = (id: string, progress: (message: string, done: boolean, error?: string) => void) => { void portwyrmStore.renewCertificate(id, progress); };

  const hosts = <HostsView hosts={portwyrmStore.hosts} certificates={portwyrmStore.certificates} accessLists={portwyrmStore.accessLists} currentUser={currentUser} onAddHost={openCreate} onEditHost={openEdit} onDeleteHost={deleteHost} onToggleHostStatus={id => void portwyrmStore.toggleHostStatus(id)} defaultSubTab={currentTab === 'certificates' ? 'certificates' : 'hosts'} onAddCert={data => void portwyrmStore.addCertificate(data)} onRequestLetsEncrypt={(name, domains, challenge, progress) => void portwyrmStore.requestLetsEncrypt(name, domains, challenge, progress)} onRenewCert={renew} onDeleteCert={id => portwyrmStore.deleteCertificate(id)} onDuplicateHost={host => { setEditingHost({...host, id: '', source: `copy-${host.source}`}); setIsCreateHostOpen(true); }} />;

  return (
    <Layout currentTab={currentTab} onTabChange={navigate} onSignOut={() => void portwyrmStore.signOut()} storeState={{health: portwyrmStore.health, currentUser, allUsers: portwyrmStore.users}}>
      {currentTab === 'overview' && <OverviewView hosts={portwyrmStore.hosts} certificates={portwyrmStore.certificates} auditLogs={portwyrmStore.auditLogs} health={portwyrmStore.health} onNavigate={(tab, filter) => navigate(tab === 'hosts' && filter === 'certificates' ? 'certificates' : tab)} onOpenCreateHost={openCreate} onRenewCert={id => renew(id, (message, done, error) => { if (done) feedback.toast(error || message, error ? 'error' : 'success'); })} onReconcileDrift={() => void portwyrmStore.refresh()} />}
      {(currentTab === 'hosts' || currentTab === 'certificates') && hosts}
      {currentTab === 'access-lists' && <AccessListsView accessLists={portwyrmStore.accessLists} hosts={portwyrmStore.hosts} users={portwyrmStore.users} currentUser={currentUser} onAddAccessList={data => void portwyrmStore.addAccessList(data)} onUpdateAccessList={(id, data) => void portwyrmStore.updateAccessList(id, data)} onDeleteAccessList={id => portwyrmStore.deleteAccessList(id)} />}
      {currentTab === 'users' && <UsersView users={portwyrmStore.users} accessLists={portwyrmStore.accessLists} currentUser={currentUser} onAddUser={(data, aclIds) => void portwyrmStore.addUser(data, aclIds)} onUpdateUser={(id, data) => void portwyrmStore.updateUser(id, data)} onDeleteUser={id => portwyrmStore.deleteUser(id)} />}
      {currentTab === 'audit' && <AuditView auditLogs={portwyrmStore.auditLogs} currentUser={currentUser} />}
      {currentTab === 'settings' && <SettingsView currentUser={currentUser} users={portwyrmStore.users} health={portwyrmStore.health} onPreviewImport={(bundle, replace) => portwyrmStore.previewPortableImport(bundle, replace)} onApplyImport={(bundle, replace) => portwyrmStore.applyPortableImport(bundle, replace)} />}
      <HostDialog isOpen={isCreateHostOpen} onClose={() => {setIsCreateHostOpen(false); setEditingHost(null);}} onSubmit={(data, progress) => editingHost?.id ? void portwyrmStore.updateHost(editingHost.id, data, progress) : void portwyrmStore.addHost(data, progress)} certificates={portwyrmStore.certificates} accessLists={portwyrmStore.accessLists} editingHost={editingHost} onDeleteHost={deleteHost} />
    </Layout>
  );
}
