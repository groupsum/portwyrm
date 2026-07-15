import React, { useRef, useState } from 'react';
import { AlertTriangle, ArchiveRestore, CheckCircle2, Cpu, Database, Download, HardDrive, Loader2, ShieldCheck, Upload } from 'lucide-react';
import type { SystemHealth, User } from '../types';

type SettingsTab = 'mfa' | 'runtime' | 'portability';
type Json = Record<string, any>;

interface SettingsViewProps {
  currentUser: User;
  users: User[];
  health: SystemHealth;
  onPreviewImport: (bundle: Json, replace: boolean) => Promise<Json>;
  onApplyImport: (bundle: Json, replace: boolean) => Promise<Json>;
}

const tabs = [
  {id: 'mfa' as const, label: 'MFA', description: 'Enrollment and authentication posture', icon: ShieldCheck},
  {id: 'runtime' as const, label: 'Runtime & persistence', description: 'Proxy runtime and state backend', icon: Database},
  {id: 'portability' as const, label: 'Portability', description: 'Backup, preview, and import', icon: ArchiveRestore},
];

export default function SettingsView({currentUser, users, health, onPreviewImport, onApplyImport}: SettingsViewProps) {
  const [activeTab, setActiveTab] = useState<SettingsTab>('mfa');
  const [bundle, setBundle] = useState<Json | null>(null);
  const [fileName, setFileName] = useState('');
  const [replace, setReplace] = useState(false);
  const [preview, setPreview] = useState<Json | null>(null);
  const [busy, setBusy] = useState<'preview' | 'import' | null>(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Json | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const readBundle = async (file?: File) => {
    if (!file) return;
    setError(''); setPreview(null); setResult(null);
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Backup must contain a JSON object.');
      setBundle(parsed); setFileName(file.name);
    } catch (reason) {
      setBundle(null); setFileName('');
      setError(reason instanceof Error ? reason.message : 'Unable to read backup');
    }
  };

  const previewBundle = async () => {
    if (!bundle) return;
    setBusy('preview'); setError(''); setResult(null);
    try { setPreview(await onPreviewImport(bundle, replace)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to preview import'); }
    finally { setBusy(null); }
  };

  const importBundle = async () => {
    if (!bundle || !preview) return;
    setBusy('import'); setError('');
    try { setResult(await onApplyImport(bundle, replace)); setPreview(null); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to import backup'); }
    finally { setBusy(null); }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <header className="border-b border-slate-200 pb-5 dark:border-zinc-800">
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">Global settings</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-zinc-400">System-wide security, runtime, persistence, and portability controls for this Portwyrm.</p>
      </header>

      <div className="overflow-x-auto border-b border-slate-200 dark:border-zinc-800">
        <div role="tablist" aria-label="Global settings sections" className="flex min-w-max gap-1">
          {tabs.map(tab => { const Icon = tab.icon; const selected = activeTab === tab.id; return <button key={tab.id} id={`settings-tab-${tab.id}`} role="tab" aria-selected={selected} aria-controls={`settings-panel-${tab.id}`} onClick={() => setActiveTab(tab.id)} className={`flex min-w-48 items-center gap-3 border-b-2 px-4 py-3 text-left transition-colors ${selected ? 'border-indigo-600 text-indigo-700 dark:text-indigo-400' : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800 dark:hover:text-zinc-200'}`}><Icon className="h-5 w-5 shrink-0" /><span><strong className="block text-xs">{tab.label}</strong><small className="text-[10px] opacity-75">{tab.description}</small></span></button>; })}
        </div>
      </div>

      {activeTab === 'mfa' && <section id="settings-panel-mfa" role="tabpanel" aria-labelledby="settings-tab-mfa" className="space-y-5">
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-3xs dark:border-zinc-800 dark:bg-zinc-900">
            <div className="border-b border-slate-100 px-5 py-4 dark:border-zinc-800"><h3 className="flex items-center gap-2 text-sm font-extrabold"><ShieldCheck className="h-5 w-5 text-indigo-500" />Operator enrollment</h3><p className="mt-1 text-xs text-slate-500">Review MFA coverage across operator identities. Enrollment secrets remain personal to each operator.</p></div>
            <div className="divide-y divide-slate-100 dark:divide-zinc-800">{users.map(user => <div key={user.id} className="flex items-center justify-between gap-4 px-5 py-3"><span className="min-w-0"><strong className="block truncate text-xs">{user.displayName}</strong><small className="text-[10px] text-slate-500">{user.username} · {user.role}</small></span><span className={`shrink-0 rounded-full px-2.5 py-1 text-[10px] font-extrabold ${user.mfa ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400' : 'bg-slate-100 text-slate-500 dark:bg-zinc-800 dark:text-zinc-400'}`}>{user.mfa ? 'Enrolled' : 'Not enrolled'}</span></div>)}</div>
          </div>
          <aside className="space-y-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-3xs dark:border-zinc-800 dark:bg-zinc-900"><h3 className="text-sm font-extrabold">Responsibility boundary</h3><p className="text-xs leading-relaxed text-slate-500">This global tab reports system-wide enrollment posture. Personal authenticator enrollment, recovery codes, and credential changes belong to each operator’s account experience.</p><div className="rounded-xl bg-indigo-50 p-3 text-xs font-semibold text-indigo-700 dark:bg-indigo-950/20 dark:text-indigo-300">Signed in as {currentUser.displayName}, {currentUser.role}</div></aside>
        </div>
      </section>}

      {activeTab === 'runtime' && <section id="settings-panel-runtime" role="tabpanel" aria-labelledby="settings-tab-runtime" className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-3xs dark:border-zinc-800 dark:bg-zinc-900"><h3 className="mb-4 flex items-center gap-2 text-sm font-extrabold"><Cpu className="h-5 w-5 text-indigo-500" />Proxy runtime</h3><dl className="space-y-3 text-xs"><div className="flex justify-between rounded-xl bg-slate-50 p-3 dark:bg-zinc-950"><dt className="text-slate-500">Nginx engine</dt><dd className="font-bold">{health.nginxState}</dd></div><div className="flex justify-between rounded-xl bg-slate-50 p-3 dark:bg-zinc-950"><dt className="text-slate-500">Applied generation</dt><dd className="font-mono font-bold">#{health.currentGeneration}</dd></div><div className="flex justify-between rounded-xl bg-slate-50 p-3 dark:bg-zinc-950"><dt className="text-slate-500">Certificate scheduler</dt><dd className="font-bold text-emerald-600">{health.schedulerState}</dd></div></dl></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-3xs dark:border-zinc-800 dark:bg-zinc-900"><h3 className="mb-4 flex items-center gap-2 text-sm font-extrabold"><Database className="h-5 w-5 text-indigo-500" />Persistence</h3><div className="flex items-center justify-between rounded-xl bg-slate-50 p-4 text-xs dark:bg-zinc-950"><span className="text-slate-500">Active backend</span><strong className="font-mono uppercase">{health.databaseBackend}</strong></div><p className="mt-4 text-xs leading-relaxed text-slate-500">Persistence selection is deployment-owned. Change the container’s Portwyrm database configuration and restart the service to migrate between supported backends.</p></div>
      </section>}

      {activeTab === 'portability' && <section id="settings-panel-portability" role="tabpanel" aria-labelledby="settings-tab-portability" className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-3xs dark:border-zinc-800 dark:bg-zinc-900"><h3 className="flex items-center gap-2 text-sm font-extrabold"><HardDrive className="h-5 w-5 text-indigo-500" />Export backup</h3><p className="my-4 text-xs leading-relaxed text-slate-500">Download the current configuration as a versioned portable JSON bundle suitable for another Portwyrm instance.</p><a href="/api/v2/export" download className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 py-2.5 text-xs font-bold text-white hover:bg-indigo-700"><Download className="h-4 w-4" />Download portable backup</a></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-3xs dark:border-zinc-800 dark:bg-zinc-900"><h3 className="flex items-center gap-2 text-sm font-extrabold"><Upload className="h-5 w-5 text-indigo-500" />Import backup</h3><p className="my-4 text-xs leading-relaxed text-slate-500">Select a portable bundle, preview its impact, then explicitly apply it.</p><input ref={fileInput} type="file" accept="application/json,.json" onChange={event => void readBundle(event.target.files?.[0])} className="sr-only" /><button type="button" onClick={() => fileInput.current?.click()} className="w-full rounded-xl border border-dashed border-slate-300 p-4 text-xs font-bold text-slate-600 hover:bg-slate-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">{fileName || 'Choose portable JSON bundle'}</button><label className="mt-4 flex items-start gap-2 text-xs"><input type="checkbox" checked={replace} onChange={event => {setReplace(event.target.checked); setPreview(null);}} className="mt-0.5" /><span><strong className="block">Replace conflicting records</strong><small className="text-slate-500">When off, existing records remain unchanged.</small></span></label>
          {error && <p role="alert" className="mt-4 flex gap-2 rounded-xl bg-red-50 p-3 text-xs font-bold text-red-700"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</p>}
          {preview && <div role="status" className="mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-xs dark:border-indigo-900 dark:bg-indigo-950/20"><strong className="block text-indigo-700 dark:text-indigo-300">Preview ready</strong><div className="mt-2 grid grid-cols-3 gap-2 text-center"><span>Created<br/><b>{preview.created ?? 0}</b></span><span>Replaced<br/><b>{preview.replaced ?? 0}</b></span><span>Unchanged<br/><b>{preview.unchanged ?? 0}</b></span></div></div>}
          {result && <p role="status" className="mt-4 flex gap-2 rounded-xl bg-emerald-50 p-3 text-xs font-bold text-emerald-700"><CheckCircle2 className="h-4 w-4" />Import completed: {result.created ?? 0} created, {result.replaced ?? 0} replaced.</p>}
          <div className="mt-4 flex gap-2"><button type="button" disabled={!bundle || Boolean(busy)} onClick={() => void previewBundle()} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-200 py-2.5 text-xs font-bold text-slate-700 disabled:opacity-50">{busy === 'preview' && <Loader2 className="h-4 w-4 animate-spin" />}Preview import</button><button type="button" disabled={!preview || Boolean(busy)} onClick={() => void importBundle()} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-indigo-600 py-2.5 text-xs font-bold text-white disabled:opacity-50">{busy === 'import' && <Loader2 className="h-4 w-4 animate-spin" />}Apply import</button></div>
        </div>
      </section>}
    </div>
  );
}
