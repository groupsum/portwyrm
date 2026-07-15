import React, { useEffect, useId, useMemo, useState } from 'react';
import { Check, Clipboard, Clock3, KeyRound, Loader2, MoreVertical, Plus, RotateCw, Search, ShieldCheck, Trash2, X } from 'lucide-react';
import type { AccessToken, CreatedAccessToken, PermissionAction, PermissionResource, User } from '../types';
import ActionModal from './ActionModal';
import { useFeedback } from './Feedback';

const RESOURCES: {id: PermissionResource; label: string}[] = [
  {id: 'proxy_hosts', label: 'Proxy hosts'}, {id: 'redirection_hosts', label: 'Redirects'},
  {id: 'dead_hosts', label: 'Dead hosts'}, {id: 'streams', label: 'Streams'},
  {id: 'access_lists', label: 'Access lists'}, {id: 'certificates', label: 'Certificates'},
];
const ACTIONS: PermissionAction[] = ['create', 'read', 'update', 'delete'];

interface Props {
  open: boolean;
  currentUser: User;
  onClose: () => void;
  onList: () => Promise<AccessToken[]>;
  onCreate: (data: {name: string; scopes: string[]; expiresAt: number | null}) => Promise<CreatedAccessToken>;
  onRotate: (id: string) => Promise<CreatedAccessToken>;
  onRevoke: (id: string) => Promise<void>;
}

function timeLabel(epoch: number | null): string {
  if (!epoch) return 'Never';
  return new Intl.DateTimeFormat(undefined, {month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit'}).format(new Date(epoch * 1000));
}

function tokenStatus(token: AccessToken): 'Active' | 'Expired' | 'Revoked' {
  if (token.revokedAt) return 'Revoked';
  if (token.expiresAt && token.expiresAt <= Date.now() / 1000) return 'Expired';
  return 'Active';
}

export default function AccessTokensModal({open, currentUser, onClose, onList, onCreate, onRotate, onRevoke}: Props) {
  const titleId = useId();
  const feedback = useFeedback();
  const [tokens, setTokens] = useState<AccessToken[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<CreatedAccessToken | null>(null);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState('90');
  const [accessMode, setAccessMode] = useState<'full' | 'read' | 'custom'>('read');
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const [actionTokenId, setActionTokenId] = useState<string | null>(null);

  const reload = async () => {
    setLoading(true); setError('');
    try { setTokens((await onList()).sort((a, b) => b.createdAt - a.createdAt)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load access tokens'); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    if (open) void reload();
    else {
      setSecret(null);
      setCreating(false);
      setName('');
      setSelectedScopes([]);
      setError('');
    }
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busy) onClose(); };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, busy, onClose]);

  const permittedScopes = useMemo(() => RESOURCES.flatMap(resource => ACTIONS
    .filter(action => currentUser.role === 'Administrator' || currentUser.permissions[resource.id][action])
    .map(action => `${resource.id}:${action}`)), [currentUser]);
  const readScopes = permittedScopes.filter(scope => scope.endsWith(':read'));
  const filtered = tokens.filter(token => `${token.name} ${token.scopes.join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  const actionToken = tokens.find(token => token.id === actionTokenId) || null;

  if (!open) return null;

  const resetCreate = () => { setCreating(false); setName(''); setExpiry('90'); setAccessMode('read'); setSelectedScopes([]); };
  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    const scopes = accessMode === 'full' ? ['user'] : accessMode === 'read' ? readScopes : selectedScopes;
    if (!scopes.length) { setError('Select at least one permission for this token.'); return; }
    const days = Number(expiry);
    const expiresAt = expiry === 'never' ? null : Math.floor(Date.now() / 1000) + days * 86_400;
    setBusy(true); setError('');
    try { const created = await onCreate({name, scopes, expiresAt}); setSecret(created); resetCreate(); await reload(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to create access token'); }
    finally { setBusy(false); }
  };
  const copySecret = async () => { if (!secret) return; await navigator.clipboard.writeText(secret.token); feedback.toast('Access token copied', 'success'); };
  const rotate = async (token: AccessToken) => {
    setActionTokenId(null);
    const accepted = await feedback.confirm({title: 'Rotate access token?', description: `This immediately revokes “${token.name}”. Apps using it will stop working until you replace the token.`, confirmLabel: 'Rotate token'});
    if (!accepted) return;
    setBusy(true);
    try { const replacement = await onRotate(token.id); setSecret(replacement); await reload(); feedback.toast('Access token rotated', 'success'); }
    catch (reason) { feedback.toast(reason instanceof Error ? reason.message : 'Unable to rotate token', 'error'); }
    finally { setBusy(false); }
  };
  const revoke = async (token: AccessToken) => {
    setActionTokenId(null);
    const accepted = await feedback.confirm({title: 'Revoke access token?', description: `“${token.name}” will stop authenticating immediately. This cannot be undone.`, confirmLabel: 'Revoke token', destructive: true});
    if (!accepted) return;
    setBusy(true);
    try { await onRevoke(token.id); await reload(); feedback.toast('Access token revoked', 'success'); }
    catch (reason) { feedback.toast(reason instanceof Error ? reason.message : 'Unable to revoke token', 'error'); }
    finally { setBusy(false); }
  };

  return <div className="fixed inset-0 z-[80] flex items-center justify-center overflow-y-auto bg-slate-950/65 p-4" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <section role="dialog" aria-modal="true" aria-labelledby={titleId} className="flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-zinc-900">
      <header className="flex items-start justify-between gap-4 border-b border-slate-100 bg-slate-50 px-6 py-4 dark:border-zinc-800 dark:bg-zinc-900/50">
        <div><div className="mb-1 flex items-center gap-2 text-indigo-600 dark:text-indigo-400"><KeyRound className="h-4 w-4" /><span className="text-[10px] font-extrabold uppercase tracking-[0.18em]">Personal security</span></div><h2 id={titleId} className="text-lg font-extrabold">Access tokens</h2><p className="mt-1 text-xs text-slate-500">Create scoped credentials for npmctl, automation, and API clients.</p></div>
        <button type="button" onClick={onClose} disabled={busy} aria-label="Close access tokens" className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-200 dark:hover:bg-zinc-800"><X className="h-5 w-5" /></button>
      </header>
      <div className="flex-1 overflow-y-auto p-6">
        {error && <p role="alert" className="mb-4 rounded-xl border border-red-200 bg-red-50 p-3 text-xs font-bold text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300">{error}</p>}
        {secret && <section className="mb-5 rounded-2xl border border-amber-200 bg-amber-50 p-5 dark:border-amber-900 dark:bg-amber-950/20" aria-label="New access token">
          <div className="flex items-start gap-3"><ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" /><div className="min-w-0 flex-1"><h3 className="font-extrabold text-amber-950 dark:text-amber-200">Copy this token now</h3><p className="mt-1 text-xs leading-relaxed text-amber-800 dark:text-amber-300">Portwyrm stores only its secure hash. This value will not be shown again.</p><div className="mt-3 flex gap-2"><code className="min-w-0 flex-1 overflow-x-auto rounded-xl border border-amber-200 bg-white px-3 py-2.5 font-mono text-xs text-slate-800 dark:border-amber-900 dark:bg-zinc-950 dark:text-zinc-100">{secret.token}</code><button type="button" onClick={() => void copySecret()} className="flex shrink-0 items-center gap-2 rounded-xl bg-amber-600 px-4 py-2 text-xs font-bold text-white hover:bg-amber-700"><Clipboard className="h-4 w-4" />Copy</button></div></div><button type="button" onClick={() => setSecret(null)} aria-label="Dismiss token value" className="text-amber-700"><X className="h-4 w-4" /></button></div>
        </section>}

        {creating ? <form onSubmit={create} className="mb-6 space-y-5 rounded-2xl border border-indigo-200 bg-indigo-50/40 p-5 dark:border-indigo-950 dark:bg-indigo-950/10">
          <div className="flex items-center justify-between"><div><h3 className="font-extrabold">Create access token</h3><p className="mt-1 text-xs text-slate-500">Use the least access your client needs.</p></div><button type="button" onClick={resetCreate} disabled={busy} className="rounded-lg p-1.5 text-slate-400 hover:bg-white dark:hover:bg-zinc-800"><X className="h-4 w-4" /></button></div>
          <div className="grid gap-4 sm:grid-cols-2"><label className="text-xs font-bold">Token name<input autoFocus value={name} onChange={event => setName(event.target.value)} maxLength={100} placeholder="e.g. Production npmctl" required className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" /></label><label className="text-xs font-bold">Expires<select value={expiry} onChange={event => setExpiry(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950"><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option><option value="never">Never</option></select></label></div>
          <fieldset><legend className="text-xs font-extrabold">Access</legend><div className="mt-2 grid gap-2 sm:grid-cols-3">{([{id: 'read', label: 'Read only', copy: 'View permitted resources'}, {id: 'full', label: 'Full account', copy: 'Inherit all account access'}, {id: 'custom', label: 'Custom', copy: 'Choose each action'}] as const).map(option => <label key={option.id} className={`cursor-pointer rounded-xl border p-3 ${accessMode === option.id ? 'border-indigo-500 bg-white ring-2 ring-indigo-100 dark:bg-zinc-950 dark:ring-indigo-950' : 'border-slate-200 bg-white/60 dark:border-zinc-800 dark:bg-zinc-900'}`}><input type="radio" name="token-access" value={option.id} checked={accessMode === option.id} onChange={() => setAccessMode(option.id)} className="sr-only" /><span className="flex items-center gap-2 text-xs font-extrabold">{accessMode === option.id && <Check className="h-3.5 w-3.5 text-indigo-600" />}{option.label}</span><span className="mt-1 block text-[10px] text-slate-500">{option.copy}</span></label>)}</div></fieldset>
          {accessMode === 'custom' && <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-zinc-800 dark:bg-zinc-950"><table className="w-full min-w-[560px] text-xs"><thead className="border-b border-slate-200 bg-slate-50 text-[10px] uppercase tracking-wider text-slate-500 dark:border-zinc-800 dark:bg-zinc-900"><tr><th className="px-3 py-2 text-left">Resource</th>{ACTIONS.map(action => <th key={action} className="px-3 py-2 text-center">{action}</th>)}</tr></thead><tbody className="divide-y divide-slate-100 dark:divide-zinc-800">{RESOURCES.map(resource => <tr key={resource.id}><th className="px-3 py-2 text-left">{resource.label}</th>{ACTIONS.map(action => { const scope = `${resource.id}:${action}`; const allowed = permittedScopes.includes(scope); return <td key={action} className="px-3 py-2 text-center"><input type="checkbox" disabled={!allowed} checked={selectedScopes.includes(scope)} onChange={event => setSelectedScopes(current => event.target.checked ? [...current, scope] : current.filter(item => item !== scope))} aria-label={`${resource.label}: ${action}`} className="h-4 w-4 rounded border-slate-300 text-indigo-600 disabled:opacity-30" /></td>; })}</tr>)}</tbody></table></div>}
          <div className="flex justify-end gap-2"><button type="button" onClick={resetCreate} disabled={busy} className="rounded-xl bg-slate-200 px-4 py-2.5 text-xs font-bold text-slate-700 dark:bg-zinc-800 dark:text-zinc-200">Cancel</button><button disabled={busy} className="flex min-w-36 items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-60">{busy && <Loader2 className="h-4 w-4 animate-spin" />}{busy ? 'Creating…' : 'Create token'}</button></div>
        </form> : <div className="mb-4 flex flex-col justify-between gap-3 sm:flex-row"><div className="relative flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" /><input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search token names or scopes" className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-xs font-semibold dark:border-zinc-800 dark:bg-zinc-950" /></div><button type="button" onClick={() => setCreating(true)} className="flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700"><Plus className="h-4 w-4" />Create token</button></div>}

        <div className="overflow-hidden rounded-2xl border border-slate-200 dark:border-zinc-800">
          {loading ? <div className="grid min-h-40 place-items-center"><Loader2 className="h-6 w-6 animate-spin text-indigo-600" /></div> : filtered.length === 0 ? <div className="px-6 py-12 text-center"><KeyRound className="mx-auto h-8 w-8 text-slate-300" /><h3 className="mt-3 text-sm font-extrabold">{search ? 'No matching tokens' : 'No access tokens yet'}</h3><p className="mt-1 text-xs text-slate-500">{search ? 'Try another search.' : 'Create a scoped token for an API client or automation.'}</p></div> : <div className="divide-y divide-slate-100 dark:divide-zinc-800">{filtered.map(token => { const status = tokenStatus(token); return <article key={token.id} className="grid gap-4 p-4 sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-center"><div className="min-w-0"><div className="flex items-center gap-2"><h3 className="truncate text-sm font-extrabold">{token.name}</h3><span className={`rounded-md px-1.5 py-0.5 text-[9px] font-extrabold uppercase ${status === 'Active' ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400' : 'bg-slate-100 text-slate-500 dark:bg-zinc-800'}`}>{status}</span></div><p className="mt-1 truncate font-mono text-[10px] text-slate-400">{token.scopes.length === 1 && token.scopes[0] === 'user' ? 'Full account access' : `${token.scopes.filter(scope => scope !== 'user').length} scoped permissions`}</p></div><div className="text-[10px] text-slate-500"><span className="block font-bold uppercase tracking-wider text-slate-400">Created</span>{timeLabel(token.createdAt)}</div><div className="text-[10px] text-slate-500"><span className="block font-bold uppercase tracking-wider text-slate-400">Last used</span>{timeLabel(token.lastUsedAt)}<span className="mt-1 block"><Clock3 className="mr-1 inline h-3 w-3" />Expires {timeLabel(token.expiresAt)}</span></div><button type="button" onClick={() => setActionTokenId(token.id)} disabled={status !== 'Active' || busy} aria-label={`Actions for ${token.name}`} className="justify-self-end rounded-lg p-2 text-slate-500 hover:bg-slate-100 disabled:opacity-30 dark:hover:bg-zinc-800"><MoreVertical className="h-4 w-4" /></button></article>; })}</div>}
        </div>
      </div>
      <footer className="flex justify-end border-t border-slate-100 bg-slate-50 px-6 py-4 dark:border-zinc-800 dark:bg-zinc-900"><button type="button" onClick={onClose} disabled={busy} className="rounded-xl bg-slate-200 px-4 py-2.5 text-xs font-bold text-slate-700 dark:bg-zinc-800 dark:text-zinc-200">Close</button></footer>
    </section>
    <ActionModal open={Boolean(actionToken)} title={actionToken ? `Token actions — ${actionToken.name}` : 'Token actions'} description="Token values cannot be recovered after creation." onClose={() => setActionTokenId(null)}>{actionToken && <><button type="button" onClick={() => void rotate(actionToken)} className="text-slate-700 hover:bg-slate-50 dark:text-zinc-300 dark:hover:bg-zinc-800"><RotateCw className="h-4 w-4" />Rotate token</button><button type="button" onClick={() => void revoke(actionToken)} className="text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20"><Trash2 className="h-4 w-4" />Revoke token</button></>}</ActionModal>
  </div>;
}
