import React, { useEffect, useId, useState } from 'react';
import { CheckCircle2, KeyRound, Loader2, UserRound, X } from 'lucide-react';
import type { User } from '../types';

interface AccountSettingsModalProps {
  open: boolean;
  currentUser: User;
  onClose: () => void;
  onSave: (data: {displayName: string; username: string; email: string; currentPassword: string; password: string}) => Promise<void>;
}

export default function AccountSettingsModal({open, currentUser, onClose, onSave}: AccountSettingsModalProps) {
  const titleId = useId();
  const [displayName, setDisplayName] = useState(currentUser.displayName);
  const [username, setUsername] = useState(currentUser.username);
  const [email, setEmail] = useState(currentUser.email);
  const [currentPassword, setCurrentPassword] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!open) return;
    setDisplayName(currentUser.displayName);
    setUsername(currentUser.username);
    setEmail(currentUser.email);
    setCurrentPassword('');
    setPassword('');
    setConfirmPassword('');
    setError('');
    setSaved(false);
  }, [open, currentUser]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busy) onClose(); };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, busy, onClose]);

  if (!open) return null;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }
    if (password && !currentPassword) {
      setError('Enter your current password to set a new password.');
      return;
    }
    setBusy(true); setError(''); setSaved(false);
    try {
      await onSave({displayName, username, email, currentPassword, password});
      setCurrentPassword(''); setPassword(''); setConfirmPassword(''); setSaved(true);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to update account');
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center overflow-y-auto bg-black/60 p-4" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby={titleId} className="w-full max-w-xl overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-zinc-900">
        <header className="flex items-start justify-between gap-4 border-b border-slate-100 bg-slate-50 px-6 py-4 dark:border-zinc-800 dark:bg-zinc-900/50">
          <div><div className="mb-1 flex items-center gap-2 text-indigo-600 dark:text-indigo-400"><UserRound className="h-4 w-4" /><span className="text-[10px] font-extrabold uppercase tracking-[0.18em]">Personal settings</span></div><h2 id={titleId} className="text-lg font-extrabold">My account</h2><p className="mt-1 text-xs text-slate-500">Manage your identity and sign-in credentials.</p></div>
          <button type="button" onClick={onClose} disabled={busy} aria-label="Close account settings" className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-200 dark:hover:bg-zinc-800"><X className="h-5 w-5" /></button>
        </header>
        <form onSubmit={submit} aria-busy={busy} className="space-y-5 p-6">
          {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 p-3 text-xs font-bold text-red-700">{error}</p>}
          {saved && <p role="status" className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs font-bold text-emerald-700"><CheckCircle2 className="h-4 w-4" />Account updated</p>}
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="text-xs font-bold">Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" required /></label>
            <label className="text-xs font-bold">Username<input value={username} onChange={event => setUsername(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" required /></label>
          </div>
          <label className="block text-xs font-bold">Email<input type="email" value={email} onChange={event => setEmail(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" required /></label>
          <fieldset className="space-y-4 rounded-xl border border-slate-200 p-4 dark:border-zinc-800">
            <legend className="px-2 text-xs font-extrabold"><span className="flex items-center gap-2"><KeyRound className="h-4 w-4 text-indigo-500" />Change password</span></legend>
            <p className="text-xs text-slate-500">Leave all three fields blank to keep your current password.</p>
            <div className="grid gap-4 sm:grid-cols-3">
              <label className="text-xs font-bold">Current password<input type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} required={Boolean(password)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" /></label>
              <label className="text-xs font-bold">New password<input type="password" autoComplete="new-password" minLength={8} value={password} onChange={event => setPassword(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" /></label>
              <label className="text-xs font-bold">Confirm new password<input type="password" autoComplete="new-password" minLength={8} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} required={Boolean(password)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white p-2.5 dark:border-zinc-700 dark:bg-zinc-950" /></label>
            </div>
          </fieldset>
          <div className="flex justify-end gap-2 border-t border-slate-100 pt-4 dark:border-zinc-800"><button type="button" onClick={onClose} disabled={busy} className="rounded-xl bg-slate-200 px-4 py-2.5 text-xs font-bold text-slate-700">Cancel</button><button disabled={busy} className="flex min-w-32 items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-60">{busy && <Loader2 className="h-4 w-4 animate-spin" />}{busy ? 'Saving…' : 'Save account'}</button></div>
        </form>
      </section>
    </div>
  );
}
