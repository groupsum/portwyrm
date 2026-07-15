import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react';

type ToastTone = 'success' | 'error' | 'info';

interface ConfirmRequest {
  title: string;
  description: string;
  confirmLabel?: string;
  destructive?: boolean;
}

interface FeedbackApi {
  toast: (message: string, tone?: ToastTone) => void;
  confirm: (request: ConfirmRequest) => Promise<boolean>;
}

interface ToastItem { id: number; message: string; tone: ToastTone }
interface PendingConfirm extends ConfirmRequest { resolve: (accepted: boolean) => void }

const FeedbackContext = createContext<FeedbackApi | null>(null);

export function FeedbackProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  const nextId = useRef(1);

  const toast = useCallback((message: string, tone: ToastTone = 'info') => {
    const id = nextId.current++;
    setToasts(current => [...current, { id, message, tone }]);
    window.setTimeout(() => setToasts(current => current.filter(item => item.id !== id)), 4200);
  }, []);

  const confirm = useCallback((request: ConfirmRequest) => new Promise<boolean>(resolve => {
    setPending({ ...request, resolve });
  }), []);

  const settle = (accepted: boolean) => {
    pending?.resolve(accepted);
    setPending(null);
  };

  return <FeedbackContext.Provider value={{ toast, confirm }}>
    {children}
    {pending && <div className="fixed inset-0 z-[120] flex items-center justify-center bg-slate-950/60 p-4" onMouseDown={event => { if (event.target === event.currentTarget) settle(false); }}>
      <section role="alertdialog" aria-modal="true" aria-labelledby="feedback-confirm-title" aria-describedby="feedback-confirm-description" className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl dark:border-zinc-800 dark:bg-zinc-900">
        <div className="flex items-start gap-3">
          <span className={`rounded-xl p-2 ${pending.destructive ? 'bg-red-50 text-red-600 dark:bg-red-950/30' : 'bg-indigo-50 text-indigo-600 dark:bg-indigo-950/30'}`}><AlertTriangle className="h-5 w-5" /></span>
          <div className="min-w-0 flex-1"><h2 id="feedback-confirm-title" className="font-extrabold text-slate-900 dark:text-zinc-100">{pending.title}</h2><p id="feedback-confirm-description" className="mt-2 text-sm leading-relaxed text-slate-500 dark:text-zinc-400">{pending.description}</p></div>
          <button type="button" onClick={() => settle(false)} aria-label="Close confirmation" className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-zinc-800"><X className="h-4 w-4" /></button>
        </div>
        <div className="mt-6 flex justify-end gap-2"><button type="button" onClick={() => settle(false)} className="rounded-xl bg-slate-200 px-4 py-2.5 text-xs font-bold text-slate-700 dark:bg-zinc-800 dark:text-zinc-200">Cancel</button><button type="button" autoFocus onClick={() => settle(true)} className={`rounded-xl px-4 py-2.5 text-xs font-bold text-white ${pending.destructive ? 'bg-red-600 hover:bg-red-700' : 'bg-indigo-600 hover:bg-indigo-700'}`}>{pending.confirmLabel || 'Continue'}</button></div>
      </section>
    </div>}
    <div aria-live="polite" aria-atomic="false" className="pointer-events-none fixed bottom-6 right-6 z-[140] flex w-[min(24rem,calc(100vw-3rem))] flex-col gap-2">
      {toasts.map(item => {
        const Icon = item.tone === 'success' ? CheckCircle2 : item.tone === 'error' ? XCircle : Info;
        return <div key={item.id} role="status" className="pointer-events-auto flex items-start gap-2 rounded-xl border border-slate-200 bg-white p-3 text-xs font-bold text-slate-700 shadow-xl dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200"><Icon className={`mt-0.5 h-4 w-4 shrink-0 ${item.tone === 'success' ? 'text-emerald-500' : item.tone === 'error' ? 'text-red-500' : 'text-indigo-500'}`} /><span className="flex-1 leading-relaxed">{item.message}</span><button type="button" onClick={() => setToasts(current => current.filter(toastItem => toastItem.id !== item.id))} aria-label="Dismiss notification" className="text-slate-400"><X className="h-3.5 w-3.5" /></button></div>;
      })}
    </div>
  </FeedbackContext.Provider>;
}

export function useFeedback(): FeedbackApi {
  const context = useContext(FeedbackContext);
  if (!context) throw new Error('useFeedback must be used within FeedbackProvider');
  return context;
}
