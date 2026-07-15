import React, { useEffect, useId, useRef } from 'react';
import { createPortal } from 'react-dom';
import { MoreVertical, X } from 'lucide-react';

interface ActionModalProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: React.ReactNode;
}

export default function ActionModal({ open, title, description, onClose, children }: ActionModalProps) {
  const titleId = useId();
  const descriptionId = useId();
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeButtonRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[80] flex items-center justify-center overflow-y-auto bg-black/60 p-4"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        className="w-full max-w-md overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-zinc-900"
      >
        <header className="flex items-start justify-between gap-4 border-b border-slate-100 bg-slate-50 px-5 py-4 dark:border-zinc-800 dark:bg-zinc-900/50">
          <div className="min-w-0">
            <div className="mb-1 flex items-center gap-2 text-indigo-600 dark:text-indigo-400">
              <MoreVertical className="h-4 w-4" aria-hidden="true" />
              <span className="text-[10px] font-extrabold uppercase tracking-[0.18em]">Actions</span>
            </div>
            <h2 id={titleId} className="truncate text-sm font-extrabold text-slate-900 dark:text-zinc-100">{title}</h2>
            {description && <p id={descriptionId} className="mt-1 text-xs text-slate-500 dark:text-zinc-400">{description}</p>}
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
            aria-label="Close actions"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </header>
        <div className="grid gap-2 p-4 [&>button]:flex [&>button]:w-full [&>button]:items-center [&>button]:gap-3 [&>button]:rounded-xl [&>button]:border [&>button]:border-slate-200 [&>button]:px-4 [&>button]:py-3 [&>button]:text-left [&>button]:text-sm [&>button]:font-bold [&>button]:transition-colors dark:[&>button]:border-zinc-800">
          {children}
        </div>
      </section>
    </div>,
    document.body,
  );
}
