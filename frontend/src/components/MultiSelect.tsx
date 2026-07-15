import React, { useEffect, useMemo, useState } from 'react';
import { Check, X } from 'lucide-react';

export interface MultiSelectOption {
  value: string;
  label: string;
  description?: string;
}

interface MultiSelectProps {
  id: string;
  label: string;
  options: MultiSelectOption[];
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  noResultsText?: string;
  disabled?: boolean;
}

export default function MultiSelect({
  id,
  label,
  options,
  values,
  onChange,
  placeholder = 'None',
  noResultsText = 'No matches',
  disabled = false,
}: MultiSelectProps) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return options.filter(option => !normalized
      || option.label.toLowerCase().includes(normalized)
      || option.description?.toLowerCase().includes(normalized));
  }, [options, query]);

  useEffect(() => setActiveIndex(0), [query, open]);

  const toggle = (value: string) => {
    onChange(values.includes(value)
      ? values.filter(item => item !== value)
      : [...values, value]);
    setQuery('');
  };

  const keyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' && filtered.length) {
      event.preventDefault(); setOpen(true);
      setActiveIndex(current => Math.min(current + 1, filtered.length - 1));
    } else if (event.key === 'ArrowUp' && filtered.length) {
      event.preventDefault(); setActiveIndex(current => Math.max(current - 1, 0));
    } else if (event.key === 'Enter' && open && filtered.length) {
      event.preventDefault(); toggle(filtered[activeIndex].value);
    } else if (event.key === 'Backspace' && !query && values.length) {
      onChange(values.slice(0, -1));
    } else if (event.key === 'Escape') {
      setOpen(false);
    }
  };

  return (
    <div
      className="relative"
      onBlur={event => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <label htmlFor={id} className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-400">
        {label}
      </label>
      <div className="flex min-h-10 w-full flex-wrap items-center gap-1.5 rounded-lg border border-slate-200 bg-white p-1.5 focus-within:border-indigo-500 focus-within:ring-2 focus-within:ring-indigo-500/15 dark:border-zinc-800 dark:bg-zinc-900">
        {values.map(value => {
          const option = options.find(item => item.value === value);
          if (!option) return null;
          return (
            <span key={value} className="inline-flex max-w-full items-center gap-1 rounded-md border border-indigo-100 bg-indigo-50 px-2 py-1 text-[10px] font-bold text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-300">
              <span className="truncate">{option.label}</span>
              <button type="button" disabled={disabled} aria-label={`Remove ${option.label}`} onClick={() => toggle(value)} className="shrink-0 rounded p-0.5 hover:bg-indigo-100 disabled:opacity-50 dark:hover:bg-indigo-900">
                <X className="h-3 w-3" />
              </button>
            </span>
          );
        })}
        <input
          id={id}
          type="text"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={open}
          aria-controls={`${id}-options`}
          aria-activedescendant={filtered[activeIndex] ? `${id}-option-${filtered[activeIndex].value}` : undefined}
          disabled={disabled}
          value={query}
          onChange={event => { setQuery(event.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={keyDown}
          placeholder={values.length ? 'Add another…' : placeholder}
          className="min-w-32 flex-1 bg-transparent p-1 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none disabled:opacity-50 dark:text-zinc-100"
        />
      </div>
      {open && !disabled && (
        <div id={`${id}-options`} role="listbox" aria-label={`${label} options`} aria-multiselectable="true" className="scrollbar-portwyrm absolute z-30 mt-1 max-h-52 w-full overflow-y-auto rounded-lg border border-slate-200 bg-white p-1 shadow-xl dark:border-zinc-700 dark:bg-zinc-900">
          {filtered.length ? filtered.map((option, index) => {
            const selected = values.includes(option.value);
            return (
              <button
                key={option.value}
                id={`${id}-option-${option.value}`}
                type="button"
                role="option"
                aria-selected={selected}
                onMouseDown={event => event.preventDefault()}
                onClick={() => toggle(option.value)}
                className={`flex w-full items-center justify-between gap-3 rounded-md px-2.5 py-2 text-left ${index === activeIndex ? 'bg-slate-100 dark:bg-zinc-800' : 'hover:bg-slate-50 dark:hover:bg-zinc-800/70'}`}
              >
                <span className="min-w-0"><span className="block truncate text-xs font-bold text-slate-800 dark:text-zinc-100">{option.label}</span>{option.description && <span className="block truncate text-[9px] text-slate-400">{option.description}</span>}</span>
                {selected && <Check className="h-4 w-4 shrink-0 text-indigo-600 dark:text-indigo-400" />}
              </button>
            );
          }) : <div className="px-3 py-4 text-center text-xs text-slate-400">{noResultsText}</div>}
        </div>
      )}
    </div>
  );
}
