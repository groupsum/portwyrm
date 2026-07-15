import React, { useRef } from 'react';
import { diffConfig } from '../utils/nginxConfig';

export type CodeLanguage = 'nginx' | 'json' | 'shell' | 'text';

interface CodeBlockProps {
  code: string;
  language?: CodeLanguage;
  className?: string;
  wrap?: boolean;
}

const tokenPattern = /(#[^\n]*|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\$[A-Za-z_][\w]*|\b(?:true|false|null|server|location|upstream|stream|http|https|allow|deny|all|any)\b|\b\d+(?:\.\d+)?\b|[{}[\]():;,])/g;
const tokenTest = /^(?:#[^\n]*|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\$[A-Za-z_][\w]*|(?:true|false|null|server|location|upstream|stream|http|https|allow|deny|all|any)|\d+(?:\.\d+)?|[{}[\]():;,])$/;

function tokenClass(token: string, language: CodeLanguage): string {
  if (token.startsWith('#') || token.startsWith('//')) return 'text-slate-500 italic';
  if (token.startsWith('$')) return 'text-cyan-300';
  if (/^['"]/.test(token)) return language === 'json' ? 'text-emerald-300' : 'text-amber-300';
  if (/^\d/.test(token)) return 'text-violet-300';
  if (/^(true|false|null)$/.test(token)) return 'text-cyan-300 font-semibold';
  if (/^(server|location|upstream|stream|http|https|allow|deny|all|any)$/.test(token)) return 'text-fuchsia-300 font-semibold';
  return 'text-slate-400';
}

export function HighlightedCodeLine({ line, language = 'text' }: { line: string; language?: CodeLanguage }) {
  const parts = line.split(tokenPattern).filter(part => part !== '');
  const directive = language === 'nginx' ? line.match(/^(\s*)([A-Za-z_][\w-]*)/) : null;
  let directiveConsumed = false;
  return <>{parts.map((part, index) => {
    if (directive && !directiveConsumed && part.includes(directive[2])) {
      const offset = part.indexOf(directive[2]);
      directiveConsumed = true;
      return <React.Fragment key={index}>{part.slice(0, offset)}<span className="text-indigo-300 font-semibold">{directive[2]}</span>{part.slice(offset + directive[2].length)}</React.Fragment>;
    }
    return tokenTest.test(part) ? <span key={index} className={tokenClass(part, language)}>{part}</span> : <React.Fragment key={index}>{part}</React.Fragment>;
  })}</>;
}

export default function CodeBlock({ code, language = 'text', className = '', wrap = false }: CodeBlockProps) {
  const lines = code.split('\n');
  return <pre data-code-language={language} className={`scrollbar-portwyrm overflow-auto rounded-xl border border-zinc-800 bg-slate-950 p-4 font-mono text-[11px] leading-5 text-zinc-100 ${wrap ? 'whitespace-pre-wrap break-words' : 'whitespace-pre'} ${className}`}><code>{lines.map((line, index) => <React.Fragment key={index}><HighlightedCodeLine line={line} language={language} />{index < lines.length - 1 ? '\n' : ''}</React.Fragment>)}</code></pre>;
}

export function CodeEditor({ value, onChange, language = 'nginx', placeholder = '', rows = 5, ariaLabel = 'Code editor' }: { value: string; onChange: (value: string) => void; language?: CodeLanguage; placeholder?: string; rows?: number; ariaLabel?: string }) {
  const backdropRef = useRef<HTMLPreElement>(null);
  const lines = (value || placeholder).split('\n');
  return <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-slate-950 focus-within:border-indigo-500 focus-within:ring-2 focus-within:ring-indigo-500/20">
    <pre ref={backdropRef} aria-hidden="true" className={`scrollbar-portwyrm pointer-events-none absolute inset-0 overflow-auto whitespace-pre p-3 font-mono text-xs leading-5 ${value ? 'text-zinc-100' : 'text-slate-500'}`}>
      {lines.map((line, index) => <React.Fragment key={index}><HighlightedCodeLine line={line} language={language} />{index < lines.length - 1 ? '\n' : ''}</React.Fragment>)}
    </pre>
    <textarea
      aria-label={ariaLabel}
      data-code-language={language}
      rows={rows}
      spellCheck={false}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      onScroll={(event) => {
        if (!backdropRef.current) return;
        backdropRef.current.scrollTop = event.currentTarget.scrollTop;
        backdropRef.current.scrollLeft = event.currentTarget.scrollLeft;
      }}
      className="scrollbar-portwyrm relative z-10 w-full resize-y overflow-auto whitespace-pre bg-transparent p-3 font-mono text-xs leading-5 text-transparent caret-white selection:bg-indigo-500/40 focus:outline-none"
    />
  </div>;
}

export function InlineCode({ code, language = 'text' }: { code: string; language?: CodeLanguage }) {
  return <code className="rounded-md border border-slate-200 bg-slate-100 px-1.5 py-0.5 font-mono text-[0.92em] text-slate-800 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"><HighlightedCodeLine line={code} language={language} /></code>;
}

interface DiffRow { before?: string; after?: string; beforeChanged: boolean; afterChanged: boolean }

function sideBySideRows(before: string, after: string): DiffRow[] {
  const rows: DiffRow[] = [];
  let removed: string[] = [];
  let added: string[] = [];
  const flush = () => {
    const count = Math.max(removed.length, added.length);
    for (let index = 0; index < count; index++) rows.push({before: removed[index], after: added[index], beforeChanged: index < removed.length, afterChanged: index < added.length});
    removed = []; added = [];
  };
  for (const entry of diffConfig(before, after)) {
    if (entry.type === 'remove') removed.push(entry.line);
    else if (entry.type === 'add') added.push(entry.line);
    else { flush(); rows.push({before: entry.line, after: entry.line, beforeChanged: false, afterChanged: false}); }
  }
  flush();
  return rows;
}

export function SideBySideCodeDiff({ before, after, language = 'nginx', beforeLabel = 'Current', afterLabel = 'Proposed' }: { before: string; after: string; language?: CodeLanguage; beforeLabel?: string; afterLabel?: string }) {
  const rows = sideBySideRows(before, after);
  return <div data-testid="side-by-side-code-diff" className="scrollbar-portwyrm overflow-x-auto rounded-xl border border-zinc-800 bg-slate-950">
    <div className="grid min-w-[760px] grid-cols-2 border-b border-zinc-800 bg-zinc-900 text-[10px] font-extrabold uppercase tracking-wider text-slate-400"><div className="border-r border-zinc-800 px-4 py-2">{beforeLabel}</div><div className="px-4 py-2">{afterLabel}</div></div>
    <div className="min-w-[760px] font-mono text-[11px] leading-5 text-zinc-100">{rows.map((row, index) => <div key={index} className="grid grid-cols-2"><div className={`min-h-5 border-r border-zinc-800 px-3 ${row.beforeChanged ? 'bg-red-500/15' : ''}`}><span className="mr-2 select-none text-red-400">{row.beforeChanged ? '−' : ' '}</span>{row.before !== undefined && <HighlightedCodeLine line={row.before} language={language} />}</div><div className={`min-h-5 px-3 ${row.afterChanged ? 'bg-emerald-500/15' : ''}`}><span className="mr-2 select-none text-emerald-400">{row.afterChanged ? '+' : ' '}</span>{row.after !== undefined && <HighlightedCodeLine line={row.after} language={language} />}</div></div>)}</div>
  </div>;
}
