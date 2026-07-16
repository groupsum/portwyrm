import React, { useState, useMemo } from 'react';
import { AuditLog, User } from '../types';
import { formatDate } from '../utils/formatting';
import {
  FileText,
  Search,
  Trash2,
  Eye,
  X,
  ShieldCheck,
  XCircle,
  RefreshCw,
  Terminal,
  Lock,
  Download,
  Info
} from 'lucide-react';
import CodeBlock from './CodeBlock';

interface AuditViewProps {
  auditLogs: AuditLog[];
  currentUser: User;
  onClearLogs?: () => void;
}

export default function AuditView({ auditLogs, currentUser, onClearLogs }: AuditViewProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [actorFilter, setActorFilter] = useState('all');
  const [outcomeFilter, setOutcomeFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  // Filter lists
  const uniqueActors = useMemo(() => {
    return Array.from(new Set(auditLogs.map(l => l.actor))).filter(Boolean);
  }, [auditLogs]);

  const filteredLogs = useMemo(() => {
    let result = [...auditLogs];

    if (searchTerm.trim() !== '') {
      const q = searchTerm.toLowerCase();
      result = result.filter(l =>
        l.resource.toLowerCase().includes(q) ||
        l.action.toLowerCase().includes(q) ||
        l.summary.toLowerCase().includes(q) ||
        l.details.toLowerCase().includes(q)
      );
    }

    if (actorFilter !== 'all') {
      result = result.filter(l => l.actor === actorFilter);
    }

    if (outcomeFilter !== 'all') {
      result = result.filter(l => l.outcome === outcomeFilter);
    }

    return result;
  }, [auditLogs, searchTerm, actorFilter, outcomeFilter]);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">

      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
            Immutable Audit Logging
          </h2>
          <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">
            System Activity Trail, Redacted Security Events & Configuration Diagnostics
          </p>
        </div>

        {onClearLogs && currentUser.role === 'Administrator' && auditLogs.length > 0 && (
          <button
            onClick={onClearLogs}
            className="px-4 py-2 border border-red-200 text-red-600 hover:bg-red-50 dark:border-red-900/50 dark:text-red-400 dark:hover:bg-red-950/20 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Trash2 className="h-4 w-4" /> Clear Audit Logs
          </button>
        )}
      </div>

      {/* SEARCH & FILTERS BAR */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl p-4.5 shadow-3xs flex flex-col md:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-400" />
          <input
            type="text"
            aria-label="Search audit logs"
            placeholder="Search resources, actions, diff text, summary logs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden"
          />
        </div>

        {/* Actor */}
        <div className="w-full md:w-48">
          <select
            aria-label="Audit actor"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            className="w-full p-2.5 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs font-semibold text-slate-700 dark:text-zinc-300"
          >
            <option value="all">All Actors</option>
            {uniqueActors.map(actor => (
              <option key={actor} value={actor}>{actor}</option>
            ))}
          </select>
        </div>

        {/* Outcome */}
        <div className="w-full md:w-48">
          <select
            aria-label="Audit outcome"
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
            className="w-full p-2.5 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-xl text-xs font-semibold text-slate-700 dark:text-zinc-300"
          >
            <option value="all">All Outcomes</option>
            <option value="Success">Success</option>
            <option value="Failure">Failure</option>
            <option value="Rolled Back">Rolled Back</option>
          </select>
        </div>
      </div>

      {/* AUDIT LOG TABLE */}
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl overflow-hidden shadow-3xs">
        <table className="w-full border-collapse text-left text-sm text-slate-500 dark:text-zinc-400 font-medium">
          <thead className="bg-slate-50/50 dark:bg-zinc-900/60 text-slate-700 dark:text-zinc-300 text-xs uppercase font-extrabold border-b border-slate-200/80 dark:border-zinc-800">
            <tr>
              <th scope="col" className="px-6 py-4">Time</th>
              <th scope="col" className="px-6 py-4">Actor</th>
              <th scope="col" className="px-6 py-4">Resource</th>
              <th scope="col" className="px-6 py-4">Action</th>
              <th scope="col" className="px-6 py-4">Outcome</th>
              <th scope="col" className="px-6 py-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-slate-400 dark:text-zinc-500 font-semibold">
                  No immutable audit records found matching parameters.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const outcomeStyle = {
                  Success: 'bg-emerald-50 dark:bg-emerald-950/25 border-emerald-100 dark:border-emerald-900 text-emerald-700 dark:text-emerald-400',
                  Failure: 'bg-red-50 dark:bg-red-950/25 border-red-100 dark:border-red-900 text-red-700 dark:text-red-400',
                  'Rolled Back': 'bg-indigo-50 dark:bg-indigo-950/25 border-indigo-100 dark:border-indigo-900 text-indigo-700 dark:text-indigo-400'
                }[log.outcome] || 'bg-slate-100 border-slate-200 text-slate-700';

                return (
                  <tr key={log.id} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/20 transition-colors">

                    {/* Timestamp with localized time details */}
                    <td className="px-6 py-4.5 whitespace-nowrap font-mono text-xs text-slate-600 dark:text-zinc-400">
                      <div>{formatDate(log.timestamp)}</div>
                      <div className="text-[10px] mt-0.5 text-slate-600 dark:text-zinc-400 font-medium">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </div>
                    </td>

                    {/* Actor */}
                    <td className="px-6 py-4.5 font-bold font-mono text-xs text-slate-800 dark:text-zinc-200">
                      {log.actor}
                    </td>

                    {/* Resource */}
                    <td className="px-6 py-4.5 font-bold font-mono text-xs text-slate-700 dark:text-zinc-300">
                      {log.resource}
                    </td>

                    {/* Action */}
                    <td className="px-6 py-4.5 font-extrabold text-xs text-slate-900 dark:text-zinc-100">
                      {log.action}
                    </td>

                    {/* Outcome */}
                    <td className="px-6 py-4.5 whitespace-nowrap">
                      <span className={`inline-block px-2.5 py-0.5 text-[10px] border font-bold rounded-md uppercase tracking-wide ${outcomeStyle}`}>
                        {log.outcome}
                      </span>
                    </td>

                    {/* Expand payload details */}
                    <td className="px-6 py-4.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 border border-slate-200/50 text-slate-600 dark:bg-zinc-800 dark:border-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer ml-auto"
                      >
                        <Eye className="h-3.5 w-3.5" /> Inspect
                      </button>
                    </td>

                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* --- PAYLOAD DETAIL DISCLOSURE MODAL (REDACTED CODES) --- */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col">

            <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50">
              <div className="flex items-center gap-2">
                <Terminal className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                <h3 className="font-extrabold text-sm text-slate-800 dark:text-zinc-100">Reconciliation Payload Analysis</h3>
              </div>
              <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-slate-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">

              {/* Event descriptors */}
              <div className="grid grid-cols-2 gap-3.5 text-xs font-medium">
                <div>
                  <span className="text-slate-400 block uppercase text-[10px]">Log ID</span>
                  <strong className="text-slate-900 dark:text-zinc-100 font-mono text-[10px] block mt-0.5">{selectedLog.id}</strong>
                </div>
                <div>
                  <span className="text-slate-400 block uppercase text-[10px]">Actor Node</span>
                  <strong className="text-slate-900 dark:text-zinc-100 font-mono block mt-0.5">{selectedLog.actor}</strong>
                </div>
                <div>
                  <span className="text-slate-400 block uppercase text-[10px]">Action Event</span>
                  <strong className="text-slate-900 dark:text-zinc-100 block mt-0.5">{selectedLog.action}</strong>
                </div>
                <div>
                  <span className="text-slate-400 block uppercase text-[10px]">Resource Hash</span>
                  <strong className="text-slate-900 dark:text-zinc-100 font-mono block mt-0.5">{selectedLog.resource}</strong>
                </div>
              </div>

              {/* Secrets redaction warning */}
              <div className="p-3 bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-100 dark:border-indigo-900 rounded-xl flex items-start gap-2.5 text-indigo-900 dark:text-indigo-300">
                <Lock className="h-4.5 w-4.5 mt-0.5 shrink-0 text-indigo-500" />
                <div className="text-[11px] leading-relaxed">
                  <strong>Secure Credentials Masked:</strong> Following security compliance policies, all private SSL keys, API tokens, user password hashes, and recovery secrets have been fully redacted [REDACTED_SECRET_RECON_RESERVED] in this immutable audit trace.
                </div>
              </div>

              {/* Code blocks payload */}
              <div className="space-y-1">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Raw Execution Details & Config Diffs</span>
                <CodeBlock code={selectedLog.details} language="json" className="max-h-64" wrap />
              </div>

            </div>

            <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4.5 py-2 bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 rounded-xl text-xs font-bold cursor-pointer"
              >
                Close Analysis
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
