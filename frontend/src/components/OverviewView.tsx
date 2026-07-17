import { Host, Certificate, AuditLog, SystemHealth } from '../types';
import { formatDate } from '../utils/formatting';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
  Globe,
  Shield,
  Users,
  FileText,
  Plus,
  RefreshCw,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

interface OverviewViewProps {
  hosts: Host[];
  certificates: Certificate[];
  auditLogs: AuditLog[];
  health: SystemHealth;
  onNavigate: (tab: string, subfilter?: string) => void;
  onOpenCreateHost: () => void;
  onRenewCert: (id: string) => void;
  onReconcileDrift: () => void;
}

export default function OverviewView({
  hosts,
  certificates,
  auditLogs,
  health,
  onNavigate,
  onOpenCreateHost,
  onRenewCert,
  onReconcileDrift
}: OverviewViewProps) {

  // 1. Gather Attention Needed Items
  const attentionItems: {
    id: string;
    type: 'failed_apply' | 'degraded_host' | 'expired_cert' | 'expiring_cert' | 'system_drift';
    severity: 'critical' | 'warning';
    title: string;
    description: string;
    actionText: string;
    onAction: () => void;
  }[] = [];

  // System Drift
  if (health.driftDetected) {
    attentionItems.push({
      id: 'system-drift',
      type: 'system_drift',
      severity: 'critical',
      title: 'Active Nginx Configuration Drift Discovered',
      description: 'Active Nginx files differ from the control database schema. Traffic may be routed incorrectly.',
      actionText: 'Atomic Reconcile Now',
      onAction: onReconcileDrift
    });
  }

  // Failed / Rolled-back Applies
  hosts.forEach(host => {
    if (host.deploymentState === 'rolled_back' || host.deploymentState === 'failed') {
      attentionItems.push({
        id: `rolledback-${host.id}`,
        type: 'failed_apply',
        severity: 'critical',
        title: `Host Failed Activation: ${host.source}`,
        description: host.lastError || 'Nginx syntax validation failed. Active proxy safely fell back to previous generation.',
        actionText: 'Modify & Re-Apply Config',
        onAction: () => onNavigate('hosts', `search:${host.source}`)
      });
    } else if (host.reachabilityState === 'offline' || host.reachabilityState === 'stale') {
      attentionItems.push({
        id: `degraded-${host.id}`,
        type: 'degraded_host',
        severity: 'warning',
        title: `Upstream ${host.reachabilityState === 'offline' ? 'Offline' : 'Health Check Stale'}: ${host.source}`,
        description: host.lastError || (host.checkedAt ? `Last checked ${formatDate(new Date(host.checkedAt * 1000).toISOString())}.` : 'This upstream has not produced a fresh health observation.'),
        actionText: 'Inspect Host Routing',
        onAction: () => onNavigate('hosts', `search:${host.source}`)
      });
    }
  });

  // Certificates expired or expiring soon
  certificates.forEach(cert => {
    if (cert.status === 'expired') {
      attentionItems.push({
        id: `expired-cert-${cert.id}`,
        type: 'expired_cert',
        severity: 'critical',
        title: `TLS Certificate Expired: ${cert.name}`,
        description: `Expired on ${formatDate(cert.expiration)}. Attached hosts are throwing security warnings.`,
        actionText: 'Force Renew Let\'s Encrypt',
        onAction: () => onRenewCert(cert.id)
      });
    } else if (cert.status === 'expiring_soon') {
      attentionItems.push({
        id: `expiring-cert-${cert.id}`,
        type: 'expiring_cert',
        severity: 'warning',
        title: `TLS Certificate Expiring Soon: ${cert.name}`,
        description: `Expires in less than 14 days (${formatDate(cert.expiration)}).`,
        actionText: 'Request Early Renewal',
        onAction: () => onRenewCert(cert.id)
      });
    } else if (cert.status === 'renewal_failed') {
      attentionItems.push({
        id: `failed-cert-${cert.id}`,
        type: 'expired_cert',
        severity: 'critical',
        title: `TLS Auto-Renewal Failed: ${cert.name}`,
        description: `Let's Encrypt renewal timed out on DNS challenge verification. Action required.`,
        actionText: 'Retry Issue Request',
        onAction: () => onRenewCert(cert.id)
      });
    }
  });

  // Inventory Aggregates
  const stats = [
    { label: 'HTTP Reverse Proxies', count: hosts.filter(h => h.type === 'proxy').length, link: 'hosts', filter: 'proxy', icon: Globe },
    { label: 'Online Proxy Upstreams', count: hosts.filter(h => h.type === 'proxy' && h.reachabilityState === 'online').length, link: 'hosts', filter: 'all', icon: CheckCircle2 },
    { label: 'Active TLS Certificates', count: certificates.filter(c => c.status === 'valid').length, link: 'hosts', filter: 'certificates', icon: Clock },
    { label: 'Configured Access Policies', count: 2, link: 'access-lists', filter: '', icon: Shield },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-200">

      {/* HEADER SECTION */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 dark:border-zinc-800 pb-5">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
            Proxy Workspace Overview
          </h2>
          <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">
            Reconciliation Plane Status & Active Proxy Diagnostics
          </p>
        </div>

        <button
          onClick={onOpenCreateHost}
          className="inline-flex items-center gap-2 px-4.5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-xl text-sm font-bold shadow-sm transition-all cursor-pointer"
          id="btn-create-host-overview"
        >
          <Plus className="h-4.5 w-4.5" />
          Create New Host
        </button>
      </div>

      {/* ATTENTION REQUIRED QUEUE */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
          <h3 className="font-bold text-base text-slate-900 dark:text-zinc-100">
            Attention Required Queue ({attentionItems.length})
          </h3>
        </div>

        {attentionItems.length === 0 ? (
          <div className="p-8 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl flex items-center gap-4 text-emerald-800 dark:text-emerald-400">
            <CheckCircle2 className="h-8 w-8 text-emerald-500 shrink-0" />
            <div>
              <h4 className="font-bold text-sm">All Systems Nominal & Clean</h4>
              <p className="text-xs mt-0.5 opacity-90">
                No offline hosts, expired certificates, drift failures, or active errors detected. Nginx is happily routing traffic.
              </p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3.5">
            {attentionItems.map((item) => (
              <div
                key={item.id}
                className={`p-4 border rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-2xs transition-all ${
                  item.severity === 'critical'
                    ? 'bg-red-500/5 border-red-500/20 dark:border-red-500/10 text-red-950 dark:text-red-300'
                    : 'bg-amber-500/5 border-amber-500/20 dark:border-amber-500/10 text-amber-950 dark:text-amber-300'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className="mt-1">
                    {item.severity === 'critical' ? (
                      <XCircle className="h-5 w-5 text-red-500 shrink-0" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />
                    )}
                  </div>
                  <div>
                    <h4 className="font-bold text-sm text-slate-900 dark:text-zinc-100 flex items-center gap-2">
                      {item.title}
                      <span className={`inline-block text-[9px] uppercase px-1.5 py-0.2 rounded font-bold tracking-wider ${
                        item.severity === 'critical'
                          ? 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-400 border border-red-200/50'
                          : 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-400 border border-amber-200/50'
                      }`}>
                        {item.severity}
                      </span>
                    </h4>
                    <p className="text-xs mt-1 text-slate-600 dark:text-zinc-400 font-medium">
                      {item.description}
                    </p>
                  </div>
                </div>

                <button
                  onClick={item.onAction}
                  className={`px-3.5 py-2 rounded-lg text-xs font-bold shrink-0 transition-all cursor-pointer flex items-center gap-1.5 ${
                    item.severity === 'critical'
                      ? 'bg-red-600 hover:bg-red-700 text-white dark:bg-red-500/10 dark:text-red-400 dark:hover:bg-red-500/25'
                      : 'bg-amber-600 hover:bg-amber-700 text-white dark:bg-amber-500/10 dark:text-amber-400 dark:hover:bg-amber-500/25'
                  }`}
                >
                  {item.actionText}
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* QUICK INVENTORY METRICS */}
      <section className="space-y-3">
        <h3 className="font-bold text-sm text-slate-600 dark:text-zinc-400 uppercase tracking-wider">
          Reconciliation Database Inventory
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => {
            const Icon = stat.icon;
            return (
              <div
                key={i}
                onClick={() => onNavigate(stat.link, stat.filter)}
                className="p-5 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl hover:border-slate-300 dark:hover:border-zinc-700 shadow-3xs hover:shadow-2xs cursor-pointer transition-all group flex justify-between items-center"
              >
                <div className="space-y-1">
                  <span className="text-xs font-semibold text-slate-500 dark:text-zinc-400">
                    {stat.label}
                  </span>
                  <div className="text-2xl font-black text-slate-900 dark:text-zinc-100">
                    {stat.count}
                  </div>
                </div>
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-zinc-800 group-hover:bg-indigo-50 dark:group-hover:bg-indigo-950/30 text-slate-500 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                  <Icon className="h-5 w-5" />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* RECENT AUDIT TRAIL */}
      <section className="space-y-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            <h3 className="font-bold text-base text-slate-900 dark:text-zinc-100">
              Recent Reconciliation History
            </h3>
          </div>
          <button
            onClick={() => onNavigate('audit')}
            className="text-xs font-bold text-indigo-600 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300 flex items-center gap-1"
          >
            Full Audit Logs
            <ArrowRight className="h-3 w-3" />
          </button>
        </div>

        <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl overflow-hidden shadow-3xs">
          <div className="divide-y divide-slate-100 dark:divide-zinc-800">
            {auditLogs.slice(0, 3).map((log) => {
              const outcomeStyle = {
                Success: 'bg-emerald-50 dark:bg-emerald-950/35 text-emerald-700 dark:text-emerald-400 border-emerald-200/50',
                Failure: 'bg-red-50 dark:bg-red-950/35 text-red-700 dark:text-red-400 border-red-200/50',
                'Rolled Back': 'bg-indigo-50 dark:bg-indigo-950/35 text-indigo-700 dark:text-indigo-400 border-indigo-200/50'
              }[log.outcome];

              return (
                <div key={log.id} className="p-4 hover:bg-slate-50/50 dark:hover:bg-zinc-800/30 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1 max-w-xl">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-slate-500 dark:text-zinc-400">
                        {log.actor}
                      </span>
                      <span className="text-slate-300 dark:text-zinc-700">•</span>
                      <span className="font-semibold text-xs text-slate-700 dark:text-zinc-300">
                        {log.action}
                      </span>
                      <span className="text-slate-300 dark:text-zinc-700">•</span>
                      <span className="font-mono text-xs text-slate-600 dark:text-zinc-300">
                        {log.resource}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-zinc-400 font-medium">
                      {log.summary}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[11px] text-slate-600 dark:text-zinc-400 font-semibold font-mono">
                      {formatDate(log.timestamp)}
                    </span>
                    <span className={`px-2 py-0.5 text-[9px] uppercase font-bold border rounded-md tracking-wider ${outcomeStyle}`}>
                      {log.outcome}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

    </div>
  );
}
