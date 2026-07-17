import type { Host } from '../types';

const badgeStyles = {
  enabled: 'border-indigo-500/20 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  disabled: 'border-slate-500/20 bg-slate-500/10 text-slate-700 dark:text-zinc-400',
  pending: 'border-indigo-500/20 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
  applying: 'border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  applied: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  failed: 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-300',
  drifted: 'border-red-500/30 bg-red-500/15 text-red-800 dark:text-red-300',
  rolled_back: 'border-orange-500/20 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  unknown: 'border-slate-500/20 bg-slate-500/10 text-slate-700 dark:text-zinc-400',
  probing: 'border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  online: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  offline: 'border-rose-500/20 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  stale: 'border-orange-500/20 bg-orange-500/10 text-orange-700 dark:text-orange-300',
} as const;

const labels: Record<string, string> = {
  enabled: 'Enabled',
  disabled: 'Disabled',
  pending: 'Pending apply',
  applying: 'Applying',
  applied: 'Applied',
  failed: 'Apply failed',
  drifted: 'Drifted',
  rolled_back: 'Rolled back',
  unknown: 'Not checked',
  probing: 'Probing',
  online: 'Online',
  offline: 'Offline',
  stale: 'Stale check',
};

function Badge({value, title}: {value: keyof typeof badgeStyles; title: string}) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-bold ${badgeStyles[value]}`}
      title={title}
    >
      {labels[value]}
    </span>
  );
}

export default function HostStatusBadges({host}: {host: Host}) {
  const checked = host.checkedAt ? new Date(host.checkedAt * 1000).toLocaleString() : 'Never checked';
  const reachabilityTitle = [
    `Reachability: ${labels[host.reachabilityState]}`,
    checked,
    host.latencyMs == null ? null : `${host.latencyMs} ms`,
    host.httpStatus == null ? null : `HTTP ${host.httpStatus}`,
    host.probeError,
  ].filter(Boolean).join(' · ');

  return (
    <div className="flex min-w-36 flex-wrap gap-1" aria-label={`Host state: ${host.administrativeState}, ${host.deploymentState}, ${host.reachabilityState}`}>
      <Badge value={host.administrativeState} title="Administrative state" />
      <Badge value={host.deploymentState} title="Nginx deployment state" />
      {host.type === 'proxy' && <Badge value={host.reachabilityState} title={reachabilityTitle} />}
    </div>
  );
}
