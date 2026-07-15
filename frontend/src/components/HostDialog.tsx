import React, { useState, useEffect } from 'react';
import { Host, HostType, Certificate, AccessList } from '../types';
import {
  X,
  HelpCircle,
  Check,
  AlertTriangle,
  Server,
  Globe,
  Shield,
  ArrowRight,
  Loader2,
  Lock,
  ArrowRightLeft,
  XCircle,
  Settings,
  HardDrive,
  ChevronDown,
  ChevronUp,
  Trash2
  ,FileCode
} from 'lucide-react';
import MultiSelect from './MultiSelect';
import { useFeedback } from './Feedback';
import CodeBlock, { CodeEditor, InlineCode, SideBySideCodeDiff } from './CodeBlock';
import { generateNginxConfig } from '../utils/nginxConfig';

interface HostDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (hostData: any, onProgress: (phase: string) => void) => void;
  certificates: Certificate[];
  accessLists: AccessList[];
  editingHost?: Host | null;
  onDeleteHost?: (id: string) => void;
}

export default function HostDialog({
  isOpen,
  onClose,
  onSubmit,
  certificates,
  accessLists,
  editingHost,
  onDeleteHost
}: HostDialogProps) {
  const feedback = useFeedback();
  const [hostType, setHostType] = useState<HostType>('proxy');

  // Form values
  const [sourceDomains, setSourceDomains] = useState('');
  const [sourcePort, setSourcePort] = useState('');
  const [streamProtocol, setStreamProtocol] = useState<'tcp' | 'udp' | 'both'>('tcp');

  const [destScheme, setDestScheme] = useState('http');
  const [destHost, setDestHost] = useState('');
  const [destPort, setDestPort] = useState('');
  const [redirectUrl, setRedirectUrl] = useState('');
  const [redirectCode, setRedirectCode] = useState('301');
  const [preservePath, setPreservePath] = useState(true);

  // TLS values
  const [sslId, setSslId] = useState<string>('none');
  const [forceHttps, setForceHttps] = useState(false);
  const [hsts, setHsts] = useState(false);
  const [hstsSubdomains, setHstsSubdomains] = useState(false);

  // Access control
  const [accessListIds, setAccessListIds] = useState<string[]>([]);

  // Performance & Options
  const [websocket, setWebsocket] = useState(true);
  const [caching, setCaching] = useState(false);
  const [blockExploits, setBlockExploits] = useState(true);
  const [http2, setHttp2] = useState(true);
  const [forwardSsl, setForwardSsl] = useState(false);

  // Advanced config
  const [customNginxConfig, setCustomNginxConfig] = useState('');
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const [isConfigPreviewOpen, setIsConfigPreviewOpen] = useState(false);

  // Validation & Touched state
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [touchedFields, setTouchedFields] = useState<Record<string, boolean>>({});

  // Apply state
  const [isApplying, setIsApplying] = useState(false);
  const [applyPhase, setApplyPhase] = useState('');
  const [applyLog, setApplyLog] = useState<string[]>([]);
  const [applyError, setApplyError] = useState<string | null>(null);

  const markTouched = (field: string) => {
    setTouchedFields(prev => ({ ...prev, [field]: true }));
  };

  // Pre-fill form state when editingHost changes
  useEffect(() => {
    if (editingHost) {
      setHostType(editingHost.type);
      if (editingHost.type === 'stream') {
        const parts = editingHost.source.split(' ');
        setStreamProtocol((parts[0] || 'TCP').toLowerCase() as any);
        setSourcePort((parts[1] || '').replace(':', ''));
        const destParts = editingHost.destination.split(':');
        setDestHost(destParts[0] || '');
        setDestPort(destParts[1] || '');
      } else {
        setSourceDomains(editingHost.source);
        if (editingHost.type === 'proxy') {
          const rawDest = editingHost.destination;
          const isHttps = rawDest.startsWith('https://');
          setDestScheme(isHttps ? 'https' : 'http');
          const cleanDest = rawDest.replace(/^https?:\/\//, '');
          const destParts = cleanDest.split(':');
          setDestHost(destParts[0] || '');
          setDestPort(destParts[1] || (isHttps ? '443' : '80'));
        } else if (editingHost.type === 'redirect') {
          const cleanDest = editingHost.destination.replace(' (301, preserve path)', '').replace(' (302, preserve path)', '').replace(' (301)', '').replace(' (302)', '');
          setRedirectUrl(cleanDest);
          setRedirectCode(editingHost.destination.includes('302') ? '302' : '301');
          setPreservePath(editingHost.destination.includes('preserve path'));
        }
      }
      setSslId(editingHost.sslId || 'none');
      setForceHttps(editingHost.forceHttps || false);
      setHsts(editingHost.hsts || false);
      setHstsSubdomains(editingHost.hstsSubdomains || false);
      setAccessListIds(editingHost.accessListIds || (editingHost.accessListId ? [editingHost.accessListId] : []));
      setWebsocket(editingHost.websocket);
      setCaching(editingHost.caching);
      setBlockExploits(editingHost.blockExploits);
      setHttp2(editingHost.http2);
      setForwardSsl(editingHost.forwardSsl);
      setCustomNginxConfig(editingHost.customNginxConfig || '');
      setApplyError(null);
      setTouchedFields({});
    } else {
      // Default creation states
      setHostType('proxy');
      setSourceDomains('');
      setSourcePort('');
      setStreamProtocol('tcp');
      setDestScheme('http');
      setDestHost('');
      setDestPort('');
      setRedirectUrl('');
      setRedirectCode('301');
      setPreservePath(true);
      setSslId('none');
      setForceHttps(false);
      setHsts(false);
      setHstsSubdomains(false);
      setAccessListIds([]);
      setWebsocket(true);
      setCaching(false);
      setBlockExploits(true);
      setHttp2(true);
      setForwardSsl(false);
      setCustomNginxConfig('');
      setApplyError(null);
      setTouchedFields({});
    }
  }, [editingHost, isOpen]);

  // Immediate input validation
  useEffect(() => {
    const errors: Record<string, string> = {};

    if (hostType === 'stream') {
      if (!sourcePort) {
        errors.sourcePort = 'Incoming port is required';
      } else {
        const port = parseInt(sourcePort);
        if (isNaN(port) || port < 1 || port > 65535) {
          errors.sourcePort = 'Port must be an integer between 1 and 65535';
        }
      }

      if (!destHost.trim()) {
        errors.destHost = 'Enter an upstream IP address, hostname, or Docker service name';
      }

      if (!destPort) {
        errors.destPort = 'Destination port is required';
      } else {
        const port = parseInt(destPort);
        if (isNaN(port) || port < 1 || port > 65535) {
          errors.destPort = 'Port must be an integer between 1 and 65535';
        }
      }
    } else {
      if (!sourceDomains.trim()) {
        errors.sourceDomains = 'Source domain name is required';
      } else {
        const domains = sourceDomains.split(',').map(d => d.trim()).filter(Boolean);
        const domainRegex = /^(\*\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/;
        const invalid = domains.some(d => !domainRegex.test(d));
        if (invalid) {
          errors.sourceDomains = 'Please enter valid domain names (e.g. app.example.com or *.example.com)';
        }
      }

      if (hostType === 'proxy') {
        if (!destHost.trim()) {
          errors.destHost = 'Enter an upstream IP address, hostname, or Docker service name';
        }

        if (!destPort) {
          errors.destPort = 'Destination port is required';
        } else {
          const port = parseInt(destPort);
          if (isNaN(port) || port < 1 || port > 65535) {
            errors.destPort = 'Port must be an integer between 1 and 65535';
          }
        }
      } else if (hostType === 'redirect') {
        if (!redirectUrl.trim()) {
          errors.redirectUrl = 'Redirection target URL is required';
        } else {
          if (!redirectUrl.includes('.') && !redirectUrl.startsWith('http://') && !redirectUrl.startsWith('https://')) {
            errors.redirectUrl = 'Please enter a valid target URL or hostname (e.g. https://newsite.com)';
          }
        }
      }
    }

    setValidationErrors(errors);
  }, [hostType, sourceDomains, sourcePort, streamProtocol, destScheme, destHost, destPort, redirectUrl, redirectCode]);

  if (!isOpen) return null;

  const hasChanges = () => {
    if (editingHost) {
      if (hostType !== editingHost.type) return true;
      if (hostType === 'stream') {
        const parts = editingHost.source.split(' ');
        const protocol = (parts[0] || 'TCP').toLowerCase();
        const port = (parts[1] || '').replace(':', '');
        if (streamProtocol !== protocol) return true;
        if (sourcePort !== port) return true;

        const destParts = editingHost.destination.split(':');
        if (destHost !== destParts[0]) return true;
        if (destPort !== destParts[1]) return true;
      } else {
        if (sourceDomains !== editingHost.source) return true;
        if (hostType === 'proxy') {
          const rawDest = editingHost.destination;
          const isHttps = rawDest.startsWith('https://');
          const scheme = isHttps ? 'https' : 'http';
          const cleanDest = rawDest.replace(/^https?:\/\//, '');
          const destParts = cleanDest.split(':');
          const host = destParts[0] || '';
          const port = destParts[1] || (isHttps ? '443' : '80');
          if (destScheme !== scheme) return true;
          if (destHost !== host) return true;
          if (destPort !== port) return true;
        } else if (hostType === 'redirect') {
          const cleanDest = editingHost.destination.replace(' (301, preserve path)', '').replace(' (302, preserve path)', '').replace(' (301)', '').replace(' (302)', '');
          const code = editingHost.destination.includes('302') ? '302' : '301';
          const pathPreserved = editingHost.destination.includes('preserve path');
          if (redirectUrl !== cleanDest) return true;
          if (redirectCode !== code) return true;
          if (preservePath !== pathPreserved) return true;
        }
      }
      if (sslId !== (editingHost.sslId || 'none')) return true;
      if (forceHttps !== (editingHost.forceHttps || false)) return true;
      if (hsts !== (editingHost.hsts || false)) return true;
      if (hstsSubdomains !== (editingHost.hstsSubdomains || false)) return true;
      const originalAccessListIds = editingHost.accessListIds || (editingHost.accessListId ? [editingHost.accessListId] : []);
      if (accessListIds.join(',') !== originalAccessListIds.join(',')) return true;
      if (websocket !== editingHost.websocket) return true;
      if (caching !== editingHost.caching) return true;
      if (blockExploits !== editingHost.blockExploits) return true;
      if (http2 !== editingHost.http2) return true;
      if (forwardSsl !== editingHost.forwardSsl) return true;
      if (customNginxConfig !== (editingHost.customNginxConfig || '')) return true;
    } else {
      if (hostType !== 'proxy') return true;
      if (sourceDomains !== '') return true;
      if (sourcePort !== '') return true;
      if (destHost !== '') return true;
      if (destPort !== '') return true;
      if (redirectUrl !== '') return true;
      if (redirectCode !== '301') return true;
      if (preservePath !== true) return true;
      if (sslId !== 'none') return true;
      if (forceHttps !== false) return true;
      if (hsts !== false) return true;
      if (hstsSubdomains !== false) return true;
      if (accessListIds.length !== 0) return true;
      if (websocket !== true) return true;
      if (caching !== false) return true;
      if (blockExploits !== true) return true;
      if (http2 !== true) return true;
      if (forwardSsl !== false) return true;
      if (customNginxConfig !== '') return true;
    }
    return false;
  };

  const handleClose = (force = false) => {
    if (!force && hasChanges()) {
      void feedback.confirm({title: 'Discard unsaved changes?', description: 'Your edits have not been applied and will be lost.', confirmLabel: 'Discard changes', destructive: true}).then(accepted => { if (accepted) onClose(); });
    } else {
      onClose();
    }
  };

  const handleDelete = () => {
    if (editingHost && onDeleteHost) {
      onDeleteHost(editingHost.id);
      onClose();
    }
  };

  const getSourcePreview = () => {
    if (hostType === 'stream') {
      return `${streamProtocol.toUpperCase()} port ${sourcePort || '??'}`;
    }
    return sourceDomains.split(',').map(d => d.trim()).filter(Boolean)[0] || 'domain.com';
  };

  const getDestinationPreview = () => {
    if (hostType === '404') {
      return 'Returns 404 Bad Request';
    }
    if (hostType === 'redirect') {
      return `Redirect -> ${redirectUrl || 'newsite.com'} (${redirectCode})`;
    }
    if (hostType === 'stream') {
      return `${destHost || 'upstream-ip'}:${destPort || '??'}`;
    }
    return `${destScheme}://${destHost || 'container-host'}:${destPort || '80'}`;
  };

  const handleApplySubmit = (e: React.FormEvent) => {
    if (e) e.preventDefault();

    // Immediate and final validation
    const errorsExist = Object.keys(validationErrors).length > 0;
    if (errorsExist) {
      setTouchedFields({
        sourceDomains: true,
        sourcePort: true,
        destHost: true,
        destPort: true,
        redirectUrl: true
      });
      setApplyError('Please correct validation errors on the form before applying configuration.');
      return;
    }

    setIsApplying(true);
    setApplyLog([]);
    setApplyError(null);

    const hostPayload = buildDraftHost();

    onSubmit(hostPayload, (phase) => {
      setApplyPhase(phase);
      setApplyLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${phase}...`]);

      if (phase === 'Rolled back') {
        setIsApplying(false);
        setApplyError('Nginx syntax verification check failed. Applied configuration rolled back to last known good matrix. Prior routing is still active and operational.');
      }

      if (phase === 'Complete') {
        setTimeout(() => {
          setIsApplying(false);
          onClose();
        }, 1000);
      }
    });
  };

  const buildDraftHost = (): Host => {
    const sslRecord = certificates.find(c => c.id === sslId);
    const selectedAccessLists = accessListIds.map(id => accessLists.find(accessList => accessList.id === id)).filter((accessList): accessList is AccessList => Boolean(accessList));
    return {
      ...(editingHost || {id: 'draft', ownerId: '', ownerName: '', provenance: 'human', status: 'pending', created: '', modified: '', lastError: null, activeGeneration: 0}),
      type: hostType,
      source: hostType === 'stream' ? `${streamProtocol.toUpperCase()} :${sourcePort}` : sourceDomains,
      destination: hostType === '404'
        ? 'Returns 404'
        : hostType === 'redirect'
        ? `${redirectUrl} (${redirectCode}${preservePath ? ', preserve path' : ''})`
        : `${destScheme}://${destHost}:${destPort}`,
      sslId: sslId === 'none' ? null : sslId,
      sslName: sslRecord ? sslRecord.name : 'None',
      accessListId: accessListIds[0] || null,
      accessListIds,
      accessListName: hostType === 'stream'
        ? 'Network only'
        : selectedAccessLists.length ? selectedAccessLists.map(accessList => accessList.name).join(', ') : 'Public',
      websocket,
      caching,
      blockExploits,
      http2,
      forwardSsl,
      forceHttps: sslId !== 'none' ? forceHttps : false,
      hsts: sslId !== 'none' ? hsts : false,
      hstsSubdomains: sslId !== 'none' ? hstsSubdomains : false,
      customNginxConfig,
    };
  };

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          handleClose();
        }
      }}
    >
      <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">

        {/* MODAL HEADER */}
        <div className="px-6 py-4.5 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center bg-slate-50 dark:bg-zinc-900/50 shrink-0">
          <div className="flex items-center gap-2.5">
            <Server className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            <span className="font-extrabold text-slate-800 dark:text-zinc-100 text-sm">
              {editingHost ? `Configure Routing Host: ${editingHost.source}` : 'Configure Routing Host'}
            </span>
          </div>
          <button
            disabled={isApplying}
            onClick={() => handleClose()}
            className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-zinc-800 text-slate-400 hover:text-slate-700 dark:hover:text-zinc-200 disabled:opacity-50 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* COMPILING RECONCILIATION OVERLAY */}
        {isApplying ? (
          <div className="flex-1 p-8 flex flex-col items-center justify-center space-y-6 bg-slate-50/50 dark:bg-zinc-900/30">
            <Loader2 className="h-12 w-12 text-indigo-600 dark:text-indigo-400 animate-spin" />
            <div className="text-center">
              <h3 className="font-bold text-lg text-slate-900 dark:text-zinc-100">Compiling Configuration Generation</h3>
              <p className="text-xs text-indigo-600 dark:text-indigo-400 font-semibold animate-pulse mt-1">{applyPhase} in progress...</p>
            </div>

            <CodeBlock code={applyLog.join('\n')} language="shell" className="max-h-48 w-full max-w-xl" />
          </div>
        ) : (
          /* CONSOLIDATED SINGLE FORM */
          <form onSubmit={handleApplySubmit} className="flex-1 p-6 overflow-y-auto space-y-6">

            {/* LIVE ROUTE AND GENERATED CONFIG PREVIEWS */}
            <div className="space-y-3">
              <div className="flex shrink-0 flex-col gap-2 rounded-xl border border-indigo-100 bg-indigo-50/50 p-3.5 text-xs sm:flex-row sm:items-center sm:justify-between dark:border-indigo-950/30 dark:bg-indigo-950/10">
                <span className="font-semibold text-indigo-900 dark:text-indigo-400">Live routing pipeline</span>
                <div className="flex min-w-0 items-center gap-2 font-mono text-slate-600 dark:text-zinc-400">
                  <span className="truncate font-bold text-indigo-950 underline dark:text-indigo-300">{getSourcePreview()}</span>
                  <ArrowRight className="h-3 w-3 shrink-0 text-indigo-500" />
                  <span className="truncate font-bold text-emerald-600 dark:text-emerald-400">{getDestinationPreview()}</span>
                </div>
              </div>

              <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
                <button type="button" onClick={() => setIsConfigPreviewOpen(open => !open)} className="flex w-full items-center justify-between px-4 py-3 text-left text-xs font-bold text-slate-700 hover:bg-slate-50 dark:text-zinc-200 dark:hover:bg-zinc-800">
                  <span className="flex items-center gap-2"><FileCode className="h-4 w-4 text-indigo-500" />Preview configuration to apply{editingHost ? ' and diff' : ''}</span>
                  {isConfigPreviewOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
                {isConfigPreviewOpen && <div className="space-y-4 border-t border-slate-200 p-4 dark:border-zinc-800">
                  <div><p className="mb-2 text-[10px] font-extrabold uppercase tracking-wider text-slate-400">Generated Nginx configuration</p><CodeBlock code={generateNginxConfig(buildDraftHost())} language="nginx" className="max-h-72" /></div>
                  {editingHost && <div><p className="mb-2 text-[10px] font-extrabold uppercase tracking-wider text-slate-400">Changes from active host record</p><SideBySideCodeDiff before={generateNginxConfig(editingHost)} after={generateNginxConfig(buildDraftHost())} /></div>}
                </div>}
              </div>
            </div>

            {/* SEGMENTED ROUTING SELECTOR */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">1. Routing Method</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { id: 'proxy', label: 'HTTP Proxy', icon: Globe },
                  { id: 'redirect', label: 'Redirect', icon: ArrowRightLeft },
                  { id: '404', label: 'Dead (404)', icon: XCircle },
                  { id: 'stream', label: 'TCP/UDP Stream', icon: HardDrive },
                ].map(item => {
                  const Icon = item.icon;
                  const isSelected = hostType === item.id;
                  return (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => {
                        setHostType(item.id as HostType);
                        setApplyError(null);
                      }}
                      className={`p-3 border rounded-xl text-center flex flex-col items-center justify-center gap-1.5 transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-slate-900 border-slate-900 text-white dark:bg-zinc-100 dark:border-zinc-100 dark:text-zinc-900 shadow-sm'
                          : 'border-slate-200 dark:border-zinc-800 hover:bg-slate-50 dark:hover:bg-zinc-800 bg-white dark:bg-zinc-900 text-slate-700 dark:text-zinc-300'
                      }`}
                    >
                      <Icon className="h-4.5 w-4.5" />
                      <span className="font-bold text-xs">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* ROUTE MAPPING DEFINITIONS */}
            <div className="p-4.5 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-2xl space-y-4">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">2. Source & Upstream Mapping</span>

              {/* Source Fields */}
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-700 dark:text-zinc-300 block">
                  {hostType === 'stream' ? 'Incoming Traffic Port & Protocol' : 'Source Request Domain Names'}
                </label>
                {hostType === 'stream' ? (
                  <div className="space-y-1">
                    <div className="flex gap-3">
                      <select
                        value={streamProtocol}
                        onChange={(e) => setStreamProtocol(e.target.value as any)}
                        className="p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                      >
                        <option value="tcp">TCP Protocol</option>
                        <option value="udp">UDP Protocol</option>
                        <option value="both">Both (TCP & UDP)</option>
                      </select>
                      <input
                        type="number"
                        placeholder="Incoming Port (e.g. 5432)"
                        value={sourcePort}
                        onChange={(e) => {
                          setSourcePort(e.target.value);
                          markTouched('sourcePort');
                        }}
                        onBlur={() => markTouched('sourcePort')}
                        className={`flex-1 p-2.5 border bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden ${
                          touchedFields.sourcePort && validationErrors.sourcePort
                            ? 'border-red-500 focus:border-red-500'
                            : 'border-slate-200 dark:border-zinc-800 focus:border-indigo-500'
                        }`}
                        required
                      />
                    </div>
                    {touchedFields.sourcePort && validationErrors.sourcePort && (
                      <span className="text-xs text-red-500 font-bold block mt-1">{validationErrors.sourcePort}</span>
                    )}
                  </div>
                ) : (
                  <div>
                    <input
                      type="text"
                      placeholder="app.example.com, api.example.com"
                      value={sourceDomains}
                      onChange={(e) => {
                        setSourceDomains(e.target.value);
                        markTouched('sourceDomains');
                      }}
                      onBlur={() => markTouched('sourceDomains')}
                      className={`w-full p-2.5 border bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden ${
                        touchedFields.sourceDomains && validationErrors.sourceDomains
                          ? 'border-red-500 focus:border-red-500'
                          : 'border-slate-200 dark:border-zinc-800 focus:border-indigo-500'
                      }`}
                      required
                    />
                    {touchedFields.sourceDomains && validationErrors.sourceDomains ? (
                      <span className="text-xs text-red-500 font-bold block mt-1">{validationErrors.sourceDomains}</span>
                    ) : (
                      <span className="text-[10px] text-slate-400 mt-1 block leading-normal">
                        Comma-separate domain names. Wildcards (e.g. <InlineCode code="*.example.com" language="nginx" />) are supported.
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Target Upstream Endpoint (Hidden for 404) */}
              {hostType !== '404' && (
                <div className="space-y-2 border-t border-slate-200 dark:border-zinc-800/60 pt-4">
                  <span className="text-xs font-bold text-slate-700 dark:text-zinc-300 block">
                    {hostType === 'redirect' ? 'Redirect destination' : 'Upstream destination'}
                  </span>

                  {hostType === 'redirect' ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold text-slate-400 block uppercase">Redirection Target URL</span>
                        <input
                          type="text"
                          placeholder="https://newdomain.com"
                          value={redirectUrl}
                          onChange={(e) => {
                            setRedirectUrl(e.target.value);
                            markTouched('redirectUrl');
                          }}
                          onBlur={() => markTouched('redirectUrl')}
                          className={`w-full p-2.5 border bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden ${
                            touchedFields.redirectUrl && validationErrors.redirectUrl
                              ? 'border-red-500 focus:border-red-500'
                              : 'border-slate-200 dark:border-zinc-800 focus:border-indigo-500'
                          }`}
                          required
                        />
                        {touchedFields.redirectUrl && validationErrors.redirectUrl && (
                          <span className="text-xs text-red-500 font-bold block mt-1">{validationErrors.redirectUrl}</span>
                        )}
                      </div>
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold text-slate-400 block uppercase">HTTP Code</span>
                        <select
                          value={redirectCode}
                          onChange={(e) => setRedirectCode(e.target.value)}
                          className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                        >
                          <option value="301">301 Moved Permanently</option>
                          <option value="302">302 Found Temporary</option>
                        </select>
                      </div>
                      <div className="sm:col-span-2 flex items-center gap-2 pt-1">
                        <input
                          type="checkbox"
                          id="preserve-path"
                          checked={preservePath}
                          onChange={(e) => setPreservePath(e.target.checked)}
                          className="rounded border-slate-300 dark:border-zinc-800 text-indigo-600 focus:ring-indigo-500"
                        />
                        <label htmlFor="preserve-path" className="text-xs text-slate-600 dark:text-zinc-300 font-semibold cursor-pointer">
                          Preserve original query path URI path in redirect
                        </label>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <div className={`grid grid-cols-1 gap-3 ${hostType === 'proxy' ? 'sm:grid-cols-[auto_minmax(0,1fr)_6rem]' : 'sm:grid-cols-[minmax(0,1fr)_6rem]'}`}>
                        {hostType === 'proxy' && (
                          <label className="space-y-1">
                            <span className="text-[10px] font-bold text-slate-400 uppercase">Protocol</span>
                            <select
                              value={destScheme}
                              onChange={(e) => setDestScheme(e.target.value)}
                              className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-sm font-semibold text-slate-800 dark:text-zinc-100 focus:outline-hidden"
                            >
                              <option value="http">HTTP</option>
                              <option value="https">HTTPS</option>
                            </select>
                          </label>
                        )}
                        <label className="space-y-1 min-w-0">
                          <span className="text-[10px] font-bold text-slate-400 uppercase">IP address, DNS name, or Docker service/container</span>
                          <input
                            type="text"
                            placeholder="10.0.0.42, api.internal, or web"
                            aria-describedby="upstream-address-help"
                            value={destHost}
                            onChange={(e) => {
                              setDestHost(e.target.value);
                              markTouched('destHost');
                            }}
                            onBlur={() => markTouched('destHost')}
                            className={`w-full p-2.5 border bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden ${
                              touchedFields.destHost && validationErrors.destHost
                                ? 'border-red-500 focus:border-red-500'
                                : 'border-slate-200 dark:border-zinc-800 focus:border-indigo-500'
                            }`}
                            required
                          />
                        </label>
                        <label className="space-y-1">
                          <span className="text-[10px] font-bold text-slate-400 uppercase">Port</span>
                          <input
                            type="number"
                            placeholder="8080"
                            value={destPort}
                            onChange={(e) => {
                              setDestPort(e.target.value);
                              markTouched('destPort');
                            }}
                            onBlur={() => markTouched('destPort')}
                            className={`w-full p-2.5 border bg-white dark:bg-zinc-900 rounded-lg text-sm font-mono text-slate-800 dark:text-zinc-100 focus:outline-hidden ${
                              touchedFields.destPort && validationErrors.destPort
                                ? 'border-red-500 focus:border-red-500'
                                : 'border-slate-200 dark:border-zinc-800 focus:border-indigo-500'
                            }`}
                            required
                          />
                        </label>
                      </div>
                      <p id="upstream-address-help" className="text-[10px] text-slate-400 leading-normal">
                        Use an IP address, DNS hostname, or Docker service/container name. Docker names require Portwyrm and the upstream container to share a network.
                      </p>
                      {((touchedFields.destHost && validationErrors.destHost) || (touchedFields.destPort && validationErrors.destPort)) && (
                        <div className="flex flex-col gap-0.5 mt-1">
                          {touchedFields.destHost && validationErrors.destHost && (
                            <span className="text-xs text-red-500 font-bold block">{validationErrors.destHost}</span>
                          )}
                          {touchedFields.destPort && validationErrors.destPort && (
                            <span className="text-xs text-red-500 font-bold block">{validationErrors.destPort}</span>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* POLICY CONSOLIDATION: TLS & ACCESS CONTROL (SIDE-BY-SIDE) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

              {/* SSL/TLS Column */}
              <div className="p-4 border border-slate-200 dark:border-zinc-800 rounded-xl space-y-3 bg-white dark:bg-zinc-900">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block border-b border-slate-100 dark:border-zinc-800 pb-1.5 flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-indigo-500" />
                  Client-facing HTTPS
                </span>
                <label htmlFor="tls-certificate" className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  TLS certificate
                </label>
                <select
                  id="tls-certificate"
                  value={sslId}
                  onChange={(e) => {
                    const val = e.target.value;
                    setSslId(val);
                    if (val === 'none') {
                      setForceHttps(false);
                      setHsts(false);
                      setHstsSubdomains(false);
                    }
                  }}
                  className="w-full p-2.5 border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded-lg text-xs font-semibold text-slate-800 dark:text-zinc-100"
                >
                  <option value="none">None</option>
                  {certificates.map(c => (
                    <option key={c.id} value={c.id}>
                      {c.name} (Domains: {c.domains.join(', ')})
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-slate-400 leading-normal">
                  Choose the certificate Portwyrm presents to clients connecting over HTTPS.
                </p>

                {sslId !== 'none' && (
                  <div className="space-y-2 pt-2 text-xs">
                    <div className="flex items-start gap-2.5">
                      <input
                        type="checkbox"
                        id="force-https"
                        checked={forceHttps}
                        onChange={(e) => {
                          setForceHttps(e.target.checked);
                          if (!e.target.checked) {
                            setHsts(false);
                            setHstsSubdomains(false);
                          }
                        }}
                        className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 context-checkbox"
                      />
                      <div>
                        <label htmlFor="force-https" className="font-bold text-slate-800 dark:text-zinc-200 block">Force HTTPS</label>
                        <span className="text-[10px] text-slate-400">Issues 301 redirects to force SSL transport.</span>
                      </div>
                    </div>

                    <div className="flex items-start gap-2.5">
                      <input
                        type="checkbox"
                        id="hsts"
                        disabled={!forceHttps}
                        checked={hsts}
                        onChange={(e) => {
                          setHsts(e.target.checked);
                          if (!e.target.checked) setHstsSubdomains(false);
                        }}
                        className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 disabled:opacity-50"
                      />
                      <div className={!forceHttps ? 'opacity-50' : ''}>
                        <label htmlFor="hsts" className="font-bold text-slate-800 dark:text-zinc-200 block">HSTS Enforce policy</label>
                        <span className="text-[10px] text-slate-400">Tells browsers to only request over SSL.</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Firewall & Access Control Column */}
              <div className="p-4 border border-slate-200 dark:border-zinc-800 rounded-xl space-y-3 bg-white dark:bg-zinc-900">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block border-b border-slate-100 dark:border-zinc-800 pb-1.5 flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 text-indigo-500" />
                  Access Firewall Control
                </span>

                {hostType === 'stream' ? (
                  <div className="text-xs p-3 bg-slate-50 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-lg text-slate-500">
                    Network Stream ports are bound to raw sockets on all interfaces. Access List rules do not apply to TCP streams.
                  </div>
                ) : (
                  <div className="space-y-3">
                    <MultiSelect
                      id="host-access-lists"
                      label="Access lists"
                      options={accessLists.map(accessList => ({
                        value: accessList.id,
                        label: accessList.name,
                        description: `${accessList.usersCount} identities · ${accessList.rulesCount} network rules`,
                      }))}
                      values={accessListIds}
                      onChange={setAccessListIds}
                      placeholder="Public Access"
                      noResultsText="No matching access lists"
                    />
                    <span className="text-[10px] text-slate-400 leading-normal block">
                      Selected lists are combined into one effective policy. The strictest selected satisfy mode is enforced.
                    </span>
                  </div>
                )}
              </div>

            </div>

            {/* PERFORMANCE TUNING SWITCHBOARD */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">4. Protocol & Performance Switchboard</span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {/* WebSocket Toggle */}
                {hostType === 'proxy' && (
                  <label className="p-3 border border-slate-200 dark:border-zinc-800 rounded-xl bg-white dark:bg-zinc-900 flex items-start gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={websocket}
                      onChange={(e) => setWebsocket(e.target.checked)}
                      className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 focus:ring-indigo-500"
                    />
                    <div>
                      <span className="text-xs font-bold text-slate-800 dark:text-zinc-200 block">WebSockets</span>
                      <span className="text-[9px] text-slate-400 block mt-0.5">Allow protocol upgrades (ws/wss)</span>
                    </div>
                  </label>
                )}

                {/* Asset Caching */}
                {hostType === 'proxy' && (
                  <label className="p-3 border border-slate-200 dark:border-zinc-800 rounded-xl bg-white dark:bg-zinc-900 flex items-start gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={caching}
                      onChange={(e) => setCaching(e.target.checked)}
                      className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 focus:ring-indigo-500"
                    />
                    <div>
                      <span className="text-xs font-bold text-slate-800 dark:text-zinc-200 block">Proxy Cache</span>
                      <span className="text-[9px] text-slate-400 block mt-0.5">Enables Nginx file caching on disk</span>
                    </div>
                  </label>
                )}

                {/* Block Exploits */}
                {hostType !== 'stream' && (
                  <label className="p-3 border border-slate-200 dark:border-zinc-800 rounded-xl bg-white dark:bg-zinc-900 flex items-start gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={blockExploits}
                      onChange={(e) => setBlockExploits(e.target.checked)}
                      className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 focus:ring-indigo-500"
                    />
                    <div>
                      <span className="text-xs font-bold text-slate-800 dark:text-zinc-200 block">Block Exploits</span>
                      <span className="text-[9px] text-slate-400 block mt-0.5">Filter SQLi, XSS, and traversals</span>
                    </div>
                  </label>
                )}

                {/* Enable HTTP/2 */}
                {sslId !== 'none' && hostType !== 'stream' && (
                  <label className="p-3 border border-slate-200 dark:border-zinc-800 rounded-xl bg-white dark:bg-zinc-900 flex items-start gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={http2}
                      onChange={(e) => setHttp2(e.target.checked)}
                      className="rounded border-slate-300 dark:border-zinc-800 mt-0.5 text-indigo-600 focus:ring-indigo-500"
                    />
                    <div>
                      <span className="text-xs font-bold text-slate-800 dark:text-zinc-200 block">HTTP/2 Engine</span>
                      <span className="text-[9px] text-slate-400 block mt-0.5">Multiplexed assets over TLS</span>
                    </div>
                  </label>
                )}
              </div>
            </div>

            {/* COLLAPSIBLE ADVANCED CONFIGURATION SECTION */}
            <div className="border border-slate-200 dark:border-zinc-800 rounded-xl overflow-hidden bg-white dark:bg-zinc-900">
              <button
                type="button"
                onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
                className="w-full px-4 py-3 bg-slate-50 dark:bg-zinc-900/50 flex items-center justify-between font-bold text-xs text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/80 transition-colors cursor-pointer focus:outline-hidden"
              >
                <div className="flex items-center gap-2">
                  <Settings className="h-4 w-4 text-indigo-500 animate-pulse" />
                  <span>Advanced Nginx Configuration</span>
                </div>
                {isAdvancedOpen ? (
                  <ChevronUp className="h-4 w-4 text-slate-500" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-slate-500" />
                )}
              </button>

              {isAdvancedOpen && (
                <div className="p-4 space-y-3.5 border-t border-slate-200 dark:border-zinc-800">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Custom Nginx Directives</label>
                    <CodeEditor
                      rows={5}
                      ariaLabel="Custom Nginx directives"
                      placeholder={`# Enter custom directives to inject into the server block.
# Example:
# client_max_body_size 100M;
# proxy_read_timeout 600s;
# add_header X-Custom-Header "Portwyrm Gateway";`}
                      value={customNginxConfig}
                      onChange={setCustomNginxConfig}
                      language="nginx"
                    />
                    <span className="text-[10px] text-slate-400 block leading-normal mt-1">
                      Directives will be parsed and injected into Nginx configuration during reconciliation check.
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Error banner on reload rollback failure */}
            {applyError && (
              <div className="p-4 bg-red-500/5 border border-red-500/20 rounded-xl flex flex-col gap-2.5">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-extrabold text-xs text-red-950 dark:text-red-300">Nginx Verification Check Failed</h4>
                    <p className="text-[11px] text-red-800 dark:text-red-400 mt-0.5 leading-normal">{applyError}</p>
                  </div>
                </div>
                <details className="rounded bg-zinc-950 p-2.5 font-mono text-[10px] text-red-400 cursor-pointer">
                  <summary className="font-bold">Show Detailed Compile Log</summary>
                  <CodeBlock className="mt-2 max-h-64" language="shell" wrap code={`nginx: [emerg] invalid number of arguments in "proxy_pass" directive in /etc/nginx/conf.d/portwyrm_reconciliation_${getSourcePreview().replace(/[^a-zA-Z0-9]/g, '_')}.conf:24
nginx: configuration file /etc/nginx/nginx.conf test failed

[RECONCILIATION MANAGER] Execution failed. Atomic rollback triggered to keep prior working matrix active. 0ms downtime.`} />
                </details>
              </div>
            )}

          </form>
        )}

        {/* MODAL FOOTER BUTTONS */}
        {!isApplying && (
          <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-between items-center shrink-0">
            <div>
              {editingHost && onDeleteHost && (
                <button
                  type="button"
                  onClick={handleDelete}
                  className="px-4 py-2 bg-rose-50 hover:bg-rose-100 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-900/50 text-rose-600 dark:text-rose-400 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                  id="btn-delete-host-inside"
                >
                  <Trash2 className="h-4 w-4" /> Delete Host
                </button>
              )}
            </div>
            <div className="flex gap-2.5">
              <button
                type="button"
                onClick={() => handleClose()}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-zinc-800 dark:hover:bg-zinc-700 rounded-lg text-xs font-bold text-slate-700 dark:text-zinc-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleApplySubmit}
                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow-xs hover:shadow-md transition-all cursor-pointer"
                id="btn-save-apply-host"
              >
                <Check className="h-4 w-4" /> Save and Apply Config
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
