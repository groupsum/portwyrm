import React, { useState, useEffect } from 'react';
import { portwyrmStore } from '../store';
import { User, SystemHealth } from '../types';
import {
  Activity,
  Shield,
  Users,
  FileText,
  Settings as SettingsIcon,
  Globe,
  UserCheck,
  Sun,
  Moon,
  ChevronDown,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  Server,
  Key,
  LogOut,
  Sliders,
  CheckCircle2,
  AlertCircle,
  X,
  Info
} from 'lucide-react';
import AccountSettingsModal from './AccountSettingsModal';
import { can, HOST_PERMISSION_RESOURCES } from '../utils/permissions';
import { useFeedback } from './Feedback';

interface LayoutProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  onSignOut: () => void;
  children: React.ReactNode;
  storeState: {
    health: SystemHealth;
    currentUser: User;
    allUsers: User[];
  };
}

export default function Layout({ currentTab, onTabChange, onSignOut, children, storeState }: LayoutProps) {
  const feedback = useFeedback();
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);
  const [isAccountSettingsOpen, setIsAccountSettingsOpen] = useState(false);
  const [isHealthModalOpen, setIsHealthModalOpen] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('portwyrm_theme') as 'light' | 'dark') || 'light';
  });

  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('portwyrm_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const { health, currentUser } = storeState;

  // Determine Nginx status colors and text
  const getNginxStatusDetails = () => {
    switch (health.nginxState) {
      case 'Active':
        return {
          bg: 'bg-emerald-500/10 dark:bg-emerald-400/5',
          border: 'border-emerald-500/30 dark:border-emerald-400/20',
          text: 'text-emerald-700 dark:text-emerald-400',
          dot: 'bg-emerald-500 animate-pulse',
          label: 'Active & Secure'
        };
      case 'Reloading':
        return {
          bg: 'bg-amber-500/10 dark:bg-amber-400/5',
          border: 'border-amber-500/30 dark:border-amber-400/20',
          text: 'text-amber-700 dark:text-amber-400',
          dot: 'bg-amber-500 animate-spin',
          label: 'Reconciling Config'
        };
      case 'Degraded':
        return {
          bg: 'bg-red-500/10 dark:bg-red-400/5',
          border: 'border-red-500/30 dark:border-red-400/20',
          text: 'text-red-700 dark:text-red-400',
          dot: 'bg-red-500 animate-pulse',
          label: 'Drift Detected / Degraded'
        };
      default:
        return {
          bg: 'bg-gray-500/10 dark:bg-gray-400/5',
          border: 'border-gray-500/30 dark:border-gray-400/20',
          text: 'text-gray-700 dark:text-gray-400',
          dot: 'bg-gray-400',
          label: 'Unavailable'
        };
    }
  };

  const statusStyle = getNginxStatusDetails();

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-zinc-950 text-slate-800 dark:text-zinc-100 transition-colors duration-200">

      {/* TOP HEADER */}
      <header className="sticky top-0 z-40 bg-white dark:bg-zinc-900 border-b border-slate-200 dark:border-zinc-800 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">

            {/* Left: Branding */}
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-900 dark:bg-zinc-100 rounded-lg text-white dark:text-zinc-900">
                <Globe className="h-6 w-6 animate-pulse" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-slate-900 to-indigo-800 dark:from-zinc-100 dark:to-zinc-300 bg-clip-text text-transparent">
                  Portwyrm
                </span>
                <span className="text-[10px] font-medium text-slate-500 dark:text-zinc-400 -mt-1 uppercase tracking-wider">
                  Reverse Proxy Plane
                </span>
              </div>
            </div>

            {/* Middle: Navigation */}
            <nav className="hidden md:flex items-center gap-1">
              {[
                { id: 'overview', label: 'Overview', icon: Activity, perm: true },
                { id: 'hosts', label: 'Hosts', icon: Globe, perm: HOST_PERMISSION_RESOURCES.some(resource => can(currentUser, resource, 'read')) },
                { id: 'access-lists', label: 'Access Lists', icon: Shield, perm: can(currentUser, 'access_lists', 'read') },
                { id: 'users', label: 'Users', icon: Users, perm: currentUser.role === 'Administrator' }, // admin only
                { id: 'audit', label: 'Audit', icon: FileText, perm: true },
                { id: 'settings', label: 'Settings', icon: SettingsIcon, perm: currentUser.role === 'Administrator' },
              ].map((tab) => {
                if (!tab.perm) return null;
                const Icon = tab.icon;
                const isActive = currentTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => onTabChange(tab.id)}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition-all duration-150 ${
                      isActive
                        ? 'bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900 dark:text-zinc-400 dark:hover:text-zinc-200 hover:bg-slate-100 dark:hover:bg-zinc-800/60'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                );
              })}
            </nav>

            {/* Right: Actions & User Cluster */}
            <div className="flex items-center gap-3">

              {/* Theme Control */}
              <button
                onClick={toggleTheme}
                className="p-2.5 rounded-lg text-slate-500 hover:text-slate-800 dark:text-zinc-400 dark:hover:text-zinc-100 hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors"
                title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
                id="theme-toggle-btn"
              >
                {theme === 'light' ? <Moon className="h-5 w-5" /> : <Sun className="h-5 w-5" />}
              </button>

              {/* User Dropdown Selector */}
              <div className="relative">
                <button
                  onClick={() => setIsUserDropdownOpen(!isUserDropdownOpen)}
                  className="flex items-center gap-3 text-left p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
                  id="user-menu-btn"
                >
                  <div className="w-9 h-9 rounded-full bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 font-bold text-sm flex items-center justify-center border-2 border-slate-200 dark:border-zinc-700">
                    {currentUser.displayName.split(' ').map(n => n[0]).join('')}
                  </div>

                  <div className="hidden sm:block leading-tight pr-1">
                    <div className="text-xs font-bold text-slate-800 dark:text-zinc-100 truncate max-w-[120px]">
                      {currentUser.displayName}
                    </div>
                    <div className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-zinc-400">
                      <span>{currentUser.username}</span>
                      <span>·</span>
                      <span>{currentUser.role}</span>
                    </div>
                  </div>
                  <ChevronDown className="h-4 w-4 text-slate-400" />
                </button>

                {isUserDropdownOpen && (
                  <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl shadow-xl z-50 overflow-hidden py-1.5">

                    <div className="px-4 py-2 border-b border-slate-100 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/45">
                      <div className="font-bold text-xs text-slate-800 dark:text-zinc-100">{currentUser.displayName}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{currentUser.username}</div>
                    </div>

                    <div className="p-1 space-y-0.5">
                      <button
                        onClick={() => {
                          setIsUserDropdownOpen(false);
                          setIsAccountSettingsOpen(true);
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 rounded-lg flex items-center gap-2 cursor-pointer"
                      >
                        <UserCheck className="h-3.5 w-3.5 text-slate-400" /> My account
                      </button>

                      <button
                        onClick={() => {
                          setIsUserDropdownOpen(false);
                          feedback.toast('Access token management is not available in this build.', 'info');
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 rounded-lg flex items-center gap-2 cursor-pointer"
                      >
                        <Key className="h-3.5 w-3.5 text-slate-400" /> Access tokens
                      </button>

                      <hr className="border-slate-100 dark:border-zinc-800/80 my-1" />

                      <button
                        onClick={() => {
                          setIsUserDropdownOpen(false);
                          onSignOut();
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs font-semibold text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg flex items-center gap-2 cursor-pointer"
                      >
                        <LogOut className="h-3.5 w-3.5" /> Sign out
                      </button>
                    </div>

                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      </header>

      <AccountSettingsModal
        open={isAccountSettingsOpen}
        currentUser={currentUser}
        onClose={() => setIsAccountSettingsOpen(false)}
        onSave={data => portwyrmStore.updateMyAccount(data)}
      />

      {/* MOBILE HEADER OVERFLOW */}
      <div className="md:hidden sticky top-[64px] z-30 bg-slate-100 dark:bg-zinc-800 border-b border-slate-200 dark:border-zinc-700 px-4 py-2 overflow-x-auto flex gap-1.5">
        {[
          { id: 'overview', label: 'Overview', perm: true },
          { id: 'hosts', label: 'Hosts', perm: HOST_PERMISSION_RESOURCES.some(resource => can(currentUser, resource, 'read')) },
          { id: 'access-lists', label: 'Access Lists', perm: can(currentUser, 'access_lists', 'read') },
          { id: 'users', label: 'Users', perm: currentUser.role === 'Administrator' },
          { id: 'audit', label: 'Audit', perm: true },
          { id: 'settings', label: 'Settings', perm: currentUser.role === 'Administrator' },
        ].map((tab) => {
          if (!tab.perm) return null;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`px-3 py-1 rounded-md text-xs font-semibold whitespace-nowrap transition-colors ${
                isActive
                  ? 'bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900'
                  : 'text-slate-600 dark:text-zinc-400 hover:bg-slate-200 dark:hover:bg-zinc-700'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* MAIN LAYOUT CONTAINER */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* PERSISTENT STATUS FOOTER */}
      <footer
        onClick={() => setIsHealthModalOpen(true)}
        className="sticky bottom-0 z-40 bg-white dark:bg-zinc-900 border-t border-slate-200 dark:border-zinc-800 py-3 px-4 sm:px-6 hover:bg-slate-50 dark:hover:bg-zinc-800/50 cursor-pointer transition-colors"
        id="status-footer"
      >
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">

          {/* Left: Overall Nginx State */}
          <div className="flex items-center gap-2.5">
            <div className={`flex items-center gap-2 px-2.5 py-1 rounded-full border ${statusStyle.bg} ${statusStyle.border} ${statusStyle.text} font-semibold`}>
              <span className={`w-2 h-2 rounded-full ${statusStyle.dot}`}></span>
              <span>Proxy Engine: {statusStyle.label}</span>
            </div>
            {health.driftDetected && (
              <span className="flex items-center gap-1 px-2 py-0.5 bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-400 rounded-sm font-bold animate-pulse">
                <AlertTriangle className="h-3.5 w-3.5" /> Drift Detected
              </span>
            )}
          </div>

          {/* Center: System statistics */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-slate-500 dark:text-zinc-400">
            <div className="flex items-center gap-1">
              <span className="font-bold text-slate-700 dark:text-zinc-300">{health.activeConnections}</span>
              <span>connections</span>
            </div>
            <div className="hidden sm:inline-block">•</div>
            <div className="flex items-center gap-4">
              <span>Reading: <strong className="text-slate-700 dark:text-zinc-300">{health.reading}</strong></span>
              <span>Writing: <strong className="text-slate-700 dark:text-zinc-300">{health.writing}</strong></span>
              <span>Waiting: <strong className="text-slate-700 dark:text-zinc-300">{health.waiting}</strong></span>
            </div>
          </div>

          {/* Right: Version and Active Generation details */}
          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500 dark:text-zinc-400">
            <div>
              DB: <span className="font-semibold text-slate-700 dark:text-zinc-300">{health.databaseBackend}</span>
            </div>
            <div className="text-slate-300 dark:text-zinc-700">|</div>
            <div>
              Applied Gen: <span className="bg-slate-100 dark:bg-zinc-800 text-slate-800 dark:text-zinc-300 px-1.5 py-0.5 rounded font-bold">#{health.currentGeneration}</span>
            </div>
            <div className="text-slate-300 dark:text-zinc-700">|</div>
            <div className="font-bold text-slate-700 dark:text-zinc-300 flex items-center gap-1">
              <Server className="h-3 w-3" /> {health.version}
            </div>
          </div>

        </div>
      </footer>

      {/* SYSTEM HEALTH MODAL (TRIGGERED FROM FOOTER) */}
      {isHealthModalOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl animate-in fade-in-50 zoom-in-95 duration-150">

            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-100 dark:border-zinc-800 flex items-center justify-between bg-slate-50 dark:bg-zinc-900/50">
              <div className="flex items-center gap-2.5">
                <Server className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                <h3 className="font-bold text-lg text-slate-900 dark:text-zinc-100">System Health & Diagnostics</h3>
              </div>
              <button
                onClick={() => setIsHealthModalOpen(false)}
                className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-zinc-800 text-slate-400 hover:text-slate-700 dark:hover:text-zinc-200"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">

              {/* Overall Status Alert banner */}
              <div className={`p-4 rounded-xl border flex items-start gap-3 ${
                health.driftDetected
                  ? 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-900 text-red-900 dark:text-red-300'
                  : 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900 text-emerald-900 dark:text-emerald-300'
              }`}>
                {health.driftDetected ? <AlertCircle className="h-5 w-5 mt-0.5 shrink-0 text-red-600 dark:text-red-400" /> : <CheckCircle2 className="h-5 w-5 mt-0.5 shrink-0 text-emerald-600 dark:text-emerald-400" />}
                <div>
                  <h4 className="font-bold text-sm">
                    {health.driftDetected ? 'System Out of Sync (Configuration Drift)' : 'Control Plane fully Synced'}
                  </h4>
                  <p className="text-xs mt-1 opacity-90">
                    {health.driftDetected
                      ? 'Drift was detected between Nginx’s disk configurations and Portwyrm’s local database state. An atomic synchronization reload is recommended.'
                      : 'All active routing matrices in Nginx correctly match Portwyrm’s desired definitions. Local proxy operations are operating without error.'}
                  </p>
                  {health.driftDetected && (
                    <button
                      onClick={() => {
                        portwyrmStore.resolveDrift();
                        setIsHealthModalOpen(false);
                      }}
                      className="mt-3 flex items-center gap-1.5 px-3 py-1.5 bg-red-600 text-white rounded-lg text-xs font-bold hover:bg-red-700 transition-colors"
                    >
                      <RefreshCw className="h-3 w-3" /> Reconcile & Synchronize Now
                    </button>
                  )}
                </div>
              </div>

              {/* Server Details Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">

                {/* Connections Panel */}
                <div className="p-4 bg-slate-50 dark:bg-zinc-800/40 rounded-xl border border-slate-100 dark:border-zinc-800">
                  <span className="text-[10px] font-bold text-slate-400 dark:text-zinc-500 uppercase tracking-wider block mb-2">Nginx Connections</span>
                  <div className="space-y-2 font-mono text-sm">
                    <div className="flex justify-between border-b border-slate-100 dark:border-zinc-800 pb-1.5">
                      <span className="text-slate-500">Active Handshakes:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.activeConnections}</strong>
                    </div>
                    <div className="flex justify-between pt-0.5 text-xs">
                      <span className="text-slate-500">Reading Stream:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.reading}</strong>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-500">Writing Upstream:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.writing}</strong>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-500">Keepalive Waiting:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.waiting}</strong>
                    </div>
                  </div>
                </div>

                {/* Software Environment Panel */}
                <div className="p-4 bg-slate-50 dark:bg-zinc-800/40 rounded-xl border border-slate-100 dark:border-zinc-800">
                  <span className="text-[10px] font-bold text-slate-400 dark:text-zinc-500 uppercase tracking-wider block mb-2">Environment State</span>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between border-b border-slate-100 dark:border-zinc-800 pb-1.5 font-mono">
                      <span className="text-slate-500 text-xs">Database Backend:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.databaseBackend}</strong>
                    </div>
                    <div className="flex justify-between pt-0.5 text-xs">
                      <span className="text-slate-500">Control Plane Version:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">{health.version}</strong>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-500">Applied Generation:</span>
                      <strong className="text-slate-800 dark:text-zinc-200">#{health.currentGeneration}</strong>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-500">Scheduler Daemon:</span>
                      <strong className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-bold">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        {health.schedulerState}
                      </strong>
                    </div>
                  </div>
                </div>

              </div>

              {/* Developer Testing Controls inside Diagnostics */}
              <div className="p-4 bg-indigo-50/50 dark:bg-indigo-950/10 border border-indigo-100 dark:border-indigo-950 rounded-xl">
                <h4 className="text-xs font-bold text-indigo-950 dark:text-indigo-300 flex items-center gap-1.5">
                  <Sliders className="h-3.5 w-3.5" /> Runtime Operations
                </h4>
                <p className="text-[11px] text-indigo-700/80 dark:text-indigo-400/80 mt-1">
                  Inject Nginx degradation states or trigger configuration drift to verify Portwyrm’s real-time safety, rollback procedures, and robust layout feedback.
                </p>
                <div className="mt-4 flex flex-wrap gap-3">
                  <button
                    onClick={() => {
                      portwyrmStore.resolveDrift();
                    }}
                    className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5 transition-colors ${
                      health.driftDetected
                        ? 'bg-emerald-600 hover:bg-emerald-700 text-white'
                        : 'bg-red-600 hover:bg-red-700 text-white'
                    }`}
                  >
                    <RefreshCw className="h-3 w-3" />
                    Refresh runtime state
                  </button>
                  <button
                    onClick={() => {
                      setIsHealthModalOpen(false);
                      onTabChange('settings');
                    }}
                    className="px-3 py-1.5 bg-slate-200 dark:bg-zinc-800 hover:bg-slate-300 dark:hover:bg-zinc-700 text-slate-800 dark:text-zinc-200 rounded text-xs font-bold flex items-center gap-1.5 transition-colors"
                  >
                    Open runtime settings
                  </button>
                </div>
              </div>

            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 bg-slate-50 dark:bg-zinc-900 border-t border-slate-100 dark:border-zinc-800 flex justify-end">
              <button
                onClick={() => setIsHealthModalOpen(false)}
                className="px-4 py-2 bg-slate-900 text-white dark:bg-zinc-100 dark:text-zinc-900 rounded-lg text-xs font-bold hover:bg-slate-800 dark:hover:bg-zinc-200 transition-colors"
              >
                Close Diagnostics
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
