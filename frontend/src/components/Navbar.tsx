import React, { useState, useRef, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Radio, LayoutDashboard, Search, FolderGit2,
  UploadCloud, Cpu, ChevronDown, RefreshCw, LogOut, Check, Plus, Server, Sparkles
} from 'lucide-react';
import { ThemeSwitcher } from './ThemeSwitcher';
import { useAuth } from '../context/AuthContext';
import { ImapConnectModal } from './ImapConnectModal';

interface NavbarProps {
  onOpenUpload: () => void;
}

const NAV_ITEMS = [
  { path: '/monitoring', label: 'Live Gateway', icon: Radio, pulse: true },
  { path: '/dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
  { path: '/investigation', label: 'Investigation', icon: Search },
  { path: '/cases', label: 'Case Management', icon: FolderGit2 },
];

export const Navbar: React.FC<NavbarProps> = ({ onOpenUpload }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, activeMailbox, connectedMailboxes, logout, selectMailbox, disconnectMailbox } = useAuth();

  const [isAccountMenuOpen, setIsAccountMenuOpen] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [isImapModalOpen, setIsImapModalOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsAccountMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isActive = (path: string) => {
    if (path === '/monitoring') return location.pathname === '/monitoring';
    return location.pathname.startsWith(path);
  };

  const handleSyncNow = async () => {
    setIsSyncing(true);
    try {
      if (activeMailbox?.provider === 'gmail') {
        await fetch('/api/v1/oauth/gmail/sync-now', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ limit: 20 })
        });
      } else {
        await fetch('/api/v1/gmail/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ max_emails: 20 })
        });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSyncing(false);
      setIsAccountMenuOpen(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="sticky top-0 z-40 w-full backdrop-blur-xl bg-app/80 border-b border-border/60 transition-colors">
      <div className="w-full mx-auto px-6 xl:px-10 h-18 flex items-center gap-4">
        
        {/* Brand Identity */}
        <Link to="/monitoring" className="flex items-center gap-3.5 group flex-shrink-0">
          <div className="size-9 rounded-xl bg-gradient-to-br from-primary via-primaryDark to-surfaceElevated flex items-center justify-center text-white shadow-lg shadow-primary/20 group-hover:scale-105 transition-all">
            <Shield className="size-5" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-base tracking-tight text-primaryText font-mono">
                TRACEGUARD
              </span>
              <span className="eyebrow text-[10px] text-primary px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20">
                AI
              </span>
            </div>
            <span className="text-[11px] text-mutedText font-mono tracking-tight hidden sm:block">
              Digital Evidence &amp; Threat Reconstruction
            </span>
          </div>
        </Link>

        {/* Center Navigation Links */}
        <nav className="hidden lg:flex flex-1 justify-center items-center gap-1 p-1 rounded-2xl bg-surfaceSubtle/60 border border-border/50">
          {NAV_ITEMS.map((item) => {
            const active = isActive(item.path);
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`relative px-4 py-2 rounded-xl text-xs font-medium transition-all flex items-center gap-2 ${
                  active
                    ? 'text-primaryText font-semibold'
                    : 'text-secondaryText hover:text-primaryText hover:bg-surfaceElevated/40'
                }`}
              >
                {active && (
                  <motion.div
                    layoutId="navbar-active-pill"
                    className="absolute inset-0 bg-surfaceElevated rounded-xl border border-border shadow-sm"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <span className="relative z-10 flex items-center gap-2">
                  <Icon className={`size-3.5 ${active ? 'text-primary' : 'text-mutedText'}`} />
                  <span>{item.label}</span>
                  {item.pulse && (
                    <span className="size-1.5 rounded-full bg-threatCritical animate-ping" />
                  )}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Right Action Tools & Connected Account Menu */}
        <div className="flex shrink-0 items-center gap-3">
          
          {/* Theme Switcher */}
          <ThemeSwitcher />

          {/* CONNECTED ACCOUNT MENU (MASTER PLAN PHASES 9 & 10) */}
          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setIsAccountMenuOpen(!isAccountMenuOpen)}
              className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated border border-border text-xs font-medium transition-all"
            >
              <span className="size-2 rounded-full bg-threatSafe animate-pulse"></span>
              <div className="flex flex-col text-left">
                <span className="font-bold text-[11px] text-primaryText font-mono">
                  {activeMailbox?.provider === 'gmail' && 'Gmail Connected'}
                  {activeMailbox?.provider === 'microsoft' && 'Microsoft 365'}
                  {activeMailbox?.provider === 'imap' && 'IMAP Connected'}
                  {activeMailbox?.provider === 'demo' && 'Demo Environment'}
                  {!activeMailbox && 'Connected Account'}
                </span>
                <span className="text-[10px] text-mutedText truncate max-w-[120px]">
                  {activeMailbox?.email || user?.email || 'analyst@traceguard.sec'}
                </span>
              </div>
              <ChevronDown className="size-3 text-mutedText" />
            </button>

            {/* Dropdown Menu */}
            <AnimatePresence>
              {isAccountMenuOpen && (
                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 6, scale: 0.95 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 mt-2 w-72 rounded-2xl bg-surface border border-border shadow-2xl p-4 z-50 space-y-4"
                >
                  <div className="pb-3 border-b border-border/80">
                    <div className="eyebrow text-[9px] text-mutedText uppercase mb-1">Active Account</div>
                    <div className="font-bold text-sm text-primaryText truncate">
                      {activeMailbox?.email || user?.email || 'SecOps Lead'}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-threatSafe/15 text-threatSafe border border-threatSafe/30">
                        <span className="size-1.5 rounded-full bg-threatSafe"></span>
                        CONNECTED
                      </span>
                      <span className="text-[10px] font-mono text-mutedText">
                        {activeMailbox?.provider?.toUpperCase() || 'GOOGLE'}
                      </span>
                    </div>
                    <div className="text-[10px] text-mutedText font-mono mt-1.5">
                      Last sync: {activeMailbox?.last_synced_at ? new Date(activeMailbox.last_synced_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '11:42 AM'}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="space-y-1">
                    <button
                      onClick={handleSyncNow}
                      disabled={isSyncing}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:text-primaryText hover:bg-surfaceSubtle transition-colors"
                    >
                      <span className="flex items-center gap-2">
                        <RefreshCw className={`size-3.5 ${isSyncing ? 'animate-spin text-primary' : ''}`} />
                        <span>Sync Mailbox Now</span>
                      </span>
                      <span className="text-[10px] font-mono text-mutedText">Delta</span>
                    </button>

                    <button
                      onClick={() => { setIsAccountMenuOpen(false); setIsImapModalOpen(true); }}
                      className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:text-primaryText hover:bg-surfaceSubtle transition-colors"
                    >
                      <Plus className="size-3.5 text-primary" />
                      <span>Connect Another Mailbox</span>
                    </button>
                  </div>

                  {/* Connected Mailboxes List */}
                  {connectedMailboxes.length > 1 && (
                    <div className="pt-2 border-t border-border/80">
                      <div className="eyebrow text-[9px] text-mutedText uppercase mb-2">Switch Mailbox</div>
                      <div className="space-y-1 max-h-32 overflow-y-auto">
                        {connectedMailboxes.map((mb) => (
                          <div
                            key={mb.id}
                            onClick={() => selectMailbox(mb.id)}
                            className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs cursor-pointer transition-colors ${
                              mb.id === activeMailbox?.id
                                ? 'bg-primary/10 text-primary font-bold border border-primary/20'
                                : 'text-secondaryText hover:bg-surfaceSubtle'
                            }`}
                          >
                            <span className="truncate max-w-[180px]">{mb.email}</span>
                            {mb.id === activeMailbox?.id && <Check className="size-3" />}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Disconnect / Logout */}
                  <div className="pt-2 border-t border-border/80">
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold text-threatCritical hover:bg-threatCritical/10 transition-colors"
                    >
                      <LogOut className="size-3.5" />
                      <span>Disconnect &amp; Logout</span>
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Upload EML Ingestion CTA */}
          <button
            onClick={onOpenUpload}
            className="hidden 2xl:flex items-center gap-2 px-4 py-2 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
          >
            <UploadCloud className="size-4" />
            <span className="hidden sm:inline">Ingest .EML</span>
          </button>
        </div>
      </div>

      {/* Mobile/Tablet Sub-Navigation Bar */}
      <div className="lg:hidden flex items-center overflow-x-auto px-6 py-2 border-t border-border/40 gap-2 bg-surfaceSubtle/40">
        {NAV_ITEMS.map((item) => {
          const active = isActive(item.path);
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`px-3 py-1.5 rounded-lg text-xs whitespace-nowrap font-medium transition-colors ${
                active
                  ? 'bg-surfaceElevated text-primaryText font-bold border border-border'
                  : 'text-secondaryText hover:text-primaryText'
              }`}
            >
              {item.label}
            </Link>
          );
        })}
      </div>

      <ImapConnectModal
        isOpen={isImapModalOpen}
        onClose={() => setIsImapModalOpen(false)}
        onSuccess={() => setIsAccountMenuOpen(false)}
      />
    </header>
  );
};
