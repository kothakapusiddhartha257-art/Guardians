import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Radio, LayoutDashboard, Search, FolderGit2, Network, UploadCloud, Cpu } from 'lucide-react';
import { ThemeSwitcher } from './ThemeSwitcher';

interface NavbarProps {
  onOpenUpload: () => void;
}

const NAV_ITEMS = [
  { path: '/monitoring', label: 'Live Gateway', icon: Radio, pulse: true },
  { path: '/', label: 'SOC Dashboard', icon: LayoutDashboard },
  { path: '/investigation', label: 'Investigation', icon: Search },
  { path: '/cases', label: 'Case Management', icon: FolderGit2 },
  { path: '/campaigns', label: 'Campaign Clusters', icon: Network },
];

export const Navbar: React.FC<NavbarProps> = ({ onOpenUpload }) => {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <header className="sticky top-0 z-40 w-full backdrop-blur-xl bg-app/80 border-b border-border/60 transition-colors">
      <div className="max-w-7xl mx-auto px-6 h-18 flex items-center justify-between gap-6">
        
        {/* Brand Identity */}
        <Link to="/" className="flex items-center gap-3.5 group flex-shrink-0">
          <div className="size-9 rounded-xl bg-gradient-to-br from-primary via-primaryDark to-surfaceElevated flex items-center justify-center text-white shadow-lg shadow-primary/20 group-hover:scale-105 transition-all">
            <Shield className="size-5" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-base tracking-tight text-primaryText">
                TRACEGUARD
              </span>
              <span className="eyebrow text-[10px] text-primary px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20">
                AI
              </span>
            </div>
            <span className="text-[11px] text-mutedText font-mono tracking-tight hidden sm:block">
              Digital Evidence & Threat Reconstruction
            </span>
          </div>
        </Link>

        {/* Center Navigation Links with Animated Active Indicator */}
        <nav className="hidden lg:flex items-center gap-1 p-1 rounded-2xl bg-surfaceSubtle/60 border border-border/50">
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

        {/* Right Action Tools */}
        <div className="flex items-center gap-3">
          {/* Active DAG status */}
          <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surfaceSubtle border border-border/60">
            <Cpu className="size-3.5 text-infra animate-pulse" />
            <span className="eyebrow text-[10px] text-secondaryText">DAG Engine Active</span>
          </div>

          {/* Theme Switcher */}
          <ThemeSwitcher />

          {/* Upload EML Ingestion CTA */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
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
    </header>
  );
};
