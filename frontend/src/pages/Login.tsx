import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ShieldAlert, Sparkles, Server, Lock, User, KeyRound } from 'lucide-react';
import { SideRays } from '../components/SideRays';
import { ImapConnectModal } from '../components/ImapConnectModal';
import { DemoScenarioModal } from '../components/DemoScenarioModal';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated, login, authError: contextAuthError } = useAuth();

  const [isImapOpen, setIsImapOpen] = useState(false);
  const [isDemoOpen, setIsDemoOpen] = useState(false);
  const [isLoginLoading, setIsLoginLoading] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const authError = localError || contextAuthError;

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('oauth_error')) {
      setLocalError(`Authentication error: ${params.get('oauth_error')}`);
    } else if (isAuthenticated) {
      navigate('/monitoring', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!username.trim() || !password.trim()) {
      setLocalError('Username and password are required.');
      return;
    }

    setIsLoginLoading(true);
    try {
      await login(username.trim(), password);
      navigate('/monitoring');
    } catch (err: any) {
      setLocalError(err.message || 'Login failed. Check your credentials.');
    } finally {
      setIsLoginLoading(false);
    }
  };

  const connectGmail = () => {
    // OAuth tokens stay on the backend. Google returns to this local app
    // after consent, and AuthContext recognizes the authorized mailbox.
    window.location.assign('http://127.0.0.1:8000/api/v1/oauth/gmail/connect');
  };

  return (
    <div className="relative min-h-screen bg-[#07090E] text-white flex flex-col justify-between overflow-hidden selection:bg-[#EAB308]/30 selection:text-[#EAB308]">

      {/* 1. BACKGROUND SIDERAYS */}
      <div className="absolute -top-32 -right-32 pointer-events-none z-0 overflow-hidden opacity-85">
        <div style={{ width: '1080px', height: '1080px', position: 'relative' }}>
          <SideRays
            rayColor1="#EAB308"
            rayColor2="#96c8ff"
            origin="top-right"
            speed={1.9}
            intensity={1.4}
            spread={1.8}
            tilt={-21}
            saturation={1.5}
            blend={0.75}
            falloff={1.6}
            opacity={1}
          />
        </div>
      </div>

      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:32px_32px] opacity-25 pointer-events-none z-0"></div>

      {/* TOP BRAND NAVIGATION BAR */}
      <header className="relative z-10 w-full max-w-7xl mx-auto px-6 sm:px-12 py-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="size-10 rounded-2xl bg-gradient-to-br from-[#EAB308] to-amber-600 flex items-center justify-center shadow-lg shadow-amber-500/20 ring-1 ring-white/20">
            <Shield className="size-5 text-black" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-black tracking-tightest text-white font-mono">TRACEGUARD</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-[#EAB308]/20 text-[#EAB308] border border-[#EAB308]/30">AI</span>
            </div>
            <p className="text-[10px] text-neutral-400 font-mono tracking-wider uppercase">Forensic Intelligence System</p>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-xs font-mono text-neutral-400">
          <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>SYSTEM OPERATIONAL &bull; V1.0</span>
        </div>
      </header>

      {/* 2. MAIN EDITORIAL TWO-COLUMN WORKSPACE */}
      <main className="relative z-10 w-full max-w-7xl mx-auto px-6 sm:px-12 py-8 sm:py-16 flex-1 flex flex-col lg:flex-row items-center justify-between gap-12 lg:gap-16">

        {/* LEFT COLUMN */}
        <div className="flex-1 space-y-8 max-w-2xl text-left">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/5 border border-white/10 text-xs font-mono text-[#EAB308] backdrop-blur-md">
            <span className="size-2 rounded-full bg-[#EAB308]"></span>
            <span>Digital Evidence &amp; Threat Reconstruction</span>
          </div>

          <div className="space-y-4">
            <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tightest leading-[1.05] text-white">
              EVERY EMAIL<br />
              <span className="bg-gradient-to-r from-[#EAB308] via-amber-200 to-[#96c8ff] bg-clip-text text-transparent">
                LEAVES A TRAIL.
              </span>
            </h1>

            <p className="text-base sm:text-lg text-neutral-400 max-w-xl font-normal leading-relaxed pt-2">
              TRACEGUARD reconstructs the identity, infrastructure, and intent behind every incoming message. Autonomous threat defense engineered for high-consequence corporate environments.
            </p>
          </div>

          <div className="pt-6 border-t border-white/10">
            <div className="text-[10px] font-mono tracking-widest text-neutral-500 uppercase mb-3">
              Forensic Analysis Pipeline
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-neutral-300">
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">EMAIL</span>
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">IDENTITY</span>
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">INFRASTRUCTURE</span>
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">INTELLIGENCE</span>
              <span className="px-2.5 py-1 rounded-lg bg-[#EAB308]/15 text-[#EAB308] border border-[#EAB308]/30 font-bold">VERDICT</span>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: LOGIN CARD */}
        <div className="w-full max-w-md">
          <div className="relative rounded-3xl bg-[#0F141C]/80 backdrop-blur-xl border border-white/15 p-8 sm:p-10 shadow-2xl space-y-7 ring-1 ring-white/5">

            <div className="space-y-2">
              <span className="text-[10px] font-mono tracking-widest text-[#EAB308] uppercase font-bold">
                TRACEGUARD AI
              </span>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Sign in to your console
              </h2>
              <p className="text-xs text-neutral-400">
                Authenticate with your analyst credentials to start real-time threat monitoring.
              </p>
            </div>

            {authError && (
              <div className="p-3.5 rounded-2xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2.5">
                <ShieldAlert className="size-4 shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            {/* USERNAME / PASSWORD LOGIN FORM */}
            <form onSubmit={handleLogin} className="space-y-3 pt-2">
              <div className="relative">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 size-4 text-neutral-500" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Username (e.g. analyst_01)"
                  className="w-full pl-11 pr-4 py-3.5 rounded-2xl bg-white/5 border border-white/10 text-white text-sm placeholder:text-neutral-500 focus:outline-none focus:border-[#EAB308]/50 transition-all"
                  autoComplete="username"
                />
              </div>

              <div className="relative">
                <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 size-4 text-neutral-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  className="w-full pl-11 pr-4 py-3.5 rounded-2xl bg-white/5 border border-white/10 text-white text-sm placeholder:text-neutral-500 focus:outline-none focus:border-[#EAB308]/50 transition-all"
                  autoComplete="current-password"
                />
              </div>

              <button
                type="submit"
                disabled={isLoginLoading}
                className="w-full flex items-center justify-center gap-3 px-6 py-3.5 rounded-2xl bg-gradient-to-r from-[#EAB308] to-amber-600 hover:brightness-110 text-black font-bold text-sm shadow-xl shadow-amber-500/10 hover:scale-[1.01] active:scale-[0.99] transition-all disabled:opacity-50"
              >
                <span>{isLoginLoading ? 'Authenticating...' : 'Sign In'}</span>
              </button>

              {/* DIVIDER */}
              <div className="relative py-2 flex items-center justify-center">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-white/10"></div>
                </div>
                <span className="relative px-3 bg-[#0F141C] text-[10px] font-mono tracking-widest text-neutral-500 uppercase">
                  OR CONNECT MAILBOX
                </span>
              </div>

              <button
                type="button"
                onClick={connectGmail}
                className="w-full flex items-center justify-center gap-2.5 px-4 py-3 rounded-2xl bg-[#4285F4]/15 hover:bg-[#4285F4]/25 text-white text-xs font-bold border border-[#4285F4]/30 transition-all"
              >
                <span className="text-sm">G</span>
                <span>Continue with connected Gmail</span>
              </button>

              <button
                type="button"
                onClick={() => setIsImapOpen(true)}
                className="w-full flex items-center justify-center gap-2.5 px-4 py-3 rounded-2xl bg-white/5 hover:bg-white/10 text-neutral-300 hover:text-white text-xs font-bold border border-white/10 transition-all"
              >
                <Server className="size-4 text-[#EAB308]" />
                <span>Connect with IMAP</span>
              </button>

              <button
                type="button"
                onClick={() => setIsDemoOpen(true)}
                className="w-full flex items-center justify-between px-4 py-3 rounded-2xl bg-gradient-to-r from-amber-500/10 to-[#96c8ff]/10 hover:from-amber-500/20 hover:to-[#96c8ff]/20 text-white text-xs font-bold border border-white/15 transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <Sparkles className="size-4 text-[#EAB308]" />
                  <span>Enter Demo Environment</span>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[9px] font-mono bg-[#EAB308]/20 text-[#EAB308] border border-[#EAB308]/30">
                  DEMO MODE
                </span>
              </button>
            </form>

            <div className="pt-4 border-t border-white/10 flex items-center justify-between text-[11px] text-neutral-400 font-mono">
              <div className="flex items-center gap-1.5">
                <Lock className="size-3 text-[#EAB308]" />
                <span>Tokens encrypted at rest</span>
              </div>
              <span>Credentials never stored</span>
            </div>

          </div>
        </div>

      </main>

      {/* FOOTER */}
      <footer className="relative z-10 w-full max-w-7xl mx-auto px-6 sm:px-12 py-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-neutral-500 border-t border-white/5">
        <div>
          TRACEGUARD AI &bull; Autonomous Forensic Detection &amp; Threat Defense
        </div>
        <div className="flex items-center gap-6">
          <span className="hover:text-neutral-300 cursor-pointer">Security Whitepaper</span>
          <span className="hover:text-neutral-300 cursor-pointer">Data Handling Policy</span>
          <span className="hover:text-neutral-300 cursor-pointer">API Reference</span>
        </div>
      </footer>

      {/* MODALS */}
      <ImapConnectModal
        isOpen={isImapOpen}
        onClose={() => setIsImapOpen(false)}
        onSuccess={() => navigate('/monitoring')}
      />

      <DemoScenarioModal
        isOpen={isDemoOpen}
        onClose={() => setIsDemoOpen(false)}
        onSuccess={() => navigate('/monitoring')}
      />

    </div>
  );
};
