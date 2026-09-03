import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ShieldAlert, Sparkles, Server, Lock, ArrowRight, CheckCircle2, ChevronRight } from 'lucide-react';
import { SideRays } from '../components/SideRays';
import { ImapConnectModal } from '../components/ImapConnectModal';
import { DemoScenarioModal } from '../components/DemoScenarioModal';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated, loginWithGoogle, loginWithMicrosoft } = useAuth();

  const [isImapOpen, setIsImapOpen] = useState(false);
  const [isDemoOpen, setIsDemoOpen] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [isMsLoading, setIsMsLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    // Check URL parameters for OAuth errors
    const params = new URLSearchParams(window.location.search);
    if (params.get('oauth_error')) {
      setAuthError(`Authentication error: ${params.get('oauth_error')}`);
    } else if (params.get('gmail_connected') === 'true') {
      navigate('/monitoring', { replace: true });
    } else if (isAuthenticated) {
      navigate('/monitoring', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleGoogleLogin = async () => {
    setIsGoogleLoading(true);
    setAuthError(null);
    try {
      await loginWithGoogle();
    } catch (err: any) {
      setAuthError(err.message || 'Failed to initiate Google authentication');
      setIsGoogleLoading(false);
    }
  };

  const handleMicrosoftLogin = async () => {
    setIsMsLoading(true);
    setAuthError(null);
    try {
      await loginWithMicrosoft();
      navigate('/monitoring');
    } catch (err: any) {
      setAuthError(err.message || 'Failed to connect Microsoft 365');
    } finally {
      setIsMsLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen bg-[#07090E] text-white flex flex-col justify-between overflow-hidden selection:bg-[#EAB308]/30 selection:text-[#EAB308]">
      
      {/* 1. BACKGROUND SIDERAYS (EXACT REACT-BITS LIGHTING ENGINE) */}
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

      {/* Ambient Depth Grid */}
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
        
        {/* LEFT COLUMN: EDITORIAL TYPOGRAPHY & FORENSIC INTEL */}
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

          {/* Forensic Pipeline Visual Progression (Minimalist) */}
          <div className="pt-6 border-t border-white/10">
            <div className="text-[10px] font-mono tracking-widest text-neutral-500 uppercase mb-3">
              Forensic Analysis Pipeline
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-neutral-300">
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">EMAIL</span>
              <ChevronRight className="size-3 text-neutral-500" />
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">IDENTITY</span>
              <ChevronRight className="size-3 text-neutral-500" />
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">INFRASTRUCTURE</span>
              <ChevronRight className="size-3 text-neutral-500" />
              <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10">INTELLIGENCE</span>
              <ChevronRight className="size-3 text-neutral-500" />
              <span className="px-2.5 py-1 rounded-lg bg-[#EAB308]/15 text-[#EAB308] border border-[#EAB308]/30 font-bold">VERDICT</span>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: AUTHENTICATION / CONNECTION CARD */}
        <div className="w-full max-w-md">
          <div className="relative rounded-3xl bg-[#0F141C]/80 backdrop-blur-xl border border-white/15 p-8 sm:p-10 shadow-2xl space-y-7 ring-1 ring-white/5">
            
            <div className="space-y-2">
              <span className="text-[10px] font-mono tracking-widest text-[#EAB308] uppercase font-bold">
                TRACEGUARD AI
              </span>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Connect your workspace
              </h2>
              <p className="text-xs text-neutral-400">
                Authenticate your corporate identity to start real-time threat monitoring.
              </p>
            </div>

            {/* Error Banner */}
            {authError && (
              <div className="p-3.5 rounded-2xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2.5">
                <ShieldAlert className="size-4 shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            {/* Connection Actions */}
            <div className="space-y-3 pt-2">
              
              {/* PRIMARY OPTION: GOOGLE OAUTH */}
              <button
                onClick={handleGoogleLogin}
                disabled={isGoogleLoading}
                className="w-full flex items-center justify-center gap-3 px-6 py-3.5 rounded-2xl bg-white hover:bg-neutral-100 text-neutral-900 font-bold text-sm shadow-xl shadow-white/5 hover:scale-[1.01] active:scale-[0.99] transition-all disabled:opacity-50 group"
              >
                <svg className="size-4 shrink-0" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                </svg>
                <span>{isGoogleLoading ? 'Connecting securely...' : 'Continue with Google'}</span>
              </button>

              {/* ENTERPRISE OPTION: MICROSOFT OAUTH */}
              <button
                onClick={handleMicrosoftLogin}
                disabled={isMsLoading}
                className="w-full flex items-center justify-center gap-3 px-6 py-3.5 rounded-2xl bg-white/5 hover:bg-white/10 text-white font-bold text-sm border border-white/10 hover:border-white/20 transition-all disabled:opacity-50"
              >
                <svg className="size-4 shrink-0" viewBox="0 0 23 23">
                  <path fill="#f35325" d="M1 1h10v10H1z"/>
                  <path fill="#81bc06" d="M12 1h10v10H12z"/>
                  <path fill="#05a6f0" d="M1 12h10v10H1z"/>
                  <path fill="#ffba08" d="M12 12h10v10H12z"/>
                </svg>
                <span>{isMsLoading ? 'Connecting Microsoft 365...' : 'Continue with Microsoft'}</span>
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

              {/* SECONDARY PROTOCOLS */}
              <button
                onClick={() => setIsImapOpen(true)}
                className="w-full flex items-center justify-center gap-2.5 px-4 py-3 rounded-2xl bg-white/5 hover:bg-white/10 text-neutral-300 hover:text-white text-xs font-bold border border-white/10 transition-all"
              >
                <Server className="size-4 text-[#EAB308]" />
                <span>Connect with IMAP</span>
              </button>

              {/* PRESENTATION DEMO ENVIRONMENT (SEPARATED) */}
              <button
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

            </div>

            {/* TRUST & SECURITY DISCLOSURE */}
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
