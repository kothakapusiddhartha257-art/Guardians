import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ShieldAlert, ShieldCheck, AlertOctagon, Activity, Share2, FileSearch,
  ArrowUpRight, Clock, ChevronRight, Zap, RefreshCw, ArrowRight,
  Mail, Server, Globe, Key, Shield, AlertTriangle
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { api } from '../api/client';

interface DashboardProps {
  onOpenUpload: () => void;
}

const CHAIN = [
  { label: 'Email Metadata', value: 'finance@micros0ft-security.com', tone: 'text-primaryText' },
  { label: 'Authentication', value: 'SPF FAIL · DKIM FAIL · DMARC FAIL', tone: 'text-threatCritical' },
  { label: 'SMTP Relay Chain', value: 'M365 → smtp-relay.net → ⚠ Frontier Hop', tone: 'text-threatHigh' },
  { label: 'Origin IP & Geo', value: '185.23.11.4 · Frankfurt, DE (AS208091)', tone: 'text-infra' },
  { label: 'Threat Intelligence', value: 'BEC Wire Transfer Directive · 94%', tone: 'text-threatCritical' },
  { label: 'Campaign Correlation', value: 'CAM-2026-08 · 4 previous cases linked', tone: 'text-attribution' },
  { label: 'Digital Evidence', value: 'SHA-256 preserved · Tamper-evident chain', tone: 'text-threatSafe' },
];

const AXES = [
  {
    n: '01',
    name: 'Threat Severity',
    value: 94,
    color: 'text-threatCritical',
    bgRing: 'stroke-threatCritical',
    question: 'How malicious and dangerous is the content and payload?',
    signals: ['Executive Impersonation', 'Urgent Wire Transfer Phrasing', 'Deceptive IP-Literal Link', 'Executable Masquerade'],
  },
  {
    n: '02',
    name: 'Infrastructure Trust',
    value: 83,
    color: 'text-infra',
    bgRing: 'stroke-infra',
    question: 'How trustworthy and cryptographically valid is the sending path?',
    signals: ['SPF Alignment Failure', 'DKIM Signature Mismatch', 'External Relay Boundary', 'Domain Age <15 Days'],
  },
  {
    n: '03',
    name: 'Attribution Confidence',
    value: 40,
    color: 'text-attribution',
    bgRing: 'stroke-attribution',
    question: 'Can the sending infrastructure be linked to a known campaign?',
    signals: ['Origin IP Cluster Match', 'Shared Threat Actor Domains', 'Historical Case Overlap', 'Multi-Tenant Proxies'],
  },
];

export const Dashboard: React.FC<DashboardProps> = ({ onOpenUpload }) => {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<any>(null);
  const [trend, setTrend] = useState<any[]>([]);
  const [recentThreats, setRecentThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [sumRes, trendRes, recentRes] = await Promise.all([
        api.getDashboardSummary(),
        api.getDashboardTrend(),
        api.getRecentThreats()
      ]);
      setSummary(sumRes);
      setTrend(trendRes);
      setRecentThreats(recentRes);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getScoreBadgeColor = (score: number) => {
    if (score >= 0.75) return 'bg-threatCritical/15 text-threatCritical border-threatCritical/30';
    if (score >= 0.35) return 'bg-threatMedium/15 text-threatMedium border-threatMedium/30';
    return 'bg-threatLow/15 text-threatLow border-threatLow/30';
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-16 animate-in fade-in duration-300">
      
      {/* 1. HERO SECTION: The Intelligence Chain */}
      <section className="space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
          <div className="space-y-3">
            <p className="eyebrow text-primary">Autonomous Cyber Intelligence & Forensic Reconstruction</p>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black text-primaryText tracking-tightest leading-none">
              The Forensic <br />
              <span className="text-mutedText font-light">Intelligence Chain.</span>
            </h1>
            <p className="text-xs sm:text-sm text-secondaryText max-w-xl leading-relaxed">
              TraceGuard unpacks inbound digital communication across eleven forensic dimensions before it ever touches a mailbox.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={onOpenUpload}
              className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-primaryText text-xs font-bold shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center gap-2"
            >
              <FileSearch className="size-4" />
              <span>Inspect Live Evidence (.EML)</span>
            </button>
            <Link
              to="/monitoring"
              className="px-4 py-2.5 rounded-xl bg-surface hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-semibold border border-border transition-colors flex items-center gap-1.5"
            >
              <Activity className="size-3.5 text-threatCritical animate-pulse" />
              <span>Live Threat Gateway &rarr;</span>
            </Link>
          </div>
        </div>

        {/* The 7-Step Step-Ladder Chain Flow */}
        <div className="p-7 rounded-3xl border border-border bg-surface shadow-2xl space-y-3">
          <div className="flex items-center justify-between border-b border-border/70 pb-3">
            <span className="eyebrow text-[10px]">Real-Time Forensics DAG Pipeline</span>
            <span className="eyebrow text-[10px] text-threatSafe">Zero-Trust Pipeline Active</span>
          </div>

          <div className="flex flex-col space-y-1 pt-2">
            {CHAIN.map((step, i) => (
              <motion.div
                key={step.label}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 + i * 0.05, duration: 0.3 }}
                className="flex items-start gap-4 p-2.5 rounded-xl hover:bg-surfaceElevated transition-colors"
              >
                <div className="mt-0.5 flex size-5 items-center justify-center rounded-full border border-border bg-surfaceSubtle text-[10px] font-mono font-bold text-secondaryText">
                  {i + 1}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="eyebrow text-[10px] text-mutedText">
                    {step.label}
                  </p>
                  <p className={`mt-0.5 truncate font-mono text-xs font-bold ${step.tone}`}>
                    {step.value}
                  </p>
                </div>
                <span className="text-[10px] font-mono text-mutedText flex-shrink-0 pt-0.5">
                  &bull;&bull;&bull;
                </span>
              </motion.div>
            ))}
          </div>

          <div className="mt-4 flex items-center justify-between rounded-2xl border border-threatCritical/40 bg-threatCritical/10 px-4 py-3">
            <span className="text-xs font-bold text-threatCritical">Final Decision-Level Verdict:</span>
            <span className="font-mono text-xs font-extrabold text-primaryText bg-threatCritical px-2.5 py-1 rounded-lg">
              MALICIOUS — 94% THREAT
            </span>
          </div>
        </div>
      </section>

      {/* 2. THE THREE-AXIS SIGNATURE MODEL HERO */}
      <section className="space-y-8 pt-6 border-t border-border/80">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <p className="eyebrow text-primary">The Three-Axis Intelligence Model</p>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-primaryText tracking-tight">
              Three Questions. One Calibrated Verdict.
            </h2>
          </div>
          <p className="max-w-md text-xs sm:text-sm text-secondaryText leading-relaxed">
            Rather than collapsing complex uncertainty into a single probability, TRACEGUARD exposes three mathematically independent axes so analysts always know what is dangerous, what is untrustworthy, and what is connected.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {AXES.map((axis) => (
            <div
              key={axis.n}
              className="p-7 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all space-y-6 shadow-xl relative overflow-hidden group"
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="eyebrow text-mutedText">{axis.n}</span>
                  <h3 className="text-xl font-black text-primaryText mt-1">{axis.name}</h3>
                </div>

                {/* SVG Radial Dial */}
                <div className="relative size-14 flex items-center justify-center flex-shrink-0">
                  <svg className="size-full -rotate-90" viewBox="0 0 36 36">
                    <path
                      className="text-surfaceSubtle stroke-current"
                      strokeWidth="3.5"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path
                      className={`${axis.bgRing}`}
                      strokeDasharray={`${axis.value}, 100`}
                      strokeWidth="3.5"
                      strokeLinecap="round"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                  </svg>
                  <span className={`absolute font-mono text-xs font-black ${axis.color}`}>
                    {axis.value}%
                  </span>
                </div>
              </div>

              <p className="text-xs text-secondaryText font-medium leading-relaxed">
                {axis.question}
              </p>

              <ul className="flex flex-col space-y-2 pt-4 border-t border-border/60 font-mono text-xs">
                {axis.signals.map((s, idx) => (
                  <li key={idx} className="flex items-center gap-2.5 text-secondaryText">
                    <span className={`size-1.5 rounded-full ${axis.color} bg-current`} />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* 3. FORENSIC LENSES GRID */}
      <section className="space-y-8 pt-6 border-t border-border/80">
        <div>
          <p className="eyebrow text-primary">Multi-Engine Digital Forensics</p>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-primaryText tracking-tight">
            Eleven Forensic Lenses into the Truth
          </h2>
          <p className="text-xs sm:text-sm text-secondaryText mt-1">
            Every email is unpacked across eleven deterministic and ML analysis engines.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Lens 1: Content NLP */}
          <div
            onClick={() => navigate('/investigation?lens=content')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">01 · Content NLP</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Understand what the attacker wants</h3>
            <p className="text-xs text-secondaryText leading-relaxed font-mono bg-surfaceSubtle p-3.5 rounded-2xl border border-border/70">
              "I need you to process an <span className="bg-threatCritical/20 text-threatCritical font-bold px-1 rounded">URGENT</span> request. <span className="bg-threatCritical/20 text-threatCritical font-bold px-1 rounded">Wire transfer immediately</span> to the account..."
            </p>
          </div>

          {/* Lens 2: Headers & Anomalies */}
          <div
            onClick={() => navigate('/investigation?lens=headers')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">02 · Header Forensics</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Find what the sender tried to hide</h3>
            <div className="space-y-2 font-mono text-xs">
              <div className="text-secondaryText">From: <span className="text-primaryText font-bold">ceo@company.com</span></div>
              <div className="p-2.5 rounded-xl bg-threatCritical/10 border border-threatCritical/30 text-threatCritical">
                Reply-To Mismatch: payment@external-diversion.co
              </div>
            </div>
          </div>

          {/* Lens 3: Authentication */}
          <div
            onClick={() => navigate('/investigation?lens=auth')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">03 · Authentication</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Verify cryptographic legitimacy</h3>
            <div className="grid grid-cols-2 gap-2 font-mono text-xs">
              <div className="p-2.5 rounded-xl bg-threatCritical/10 border border-threatCritical/20 text-threatCritical font-bold">
                SPF: FAIL
              </div>
              <div className="p-2.5 rounded-xl bg-threatCritical/10 border border-threatCritical/20 text-threatCritical font-bold">
                DKIM: FAIL
              </div>
              <div className="p-2.5 rounded-xl bg-threatCritical/10 border border-threatCritical/20 text-threatCritical font-bold">
                DMARC: FAIL
              </div>
              <div className="p-2.5 rounded-xl bg-threatSafe/10 border border-threatSafe/20 text-threatSafe font-bold">
                ARC: PASS
              </div>
            </div>
          </div>

          {/* Lens 4: SMTP Relay Frontier */}
          <div
            onClick={() => navigate('/investigation?lens=relay')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">04 · Relay Trust Frontier</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Backward SMTP hop traversal</h3>
            <div className="space-y-1.5 font-mono text-xs">
              <div className="text-threatSafe flex items-center gap-1">✓ Recipient MTA (Trusted)</div>
              <div className="text-threatWarning flex items-center gap-1">⚠ smtp-relay.net (Frontier)</div>
              <div className="text-threatCritical flex items-center gap-1">✗ 185.23.11.4 (Origin Server)</div>
            </div>
          </div>

          {/* Lens 5: Domains & Homoglyphs */}
          <div
            onClick={() => navigate('/investigation?lens=domains')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">05 · Domain Intelligence</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Lookalike & Homoglyph detection</h3>
            <div className="p-3 rounded-xl bg-surfaceSubtle border border-border/60 font-mono text-xs space-y-1">
              <div className="text-secondaryText">Target: <span className="text-primaryText font-bold">microsoft.com</span></div>
              <div className="text-threatCritical">Spoof: micr<span className="underline font-black">0</span>s0ft-security.com</div>
            </div>
          </div>

          {/* Lens 6: Campaign Graph */}
          <div
            onClick={() => navigate('/campaigns')}
            className="p-6 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all cursor-pointer space-y-4 shadow-md group"
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow text-[10px] text-primary">06 · Graph Correlation</span>
              <ArrowRight className="size-4 text-mutedText group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="text-base font-bold text-primaryText">Cross-case infrastructure reuse</h3>
            <div className="p-3 rounded-xl bg-attribution/10 border border-attribution/25 text-attribution font-mono text-xs flex items-center gap-2">
              <Share2 className="size-4 text-attribution" />
              <span>Origin IP appeared in 4 prior cases</span>
            </div>
          </div>
        </div>
      </section>

      {/* 4. SOC ANALYTICS & TIME-SERIES TREND */}
      <section className="space-y-6 pt-6 border-t border-border/80">
        <div className="flex items-center justify-between">
          <div>
            <p className="eyebrow text-primary">Temporal Analytics</p>
            <h2 className="text-2xl font-extrabold text-primaryText">7-Day Threat Volume Trend</h2>
          </div>
          <button
            onClick={loadData}
            className="p-2 rounded-xl bg-surface hover:bg-surfaceElevated text-secondaryText hover:text-primaryText border border-border transition-colors"
          >
            <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <div className="bg-surface p-6 rounded-3xl border border-border shadow-xl">
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--threat-critical)" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="var(--threat-critical)" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="becGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'var(--bg-surface-secondary)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)', borderRadius: '0.75rem', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="phishing" stroke="var(--threat-critical)" strokeWidth={2} fillOpacity={1} fill="url(#phishGrad)" />
                <Area type="monotone" dataKey="bec" stroke="var(--accent-primary)" strokeWidth={2} fillOpacity={1} fill="url(#becGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* 5. RECENT HIGH-RISK THREATS TABLE */}
      <section className="bg-surface rounded-3xl border border-border shadow-xl overflow-hidden space-y-4 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-primaryText">Recent High-Risk Investigations</h2>
            <p className="text-xs text-secondaryText">Click any threat to inspect full technical reconstruction and evidence dossier</p>
          </div>
          <button
            onClick={() => navigate('/cases')}
            className="text-xs font-bold text-primary hover:text-primaryDark flex items-center gap-1 transition-colors"
          >
            <span>View All Cases</span>
            <ChevronRight className="size-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border/80 text-secondaryText font-bold uppercase tracking-wider bg-surfaceSubtle">
                <th className="py-3 px-4">Threat Score</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">From Address</th>
                <th className="py-3 px-4">Case Reference</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40 font-mono">
              {recentThreats.map((threat) => (
                <tr
                  key={threat.email_id}
                  onClick={() => navigate(`/investigation?id=${threat.email_id}`)}
                  className="hover:bg-surfaceElevated cursor-pointer transition-colors group"
                >
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-1 rounded-lg text-xs font-extrabold border ${getScoreBadgeColor(threat.threat_score)}`}>
                        {Math.round(threat.threat_score * 100)}%
                      </span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 font-sans font-bold text-primaryText">
                    <span className="px-2 py-0.5 rounded bg-surfaceSubtle text-secondaryText border border-border">
                      {threat.classification}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-sans font-semibold text-primaryText max-w-xs truncate group-hover:text-primary transition-colors">
                    {threat.subject}
                  </td>
                  <td className="py-3.5 px-4 text-secondaryText max-w-xs truncate">
                    {threat.from_address}
                  </td>
                  <td className="py-3.5 px-4 text-secondaryText">
                    {threat.case_id}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <span className="px-3 py-1.5 rounded-lg bg-surfaceSubtle group-hover:bg-primary group-hover:text-white text-secondaryText text-xs font-bold transition-colors inline-flex items-center gap-1">
                      Inspect
                      <ChevronRight className="size-3" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
