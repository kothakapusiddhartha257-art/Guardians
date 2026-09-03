import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, FileSearch, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';

interface ThreatOverviewProps { onOpenUpload: () => void; }
export const ThreatOverview: React.FC<ThreatOverviewProps> = ({ onOpenUpload }) => {
  const [reports, setReports] = useState<any[]>([]);
  useEffect(() => { api.getInvestigationHistory().then(setReports).catch(() => setReports([])); }, []);
  const critical = reports.filter(item => item.classification === 'CRITICAL').length;
  const suspicious = reports.filter(item => item.classification === 'SUSPICIOUS').length;
  const safe = reports.filter(item => item.classification === 'SAFE').length;
  const badge = (item: any) => item.classification === 'CRITICAL' ? 'bg-threatCritical/10 text-threatCritical border-threatCritical/30' : item.classification === 'SUSPICIOUS' ? 'bg-threatHigh/10 text-threatHigh border-threatHigh/30' : 'bg-threatSafe/10 text-threatSafe border-threatSafe/30';
  return <div className="max-w-6xl mx-auto px-6 py-10 space-y-8 animate-in fade-in duration-300">
    <section className="flex flex-col md:flex-row md:items-end md:justify-between gap-5"><div><p className="eyebrow text-primary">Email protection</p><h1 className="text-4xl font-black text-primaryText">Threat Overview</h1><p className="mt-2 text-secondaryText">Your latest email checks, explained simply.</p></div><div className="flex gap-3"><Link to="/monitoring" className="px-5 py-3 rounded-xl bg-primary text-white font-bold text-sm">Scan Gmail</Link><button onClick={onOpenUpload} className="px-5 py-3 rounded-xl border border-border bg-surface text-primaryText font-bold text-sm">Upload .eml</button></div></section>
    <section className="grid grid-cols-1 sm:grid-cols-4 gap-4">{[['Reports stored', reports.length, FileSearch, 'text-primary'], ['Critical', critical, ShieldAlert, 'text-threatCritical'], ['Suspicious', suspicious, AlertTriangle, 'text-threatHigh'], ['Safe', safe, CheckCircle2, 'text-threatSafe']].map(([label, value, Icon, tone]: any) => <div key={label} className="p-5 rounded-2xl bg-surface border border-border"><Icon className={`size-5 ${tone}`} /><div className="mt-4 text-3xl font-black text-primaryText">{value}</div><div className="mt-1 text-sm text-secondaryText">{label}</div></div>)}</section>
    <section className="rounded-3xl bg-surface border border-border overflow-hidden"><div className="px-6 py-5 border-b border-border flex justify-between"><div><h2 className="font-black text-xl text-primaryText">Recent investigations</h2><p className="text-xs text-mutedText mt-1">The latest 20 reports are saved locally.</p></div><Link to="/investigation" className="text-sm font-bold text-primary">View all</Link></div>{reports.length ? <div className="divide-y divide-border">{reports.slice(0, 5).map((item) => <Link key={item.email_id} to={`/report/${item.email_id}`} className="flex items-center justify-between gap-4 px-6 py-4 hover:bg-surfaceSubtle"><div className="min-w-0"><div className="font-bold text-primaryText truncate">{item.subject}</div><div className="text-xs text-mutedText mt-1 truncate">{item.from_address}</div></div><span className={`shrink-0 px-2.5 py-1 rounded-lg border text-xs font-mono font-bold ${badge(item)}`}>{item.classification} · {Math.round((item.threat_score || 0) * 100)}%</span></Link>)}</div> : <div className="p-10 text-center text-secondaryText"><ShieldCheck className="size-9 mx-auto text-primary mb-3"/>No investigations yet. Scan Gmail or upload an email to begin.</div>}</section>
  </div>;
};
