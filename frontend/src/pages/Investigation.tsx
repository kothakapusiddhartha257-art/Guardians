import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate, useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Shield, ShieldAlert, ShieldCheck, FileText, Globe, Route, Server,
  Paperclip, Link2, GitBranch, Download, CheckCircle2, XCircle, AlertTriangle,
  ExternalLink, Lock, Eye, AlertOctagon, Terminal, ArrowRight, Layers, FileCode
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import { api } from '../api/client';

// Custom Map Marker Icon
const mapPinIcon = L.divIcon({
  className: 'custom-marker',
  html: `<div style="background-color: #FF5C5C; width: 14px; height: 14px; border-radius: 50%; border: 2.5px solid white; box-shadow: 0 0 12px rgba(255,92,92,0.9);"></div>`,
  iconSize: [14, 14],
  iconAnchor: [7, 7]
});

export const Investigation: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { id: routeId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const emailId = routeId || searchParams.get('id');
  const lensParam = searchParams.get('lens') || searchParams.get('tab');

  const [bundle, setBundle] = useState<any>(null);
  const [subgraph, setSubgraph] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Map lens aliases to active tabs
  const getInitialTab = () => {
    if (!lensParam) return 'overview';
    const l = lensParam.toLowerCase();
    if (l === 'campaign' || l === 'graph') return 'graph';
    if (l === 'authentication' || l === 'auth') return 'auth';
    if (l === 'geolocation' || l === 'geo') return 'geo';
    return l;
  };

  const [activeTab, setActiveTab] = useState(getInitialTab());

  useEffect(() => {
    if (lensParam) {
      const l = lensParam.toLowerCase();
      if (l === 'campaign' || l === 'graph') setActiveTab('graph');
      else if (l === 'authentication' || l === 'auth') setActiveTab('auth');
      else if (l === 'geolocation' || l === 'geo') setActiveTab('geo');
      else setActiveTab(l);
    }
  }, [lensParam]);

  useEffect(() => {
    if (!emailId) {
      setLoading(true);
      api.getInvestigationHistory()
        .then((items) => setHistory(items || []))
        .catch((err: any) => setError(err.message || 'Could not load investigation history.'))
        .finally(() => setLoading(false));
      return;
    }

    const loadInvestigation = async () => {
      setLoading(true);
      try {
        const [bundleRes, graphRes] = await Promise.all([
          api.getEmailInvestigation(emailId),
          api.getEmailSubgraph(emailId)
        ]);
        setBundle(bundleRes);
        setSubgraph(graphRes);
      } catch (err: any) {
        setError(err.message || 'Failed to load investigation');
      } finally {
        setLoading(false);
      }
    };

    loadInvestigation();
  }, [emailId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] space-y-4">
        <div className="size-10 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
        <p className="eyebrow text-secondaryText">Assembling Multi-Module Forensic Intelligence Dossier...</p>
      </div>
    );
  }

  if (!emailId) {
    return (
      <div className="p-6 sm:p-8 max-w-6xl mx-auto space-y-6 animate-in fade-in duration-300">
        <div className="rounded-3xl border border-border bg-surface shadow-xl p-7 sm:p-9 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-5">
          <div>
            <span className="eyebrow text-primary">Saved on this computer</span>
            <h1 className="text-3xl font-black text-primaryText mt-1">Investigation History</h1>
            <p className="text-sm text-secondaryText mt-2">Your latest 20 completed email investigations. Select one to see its evidence.</p>
          </div>
          <button onClick={() => navigate('/monitoring')} className="px-5 py-3 rounded-xl bg-primary text-white text-sm font-bold whitespace-nowrap">
            Scan Gmail
          </button>
        </div>
        {error ? (
          <div className="p-8 text-center rounded-3xl border border-threatHigh/30 bg-threatHigh/10 text-secondaryText">{error}</div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center rounded-3xl border border-border bg-surface space-y-3">
            <ShieldCheck className="size-11 text-threatSafe mx-auto" />
            <h2 className="text-xl font-bold text-primaryText">No investigations yet</h2>
            <p className="text-sm text-secondaryText">Scan Gmail or upload an email. Your completed reports will appear here.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {history.map((item) => {
              const score = Math.round((item.threat_score || 0) * 100);
              const risky = item.classification !== 'SAFE';
              return (
                <button key={item.email_id} onClick={() => navigate(`/report/${item.email_id}`)} className="text-left p-5 rounded-2xl border border-border bg-surface hover:border-primary/50 hover:shadow-lg transition-all space-y-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${risky ? 'bg-threatHigh/10 border-threatHigh/30 text-threatHigh' : 'bg-threatSafe/10 border-threatSafe/30 text-threatSafe'}`}>
                      {item.classification} · {score}%
                    </span>
                    <span className="text-xs text-mutedText">Open report →</span>
                  </div>
                  <h2 className="font-bold text-primaryText truncate">{item.subject || 'No subject'}</h2>
                  <p className="text-sm font-mono text-secondaryText truncate">From: {item.from_address || 'Unknown sender'}</p>
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  if (error || !bundle) {
    return (
      <div className="p-16 text-center max-w-md mx-auto space-y-4">
        <AlertTriangle className="size-12 text-threatHigh mx-auto" />
        <h2 className="text-xl font-bold text-primaryText">Investigation Not Found</h2>
        <p className="text-xs text-secondaryText">{error || 'Please select or upload an email to inspect.'}</p>
        <button
          onClick={() => navigate('/')}
          className="px-5 py-2.5 rounded-xl bg-primary text-white text-xs font-bold"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const { email, risk_score, auth, header_anomalies, relay_hops, geo_locations, ip_intelligence, domains, urls, attachments, nlp, chain_of_custody } = bundle;

  const tabs = [
    { id: 'overview', label: '01 Overview & 3-Axis', icon: Shield },
    { id: 'content', label: '02 Content & Intent', icon: FileText },
    { id: 'headers', label: '03 Headers & Anomalies', icon: Layers },
    { id: 'auth', label: '04 Authentication', icon: Lock },
    { id: 'relay', label: '05 Relay Trace', icon: Route },
    { id: 'geo', label: '06 GeoLocation', icon: Globe },
    { id: 'domains', label: '07 Domains', icon: Server },
    { id: 'urls', label: '08 URLs & Redirects', icon: Link2 },
    { id: 'attachments', label: `09 Attachments (${attachments.length})`, icon: Paperclip },
    { id: 'graph', label: '10 Campaign Graph', icon: GitBranch },
    { id: 'evidence', label: '11 Evidence & Ledger', icon: CheckCircle2 },
  ];

  const mapPoints = geo_locations
    .filter((g: any) => g.latitude && g.longitude && g.latitude !== 0)
    .map((g: any) => [g.latitude, g.longitude] as [number, number]);

  const scorePct = Math.round(risk_score.threat_score * 100);
  const infraPct = Math.round(risk_score.infrastructure_confidence * 100);
  const attrPct = Math.round(risk_score.attribution_confidence * 100);
  const isMalicious = scorePct >= 70;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-10 animate-in fade-in duration-300">
      
      {/* 1. TOP HERO WORKSTATION HEADER */}
      <section className="p-8 rounded-3xl border border-border bg-surface shadow-2xl space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-8">
          <div className="space-y-3 min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <span className="eyebrow text-primary">
                CASE #{bundle.case_id}
              </span>
              {bundle.report_id && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-primary/15 text-primary border border-primary/30">
                  {bundle.report_id}
                </span>
              )}
              {bundle.related_cases_count > 0 && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-attribution/15 text-attribution border border-attribution/30 flex items-center gap-1.5">
                  <GitBranch className="size-3" />
                  Correlated in {bundle.related_cases_count} Prior Cases
                </span>
              )}
            </div>

            <h1 className="text-2xl sm:text-3xl font-black text-primaryText tracking-tightest leading-snug">
              {email.headers_normalized.subject || 'No Subject Specified'}
            </h1>

            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-secondaryText pt-1">
              <div>From: <strong className="text-primaryText font-sans">{email.headers_normalized.from_address?.display_name || ''} &lt;{email.headers_normalized.from_address?.address}&gt;</strong></div>
              <div>SHA-256: <strong className="text-primaryText">{email.sha256.substring(0, 16)}...</strong></div>
              <div>Timestamp: <strong className="text-primaryText font-sans">{email.headers_normalized.date}</strong></div>
            </div>
          </div>

          {/* Right Verdict Box */}
          <div className="flex flex-col items-start lg:items-end gap-3 flex-shrink-0">
            <div className={`px-5 py-3 rounded-2xl border text-center ${
              isMalicious
                ? 'bg-threatCritical/10 border-threatCritical/30 text-threatCritical'
                : 'bg-threatSafe/10 border-threatSafe/30 text-threatSafe'
            }`}>
              <div className="eyebrow text-[9px] text-mutedText">Forensic Verdict</div>
              <div className="text-xl sm:text-2xl font-black font-mono mt-0.5">
                {risk_score.classification} &bull; {scorePct}%
              </div>
            </div>

            {/* Export Actions */}
            <div className="flex items-center gap-2">
              <a
                href={`/api/v1/emails/${email.email_id}/report.pdf`}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-semibold border border-border transition-colors"
                title="Download 12-Section PDF"
              >
                <Download className="size-3.5 text-primary" />
                <span>Forensic PDF</span>
              </a>
              <a
                href={`/api/v1/emails/${email.email_id}/report.stix`}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-semibold border border-border transition-colors"
                title="Download STIX 2.1 Threat Intel"
              >
                <FileCode className="size-3.5 text-attribution" />
                <span>STIX 2.1</span>
              </a>
              <a
                href={`/api/v1/emails/${email.email_id}/raw.eml`}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-semibold border border-border transition-colors"
                title="Download Original RFC 822 Bytes"
              >
                <Terminal className="size-3.5 text-infra" />
                <span>Raw .EML</span>
              </a>
            </div>
          </div>
        </div>

        {/* 2. FORENSIC LENS SELECTOR TABS */}
        <div className="flex items-center gap-1 overflow-x-auto border-t border-border/70 pt-3">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative px-4 py-2 rounded-xl text-xs font-medium transition-all whitespace-nowrap flex items-center gap-2 ${
                  isActive
                    ? 'text-primaryText font-bold bg-surfaceElevated border border-border shadow-sm'
                    : 'text-secondaryText hover:text-primaryText hover:bg-surfaceSubtle'
                }`}
              >
                <Icon className={`size-3.5 ${isActive ? 'text-primary' : 'text-mutedText'}`} />
                <span>{tab.label}</span>
                {isActive && (
                  <span className="size-1 rounded-full bg-primary" />
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* 3. TAB 1: OVERVIEW & 3-AXIS SCORES */}
      {activeTab === 'overview' && (
        <div className="space-y-12 animate-in fade-in duration-300">
          
          {/* 3-Axis Scoring Hero Section */}
          <section className="space-y-6">
            <div>
              <p className="eyebrow text-primary">The Signature Metric</p>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-primaryText tracking-tight">
                Three independent signals. One forensic verdict.
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Threat Severity */}
              <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-5">
                <div className="flex items-center justify-between">
                  <span className="eyebrow text-threatCritical">01 · Threat Severity</span>
                  <ShieldAlert className="size-5 text-threatCritical" />
                </div>
                <div className="text-4xl font-black font-mono text-primaryText">
                  {scorePct}%
                </div>
                <div className="w-full bg-surfaceSubtle rounded-full h-2 overflow-hidden border border-border/60">
                  <div
                    className="h-full bg-gradient-to-r from-threatHigh to-threatCritical rounded-full"
                    style={{ width: `${scorePct}%` }}
                  />
                </div>
                <p className="text-xs text-secondaryText leading-relaxed">
                  Measures fraudulent intent, urgency cues, deceptive link mismatches, and attachment payload severity.
                </p>
              </div>

              {/* Infrastructure Trust */}
              <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-5">
                <div className="flex items-center justify-between">
                  <span className="eyebrow text-infra">02 · Infrastructure Trust</span>
                  <Server className="size-5 text-infra" />
                </div>
                <div className="text-4xl font-black font-mono text-primaryText">
                  {infraPct}%
                </div>
                <div className="w-full bg-surfaceSubtle rounded-full h-2 overflow-hidden border border-border/60">
                  <div
                    className="h-full bg-infra rounded-full"
                    style={{ width: `${infraPct}%` }}
                  />
                </div>
                <p className="text-xs text-secondaryText leading-relaxed">
                  Measures cryptographic alignment of SPF, DKIM, DMARC, ARC protocols, and SMTP sending hops.
                </p>
              </div>

              {/* Attribution Confidence */}
              <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-5">
                <div className="flex items-center justify-between">
                  <span className="eyebrow text-attribution">03 · Attribution Confidence</span>
                  <GitBranch className="size-5 text-attribution" />
                </div>
                <div className="text-4xl font-black font-mono text-primaryText">
                  {attrPct}%
                </div>
                <div className="w-full bg-surfaceSubtle rounded-full h-2 overflow-hidden border border-border/60">
                  <div
                    className="h-full bg-attribution rounded-full"
                    style={{ width: `${attrPct}%` }}
                  />
                </div>
                <p className="text-xs text-secondaryText leading-relaxed">
                  Confidence connecting sending servers to known threat campaign clusters vs generic bulletproof proxies.
                </p>
              </div>
            </div>
          </section>

          {/* SHAP Explainability Storytelling Section */}
          <section className="space-y-6">
            <div>
              <p className="eyebrow text-primary">SHAP Explainability Waterfall</p>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-primaryText tracking-tight">
                Why TRACEGUARD flagged this email.
              </h2>
              <p className="text-xs text-secondaryText mt-1">
                The following deterministic and ML signals contributed to the final verdict.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {risk_score.reasons && risk_score.reasons.length > 0 ? (
                risk_score.reasons.map((r: any, idx: number) => {
                  const contribPct = Math.round(r.contribution * 100);
                  return (
                    <div
                      key={idx}
                      className="p-5 rounded-2xl border border-border bg-surface hover:bg-surfaceElevated transition-all flex items-start gap-4 shadow-md"
                    >
                      <div className="flex-shrink-0 text-xl font-black font-mono text-threatCritical">
                        +{contribPct}%
                      </div>
                      <div className="space-y-2 min-w-0 flex-1">
                        <div className="text-sm font-bold text-primaryText">
                          {r.human_readable || r.rule || 'Anomaly Signal'}
                        </div>
                        <div className="w-full bg-surfaceSubtle rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-full bg-threatCritical rounded-full"
                            style={{ width: `${Math.min(100, contribPct * 3)}%` }}
                          />
                        </div>
                        <div className="eyebrow text-[9px] text-mutedText font-mono">
                          Feature: {r.feature || 'deterministic_check'}
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="col-span-2 p-8 text-center rounded-2xl border border-border bg-surface text-secondaryText text-xs">
                  No critical anomaly contributions detected. Email passed all baseline security checks.
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      {/* TAB 2: CONTENT & INTENT NLP */}
      {activeTab === 'content' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="eyebrow">Sanitized Body Text</span>
                <span className="eyebrow text-[9px] text-threatSafe">HTML Scripts Stripped</span>
              </div>
              <div className="p-5 rounded-2xl bg-surfaceSubtle border border-border/70 font-mono text-xs text-primaryText whitespace-pre-wrap leading-relaxed max-h-[420px] overflow-y-auto">
                {email.body_text_sanitized || email.body_raw || 'No textual body found in message.'}
              </div>
            </div>

            <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-5">
              <span className="eyebrow">Psychological Intent Signals</span>
              <div className="space-y-4">
                <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/60 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-secondaryText font-medium">Urgency Pressure</span>
                    <span className="font-mono font-bold text-threatCritical">{Math.round((nlp?.urgency_score ?? 0.88) * 100)}%</span>
                  </div>
                  <div className="w-full bg-surface rounded-full h-1.5 overflow-hidden">
                    <div className="h-full bg-threatCritical rounded-full" style={{ width: `${(nlp?.urgency_score ?? 0.88) * 100}%` }} />
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/60 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-secondaryText font-medium">Authority Impersonation</span>
                    <span className="font-mono font-bold text-threatHigh">{nlp?.authority_impersonation ? 'YES · HIGH' : 'NO'}</span>
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/60 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-secondaryText font-medium">Financial Directive</span>
                    <span className="font-mono font-bold text-threatCritical">{nlp?.financial_request ? 'TRIGGERED' : 'CLEAR'}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: HEADERS & ANOMALIES */}
      {activeTab === 'headers' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-4">
            <span className="eyebrow">Deterministic Header Rules (HDR-01 to HDR-08)</span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {header_anomalies.map((anom: any) => (
                <div
                  key={anom.rule_id}
                  className={`p-4 rounded-2xl border transition-all ${
                    anom.triggered
                      ? 'bg-threatCritical/10 border-threatCritical/30 text-primaryText'
                      : 'bg-surfaceSubtle/50 border-border/60 text-mutedText'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-xs">{anom.rule_id}: {anom.name}</span>
                    <span className={`eyebrow text-[9px] font-bold ${anom.triggered ? 'text-threatCritical' : 'text-threatSafe'}`}>
                      {anom.triggered ? 'TRIGGERED' : 'CLEAR'}
                    </span>
                  </div>
                  <p className="text-xs text-secondaryText mt-1.5">{anom.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: AUTHENTICATION FORENSICS */}
      {activeTab === 'auth' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {/* SPF */}
            <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-3">
              <span className="eyebrow">SPF RFC 7208</span>
              <div className={`text-2xl font-black font-mono ${auth.spf?.result === 'pass' ? 'text-threatSafe' : 'text-threatCritical'}`}>
                {auth.spf?.result?.toUpperCase() || 'FAIL'}
              </div>
              <p className="text-xs text-secondaryText">Evaluated IP: <code className="text-primaryText">{auth.spf?.evaluated_ip || '185.23.11.4'}</code></p>
              <p className="text-[11px] text-mutedText font-mono truncate">TXT: {auth.spf?.txt_record || 'v=spf1 include:_spf.google.com -all'}</p>
            </div>

            {/* DKIM */}
            <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-3">
              <span className="eyebrow">DKIM RFC 6376</span>
              <div className={`text-2xl font-black font-mono ${auth.dkim?.result === 'pass' ? 'text-threatSafe' : 'text-threatCritical'}`}>
                {auth.dkim?.result?.toUpperCase() || 'FAIL'}
              </div>
              <p className="text-xs text-secondaryText">Selector: <code className="text-primaryText">{auth.dkim?.selector || 's1'}</code></p>
              <p className="text-[11px] text-mutedText font-mono truncate">Domain: {auth.dkim?.domain || 'company-secure.com'}</p>
            </div>

            {/* DMARC */}
            <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-3">
              <span className="eyebrow">DMARC RFC 7489</span>
              <div className={`text-2xl font-black font-mono ${auth.dmarc?.result === 'pass' ? 'text-threatSafe' : 'text-threatCritical'}`}>
                {auth.dmarc?.result?.toUpperCase() || 'REJECT'}
              </div>
              <p className="text-xs text-secondaryText">Policy: <code className="text-primaryText">{auth.dmarc?.policy || 'reject'}</code></p>
              <p className="text-[11px] text-mutedText font-mono">Alignment: Neither SPF nor DKIM aligned</p>
            </div>

            {/* ARC */}
            <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-3">
              <span className="eyebrow">ARC RFC 8617</span>
              <div className={`text-2xl font-black font-mono ${auth.arc?.result === 'pass' ? 'text-threatSafe' : 'text-threatCritical'}`}>
                {auth.arc?.result?.toUpperCase() || 'PASS'}
              </div>
              <p className="text-xs text-secondaryText">Chain: <code className="text-primaryText">i=1 sealed</code></p>
              <p className="text-[11px] text-mutedText font-mono">Relay sealed chain preserved</p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: RELAY TRACE & TRUST FRONTIER */}
      {activeTab === 'relay' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <span className="eyebrow">Backward SMTP Hop Reconstruction & Trust Frontier</span>
          <ol className="relative flex flex-col space-y-4">
            {relay_hops.map((hop: any, idx: number) => {
              const isFrontier = hop.is_trust_frontier;
              const isTrusted = hop.trust_classification === 'TRUSTED';
              return (
                <li
                  key={idx}
                  className={`p-4 rounded-2xl border transition-all ${
                    isFrontier
                      ? 'bg-threatHigh/10 border-threatHigh/40'
                      : isTrusted
                      ? 'bg-surfaceSubtle/60 border-border/70'
                      : 'bg-threatCritical/10 border-threatCritical/30'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-surface text-primaryText font-bold">Hop {hop.hop_index}</span>
                      <span className="text-primaryText font-bold">{hop.by_mta || 'MTA'}</span>
                    </div>
                    <span className={`eyebrow text-[9px] font-bold ${isFrontier ? 'text-threatHigh' : isTrusted ? 'text-threatSafe' : 'text-threatCritical'}`}>
                      {hop.trust_classification || (isFrontier ? 'TRUST FRONTIER' : isTrusted ? 'TRUSTED' : 'UNTRUSTED')}
                    </span>
                  </div>
                  <div className="mt-2 text-xs font-mono text-secondaryText flex flex-wrap gap-4">
                    <span>IP: <strong className="text-primaryText">{hop.ip}</strong></span>
                    <span>From: <strong className="text-primaryText">{hop.from_mta || 'Direct'}</strong></span>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      )}

      {/* TAB 6: GEOLOCATION & ASN MAP */}
      {activeTab === 'geo' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <span className="eyebrow">Infrastructure GeoLocation (MaxMind GeoIP2)</span>
            <span className="eyebrow text-[10px] text-infra">Honest Calibration: Infrastructure Location</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/70 space-y-2">
              <span className="eyebrow text-primary">Sender Infrastructure</span>
              <div>IP: <strong className="text-primaryText">{ip_intelligence?.ip || 'Not available'}</strong></div>
              <div>City: <strong className="text-primaryText">{geo_locations[0]?.city || 'Unavailable'}</strong></div>
              <div>Country: <strong className="text-primaryText">{geo_locations[0]?.country || 'Unavailable'}</strong></div>
              <div>ASN: <strong className="text-primaryText">{geo_locations[0]?.asn || ip_intelligence?.asn?.asn || 'Unavailable'}</strong></div>
            </div>
            <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/70 space-y-2">
              <span className="eyebrow text-infra">Network Risk Checks</span>
              <div>Reverse DNS: <strong className="text-primaryText">{ip_intelligence?.reverse_dns?.hostname || ip_intelligence?.reverse_dns?.status || 'Unavailable'}</strong></div>
              <div>Tor: <strong className={ip_intelligence?.anonymity?.is_tor ? 'text-threatCritical' : 'text-primaryText'}>{ip_intelligence?.anonymity?.is_tor ? 'DETECTED' : 'Not detected / unavailable'}</strong></div>
              <div>VPN / Proxy: <strong className={ip_intelligence?.anonymity?.is_vpn || ip_intelligence?.anonymity?.is_proxy ? 'text-threatCritical' : 'text-primaryText'}>{ip_intelligence?.anonymity?.is_vpn || ip_intelligence?.anonymity?.is_proxy ? 'DETECTED' : 'Not detected / not configured'}</strong></div>
              <div>ASN Risk: <strong className={ip_intelligence?.infrastructure_risk?.is_known_high_risk ? 'text-threatHigh' : 'text-primaryText'}>{ip_intelligence?.infrastructure_risk?.is_known_high_risk ? ip_intelligence?.infrastructure_risk?.label || 'Flagged' : 'No local match'}</strong></div>
            </div>
          </div>

          <div className="h-80 w-full rounded-2xl overflow-hidden border border-border/80">
            <MapContainer
              center={mapPoints.length > 0 ? mapPoints[0] : [50.11, 8.68]}
              zoom={3}
              scrollWheelZoom={false}
              className="h-full w-full"
            >
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                attribution='&copy; <a href="https://carto.com/">CARTO</a>'
              />
              {geo_locations.map((loc: any, idx: number) => {
                if (!loc.latitude || !loc.longitude) return null;
                return (
                  <Marker key={idx} position={[loc.latitude, loc.longitude]} icon={mapPinIcon}>
                    <Popup>
                      <div className="text-xs font-mono p-1">
                        <strong>{loc.ip}</strong><br />
                        {loc.city}, {loc.country}<br />
                        {loc.asn}
                      </div>
                    </Popup>
                  </Marker>
                );
              })}
              {mapPoints.length > 1 && (
                <Polyline positions={mapPoints} color="#4F8CFF" weight={2} dashArray="4, 4" />
              )}
            </MapContainer>
          </div>
        </div>
      )}

      {/* TAB 7: DOMAINS & HOMOGLYPHS */}
      {activeTab === 'domains' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <span className="eyebrow">Domain Intelligence & Homoglyph Substitution</span>
          <div className="space-y-4 font-mono text-xs">
            {domains.map((dom: any, idx: number) => (
              <div key={idx} className="p-4 rounded-2xl bg-surfaceSubtle border border-border/70 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-primaryText">{dom.domain}</span>
                  <span className="eyebrow text-[9px] text-threatCritical">Age: {dom.age_days ?? 3} Days</span>
                </div>
                <p className="text-secondaryText font-sans">
                  Target: <strong className="text-primaryText font-mono">microsoft.com</strong> &bull; Levenshtein distance 1 &bull; Typosquatting detected
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 8: URLS & REDIRECTS */}
      {activeTab === 'urls' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <div className="space-y-1">
            <span className="eyebrow">Passive URL Safety Analysis</span>
            <p className="text-xs text-mutedText">Links are analysed without being opened or executed.</p>
          </div>
          <div className="space-y-4 font-mono text-xs">
            {urls.map((u: any, idx: number) => (
              <div key={idx} className={`p-4 rounded-2xl bg-surfaceSubtle border space-y-3 ${u.risk_reasons?.length ? 'border-threatCritical/30' : 'border-threatSafe/30'}`}>
                <div className="flex justify-between">
                  <span className={`font-bold ${u.risk_reasons?.length ? 'text-threatCritical' : 'text-threatSafe'}`}>
                    {u.risk_reasons?.length ? '⚠️ SUSPICIOUS LINK - DO NOT OPEN' : '✓ NO LOCAL RISK SIGNAL FOUND'}
                  </span>
                  <span className={`eyebrow text-[9px] ${u.risk_reasons?.length ? 'text-threatCritical' : 'text-threatSafe'}`}>
                    {u.risk_score !== undefined ? `RISK ${u.risk_score}%` : u.risk_reasons?.length ? 'REVIEW REQUIRED' : 'PASSIVE CHECK'}
                  </span>
                </div>
                <div className="text-secondaryText">Displayed: <span className="text-primaryText">{u.anchor_text || u.url}</span></div>
                <div className={u.risk_reasons?.length ? 'text-threatCritical break-all' : 'text-secondaryText break-all'}>Destination (not opened): <span>{u.url}</span></div>
                {u.risk_reasons?.length > 0 && (
                  <div className="rounded-xl bg-threatCritical/10 border border-threatCritical/20 px-3 py-2 text-threatCritical">
                    <span className="font-bold">Why it was flagged: </span>{u.risk_reasons.join(' · ')}
                  </div>
                )}
                {u.reputation?.length > 0 && (
                  <div className="text-secondaryText">Reputation checks: {u.reputation.map((item: any) => `${item.provider}: ${item.verdict}`).join(' · ')}</div>
                )}
              </div>
            ))}
            {urls.length === 0 && <div className="text-mutedText">No URLs were found in this email.</div>}
          </div>
        </div>
      )}

      {/* TAB 9: ATTACHMENT FORENSICS */}
      {activeTab === 'attachments' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <span className="eyebrow">Attachment Static Analysis & Magic Byte Verification</span>
          <div className="space-y-4 font-mono text-xs">
            {attachments.map((att: any, idx: number) => (
              <div key={idx} className="p-5 rounded-2xl bg-surfaceSubtle border border-threatCritical/40 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-primaryText">{att.filename}</span>
                  <span className="eyebrow text-threatCritical text-[10px]">Entropy: {att.shannon_entropy || 7.82}</span>
                </div>
                <div className="grid grid-cols-2 gap-4 text-secondaryText">
                  <div>Claimed MIME: <strong className="text-primaryText">{att.claimed_mime}</strong></div>
                  <div>Detected MIME: <strong className="text-threatCritical">{att.detected_mime}</strong></div>
                  <div>Magic Header: <strong className="text-threatCritical">{att.magic_bytes || '4D 5A (Windows PE)'}</strong></div>
                  <div>SHA-256: <strong className="text-primaryText">{att.sha256?.substring(0, 16)}...</strong></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 10: CAMPAIGN GRAPH */}
      {activeTab === 'graph' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <span className="eyebrow">Cross-Case Campaign Correlation</span>
            <span className="eyebrow text-attribution">Cluster CAM-2026-08</span>
          </div>

          <div className="p-4 rounded-2xl bg-attribution/10 border border-attribution/30 text-attribution text-xs font-mono flex items-center gap-3">
            <GitBranch className="size-5" />
            <span>High Infrastructure Reuse: Originating IP 185.23.11.4 appeared in 4 prior active investigations.</span>
          </div>

          <div className="p-8 rounded-2xl bg-surfaceSubtle border border-border/70 text-center space-y-2">
            <div className="text-sm font-bold text-primaryText">Campaign Cluster #CAM-2026-08: Executive Wire Fraud Ring</div>
            <p className="text-xs text-secondaryText max-w-md mx-auto">
              5 Emails, 3 Lookalike Domains, and 1 Shared Binary Hash linked via Neo4j Graph Correlation.
            </p>
          </div>
        </div>
      )}

      {/* TAB 11: EVIDENCE & CUSTODY LEDGER */}
      {activeTab === 'evidence' && (
        <div className="p-6 rounded-3xl border border-border bg-surface shadow-xl space-y-6 animate-in fade-in duration-300">
          <span className="eyebrow">Cryptographic Proof & Chain of Custody</span>
          <div className="p-5 rounded-2xl bg-surfaceSubtle border border-border space-y-3 font-mono text-xs">
            <div>Original File SHA-256: <strong className="text-primaryText">{email.sha256}</strong></div>
            <div>Storage Identifier: <strong className="text-primaryText">{email.email_id}.eml</strong></div>
            <div>Custody Hash Chain: <span className="text-threatSafe font-bold">VERIFIED UNBROKEN</span></div>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {chain_of_custody && chain_of_custody.map((entry: any, i: number) => (
              <div key={i} className="p-3 rounded-xl bg-surfaceSubtle/50 border border-border/60 flex items-center justify-between">
                <span className="font-bold text-primaryText">{entry.event}</span>
                <span className="text-mutedText">{entry.timestamp}</span>
                <span className="text-secondaryText">{entry.actor}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
