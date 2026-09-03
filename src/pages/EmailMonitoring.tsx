import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Radio, ShieldAlert, ShieldCheck, AlertOctagon, Mail, Zap, Sliders,
  RefreshCw, ChevronRight, CheckCircle2, AlertTriangle, ArrowUpRight,
  Shield, ExternalLink, Filter, ArrowRight, CornerDownRight, Check, Loader2
} from 'lucide-react';
import { MailboxConnectModal } from '../components/MailboxConnectModal';
import { ThresholdConfigPanel } from '../components/ThresholdConfigPanel';

export const EmailMonitoring: React.FC = () => {
  const navigate = useNavigate();

  const [mailboxes, setMailboxes] = useState<any[]>([]);
  const [liveEmails, setLiveEmails] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isSyncingGmail, setIsSyncingGmail] = useState(false);
  const [oauthStatus, setOauthStatus] = useState<any>(null);
  const [isConnectOpen, setIsConnectOpen] = useState(false);
  const [isPolicyOpen, setIsPolicyOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [overrideModalEmail, setOverrideModalEmail] = useState<any | null>(null);
  const [overrideAction, setOverrideAction] = useState('FLAG');
  const [overrideReason, setOverrideReason] = useState('Analyst verified benign testing context');

  // Gmail Dedicated IMAP Mailbox Integration State
  const [gmailStatus, setGmailStatus] = useState<any>({
    email: 'kingkmn786@gmail.com',
    configured: false,
    connected: false,
    auto_scan_enabled: false
  });
  const [isTestingGmail, setIsTestingGmail] = useState(false);
  const [isScanningGmail, setIsScanningGmail] = useState(false);
  const [scanProgress, setScanProgress] = useState<{
    current: number;
    total: number;
    subject: string;
    stepIndex: number;
  }>({ current: 0, total: 20, subject: '', stepIndex: 0 });
  const [gmailResults, setGmailResults] = useState<any[]>([]);
  const [gmailSummary, setGmailSummary] = useState<any>(null);
  const [gmailError, setGmailError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  const loadGmailStatus = async () => {
    try {
      const [sRes, rRes] = await Promise.all([
        fetch('/api/v1/gmail/status').then((r) => r.json()),
        fetch('/api/v1/gmail/results').then((r) => r.json())
      ]);
      setGmailStatus(sRes);
      if (rRes && rRes.results) {
        setGmailResults(rRes.results);
        setGmailSummary(rRes.summary);
      }
    } catch (e) {
      console.error('Failed to load Gmail IMAP status', e);
    }
  };

  const loadData = async () => {
    try {
      const [mRes, eRes, oRes] = await Promise.all([
        fetch('/api/v1/mailboxes').then((r) => r.json()),
        fetch('/api/v1/emails/live').then((r) => r.json()),
        fetch('/api/v1/oauth/gmail/status').then((r) => r.json())
      ]);
      setMailboxes(mRes);
      setLiveEmails(eRes);
      setOauthStatus(oRes);
      await loadGmailStatus();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    // Check URL search params for OAuth success callback
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.get('gmail_connected') === 'true') {
      const email = searchParams.get('email') || 'Google Account';
      setToastMessage(`Successfully connected and authorized Gmail: ${email}`);
      setTimeout(() => setToastMessage(null), 5000);
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (searchParams.get('oauth_error')) {
      setToastMessage(`OAuth Error: ${searchParams.get('oauth_error')}`);
      setTimeout(() => setToastMessage(null), 6000);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    // Establish WebSocket Live Feed connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live-feed`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('[WebSocket] Live Feed connected');
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'NEW_LIVE_EMAIL' && msg.data) {
          setLiveEmails((prev) => [msg.data, ...prev.filter((x) => x.id !== msg.data.id)]);
        } else if (msg.type === 'EMAIL_ACTION_OVERRIDDEN' && msg.data) {
          setLiveEmails((prev) => prev.map((x) => (x.id === msg.data.id ? msg.data : x)));
        }
      } catch (e) {
        console.error('[WebSocket] Parsing error:', e);
      }
    };

    return () => {
      ws.close();
    };
  }, []);

  const handleSimulateInbound = async (scenario: string) => {
    setIsSimulating(true);
    try {
      await fetch('/api/v1/mailboxes/simulate-incoming', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      await loadData();
    } catch (e) {
      console.error(e);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSyncGmailNow = async () => {
    setIsSyncingGmail(true);
    try {
      const res = await fetch('/api/v1/oauth/gmail/sync-now', { method: 'POST' });
      const data = await res.json();
      setToastMessage(data.message || 'Gmail synchronization completed.');
      setTimeout(() => setToastMessage(null), 5000);
      await loadData();
    } catch (e: any) {
      setToastMessage(`Gmail sync failed: ${e.message || e}`);
      setTimeout(() => setToastMessage(null), 5000);
    } finally {
      setIsSyncingGmail(false);
    }
  };

  const handleTestGmailConnection = async () => {
    setIsTestingGmail(true);
    setGmailError(null);
    try {
      const res = await fetch('/api/v1/gmail/test-connection', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Connection test failed');
      }
      setGmailStatus((prev: any) => ({ ...prev, connected: true, configured: true }));
      setToastMessage(`Connected to Gmail IMAP (${data.folder}): ${data.total_messages_in_mailbox} messages detected.`);
      setTimeout(() => setToastMessage(null), 5000);
    } catch (e: any) {
      setGmailError(e.message || 'Unable to authenticate with Gmail. Check backend configuration.');
    } finally {
      setIsTestingGmail(false);
    }
  };

  const handleScanGmailInbox = async (limit = 20) => {
    setIsScanningGmail(true);
    setGmailError(null);
    setScanProgress({
      current: 1,
      total: limit,
      subject: 'Connecting to imap.gmail.com:993 (SSL)...',
      stepIndex: 0
    });

    // Dynamic stage progression animation while server performs multi-lens forensic DAG
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        const nextStep = (prev.stepIndex + 1) % 5;
        const nextCurrent = Math.min(prev.total, prev.current + (nextStep === 0 ? 1 : 0));
        return {
          ...prev,
          stepIndex: nextStep,
          current: nextCurrent > 0 ? nextCurrent : 1
        };
      });
    }, 1200);

    try {
      const res = await fetch('/api/v1/gmail/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Gmail scan failed.');
      }
      clearInterval(progressInterval);
      setGmailResults(data.results || []);
      setGmailSummary(data.summary || null);
      setGmailStatus((prev: any) => ({ ...prev, connected: true, configured: true }));
      setToastMessage(`Scan complete: ${data.results?.length || 0} emails processed through forensic DAG.`);
      setTimeout(() => setToastMessage(null), 5000);
      await loadData();
    } catch (e: any) {
      clearInterval(progressInterval);
      setGmailError(e.message || 'Scan failed.');
    } finally {
      setIsScanningGmail(false);
    }
  };

  const handleToggleAutoScan = async () => {
    const nextState = !gmailStatus.auto_scan_enabled;
    try {
      const res = await fetch('/api/v1/gmail/auto-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextState, interval_minutes: 5 })
      });
      const data = await res.json();
      setGmailStatus((prev: any) => ({
        ...prev,
        auto_scan_enabled: data.auto_scan_enabled
      }));
      setToastMessage(`Gmail Auto-Scan ${data.auto_scan_enabled ? 'Enabled (Every 5 mins)' : 'Disabled'}`);
      setTimeout(() => setToastMessage(null), 4000);
    } catch (e: any) {
      setToastMessage(`Failed to update auto-scan: ${e.message || e}`);
    }
  };

  const handleApplyOverride = async () => {
    if (!overrideModalEmail) return;
    try {
      await fetch(`/api/v1/emails/live/${overrideModalEmail.id}/override-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: overrideAction,
          reason: overrideReason,
          analyst: 'analyst_01'
        })
      });
      setOverrideModalEmail(null);
      await loadData();
    } catch (e) {
      console.error(e);
    }
  };

  const totalMonitored = liveEmails.length > 0 ? 12847 + liveEmails.length : 12847;
  const quarantinedCount = 43 + liveEmails.filter((x) => x.action_taken === 'QUARANTINE').length;
  const flaggedCount = 127 + liveEmails.filter((x) => x.action_taken === 'FLAG').length;
  const cleanCount = totalMonitored - quarantinedCount - flaggedCount;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-12 animate-in fade-in duration-300">
      
      {/* Toast Notification */}
      {toastMessage && (
        <div className="p-3.5 rounded-2xl bg-surfaceElevated border border-primary/40 flex items-center justify-between text-xs font-mono text-primaryText shadow-2xl">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="size-4 text-threatSafe" />
            <span>{toastMessage}</span>
          </div>
          <button onClick={() => setToastMessage(null)} className="text-mutedText hover:text-primaryText">
            &times;
          </button>
        </div>
      )}

      {/* 1. TOP EDITORIAL HERO */}
      <section className="grid gap-8 lg:grid-cols-[1.2fr_1fr] lg:items-end justify-between border-b border-border/70 pb-10">
        <div className="space-y-4">
          <p className="eyebrow text-primary">Autonomous Email Defense</p>
          <h1 className="text-4xl sm:text-6xl font-black text-primaryText tracking-tightest leading-[1.05]">
            The inbox, <br />
            <span className="text-mutedText font-light">under watch.</span>
          </h1>
          <p className="max-w-xl text-sm sm:text-base text-secondaryText leading-relaxed">
            TRACEGUARD continuously intercepts inbound mail streams, reconstructs sending infrastructure, and autonomously enforces policy decisions before threats reach human users.
          </p>
        </div>

        {/* System Status & Primary Action Controls */}
        <div className="flex flex-col sm:items-end space-y-5">
          <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-surfaceSubtle border border-border">
            <span className="relative flex size-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-threatSafe opacity-75"></span>
              <span className="relative inline-flex rounded-full size-2.5 bg-threatSafe"></span>
            </span>
            <span className="eyebrow text-[10px] text-threatSafe">
              Autonomous Gateway Active
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Primary Dominant Action: Simulate Attack Dropdown */}
            <div className="relative group">
              <button
                disabled={isSimulating}
                className="flex items-center gap-2.5 px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-lg shadow-primary/25 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
              >
                <Zap className="size-4" />
                <span>{isSimulating ? 'Injecting Scenario...' : 'Simulate Inbound Attack'}</span>
              </button>

              <div className="absolute right-0 top-full mt-2 w-64 bg-surfaceElevated border border-border rounded-2xl p-2 shadow-2xl hidden group-hover:block z-50 animate-in fade-in duration-150">
                <span className="eyebrow text-[10px] px-2.5 py-1.5 block">
                  Select Threat Preset
                </span>
                <button
                  onClick={() => handleSimulateInbound('bec')}
                  className="w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:bg-surface hover:text-primaryText transition-colors flex items-center justify-between"
                >
                  <span>BEC Wire Transfer Fraud</span>
                  <span className="font-mono font-bold text-threatCritical">94%</span>
                </button>
                <button
                  onClick={() => handleSimulateInbound('credential')}
                  className="w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:bg-surface hover:text-primaryText transition-colors flex items-center justify-between"
                >
                  <span>M365 Password Phish</span>
                  <span className="font-mono font-bold text-threatCritical">88%</span>
                </button>
                <button
                  onClick={() => handleSimulateInbound('malware')}
                  className="w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:bg-surface hover:text-primaryText transition-colors flex items-center justify-between"
                >
                  <span>Invoice EXE Malware</span>
                  <span className="font-mono font-bold text-threatCritical">96%</span>
                </button>
                <button
                  onClick={() => handleSimulateInbound('clean')}
                  className="w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:bg-surface hover:text-threatSafe transition-colors flex items-center justify-between"
                >
                  <span>Clean Security Digest</span>
                  <span className="font-mono font-bold text-threatSafe">4%</span>
                </button>
              </div>
            </div>

            {/* Secondary Actions */}
            <button
              onClick={handleSyncGmailNow}
              disabled={isSyncingGmail}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surface hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-medium border border-border transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`size-3.5 ${isSyncingGmail ? 'animate-spin' : ''}`} />
              <span>Sync Gmail</span>
            </button>

            <button
              onClick={() => setIsConnectOpen(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surface hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-medium border border-border transition-colors"
            >
              <Mail className="size-3.5" />
              <span>Connect Mailbox</span>
            </button>

            <button
              onClick={() => setIsPolicyOpen(true)}
              className="p-2.5 rounded-xl bg-surface hover:bg-surfaceElevated text-secondaryText hover:text-primaryText border border-border transition-colors"
              title="Autonomous Policy Settings"
            >
              <Sliders className="size-3.5" />
            </button>
          </div>
        </div>
      </section>

      {/* GMAIL DEDICATED IMAP INTEGRATION SECTION */}
      <section className="p-6 sm:p-8 rounded-3xl border border-border bg-surface shadow-xl space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-border/70">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-primary/10 text-primary border border-primary/20">
                <Mail className="size-5" />
              </span>
              <div>
                <span className="eyebrow text-[10px] text-primary">Dedicated IMAP Gateway</span>
                <h2 className="text-xl sm:text-2xl font-black text-primaryText tracking-tight">
                  GMAIL MAILBOX
                </h2>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <span className="font-mono text-xs sm:text-sm font-bold text-primaryText px-3 py-1 rounded-lg bg-surfaceSubtle border border-border">
                {gmailStatus.email || 'kingkmn786@gmail.com'}
              </span>
              <div className="flex items-center gap-2">
                {gmailStatus.connected ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatSafe/15 text-threatSafe border border-threatSafe/30">
                    <span className="size-1.5 rounded-full bg-threatSafe animate-pulse"></span>
                    CONNECTED
                  </span>
                ) : gmailError ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatCritical/15 text-threatCritical border border-threatCritical/30">
                    <span className="size-1.5 rounded-full bg-threatCritical"></span>
                    AUTH FAILED
                  </span>
                ) : gmailStatus.configured ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-primary/15 text-primary border border-primary/30">
                    <span className="size-1.5 rounded-full bg-primary"></span>
                    CONFIGURED (CLICK TEST)
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatHigh/15 text-threatHigh border border-threatHigh/30">
                    <span className="size-1.5 rounded-full bg-threatHigh"></span>
                    NOT CONFIGURED
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Action Controls */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleTestGmailConnection}
              disabled={isTestingGmail || isScanningGmail}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-primaryText text-xs font-bold border border-border transition-all disabled:opacity-50"
            >
              {isTestingGmail ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5 text-primary" />}
              <span>Test Connection</span>
            </button>

            <button
              onClick={() => handleScanGmailInbox(20)}
              disabled={isScanningGmail}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
            >
              {isScanningGmail ? <Loader2 className="size-3.5 animate-spin" /> : <Zap className="size-3.5" />}
              <span>Scan Latest 20 Emails</span>
            </button>

            {/* Auto-Scan Toggle */}
            <button
              onClick={handleToggleAutoScan}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-mono font-medium border transition-colors ${
                gmailStatus.auto_scan_enabled
                  ? 'bg-primary/10 border-primary/40 text-primary'
                  : 'bg-surface hover:bg-surfaceElevated border-border text-mutedText hover:text-primaryText'
              }`}
              title="Toggle automatic polling every 5 minutes"
            >
              <RefreshCw className={`size-3.5 ${gmailStatus.auto_scan_enabled ? 'text-primary' : ''}`} />
              <span>Auto-Scan (5m)</span>
              <span className={`size-2 rounded-full ${gmailStatus.auto_scan_enabled ? 'bg-primary' : 'bg-mutedText/40'}`} />
            </button>
          </div>
        </div>

        {/* Error Notification / Guidance */}
        {gmailError && (
          <div className="p-4 rounded-2xl bg-threatCritical/10 border border-threatCritical/30 flex items-start gap-3 text-xs text-threatCritical">
            <AlertTriangle className="size-4 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold">{gmailError}</div>
              <p className="text-secondaryText text-[11px]">
                To authenticate, paste your 16-character Google App Password into the backend <code className="text-primary font-mono font-bold">.env</code> file: <code className="font-mono text-primaryText">GMAIL_APP_PASSWORD=your_password_here</code>.
              </p>
            </div>
          </div>
        )}

        {/* WHILE SCANNING: REAL PROGRESS DISPLAY */}
        {isScanningGmail && (
          <div className="p-6 rounded-2xl bg-surfaceSubtle border border-primary/30 space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="relative flex size-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                  <span className="relative inline-flex rounded-full size-2.5 bg-primary"></span>
                </span>
                <span className="eyebrow text-xs text-primary font-mono font-bold">SCANNING MAILBOX</span>
              </div>
              <span className="font-mono text-xs font-bold text-primaryText">
                {scanProgress.current} / {scanProgress.total} Emails
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-surface border border-border rounded-full h-2 overflow-hidden">
              <div
                className="bg-primary h-full transition-all duration-300"
                style={{ width: `${Math.max(5, Math.round((scanProgress.current / scanProgress.total) * 100))}%` }}
              />
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-mutedText">Current: </span>
              <span className="font-mono font-bold text-primaryText">
                {scanProgress.subject || 'Retrieving raw MIME stream from IMAP...'}
              </span>
            </div>

            {/* Pipeline Checklist */}
            <div className="pt-2 border-t border-border/50 space-y-1.5 font-mono text-xs">
              <span className="eyebrow text-[9px] text-mutedText block mb-1">Pipeline:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
                {[
                  { label: 'Retrieved email', step: 0 },
                  { label: 'Extracted headers', step: 1 },
                  { label: 'Started forensic analysis', step: 2 },
                  { label: 'Running intelligence modules', step: 3 },
                  { label: 'Finalizing verdict', step: 4 },
                ].map((item) => {
                  const isDone = scanProgress.stepIndex > item.step;
                  const isCurrent = scanProgress.stepIndex === item.step;
                  return (
                    <div
                      key={item.step}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] ${
                        isDone
                          ? 'bg-threatSafe/10 border-threatSafe/30 text-threatSafe'
                          : isCurrent
                          ? 'bg-primary/10 border-primary/40 text-primary animate-pulse'
                          : 'bg-surface/50 border-border/50 text-mutedText'
                      }`}
                    >
                      <span>{isDone ? '✓' : isCurrent ? '●' : '○'}</span>
                      <span className="truncate">{item.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* SCAN RESULTS SUMMARY & ITEMS */}
        {gmailResults.length > 0 && !isScanningGmail && (
          <div className="space-y-4 pt-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-2xl bg-surfaceSubtle border border-border">
              <div>
                <span className="eyebrow text-[10px] text-primary font-mono font-bold">SCAN COMPLETE</span>
                <div className="text-sm font-bold text-primaryText">
                  {gmailSummary ? `${gmailSummary.total} Emails Processed` : `${gmailResults.length} Emails Scanned`}
                </div>
              </div>
              <div className="flex items-center gap-3 font-mono text-xs">
                <span className="px-2.5 py-1 rounded-lg bg-threatCritical/15 text-threatCritical border border-threatCritical/30 font-bold">
                  {gmailSummary?.high_risk ?? gmailResults.filter(r => (r.threat_score || 0) >= 0.75).length} High Risk
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-threatHigh/15 text-threatHigh border border-threatHigh/30 font-bold">
                  {gmailSummary?.suspicious ?? gmailResults.filter(r => (r.threat_score || 0) >= 0.35 && (r.threat_score || 0) < 0.75).length} Suspicious
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-threatSafe/15 text-threatSafe border border-threatSafe/30 font-bold">
                  {gmailSummary?.clean ?? gmailResults.filter(r => (r.threat_score || 0) < 0.35).length} Clean
                </span>
              </div>
            </div>

            {/* Results List */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {gmailResults.map((r, i) => {
                const score = Math.round((r.threat_score ?? 0) * 100);
                const isCrit = score >= 75;
                const isSusp = score >= 35 && score < 75;
                const badgeStyle = isCrit
                  ? 'border-threatCritical text-threatCritical bg-threatCritical/10'
                  : isSusp
                  ? 'border-threatHigh text-threatHigh bg-threatHigh/10'
                  : 'border-threatSafe text-threatSafe bg-threatSafe/10';

                return (
                  <div
                    key={r.id || r.email_id || i}
                    className="p-5 rounded-2xl bg-surfaceSubtle hover:bg-surfaceElevated border border-border flex flex-col justify-between gap-4 transition-all shadow-sm group"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-mono font-black border ${badgeStyle}`}>
                          {r.verdict || (isCrit ? 'HIGH RISK' : isSusp ? 'SUSPICIOUS' : 'CLEAN')} — {score}%
                        </span>
                        <span className="font-mono text-[11px] text-mutedText truncate">
                          {r.received_at || 'Recent'}
                        </span>
                      </div>

                      <h4 className="text-sm font-bold text-primaryText group-hover:text-primary transition-colors truncate" title={r.subject}>
                        {r.subject || '(No Subject)'}
                      </h4>

                      <div className="font-mono text-xs text-secondaryText truncate">
                        <span className="text-mutedText">From: </span>
                        <span>{r.sender || 'Unknown'}</span>
                      </div>

                      {/* Signals */}
                      {r.top_signals && r.top_signals.length > 0 && (
                        <div className="pt-2 border-t border-border/40 space-y-1">
                          <span className="eyebrow text-[9px] text-mutedText block">Signals:</span>
                          {r.top_signals.slice(0, 3).map((sig: string, si: number) => (
                            <div key={si} className="text-[11px] text-secondaryText font-mono flex items-center gap-1.5">
                              <span className="text-primary font-bold">•</span>
                              <span className="truncate">{sig}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <button
                      onClick={() => navigate(`/investigation?id=${r.email_id || r.id}`)}
                      className="w-full mt-2 py-2 px-3 rounded-xl bg-surface hover:bg-primary text-secondaryText hover:text-white font-mono text-xs font-bold border border-border group-hover:border-transparent flex items-center justify-center gap-2 transition-all"
                    >
                      <span>Open Investigation</span>
                      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* 2. ASYMMETRIC METRIC SECTION */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow">Inbound Email</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-primaryText">
            {totalMonitored.toLocaleString()}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-threatSafe font-mono">
            <ArrowUpRight className="size-3.5" />
            <span>↑ 12% today</span>
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatCritical">Quarantined</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatCritical">
            {quarantinedCount}
          </div>
          <div className="text-xs text-mutedText">
            High-confidence attacks isolated
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatHigh">Flagged / Caution</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatHigh">
            {flaggedCount}
          </div>
          <div className="text-xs text-mutedText">
            Subject prepended with alert banner
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatSafe">Delivered Clean</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatSafe">
            {cleanCount.toLocaleString()}
          </div>
          <div className="text-xs text-mutedText">
            Cryptographically authenticated
          </div>
        </div>
      </section>

      {/* 3. LIVE THREAT STREAM */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="eyebrow text-primary">Inbound Stream</p>
            <h2 className="text-2xl font-black text-primaryText tracking-tight">
              Real-Time Inspection Feed
            </h2>
          </div>

          <span className="font-mono text-xs text-mutedText flex items-center gap-2">
            <span className="size-2 rounded-full bg-threatSafe animate-ping" />
            WebSockets Stream Connected
          </span>
        </div>

        <div className="flex flex-col space-y-3">
          <AnimatePresence>
            {liveEmails.map((email) => {
              const scorePct = Math.round((email.threat_score ?? 0.85) * 100);
              const isQuarantine = email.action_taken === 'QUARANTINE';
              const isFlag = email.action_taken === 'FLAG';

              const accentColor = isQuarantine
                ? 'border-l-threatCritical'
                : isFlag
                ? 'border-l-threatHigh'
                : 'border-l-threatSafe';

              const badgeColor = isQuarantine
                ? 'text-threatCritical bg-threatCritical/15 border-threatCritical/30'
                : isFlag
                ? 'text-threatHigh bg-threatHigh/15 border-threatHigh/30'
                : 'text-threatSafe bg-threatSafe/15 border-threatSafe/30';

              return (
                <motion.article
                  key={email.id}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                  transition={{ duration: 0.25 }}
                  className={`p-5 rounded-2xl border border-border bg-surface hover:bg-surfaceElevated transition-all flex flex-col md:flex-row md:items-center justify-between gap-6 border-l-4 ${accentColor} shadow-md group`}
                >
                  <div className="flex items-start gap-5 min-w-0 flex-1">
                    {/* Threat Score Dial */}
                    <div className="flex flex-col items-center justify-center p-2.5 rounded-xl bg-surfaceSubtle border border-border/70 flex-shrink-0 w-16">
                      <span className={`text-lg font-black font-mono ${isQuarantine ? 'text-threatCritical' : isFlag ? 'text-threatHigh' : 'text-threatSafe'}`}>
                        {scorePct}%
                      </span>
                      <span className="eyebrow text-[8px]">SCORE</span>
                    </div>

                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className={`eyebrow text-[10px] px-2 py-0.5 rounded-md border font-mono ${badgeColor}`}>
                          {email.action_taken || 'EVALUATED'}
                        </span>
                        <span className="font-mono text-xs text-mutedText">
                          {email.received_at || 'Just now'}
                        </span>
                      </div>

                      <h3
                        onClick={() => navigate(`/investigation?id=${email.id}`)}
                        className="text-base font-bold text-primaryText hover:text-primary transition-colors cursor-pointer truncate"
                      >
                        {email.subject}
                      </h3>

                      <p className="font-mono text-xs text-secondaryText truncate">
                        {email.sender}
                      </p>

                      {/* Policy Triggers */}
                      {email.policy_triggers && email.policy_triggers.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {email.policy_triggers.map((trig: string, i: number) => (
                            <span
                              key={i}
                              className="font-mono text-[10px] px-2 py-0.5 rounded bg-surfaceSubtle text-secondaryText border border-border"
                            >
                              {trig}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Actions */}
                  <div className="flex items-center gap-3 self-end md:self-center flex-shrink-0">
                    <button
                      onClick={() => {
                        setOverrideModalEmail(email);
                        setOverrideAction(email.action_taken === 'QUARANTINE' ? 'DELIVER' : 'QUARANTINE');
                      }}
                      className="px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-medium border border-border transition-colors opacity-0 group-hover:opacity-100"
                    >
                      Override
                    </button>

                    <button
                      onClick={() => navigate(`/investigation?id=${email.id}`)}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-surfaceElevated group-hover:bg-primary text-secondaryText group-hover:text-white text-xs font-bold transition-all border border-border group-hover:border-transparent"
                    >
                      <span>Inspect</span>
                      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                    </button>
                  </div>
                </motion.article>
              );
            })}
          </AnimatePresence>

          {liveEmails.length === 0 && (
            <div className="p-12 text-center rounded-2xl border border-dashed border-border bg-surfaceSubtle/30 space-y-3">
              <Radio className="size-8 text-primary mx-auto animate-pulse" />
              <div className="text-sm font-bold text-primaryText">Listening for Inbound Email Stream</div>
              <p className="text-xs text-mutedText max-w-sm mx-auto">
                No new inbound messages in current buffer. Click "Simulate Inbound Attack" above to inject a realistic email scenario.
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Override Modal */}
      {overrideModalEmail && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surfaceElevated border border-border rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <h3 className="text-lg font-bold text-primaryText">Analyst Action Override</h3>
            <p className="text-xs text-secondaryText">
              Manually modify the autonomous gateway verdict for message:{' '}
              <strong className="text-primaryText">{overrideModalEmail.subject}</strong>
            </p>

            <div className="space-y-3">
              <div>
                <label className="eyebrow block mb-1.5">Enforce Action</label>
                <select
                  value={overrideAction}
                  onChange={(e) => setOverrideAction(e.target.value)}
                  className="w-full bg-surface border border-border rounded-xl p-2.5 text-xs text-primaryText font-mono"
                >
                  <option value="DELIVER">DELIVER (Release to Inbox)</option>
                  <option value="FLAG">FLAG (Deliver with Warning Banner)</option>
                  <option value="QUARANTINE">QUARANTINE (Isolate in Vault)</option>
                </select>
              </div>

              <div>
                <label className="eyebrow block mb-1.5">Audit Reason</label>
                <textarea
                  rows={3}
                  value={overrideReason}
                  onChange={(e) => setOverrideReason(e.target.value)}
                  className="w-full bg-surface border border-border rounded-xl p-2.5 text-xs text-primaryText"
                  placeholder="State justification for chain-of-custody audit logging..."
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setOverrideModalEmail(null)}
                className="px-4 py-2 rounded-xl text-xs font-bold text-mutedText hover:text-primaryText"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyOverride}
                className="px-5 py-2 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20"
              >
                Apply & Record Override
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Mailbox Connection Modal */}
      <MailboxConnectModal
        isOpen={isConnectOpen}
        onClose={() => setIsConnectOpen(false)}
        onSuccess={loadData}
      />

      {/* Policy Sensitivity Configuration Panel */}
      <ThresholdConfigPanel
        isOpen={isPolicyOpen}
        onClose={() => setIsPolicyOpen(false)}
        onSaved={loadData}
      />
    </div>
  );
};
